use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use sentinel_agent_llm::{
    AnthropicBackend, CapabilityRegistry, LlmBackend, OpenAiBackend, ReasoningConfig, ReasoningLoop,
};
use sentinel_audit::AuditLog;
use sentinel_capabilities::all_capabilities;
use sentinel_core::ApprovalDecision;
use sentinel_exec::RealCommandExecutor;
use sentinel_policy::default_policy;
use tokio::sync::Mutex;
use uuid::Uuid;

use sentinel_tui::{
    app::App,
    event_handler::{handle_events, AppEvent},
    ui,
};

#[derive(Parser)]
#[command(name = "sentinel", version, about = "Agentic system administration tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Anthropic API key (can also be set via ANTHROPIC_API_KEY env var)
    #[arg(long, env = "ANTHROPIC_API_KEY", global = true)]
    anthropic_api_key: Option<String>,

    /// OpenAI API key (can also be set via OPENAI_API_KEY env var)
    #[arg(long, env = "OPENAI_API_KEY", global = true)]
    openai_api_key: Option<String>,

    /// LLM backend to use
    #[arg(long, default_value = "anthropic", global = true)]
    backend: String,

    /// Model identifier
    #[arg(long, default_value = "claude-opus-4-7", global = true)]
    model: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", global = true)]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Start an interactive session with a goal
    Run {
        /// Operational goal to achieve
        #[arg(help = "Operational goal to achieve")]
        goal: String,
        /// Target host
        #[arg(long, default_value = "localhost")]
        host: String,
        /// Enable dry-run mode (no real changes made)
        #[arg(long)]
        dry_run: bool,
        /// Skip the interactive approval prompt and execute immediately
        #[arg(long)]
        auto_approve: bool,
    },
    /// List available capabilities
    Capabilities,
    /// Show current policy rules
    Policy,
    /// Verify an audit log file
    VerifyAudit {
        path: std::path::PathBuf,
    },
    /// Launch the interactive TUI
    Tui {
        /// Target host
        #[arg(long, default_value = "localhost")]
        host: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    fmt()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .init();

    match cli.command.unwrap_or(Commands::Tui {
        host: "localhost".into(),
    }) {
        Commands::Tui { host } => run_tui(host).await?,
        Commands::Capabilities => list_capabilities(),
        Commands::Policy => show_policy(),
        Commands::VerifyAudit { path } => verify_audit(&path)?,
        Commands::Run {
            goal,
            host,
            dry_run,
            auto_approve,
        } => {
            run_agent(
                goal,
                host,
                dry_run,
                auto_approve,
                &cli.backend,
                cli.anthropic_api_key.as_deref(),
                cli.openai_api_key.as_deref(),
                &cli.model,
            )
            .await?
        }
    }

    Ok(())
}

// ── TUI entry point ───────────────────────────────────────────────────────────

async fn run_tui(host: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    app.set_status(format!(
        "Welcome to Sentinel! Target host: {}. Enter a goal and press Enter.",
        host
    ));

    let result = run_app(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                handle_events(app, AppEvent::Key(key)).await?;
            }
        } else {
            handle_events(app, AppEvent::Tick).await?;
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

// ── Subcommand handlers ───────────────────────────────────────────────────────

/// Wire the full agent stack — LLM backend, executor, capabilities, registry,
/// policy, audit log — and drive an investigate → plan → approve → act session.
#[allow(clippy::too_many_arguments)]
async fn run_agent(
    goal: String,
    host: String,
    dry_run: bool,
    auto_approve: bool,
    backend_name: &str,
    anthropic_api_key: Option<&str>,
    openai_api_key: Option<&str>,
    model: &str,
) -> Result<()> {
    let session_id = Uuid::new_v4();

    // 1. LLM backend.
    let backend: Box<dyn LlmBackend> = match backend_name {
        "anthropic" => {
            let key = anthropic_api_key.ok_or_else(|| {
                anyhow::anyhow!("ANTHROPIC_API_KEY is required for the anthropic backend")
            })?;
            Box::new(AnthropicBackend::new(key.to_string(), model.to_string()))
        }
        "openai" => {
            let key = openai_api_key.ok_or_else(|| {
                anyhow::anyhow!("OPENAI_API_KEY is required for the openai backend")
            })?;
            Box::new(OpenAiBackend::new(key.to_string(), model.to_string()))
        }
        other => {
            return Err(anyhow::anyhow!(
                "unknown backend '{other}'; expected 'anthropic' or 'openai'"
            ))
        }
    };

    // 2. Executor + real capability implementations.
    let executor = Arc::new(RealCommandExecutor);
    let caps = all_capabilities(executor);

    // 3. Registry of capability manifests (for prompt/planning).
    let mut registry = CapabilityRegistry::new();
    for cap in &caps {
        registry.register(cap.manifest().clone());
    }
    let registry = Arc::new(registry);

    // 4. Policy + audit log (persisted to a per-session JSONL file).
    let policy = Arc::new(default_policy());
    let audit_path = std::path::PathBuf::from(format!("sentinel-audit-{session_id}.jsonl"));
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, Some(audit_path.clone()))));

    // 5. Reasoning loop wired with the concrete capabilities.
    let agent = ReasoningLoop::new(
        backend,
        registry,
        policy,
        Arc::clone(&audit),
        ReasoningConfig::default(),
    )
    .with_capabilities(caps);

    println!("Sentinel session {session_id}");
    println!("Goal    : {goal}");
    println!("Host    : {host}");
    println!("Backend : {backend_name} ({model})");
    println!();

    // Investigate.
    println!("── Investigating ──");
    let observations = agent.investigate(session_id, &goal, &host).await?;
    println!("Collected {} observation(s).", observations.len());

    // Plan.
    println!("\n── Planning ──");
    let mut plan = agent.plan(session_id, &goal, &observations).await?;
    println!("Rationale    : {}", plan.rationale);
    println!("Overall risk : {:?}", plan.overall_risk);
    println!("Steps ({}):", plan.steps.len());
    for (i, step) in plan.steps.iter().enumerate() {
        println!(
            "  {}. [{}] {} (risk {:?})",
            i + 1,
            step.capability_id,
            step.description,
            step.risk_tier
        );
    }

    if dry_run {
        println!("\nDry-run mode: plan generated but NOT executed.");
        println!("Audit log written to {}", audit_path.display());
        return Ok(());
    }

    // Approve.
    let approval = if auto_approve {
        println!("\nAuto-approve enabled — executing plan.");
        ApprovalDecision::FullApproval
    } else {
        use std::io::Write as _;
        print!("\nApprove and execute this plan? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            ApprovalDecision::FullApproval
        } else {
            ApprovalDecision::Rejected {
                reason: "operator declined at the approval prompt".to_string(),
            }
        }
    };

    if let ApprovalDecision::Rejected { reason } = &approval {
        println!("Plan rejected: {reason}");
        println!("Audit log written to {}", audit_path.display());
        return Ok(());
    }

    // Act.
    println!("\n── Executing ──");
    let summary = agent
        .execute_plan(session_id, &host, &mut plan, approval)
        .await?;
    println!(
        "Done: {} completed, {} failed, {} rolled back in {} ms.",
        summary.steps_completed,
        summary.steps_failed,
        summary.steps_rolled_back,
        summary.total_duration_ms
    );
    println!("Audit log written to {}", audit_path.display());

    Ok(())
}

fn list_capabilities() {
    let executor = Arc::new(RealCommandExecutor);
    let caps = all_capabilities(executor);
    println!("Available capabilities ({}):", caps.len());
    for cap in &caps {
        let m = cap.manifest();
        println!(
            "  {:<30} [{:?}]  Risk: {:?}{}",
            m.id,
            m.kind,
            m.risk_tier,
            if m.has_inverse { "  [rollback]" } else { "" }
        );
        println!("    {}", m.description);
    }
}

fn show_policy() {
    let _evaluator = default_policy();
    println!("Default Sentinel policy (deny-by-default):");
    println!("{:-<60}", "");
    println!("  10  deny-critical          Deny ALL Critical-risk actions");
    println!("  20  deny-high-mutating     Deny High-risk mutating actions");
    println!("  50  require-approval-high  High-risk actions require approval");
    println!(
        "  100 require-approval-medium Mutating Medium-risk requires approval"
    );
    println!(
        "  200 allow-read-low-medium   Allow read-only Low/Medium without approval"
    );
    println!("  300 allow-low-risk         Allow all Low-risk actions");
}

fn verify_audit(path: &std::path::Path) -> Result<()> {
    use sentinel_audit::verifier::AuditVerifier;

    let content = std::fs::read_to_string(path)?;
    let result = AuditVerifier::verify_jsonl(&content)
        .map_err(|e| anyhow::anyhow!("Audit verification error: {}", e))?;

    if result.valid {
        println!(
            "Audit log VALID — {} event(s) verified.",
            result.events_checked
        );
    } else {
        eprintln!(
            "Audit log INVALID — chain broken at sequence {}.",
            result.first_broken_at.unwrap_or(0)
        );
        if let Some(err) = &result.error {
            eprintln!("Error: {}", err);
        }
        std::process::exit(1);
    }

    Ok(())
}
