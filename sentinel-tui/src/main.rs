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
use tokio::sync::{mpsc, Mutex};
use tracing_subscriber::{fmt, EnvFilter};

use sentinel_agent_llm::{
    AnthropicBackend, Budget, CapabilityRegistry, LlmBackend, OpenAiBackend, ReasoningConfig,
    ReasoningLoop, ResilientBackend, RetryPolicy,
};
use sentinel_audit::AuditLog;
use sentinel_capabilities::all_capabilities;
use sentinel_core::ApprovalDecision;
use sentinel_exec::HardenedExecutor;
use sentinel_policy::RuleCondition;
use uuid::Uuid;

use sentinel_tui::{
    agent_bridge::{run_agent_session, AgentConfig},
    app::App,
    event_handler::{handle_events, AppEvent},
    policy_source, ui,
};

mod fleet_cmd;
mod gate_cmd;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Agentic system administration tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Anthropic API key (can also be set via ANTHROPIC_API_KEY env var)
    #[arg(long, env = "ANTHROPIC_API_KEY", global = true)]
    anthropic_api_key: Option<String>,

    /// OpenAI API key (can also be set via OPENAI_API_KEY env var)
    #[arg(long, env = "OPENAI_API_KEY", global = true)]
    openai_api_key: Option<String>,

    /// Policy file (TOML).  Its rules tighten the built-in policy; see
    /// `sentinel policy` for the result
    #[arg(long, env = "SENTINEL_POLICY", global = true)]
    policy: Option<std::path::PathBuf>,

    /// Do not undo completed steps when a later step of a plan fails
    #[arg(long, env = "SENTINEL_NO_ROLLBACK", global = true)]
    no_rollback: bool,

    /// LLM backend to use
    #[arg(long, default_value = "anthropic", global = true)]
    backend: String,

    /// Model identifier
    #[arg(long, default_value = "claude-opus-4-8", global = true)]
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
    /// Verify an audit log file (hash chain, and signatures when --pubkey is given)
    VerifyAudit {
        path: std::path::PathBuf,
        /// Trusted Ed25519 public key: 64 hex chars, or a file containing them.
        /// Checks the signed checkpoints in `<PATH>.sig` against this key
        #[arg(long, env = "SENTINEL_AUDIT_PUBKEY")]
        pubkey: Option<String>,
        /// Fail unless every event is covered by a valid signature (needs --pubkey)
        #[arg(long, requires = "pubkey")]
        require_signature: bool,
    },
    /// Generate an Ed25519 audit-signing key (mode 0600) and print its public key
    AuditKeygen {
        /// Where to write the private key; refuses to overwrite
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Run a capability across multiple hosts in parallel over SSH
    Fleet {
        /// Operational goal / label for this fleet run
        #[arg(help = "Goal or label for this fleet run")]
        goal: String,
        /// Comma-separated host specs: [user@]host[:port]
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        /// Capability id to run on every host
        #[arg(long, default_value = "system_metrics")]
        capability: String,
        /// JSON arguments object for the capability
        #[arg(long, default_value = "{}")]
        args: String,
        /// Approve a run that policy marks as requiring operator approval
        #[arg(long)]
        approve: bool,
    },
    /// Host side of `sentinel fleet`: run one capability under this host's
    /// policy and print its result as JSON.  Invoked over SSH
    #[command(hide = true)]
    AgentExec {
        capability: String,
        /// JSON arguments object
        #[arg(default_value = "{}")]
        args: String,
        /// The operator approved this run on the controller
        #[arg(long)]
        approved: bool,
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
    },
    /// Launch the interactive TUI
    Tui {
        /// Target host
        #[arg(long, default_value = "localhost")]
        host: String,
        /// Run in dry-run mode (plan only, no execution)
        #[arg(long)]
        dry_run: bool,
    },
    /// Serve Sentinel as a policy gate for coding agents (MCP over stdio)
    Serve {
        /// Speak the Model Context Protocol over stdin/stdout
        #[arg(long)]
        mcp: bool,
        /// Plan store + audit log directory
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
        /// Host label used for policy evaluation and execution context
        #[arg(long, default_value = "localhost")]
        host: String,
    },
    /// List plans proposed through the MCP gate
    Plans {
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
    },
    /// Show one stored plan as JSON
    ShowPlan {
        plan_id: Uuid,
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
    },
    /// Approve a proposed plan (operator only; requires an interactive terminal)
    Approve {
        plan_id: Uuid,
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
    },
    /// Reject a proposed plan
    Reject {
        plan_id: Uuid,
        /// Reason recorded in the plan store and audit log
        #[arg(long, default_value = "rejected by operator")]
        reason: String,
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
    },
    /// Execute an approved plan (refuses anything not approved or modified since approval)
    Execute {
        plan_id: Uuid,
        #[arg(long, env = "SENTINEL_STATE_DIR")]
        state_dir: Option<std::path::PathBuf>,
        /// Per-step timeout in milliseconds
        #[arg(long, default_value_t = 60_000)]
        step_timeout_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    policy_source::set_path(cli.policy.clone());
    sentinel_tui::runtime_opts::set_no_rollback(cli.no_rollback);

    // Logs always go to stderr: stdout is reserved for command output and,
    // under `serve --mcp`, for the JSON-RPC stream.
    fmt()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .with_writer(io::stderr)
        .with_ansi(io::IsTerminal::is_terminal(&io::stderr()))
        .init();

    match cli.command.unwrap_or(Commands::Tui {
        host: "localhost".into(),
        dry_run: false,
    }) {
        Commands::Tui { host, dry_run } => {
            run_tui(
                host,
                dry_run,
                cli.backend.clone(),
                cli.anthropic_api_key.clone(),
                cli.openai_api_key.clone(),
                cli.model.clone(),
            )
            .await?
        }
        Commands::Capabilities => list_capabilities(),
        Commands::Serve {
            mcp,
            state_dir,
            host,
        } => gate_cmd::serve(mcp, state_dir, host).await?,
        Commands::Plans { state_dir } => gate_cmd::list_plans(state_dir)?,
        Commands::ShowPlan { plan_id, state_dir } => gate_cmd::show_plan(plan_id, state_dir)?,
        Commands::Approve { plan_id, state_dir } => gate_cmd::approve(plan_id, state_dir).await?,
        Commands::Reject {
            plan_id,
            reason,
            state_dir,
        } => gate_cmd::reject(plan_id, reason, state_dir).await?,
        Commands::Execute {
            plan_id,
            state_dir,
            step_timeout_ms,
        } => gate_cmd::execute(plan_id, state_dir, step_timeout_ms).await?,
        Commands::Policy => show_policy()?,
        Commands::VerifyAudit {
            path,
            pubkey,
            require_signature,
        } => verify_audit(&path, pubkey.as_deref(), require_signature)?,
        Commands::AuditKeygen { out } => audit_keygen(&out)?,
        Commands::Fleet {
            goal,
            hosts,
            capability,
            args,
            approve,
        } => fleet_cmd::run_fleet(goal, hosts, capability, args, approve).await?,
        Commands::AgentExec {
            capability,
            args,
            approved,
            state_dir,
        } => fleet_cmd::agent_exec(capability, args, approved, state_dir).await?,
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

async fn run_tui(
    host: String,
    dry_run: bool,
    backend_name: String,
    anthropic_api_key: Option<String>,
    openai_api_key: Option<String>,
    model: String,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    app.host = host.clone();
    app.dry_run = dry_run;
    app.set_status(format!(
        "Welcome to Sentinel TUI!  Host: {host}.  Enter a goal and press Enter.",
    ));

    let result = run_app(
        &mut terminal,
        &mut app,
        backend_name,
        anthropic_api_key,
        openai_api_key,
        model,
    )
    .await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Main TUI event loop.
///
/// On every tick it:
/// 1. Drains any [`SessionUpdate`]s from the running agent.
/// 2. Polls for pending approval requests.
/// 3. Spawns an agent task if the operator just submitted a new goal.
/// 4. Re-renders the terminal.
/// 5. Handles keyboard input.
async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    backend_name: String,
    anthropic_api_key: Option<String>,
    openai_api_key: Option<String>,
    model: String,
) -> Result<()> {
    loop {
        // ── Drain live agent updates ──────────────────────────────────────
        app.poll_session_updates();
        app.poll_approval();

        // ── Spawn agent task when a new goal arrives ──────────────────────
        if let Some(goal) = app.pending_goal.take() {
            let (update_tx, update_rx) = mpsc::channel(128);
            let (approval_tx, approval_rx) = mpsc::channel(4);
            app.set_session_update_channel(update_rx);
            app.set_approval_channel(approval_rx);

            let config = AgentConfig {
                goal,
                host: app.host.clone(),
                dry_run: app.dry_run,
                backend_name: backend_name.clone(),
                anthropic_api_key: anthropic_api_key.clone(),
                openai_api_key: openai_api_key.clone(),
                model: model.clone(),
            };

            tokio::spawn(run_agent_session(config, update_tx, approval_tx));
        }

        // ── Render ────────────────────────────────────────────────────────
        terminal.draw(|f| ui::draw(f, app))?;

        // ── Input ─────────────────────────────────────────────────────────
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

    // Retries with backoff, a per-request deadline and a hard session budget
    // (ADR-020).  Limits come from SENTINEL_MAX_LLM_CALLS / _TOKENS.
    let backend: Box<dyn LlmBackend> = Box::new(ResilientBackend::with(
        backend,
        RetryPolicy::default(),
        Budget::from_env(),
    ));

    // 2. Executor + real capability implementations.
    let executor = Arc::new(HardenedExecutor::for_builtin_capabilities());
    let caps = all_capabilities(executor);

    // 3. Registry of capability manifests (for prompt/planning).
    let mut registry = CapabilityRegistry::new();
    for cap in &caps {
        registry.register(cap.manifest().clone());
    }
    let registry = Arc::new(registry);

    // 4. Policy + audit log (persisted to a per-session JSONL file).
    let policy = Arc::new(policy_source::load()?);
    let audit_path = std::path::PathBuf::from(format!("sentinel-audit-{session_id}.jsonl"));
    let audit = Arc::new(Mutex::new(
        AuditLog::new(session_id, Some(audit_path.clone())).with_signer_from_env()?,
    ));

    // 5. Reasoning loop wired with the concrete capabilities.
    let agent = ReasoningLoop::new(
        backend,
        registry,
        policy,
        Arc::clone(&audit),
        ReasoningConfig {
            rollback_on_failure: sentinel_tui::runtime_opts::rollback_enabled(),
            ..ReasoningConfig::default()
        },
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
    let executor = Arc::new(HardenedExecutor::for_builtin_capabilities());
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

fn show_policy() -> Result<()> {
    let evaluator = policy_source::load()?;
    let rules = evaluator.rules();
    let print_rules = |rules: &[sentinel_policy::PolicyRule]| {
        println!("{:-<78}", "");
        println!(
            "  {:<5} {:<33} {:<16} Conditions",
            "Prio", "Rule ID", "Effect"
        );
        println!("{:-<78}", "");
        for rule in rules {
            let conditions = if rule.conditions.is_empty() {
                "<always matches>".to_string()
            } else {
                rule.conditions
                    .iter()
                    .map(describe_condition)
                    .collect::<Vec<_>>()
                    .join(" AND ")
            };
            let effect = if rule.enabled {
                format!("{:?}", rule.effect)
            } else {
                format!("{:?} (disabled)", rule.effect)
            };
            println!(
                "  {:<5} {:<33} {:<16} {}",
                rule.priority, rule.id, effect, conditions
            );
            println!("        {}", rule.description);
        }
        println!("{:-<78}", "");
    };

    match policy_source::path() {
        Some(path) => println!(
            "Sentinel policy from {} (deny-by-default) — {} rule(s):",
            path.display(),
            rules.len()
        ),
        None => println!(
            "Default Sentinel policy (deny-by-default) — {} rule(s):",
            rules.len()
        ),
    }
    print_rules(rules);
    println!("Rules are evaluated in ascending priority order; the first match wins.");
    println!("Any request not matched by an Allow/AuditOnly rule is denied by default.");

    let tightening = evaluator.tightening_rules();
    if !tightening.is_empty() {
        println!();
        println!(
            "Tightening rules from the policy file — {} rule(s):",
            tightening.len()
        );
        print_rules(tightening);
        println!("Applied after the rules above; the stricter outcome wins, never the weaker.");
    }

    println!();
    println!("Resource guards (checked before any rule; mutating requests only):");
    for guard in evaluator.resource_guards() {
        let mut protects = Vec::new();
        if !guard.protected_paths.is_empty() {
            protects.push(format!("paths {}", guard.protected_paths.join(", ")));
        }
        if !guard.protected_services.is_empty() {
            protects.push(format!("services {}", guard.protected_services.join(", ")));
        }
        println!("  {:<20} {}", guard.id, protects.join("; "));
    }
    Ok(())
}

/// Render a [`RuleCondition`] as a concise, human-readable predicate string.
fn describe_condition(cond: &RuleCondition) -> String {
    match cond {
        RuleCondition::CapabilityId { matches } => format!("capability_id == \"{matches}\""),
        RuleCondition::CapabilityIdIn { ids } => {
            format!("capability_id in [{}]", ids.join(", "))
        }
        RuleCondition::RiskTierAtLeast { tier } => format!("risk >= {tier:?}"),
        RuleCondition::RiskTierExactly { tier } => format!("risk == {tier:?}"),
        RuleCondition::TargetHost { pattern } => format!("host matches \"{pattern}\""),
        RuleCondition::ArgValueContains { path, value } => {
            format!("args.{path} contains \"{value}\"")
        }
        RuleCondition::TimeWindow {
            start_hour,
            end_hour,
            days,
        } => format!("time in [{start_hour:02}:00, {end_hour:02}:00) days={days:?}"),
        RuleCondition::CapabilityKindIs { kind } => format!("kind == {kind:?}"),
        RuleCondition::SessionPhase { phase } => format!("phase == \"{phase}\""),
        RuleCondition::Not { condition } => format!("NOT ({})", describe_condition(condition)),
        RuleCondition::And { conditions } => format!(
            "({})",
            conditions
                .iter()
                .map(describe_condition)
                .collect::<Vec<_>>()
                .join(" AND ")
        ),
        RuleCondition::Or { conditions } => format!(
            "({})",
            conditions
                .iter()
                .map(describe_condition)
                .collect::<Vec<_>>()
                .join(" OR ")
        ),
    }
}

fn audit_keygen(out: &std::path::Path) -> Result<()> {
    let signer = sentinel_audit::AuditSigner::generate()?;
    signer
        .save(out)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", out.display()))?;
    eprintln!("Private key written to {} (mode 0600).", out.display());
    eprintln!("Sign audit logs by setting SENTINEL_AUDIT_KEY to that path.");
    eprintln!(
        "Give verifiers this public key (key id {}):",
        signer.key_id()
    );
    println!("{}", signer.public_key_hex());
    Ok(())
}

fn verify_audit(
    path: &std::path::Path,
    pubkey: Option<&str>,
    require_signature: bool,
) -> Result<()> {
    use sentinel_audit::signing::{
        parse_checkpoints, parse_public_key, sidecar_path, verify_checkpoints,
    };
    use sentinel_audit::verifier::AuditVerifier;

    let content = std::fs::read_to_string(path)?;
    let events = AuditVerifier::parse_jsonl(&content)
        .map_err(|e| anyhow::anyhow!("Audit verification error: {}", e))?;
    let result = AuditVerifier::verify_events(&events);

    if !result.valid {
        eprintln!(
            "Audit log INVALID — chain broken at sequence {}.",
            result.first_broken_at.unwrap_or(0)
        );
        if let Some(err) = &result.error {
            eprintln!("Error: {}", err);
        }
        std::process::exit(1);
    }

    let sidecar = sidecar_path(path);
    let Some(pubkey) = pubkey else {
        println!(
            "Audit log VALID — {} event(s) verified.",
            result.events_checked
        );
        if sidecar.exists() {
            println!(
                "Signatures NOT checked: {} exists; pass --pubkey to verify it.",
                sidecar.display()
            );
        }
        return Ok(());
    };

    // A --pubkey value is the key itself or a file holding it.
    let key_text = if std::path::Path::new(pubkey).is_file() {
        std::fs::read_to_string(pubkey)?
    } else {
        pubkey.to_string()
    };
    let key = parse_public_key(&key_text)?;

    let checkpoints = match std::fs::read_to_string(&sidecar) {
        Ok(text) => parse_checkpoints(&text)
            .map_err(|e| anyhow::anyhow!("Signature sidecar unreadable: {e}"))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let sig = verify_checkpoints(&events, &checkpoints, &key);

    if let Some(err) = &sig.error {
        eprintln!("Audit log INVALID — hash chain is consistent but signatures are not.");
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
    if sig.fully_signed() {
        println!(
            "Audit log VALID — {} event(s) verified, {} signed checkpoint(s), every event covered.",
            result.events_checked, sig.checkpoints_verified
        );
        return Ok(());
    }

    let detail = if sig.checkpoints_verified == 0 {
        format!("no signed checkpoints found at {}", sidecar.display())
    } else {
        format!(
            "last {} of {} event(s) are not covered by a signature",
            sig.unsigned_tail, result.events_checked
        )
    };
    if require_signature {
        eprintln!("Audit log INVALID — {detail}.");
        std::process::exit(1);
    }
    println!(
        "Audit log VALID (hash chain) — {} event(s) verified; WARNING: {detail}.",
        result.events_checked
    );
    Ok(())
}
