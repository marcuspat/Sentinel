use std::io;
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
        } => {
            println!(
                "sentinel run: goal='{}' host='{}' dry_run={}",
                goal, host, dry_run
            );
            println!("Interactive run mode requires an LLM backend.");
            println!("Set ANTHROPIC_API_KEY or OPENAI_API_KEY and try again.");
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

fn list_capabilities() {
    println!("Available capabilities:");
    println!("{:-<60}", "");
    println!("  {:<35} [{:<9}] Risk: Low", "sentinel.fs.read_file", "ReadOnly");
    println!("    Read the contents of a file from the target system.");
    println!("  {:<35} [{:<9}] Risk: High", "sentinel.fs.write_file", "Mutating");
    println!("    Write or overwrite a file on the target system.");
    println!("  {:<35} [{:<9}] Risk: Low", "sentinel.svc.status", "ReadOnly");
    println!("    Query the status of a systemd service.");
    println!("  {:<35} [{:<9}] Risk: Medium", "sentinel.svc.restart", "Mutating");
    println!("    Restart a systemd service.");
    println!("  {:<35} [{:<9}] Risk: High", "sentinel.exec.run_command", "Mutating");
    println!("    Execute an arbitrary shell command.");
}

fn show_policy() {
    use sentinel_policy::default_policy;
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
