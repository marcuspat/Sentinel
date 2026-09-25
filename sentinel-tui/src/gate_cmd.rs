//! CLI handlers for the MCP policy gate (ADR-013).
//!
//! * `serve --mcp`  — agent-facing; can propose, never approve/execute.
//! * `plans`, `show-plan` — read the plan store.
//! * `approve`      — operator-only; requires an interactive terminal.
//! * `reject`       — operator; no TTY requirement (rejecting is always safe).
//! * `execute`      — runs an approved, unmodified plan.

use std::io::{IsTerminal, Write as _};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use uuid::Uuid;

use sentinel_audit::AuditEventType;
use sentinel_capabilities::all_capabilities;
use sentinel_exec::RealCommandExecutor;
use sentinel_mcp::{
    default_state_dir, execute_approved_plan, index_capabilities, plan_status_json, AuditSink,
    Gate, GateConfig, PlanStatus, PlanStore, StoredPlan,
};
use sentinel_policy::default_policy;

fn resolve_state_dir(state_dir: Option<PathBuf>) -> PathBuf {
    state_dir.unwrap_or_else(default_state_dir)
}

fn operator_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

pub async fn serve(mcp: bool, state_dir: Option<PathBuf>, host: String) -> Result<()> {
    if !mcp {
        bail!("only the MCP stdio transport is implemented; run `sentinel serve --mcp`");
    }
    let state_dir = resolve_state_dir(state_dir);
    let mut config = GateConfig::new(&state_dir);
    config.host = host;
    let caps = all_capabilities(Arc::new(RealCommandExecutor));
    let gate = Gate::new(config, caps, default_policy())?;
    tracing::info!(
        state_dir = %state_dir.display(),
        audit = %gate.audit().path().display(),
        session = %gate.session_id(),
        "sentinel MCP gate listening on stdio"
    );
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    sentinel_mcp::serve(&gate, stdin, stdout).await?;
    Ok(())
}

pub fn list_plans(state_dir: Option<PathBuf>) -> Result<()> {
    let store = PlanStore::open(&resolve_state_dir(state_dir))?;
    let plans = store.list()?;
    if plans.is_empty() {
        println!("No plans in {}", store.dir().display());
        return Ok(());
    }
    println!(
        "{:<36}  {:<16}  {:<8}  {:>5}  Goal",
        "Plan ID", "Status", "Risk", "Steps"
    );
    for rec in plans {
        println!(
            "{:<36}  {:<16}  {:<8}  {:>5}  {}",
            rec.plan.id,
            rec.status.to_string(),
            rec.plan.overall_risk.to_string(),
            rec.plan.steps.len(),
            rec.plan.goal
        );
    }
    Ok(())
}

pub fn show_plan(plan_id: Uuid, state_dir: Option<PathBuf>) -> Result<()> {
    let store = PlanStore::open(&resolve_state_dir(state_dir))?;
    let rec = store.load(plan_id)?;
    println!("{}", serde_json::to_string_pretty(&plan_status_json(&rec))?);
    Ok(())
}

fn print_plan_for_review(rec: &StoredPlan) {
    println!("Plan        : {}", rec.plan.id);
    println!("Status      : {}", rec.status);
    println!("Goal        : {}", rec.plan.goal);
    if !rec.plan.rationale.is_empty() {
        println!("Rationale   : {}", rec.plan.rationale);
    }
    println!("Host        : {}", rec.host);
    println!(
        "Proposed via: {} (session {})",
        rec.proposed_via, rec.proposer_session
    );
    println!("Overall risk: {}", rec.plan.overall_risk);
    println!("Content hash: {}", rec.content_hash);
    println!("Steps ({}):", rec.plan.steps.len());
    for s in &rec.plan.steps {
        println!(
            "  {}. {} [{}] args={}",
            s.sequence, s.capability_id, s.risk_tier, s.args
        );
        println!("     {}", s.description);
    }
}

pub async fn approve(plan_id: Uuid, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = resolve_state_dir(state_dir);
    let store = PlanStore::open(&state_dir)?;
    let rec = store.load(plan_id)?;
    print_plan_for_review(&rec);

    if rec.status != PlanStatus::PendingApproval {
        bail!("plan {plan_id} is {}, not PendingApproval", rec.status);
    }
    if !rec.integrity_ok() {
        bail!("plan {plan_id} failed its integrity check (content changed after proposal); refusing to approve");
    }

    // Speed bump against an agent that has shell access running this for
    // itself: approval needs a human at a terminal.  This is NOT a security
    // boundary against a same-UID process that can allocate a PTY or edit
    // the state dir; see ADR-013.
    if !std::io::stdin().is_terminal() {
        bail!(
            "refusing to approve: stdin is not an interactive terminal. \
             Approval must be performed by a human operator."
        );
    }
    let expected = &plan_id.to_string()[..8];
    print!("\nType the first 8 characters of the plan id to approve: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != expected {
        bail!("confirmation did not match; plan left PendingApproval");
    }

    let who = operator_identity();
    let audit = AuditSink::create(&state_dir, "approve")?;
    audit
        .record(AuditEventType::PlanApproved {
            plan_id,
            approval_mode: format!("operator_cli:{who}:{}", &rec.content_hash[..12]),
        })
        .await
        .map_err(|e| anyhow!("audit write failed; plan NOT approved: {e}"))?;
    let rec = store.approve(plan_id, &who, Some(audit.path_string()))?;
    println!(
        "Approved {} (hash {}). Run `sentinel execute {}` to execute it.",
        rec.plan.id, rec.content_hash, rec.plan.id
    );
    println!("Audit: {}", audit.path().display());
    Ok(())
}

pub async fn reject(plan_id: Uuid, reason: String, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = resolve_state_dir(state_dir);
    let store = PlanStore::open(&state_dir)?;
    let who = operator_identity();
    let audit = AuditSink::create(&state_dir, "reject")?;
    audit
        .record(AuditEventType::PlanRejected {
            plan_id,
            reason: reason.clone(),
        })
        .await
        .map_err(|e| anyhow!("audit write failed: {e}"))?;
    let rec = store.reject(plan_id, &who, &reason, Some(audit.path_string()))?;
    println!("Rejected {}: {reason}", rec.plan.id);
    Ok(())
}

pub async fn execute(
    plan_id: Uuid,
    state_dir: Option<PathBuf>,
    step_timeout_ms: u64,
) -> Result<()> {
    let state_dir = resolve_state_dir(state_dir);
    let store = PlanStore::open(&state_dir)?;
    let caps = index_capabilities(all_capabilities(Arc::new(RealCommandExecutor)));
    let policy = default_policy();
    let audit = AuditSink::create(&state_dir, "execute")?;
    let report =
        execute_approved_plan(&store, plan_id, &caps, &policy, &audit, step_timeout_ms).await?;
    for s in &report.steps {
        println!(
            "  {}. {:<20} {:<10} {}",
            s.sequence, s.capability_id, s.status, s.detail
        );
    }
    println!("Plan {} -> {}", report.plan_id, report.status);
    println!("Audit: {}", report.audit_file);
    if report.status != PlanStatus::Executed {
        std::process::exit(2);
    }
    Ok(())
}
