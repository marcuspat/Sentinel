//! Bridge between the TUI event loop and the [`ReasoningLoop`].
//!
//! [`run_agent_session`] drives the full investigate → plan → approve → act
//! lifecycle in a background tokio task, emitting [`SessionUpdate`]s into the
//! TUI's mpsc channel and surfacing a plan-gate [`ApprovalRequest`] for
//! operator sign-off before execution begins.

use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{error, info};
use uuid::Uuid;

use sentinel_agent_llm::{
    AnthropicBackend, CapabilityRegistry, LlmBackend, OpenAiBackend, ReasoningConfig,
    ReasoningLoop,
};
use sentinel_audit::AuditLog;
use sentinel_capabilities::all_capabilities;
use sentinel_core::{ApprovalDecision, SessionPhase};
use sentinel_exec::RealCommandExecutor;
use sentinel_policy::default_policy;

use crate::app::{
    ApprovalOutcome, ApprovalRequest, LogEntry, LogLevel, Plan, PlanStep, SessionUpdate,
    StepStatus,
};

// ── AgentConfig ───────────────────────────────────────────────────────────────

/// Configuration for a single agent session, passed to [`run_agent_session`].
///
/// Built in the TUI event loop when the operator submits a goal and then given
/// to a background tokio task.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The operator's natural-language goal.
    pub goal: String,
    /// Target host for capability execution.
    pub host: String,
    /// If `true`, generate a plan but skip execution.
    pub dry_run: bool,
    /// LLM backend to use ("anthropic" | "openai").
    pub backend_name: String,
    /// Anthropic API key (required when `backend_name == "anthropic"`).
    pub anthropic_api_key: Option<String>,
    /// OpenAI API key (required when `backend_name == "openai"`).
    pub openai_api_key: Option<String>,
    /// Model identifier forwarded to the backend.
    pub model: String,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Drive a full agent session in the background, emitting [`SessionUpdate`]s.
///
/// Designed to be spawned with [`tokio::spawn`].  All errors are forwarded as
/// `SessionUpdate::Error` so the TUI can surface them without panicking.
pub async fn run_agent_session(
    config: AgentConfig,
    update_tx: mpsc::Sender<SessionUpdate>,
    approval_tx: mpsc::Sender<ApprovalRequest>,
) {
    if let Err(e) = run_inner(config, &update_tx, approval_tx).await {
        let _ = update_tx
            .send(SessionUpdate::Error(format!("Agent error: {e}")))
            .await;
    }
}

// ── Session driver ────────────────────────────────────────────────────────────

async fn run_inner(
    config: AgentConfig,
    update_tx: &mpsc::Sender<SessionUpdate>,
    approval_tx: mpsc::Sender<ApprovalRequest>,
) -> Result<()> {
    let session_id = Uuid::new_v4();

    // ── 1. Build the LLM backend ──────────────────────────────────────────────
    let backend: Box<dyn LlmBackend> = match config.backend_name.as_str() {
        "anthropic" => {
            let key = config
                .anthropic_api_key
                .ok_or_else(|| anyhow::anyhow!("ANTHROPIC_API_KEY required for anthropic backend"))?;
            Box::new(AnthropicBackend::new(key, config.model.clone()))
        }
        "openai" => {
            let key = config
                .openai_api_key
                .ok_or_else(|| anyhow::anyhow!("OPENAI_API_KEY required for openai backend"))?;
            Box::new(OpenAiBackend::new(key, config.model.clone()))
        }
        other => return Err(anyhow::anyhow!("unknown backend '{other}'")),
    };

    // ── 2. Assemble capabilities, registry, policy, and audit log ─────────────
    let executor = Arc::new(RealCommandExecutor);
    let caps = all_capabilities(executor);

    let mut registry = CapabilityRegistry::new();
    for cap in &caps {
        registry.register(cap.manifest().clone());
    }
    let registry = Arc::new(registry);

    let policy = Arc::new(default_policy());
    let audit_path = std::path::PathBuf::from(format!("sentinel-audit-{session_id}.jsonl"));
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, Some(audit_path))));

    let agent = ReasoningLoop::new(
        backend,
        registry,
        policy,
        Arc::clone(&audit),
        ReasoningConfig::default(),
    )
    .with_capabilities(caps);

    // ── 3. Investigate ────────────────────────────────────────────────────────
    emit(
        update_tx,
        SessionUpdate::PhaseChanged(SessionPhase::Investigating),
    )
    .await;
    log_entry(
        update_tx,
        LogLevel::Info,
        format!("Investigating goal: {}", config.goal),
    )
    .await;

    let observations = agent
        .investigate(session_id, &config.goal, &config.host)
        .await
        .map_err(|e| anyhow::anyhow!("investigate phase: {e}"))?;

    log_entry(
        update_tx,
        LogLevel::Info,
        format!(
            "Investigation complete — {} observation(s) collected.",
            observations.len()
        ),
    )
    .await;

    // ── 4. Plan ───────────────────────────────────────────────────────────────
    emit(
        update_tx,
        SessionUpdate::PhaseChanged(SessionPhase::Planning),
    )
    .await;

    let mut core_plan = agent
        .plan(session_id, &config.goal, &observations)
        .await
        .map_err(|e| anyhow::anyhow!("planning phase: {e}"))?;

    info!(
        plan_id = %core_plan.id,
        steps = core_plan.steps.len(),
        overall_risk = ?core_plan.overall_risk,
        "plan ready — sending to TUI"
    );

    let app_plan = core_plan_to_app(&core_plan);
    emit(update_tx, SessionUpdate::PlanProposed(app_plan)).await;

    // ── 5. Dry-run short-circuit ──────────────────────────────────────────────
    if config.dry_run {
        log_entry(
            update_tx,
            LogLevel::Info,
            "Dry-run mode — plan generated but NOT executed.".to_string(),
        )
        .await;
        emit(update_tx, SessionUpdate::SessionCompleted).await;
        return Ok(());
    }

    // ── 6. Operator approval gate ─────────────────────────────────────────────
    //
    // Surface a single plan-gate ApprovalRequest so the TUI's y/n modal handles
    // it uniformly.  The gate step represents "approve the full execution plan".
    let (responder, answer_rx) = oneshot::channel::<ApprovalOutcome>();

    let gate_step = PlanStep::new(
        format!(
            "Execute plan ({} step(s), {:?} risk)",
            core_plan.steps.len(),
            core_plan.overall_risk
        ),
        "sentinel.plan.execute",
        serde_json::json!({
            "goal":         config.goal,
            "steps":        core_plan.steps.len(),
            "overall_risk": format!("{:?}", core_plan.overall_risk),
        }),
        core_plan.overall_risk,
    );

    approval_tx
        .send(ApprovalRequest {
            step: gate_step,
            responder,
        })
        .await
        .map_err(|_| anyhow::anyhow!("approval channel closed before plan-gate could be sent"))?;

    let outcome = answer_rx
        .await
        .map_err(|_| anyhow::anyhow!("approval responder dropped without reply"))?;

    match outcome {
        ApprovalOutcome::Approve => {
            emit(update_tx, SessionUpdate::PlanApproved).await;
        }
        ApprovalOutcome::Abort => {
            emit(
                update_tx,
                SessionUpdate::PlanRejected {
                    reason: "Aborted by operator.".to_string(),
                },
            )
            .await;
            return Ok(());
        }
    }

    // ── 7. Execute ────────────────────────────────────────────────────────────
    emit(
        update_tx,
        SessionUpdate::PhaseChanged(SessionPhase::Executing),
    )
    .await;
    log_entry(
        update_tx,
        LogLevel::Info,
        format!(
            "Executing {} step(s) on {}…",
            core_plan.steps.len(),
            config.host
        ),
    )
    .await;

    let summary = agent
        .execute_plan(
            session_id,
            &config.host,
            &mut core_plan,
            ApprovalDecision::FullApproval,
        )
        .await
        .map_err(|e| anyhow::anyhow!("execute_plan: {e}"))?;

    // Emit per-step completion updates from the finalised plan state.
    for step in &core_plan.steps {
        let status = core_status_to_app(&step.status);
        emit(
            update_tx,
            SessionUpdate::StepCompleted {
                step_id: step.id,
                status,
            },
        )
        .await;
    }

    log_entry(
        update_tx,
        LogLevel::Info,
        format!(
            "Execution complete — {} succeeded, {} failed, {} rolled back in {}ms.",
            summary.steps_completed,
            summary.steps_failed,
            summary.steps_rolled_back,
            summary.total_duration_ms,
        ),
    )
    .await;

    emit(update_tx, SessionUpdate::SessionCompleted).await;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Send a [`SessionUpdate`], ignoring send errors (TUI may have exited).
async fn emit(tx: &mpsc::Sender<SessionUpdate>, update: SessionUpdate) {
    if tx.send(update).await.is_err() {
        error!("TUI update channel closed — dropping update");
    }
}

/// Emit a log line as a [`SessionUpdate::LogAppended`].
async fn log_entry(tx: &mpsc::Sender<SessionUpdate>, level: LogLevel, message: String) {
    emit(
        tx,
        SessionUpdate::LogAppended(LogEntry {
            timestamp: Utc::now(),
            level,
            message,
        }),
    )
    .await;
}

/// Convert a [`sentinel_core::Plan`] into the TUI's [`Plan`] representation.
///
/// Step UUIDs are preserved so that subsequent [`SessionUpdate::StepCompleted`]
/// messages can be matched back to the displayed plan.
fn core_plan_to_app(plan: &sentinel_core::Plan) -> Plan {
    let steps = plan
        .steps
        .iter()
        .map(|s| PlanStep {
            id: s.id,
            description: s.description.clone(),
            capability_id: s.capability_id.clone(),
            args: s.args.clone(),
            risk_tier: s.risk_tier,
            estimated_duration_ms: None,
            status: StepStatus::Pending,
        })
        .collect();

    Plan {
        id: plan.id,
        goal: plan.goal.clone(),
        steps,
        overall_risk: plan.overall_risk,
        created_at: plan.created_at,
    }
}

/// Map a [`sentinel_core::StepStatus`] to the TUI's [`StepStatus`].
fn core_status_to_app(status: &sentinel_core::StepStatus) -> StepStatus {
    match status {
        sentinel_core::StepStatus::Pending
        | sentinel_core::StepStatus::Approved
        | sentinel_core::StepStatus::Executing => StepStatus::Running,
        sentinel_core::StepStatus::Completed => StepStatus::Succeeded,
        sentinel_core::StepStatus::Failed => StepStatus::Failed {
            reason: "execution error".to_string(),
        },
        sentinel_core::StepStatus::RolledBack => StepStatus::RolledBack,
        sentinel_core::StepStatus::Skipped => StepStatus::Skipped,
    }
}
