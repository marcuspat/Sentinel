//! Operator-side execution of plans that were proposed over MCP.
//!
//! This module is called by `sentinel execute <plan_id>` — never by the MCP
//! server.  It refuses to run anything unless the stored plan is
//! [`PlanStatus::Approved`] and its content still matches the hash the
//! operator approved.
//!
//! Policy is re-evaluated for every step at execution time:
//! * `Denied` stops execution (policy may have tightened since proposal).
//! * `RequiresApproval` is satisfied by the operator's out-of-band approval
//!   of this exact plan content.
//! * `Allowed` / `AuditOnly` proceed.
//!
//! Execution halts on the first denied or failed step; remaining steps are
//! marked `Skipped`.  Automatic rollback is not performed in this version
//! (see ADR-013, "Known gaps").

use serde::Serialize;
use uuid::Uuid;

use sentinel_audit::AuditEventType;
use sentinel_policy::PolicyEvaluator;
use sentinel_runner::{run_plan, RunError, RunOptions, StepState};

use crate::audit::AuditSink;
use crate::gate::CapabilitySet;
use crate::store::{PlanStatus, PlanStore, StoreError};

/// Per-step outcome reported back to the operator.
#[derive(Debug, Clone, Serialize)]
pub struct StepOutcome {
    pub sequence: u32,
    pub capability_id: String,
    pub status: String,
    pub policy: Option<String>,
    pub detail: String,
}

/// Summary of one `sentinel execute` run.
#[derive(Debug, Clone, Serialize)]
pub struct ExecuteReport {
    pub plan_id: Uuid,
    pub status: PlanStatus,
    pub steps: Vec<StepOutcome>,
    pub audit_file: String,
}

/// Why a plan could not be executed.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("plan {id} is not approved (status: {status}); an operator must run `sentinel approve {id}` first")]
    NotApproved { id: Uuid, status: PlanStatus },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("audit log write failed; execution aborted: {0}")]
    Audit(String),
}

/// Execute a stored, operator-approved plan with rollback enabled.
pub async fn execute_approved_plan(
    store: &PlanStore,
    plan_id: Uuid,
    caps: &CapabilitySet,
    policy: &PolicyEvaluator,
    audit: &AuditSink,
    step_timeout_ms: u64,
) -> Result<ExecuteReport, ExecuteError> {
    let opts = RunOptions {
        step_timeout_ms: Some(step_timeout_ms),
        rollback: true,
        stub_unimplemented: false,
    };
    execute_approved_plan_with(store, plan_id, caps, policy, audit, &opts).await
}

/// Execute a stored, operator-approved plan with explicit executor options.
pub async fn execute_approved_plan_with(
    store: &PlanStore,
    plan_id: Uuid,
    caps: &CapabilitySet,
    policy: &PolicyEvaluator,
    audit: &AuditSink,
    opts: &RunOptions,
) -> Result<ExecuteReport, ExecuteError> {
    // Claim the plan: `Approved -> Executing` under the plan lock.  Of any
    // number of concurrent `sentinel execute` processes exactly one gets
    // past this line; the rest are refused and record the refusal.
    let mut rec = match store.claim_for_execution(plan_id, Some(audit.path_string())) {
        Ok(rec) => rec,
        Err(StoreError::InvalidTransition { actual, .. }) => {
            let _ = audit
                .record(AuditEventType::PolicyDenied {
                    capability_id: format!("plan:{plan_id}"),
                    reason: format!("execution refused: plan status is {actual}"),
                })
                .await;
            return Err(ExecuteError::NotApproved {
                id: plan_id,
                status: actual,
            });
        }
        Err(StoreError::IntegrityMismatch(id)) => {
            let _ = audit
                .record(AuditEventType::PolicyDenied {
                    capability_id: format!("plan:{plan_id}"),
                    reason: "execution refused: plan content does not match approved hash".into(),
                })
                .await;
            return Err(StoreError::IntegrityMismatch(id).into());
        }
        Err(e) => return Err(e.into()),
    };

    let approver = rec
        .decision
        .as_ref()
        .map(|d| d.by.clone())
        .unwrap_or_else(|| "unknown".into());
    let audit_err = |e: sentinel_audit::AuditError| ExecuteError::Audit(e.to_string());

    let host = rec.host.clone();
    let run = async {
        audit
            .record(AuditEventType::GoalSubmitted {
                goal: rec.plan.goal.clone(),
                host: rec.host.clone(),
            })
            .await
            .map_err(audit_err)?;
        audit
            .record(AuditEventType::PlanApproved {
                plan_id,
                approval_mode: format!(
                    "out_of_band:{approver}:{}",
                    &rec.content_hash[..12.min(rec.content_hash.len())]
                ),
            })
            .await
            .map_err(audit_err)?;

        // The same executor `sentinel run` uses (ADR-019).
        let report = run_plan(
            &mut rec.plan,
            &host,
            audit.session_id(),
            caps,
            policy,
            audit,
            opts,
        )
        .await
        .map_err(|e| match e {
            RunError::Audit(msg) => ExecuteError::Audit(msg),
            // Cannot happen: the plan was claimed as Approved under the lock.
            RunError::NotApproved => ExecuteError::NotApproved {
                id: plan_id,
                status: PlanStatus::Executing,
            },
        })?;

        let halted = report.halted;
        let outcomes: Vec<StepOutcome> = report
            .steps
            .iter()
            .map(|s| StepOutcome {
                sequence: s.sequence,
                capability_id: s.capability_id.clone(),
                status: s.state.to_string(),
                policy: s.policy.clone(),
                detail: match &s.rollback {
                    Some(rb) => format!("{} (rollback: {rb})", s.detail),
                    None => s.detail.clone(),
                },
            })
            .collect();

        audit
            .record(AuditEventType::SessionCompleted {
                duration_ms: report.duration_ms,
                capabilities_executed: report.count(StepState::Completed) as u64,
            })
            .await
            .map_err(audit_err)?;
        Ok::<(Vec<StepOutcome>, bool), ExecuteError>((outcomes, halted))
    }
    .await;

    let finished_at = chrono::Utc::now();
    match run {
        Ok((outcomes, halted)) => {
            let count = |s: &str| outcomes.iter().filter(|o| o.status == s).count() as u32;
            rec.status = if halted {
                PlanStatus::ExecutionFailed
            } else {
                PlanStatus::Executed
            };
            if let Some(ex) = rec.execution.as_mut() {
                ex.finished_at = Some(finished_at);
                ex.steps_completed = count("Completed");
                ex.steps_rolled_back = count("RolledBack");
                ex.steps_failed = count("Failed") + count("Denied");
                ex.steps_skipped = count("Skipped");
            }
            store.save(&rec)?;
            Ok(ExecuteReport {
                plan_id,
                status: rec.status,
                steps: outcomes,
                audit_file: audit.path_string(),
            })
        }
        Err(e) => {
            rec.status = PlanStatus::ExecutionFailed;
            if let Some(ex) = rec.execution.as_mut() {
                ex.finished_at = Some(finished_at);
                ex.error = Some(e.to_string());
            }
            store.save(&rec)?;
            Err(e)
        }
    }
}
