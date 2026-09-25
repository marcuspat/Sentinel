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

use std::time::{Duration, Instant};

use serde::Serialize;
use uuid::Uuid;

use sentinel_audit::AuditEventType;
use sentinel_core::{CapabilityResult, ExecutionContext, StepStatus};
use sentinel_policy::{PolicyEffect, PolicyEvaluator, PolicyRequest};

use crate::audit::AuditSink;
use crate::gate::{effect_label, CapabilitySet};
use crate::store::{expect_status, ExecutionRecord, PlanStatus, PlanStore, StoreError};

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

/// Execute a stored, operator-approved plan.
pub async fn execute_approved_plan(
    store: &PlanStore,
    plan_id: Uuid,
    caps: &CapabilitySet,
    policy: &PolicyEvaluator,
    audit: &AuditSink,
    step_timeout_ms: u64,
) -> Result<ExecuteReport, ExecuteError> {
    let mut rec = store.load(plan_id)?;
    if rec.status != PlanStatus::Approved {
        // Record the refused attempt, then refuse.
        let _ = audit
            .record(AuditEventType::PolicyDenied {
                capability_id: format!("plan:{plan_id}"),
                reason: format!("execution refused: plan status is {}", rec.status),
            })
            .await;
        return Err(ExecuteError::NotApproved {
            id: plan_id,
            status: rec.status,
        });
    }
    if !rec.integrity_ok() {
        let _ = audit
            .record(AuditEventType::PolicyDenied {
                capability_id: format!("plan:{plan_id}"),
                reason: "execution refused: plan content does not match approved hash".into(),
            })
            .await;
        return Err(StoreError::IntegrityMismatch(plan_id).into());
    }

    // Claim the plan so it cannot be executed twice.
    expect_status(&rec, PlanStatus::Approved)?;
    rec.status = PlanStatus::Executing;
    rec.execution = Some(ExecutionRecord {
        started_at: chrono::Utc::now(),
        finished_at: None,
        steps_completed: 0,
        steps_failed: 0,
        steps_skipped: 0,
        audit_file: Some(audit.path_string()),
        error: None,
    });
    store.save(&rec)?;

    let approver = rec
        .decision
        .as_ref()
        .map(|d| d.by.clone())
        .unwrap_or_else(|| "unknown".into());
    let audit_err = |e: sentinel_audit::AuditError| ExecuteError::Audit(e.to_string());

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

        let mut outcomes = Vec::new();
        let mut halted = false;
        let started = Instant::now();
        let mut completed = 0u32;

        for i in 0..rec.plan.steps.len() {
            let step = rec.plan.steps[i].clone();
            if halted {
                rec.plan.steps[i].status = StepStatus::Skipped;
                outcomes.push(StepOutcome {
                    sequence: step.sequence,
                    capability_id: step.capability_id.clone(),
                    status: "Skipped".into(),
                    policy: None,
                    detail: "skipped after an earlier step was denied or failed".into(),
                });
                continue;
            }

            let Some(cap) = caps.get(&step.capability_id) else {
                rec.plan.steps[i].status = StepStatus::Failed;
                halted = true;
                outcomes.push(StepOutcome {
                    sequence: step.sequence,
                    capability_id: step.capability_id.clone(),
                    status: "Failed".into(),
                    policy: None,
                    detail: "capability is not registered in this binary".into(),
                });
                continue;
            };
            let m = cap.manifest();

            let decision = policy.evaluate(PolicyRequest {
                session_id: audit.session_id(),
                capability_id: m.id.clone(),
                capability_kind: m.kind,
                // Current manifest tier, not the (possibly stale) stored one.
                risk_tier: m.risk_tier,
                args: step.args.clone(),
                target_host: rec.host.clone(),
                timestamp: chrono::Utc::now(),
                session_phase: Some("Executing".into()),
            });
            audit
                .record(AuditEventType::PolicyEvaluated {
                    capability_id: m.id.clone(),
                    effect: effect_label(&decision.effect).into(),
                    rule_id: decision.matched_rule.clone(),
                })
                .await
                .map_err(audit_err)?;

            if let PolicyEffect::Denied { reason } = &decision.effect {
                audit
                    .record(AuditEventType::PolicyDenied {
                        capability_id: m.id.clone(),
                        reason: reason.clone(),
                    })
                    .await
                    .map_err(audit_err)?;
                rec.plan.steps[i].status = StepStatus::Skipped;
                halted = true;
                outcomes.push(StepOutcome {
                    sequence: step.sequence,
                    capability_id: m.id.clone(),
                    status: "Denied".into(),
                    policy: Some("deny".into()),
                    detail: reason.clone(),
                });
                continue;
            }

            audit
                .record(AuditEventType::CapabilityInvoked {
                    capability_id: m.id.clone(),
                    args: step.args.clone(),
                    risk_tier: format!("{:?}", m.risk_tier),
                })
                .await
                .map_err(audit_err)?;
            rec.plan.steps[i].status = StepStatus::Executing;

            let ctx = ExecutionContext::new(audit.session_id(), rec.host.clone())
                .with_timeout_ms(step_timeout_ms);
            let t0 = Instant::now();
            let result = match tokio::time::timeout(
                Duration::from_millis(step_timeout_ms),
                cap.invoke(step.args.clone(), &ctx),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    CapabilityResult::failure(format!("timed out after {step_timeout_ms}ms"), true)
                }
            };
            let duration_ms = t0.elapsed().as_millis() as u64;

            match result {
                CapabilityResult::Success { output } => {
                    audit
                        .record(AuditEventType::CapabilitySucceeded {
                            capability_id: m.id.clone(),
                            duration_ms,
                        })
                        .await
                        .map_err(audit_err)?;
                    rec.plan.steps[i].status = StepStatus::Completed;
                    completed += 1;
                    outcomes.push(StepOutcome {
                        sequence: step.sequence,
                        capability_id: m.id.clone(),
                        status: "Completed".into(),
                        policy: Some(effect_label(&decision.effect).into()),
                        detail: output.to_string(),
                    });
                }
                other => {
                    let err = match other {
                        CapabilityResult::Failure { error, .. } => error,
                        _ => "capability returned a dry-run result from invoke".into(),
                    };
                    audit
                        .record(AuditEventType::CapabilityFailed {
                            capability_id: m.id.clone(),
                            error: err.clone(),
                        })
                        .await
                        .map_err(audit_err)?;
                    rec.plan.steps[i].status = StepStatus::Failed;
                    halted = true;
                    outcomes.push(StepOutcome {
                        sequence: step.sequence,
                        capability_id: m.id.clone(),
                        status: "Failed".into(),
                        policy: Some(effect_label(&decision.effect).into()),
                        detail: err,
                    });
                }
            }
        }

        audit
            .record(AuditEventType::SessionCompleted {
                duration_ms: started.elapsed().as_millis() as u64,
                capabilities_executed: completed as u64,
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
