//! `sentinel-runner` — the single plan executor (ADR-019).
//!
//! `sentinel run` (via the reasoning loop) and `sentinel execute` (via the
//! MCP gate) used to carry two separate executors that disagreed about what
//! an approved plan means.  Both now call [`run_plan`], so these rules hold
//! on every path:
//!
//! 1. **Approval covers the plan.**  A step whose policy outcome is
//!    `RequiresApproval` runs, because the operator approved the plan that
//!    contains it.  `Denied` never runs, approved or not.
//! 2. **Policy uses the capability's current manifest**, not the kind or
//!    risk tier recorded when the plan was written.
//! 3. **A `Failure` result is a failure.**
//! 4. **Halt on the first denied or failed step.**  Later steps are skipped.
//! 5. **Rollback** (when enabled): completed steps marked `can_rollback` are
//!    undone in reverse order.  A step is `RolledBack` only when its inverse
//!    reported success.
//! 6. **Audit before action.**  If an audit write fails, execution stops.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentinel_audit::{AuditEventType, AuditLog};
use sentinel_core::{
    Capability, CapabilityManifest, CapabilityResult, ExecutionContext, Plan, StepStatus,
};
use sentinel_policy::{PolicyEffect, PolicyEvaluator, PolicyRequest};
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

/// Where the executor writes audit events.
#[async_trait]
pub trait AuditWriter: Send + Sync {
    async fn record(&self, event: AuditEventType) -> Result<(), String>;
}

#[async_trait]
impl AuditWriter for tokio::sync::Mutex<AuditLog> {
    async fn record(&self, event: AuditEventType) -> Result<(), String> {
        self.lock()
            .await
            .append(event)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// How the executor finds capabilities.
pub trait CapabilityLookup: Send + Sync {
    /// The implementation to invoke, if one is registered.
    fn implementation(&self, id: &str) -> Option<&dyn Capability>;

    /// The manifest used for the policy check.  Defaults to the
    /// implementation's manifest.
    fn manifest(&self, id: &str) -> Option<CapabilityManifest> {
        self.implementation(id).map(|c| c.manifest().clone())
    }
}

impl CapabilityLookup for HashMap<String, Box<dyn Capability>> {
    fn implementation(&self, id: &str) -> Option<&dyn Capability> {
        self.get(id).map(|b| b.as_ref())
    }
}

impl CapabilityLookup for std::collections::BTreeMap<String, Box<dyn Capability>> {
    fn implementation(&self, id: &str) -> Option<&dyn Capability> {
        self.get(id).map(|b| b.as_ref())
    }
}

/// Executor settings.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Per-step wall-clock limit.  `None` leaves timing to the capability's
    /// own executor.
    pub step_timeout_ms: Option<u64>,
    /// Undo completed, rollback-capable steps after a failure.
    pub rollback: bool,
    /// When a capability has a manifest but no implementation, record a stub
    /// success instead of failing.  Only for harnesses that run the loop
    /// without real capabilities; never set in production paths.
    pub stub_unimplemented: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            step_timeout_ms: None,
            rollback: true,
            stub_unimplemented: false,
        }
    }
}

/// Final state of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StepState {
    Completed,
    Failed,
    Denied,
    Skipped,
    RolledBack,
}

impl std::fmt::Display for StepState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StepState::Completed => "Completed",
            StepState::Failed => "Failed",
            StepState::Denied => "Denied",
            StepState::Skipped => "Skipped",
            StepState::RolledBack => "RolledBack",
        })
    }
}

/// What happened to one step.
#[derive(Debug, Clone)]
pub struct StepReport {
    pub sequence: u32,
    pub capability_id: String,
    pub state: StepState,
    /// Policy effect label (`allow`, `deny`, `require_approval`,
    /// `audit_only`); `None` when the step never reached the policy check.
    pub policy: Option<String>,
    /// Output (as JSON text), error message, or the reason it did not run.
    pub detail: String,
    /// The capability's result, when it was invoked.  Callers that feed
    /// results back to a model must treat this as untrusted data.
    pub result: Option<CapabilityResult>,
    /// Outcome of the rollback attempt, when one was made.
    pub rollback: Option<String>,
}

/// Summary of a plan run.
#[derive(Debug, Clone)]
pub struct RunReport {
    pub steps: Vec<StepReport>,
    /// A step was denied or failed; later steps were skipped.
    pub halted: bool,
    pub duration_ms: u64,
}

impl RunReport {
    pub fn count(&self, state: StepState) -> u32 {
        self.steps.iter().filter(|s| s.state == state).count() as u32
    }
}

/// Execution could not continue.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("plan is not approved for execution")]
    NotApproved,
    #[error("audit log write failed; execution aborted: {0}")]
    Audit(String),
}

/// Stable label for a policy effect, as written to the audit log.
pub fn effect_label(effect: &PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allowed => "allow",
        PolicyEffect::Denied { .. } => "deny",
        PolicyEffect::RequiresApproval => "require_approval",
        PolicyEffect::AuditOnly => "audit_only",
    }
}

/// Execute an approved plan.  See the crate docs for the rules.
///
/// Step statuses on `plan` are updated in place.  The caller writes the
/// session-level audit events (goal, approval, completion); this function
/// writes the per-step ones.
pub async fn run_plan(
    plan: &mut Plan,
    host: &str,
    session_id: Uuid,
    caps: &dyn CapabilityLookup,
    policy: &PolicyEvaluator,
    audit: &dyn AuditWriter,
    opts: &RunOptions,
) -> Result<RunReport, RunError> {
    if !plan.is_approved() {
        return Err(RunError::NotApproved);
    }

    let started = Instant::now();
    let mut steps: Vec<StepReport> = Vec::with_capacity(plan.steps.len());
    let mut halted = false;

    for i in 0..plan.steps.len() {
        let step = plan.steps[i].clone();
        let mut report = StepReport {
            sequence: step.sequence,
            capability_id: step.capability_id.clone(),
            state: StepState::Skipped,
            policy: None,
            detail: String::new(),
            result: None,
            rollback: None,
        };

        if halted {
            plan.steps[i].status = StepStatus::Skipped;
            report.detail = "skipped after an earlier step was denied or failed".into();
            steps.push(report);
            continue;
        }

        let Some(manifest) = caps.manifest(&step.capability_id) else {
            plan.steps[i].status = StepStatus::Failed;
            halted = true;
            report.state = StepState::Failed;
            report.detail = "capability is not registered in this binary".into();
            steps.push(report);
            continue;
        };

        // Rule 2: current manifest, not what the plan recorded.
        let decision = policy.evaluate(PolicyRequest {
            session_id,
            capability_id: manifest.id.clone(),
            capability_kind: manifest.kind,
            risk_tier: manifest.risk_tier,
            args: step.args.clone(),
            target_host: host.to_string(),
            timestamp: chrono::Utc::now(),
            session_phase: Some("Executing".into()),
        });
        let label = effect_label(&decision.effect);
        report.policy = Some(label.to_string());
        record(
            audit,
            AuditEventType::PolicyEvaluated {
                capability_id: manifest.id.clone(),
                effect: label.to_string(),
                rule_id: decision.matched_rule.clone(),
            },
        )
        .await?;

        // Rule 1: only `Denied` blocks a step of an approved plan.
        if let PolicyEffect::Denied { reason } = &decision.effect {
            record(
                audit,
                AuditEventType::PolicyDenied {
                    capability_id: manifest.id.clone(),
                    reason: reason.clone(),
                },
            )
            .await?;
            plan.steps[i].status = StepStatus::Skipped;
            halted = true;
            report.state = StepState::Denied;
            report.detail = reason.clone();
            steps.push(report);
            continue;
        }

        // Rule 6: the invocation is on record before it happens.
        record(
            audit,
            AuditEventType::CapabilityInvoked {
                capability_id: manifest.id.clone(),
                args: step.args.clone(),
                risk_tier: format!("{:?}", manifest.risk_tier),
            },
        )
        .await?;
        plan.steps[i].status = StepStatus::Executing;

        let mut ctx = ExecutionContext::new(session_id, host);
        if let Some(ms) = opts.step_timeout_ms {
            ctx = ctx.with_timeout_ms(ms);
        }
        let t0 = Instant::now();
        let result = match caps.implementation(&manifest.id) {
            Some(cap) => invoke_with_timeout(cap, &step.args, &ctx, opts.step_timeout_ms).await,
            None if opts.stub_unimplemented => CapabilityResult::success(
                serde_json::json!({"stub": true, "capability_id": manifest.id}),
            ),
            None => CapabilityResult::failure(
                "capability has a manifest but no implementation in this binary".to_string(),
                false,
            ),
        };
        let duration_ms = t0.elapsed().as_millis() as u64;

        match &result {
            CapabilityResult::Success { output } => {
                record(
                    audit,
                    AuditEventType::CapabilitySucceeded {
                        capability_id: manifest.id.clone(),
                        duration_ms,
                    },
                )
                .await?;
                plan.steps[i].status = StepStatus::Completed;
                report.state = StepState::Completed;
                report.detail = output.to_string();
                info!(sequence = step.sequence, capability_id = %manifest.id, duration_ms, "step completed");
            }
            other => {
                // Rule 3.
                let err = match other {
                    CapabilityResult::Failure { error, .. } => error.clone(),
                    _ => "capability returned a dry-run result from invoke".to_string(),
                };
                record(
                    audit,
                    AuditEventType::CapabilityFailed {
                        capability_id: manifest.id.clone(),
                        error: err.clone(),
                    },
                )
                .await?;
                plan.steps[i].status = StepStatus::Failed;
                halted = true;
                report.state = StepState::Failed;
                report.detail = err;
                warn!(sequence = step.sequence, capability_id = %manifest.id, "step failed");
            }
        }
        report.result = Some(result);
        steps.push(report);
    }

    if halted && opts.rollback {
        roll_back(plan, host, session_id, caps, policy, audit, &mut steps).await?;
    }

    Ok(RunReport {
        steps,
        halted,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

async fn invoke_with_timeout(
    cap: &dyn Capability,
    args: &serde_json::Value,
    ctx: &ExecutionContext,
    timeout_ms: Option<u64>,
) -> CapabilityResult {
    match timeout_ms {
        None => cap.invoke(args.clone(), ctx).await,
        Some(ms) => {
            match tokio::time::timeout(Duration::from_millis(ms), cap.invoke(args.clone(), ctx))
                .await
            {
                Ok(r) => r,
                Err(_) => CapabilityResult::failure(format!("timed out after {ms}ms"), true),
            }
        }
    }
}

/// Rule 5: undo completed steps, newest first.
async fn roll_back(
    plan: &mut Plan,
    host: &str,
    session_id: Uuid,
    caps: &dyn CapabilityLookup,
    policy: &PolicyEvaluator,
    audit: &dyn AuditWriter,
    steps: &mut [StepReport],
) -> Result<(), RunError> {
    for i in (0..plan.steps.len()).rev() {
        if steps[i].state != StepState::Completed || !plan.steps[i].can_rollback {
            continue;
        }
        let id = plan.steps[i].capability_id.clone();
        let args = plan.steps[i].args.clone();
        let (Some(cap), Some(manifest)) = (caps.implementation(&id), caps.manifest(&id)) else {
            steps[i].rollback = Some("not attempted: no implementation".into());
            continue;
        };

        // The inverse is itself a change to the host.  Policy can still veto
        // it (kill switch, resource guard, an explicit deny); a plan approval
        // is enough for anything short of that.
        let decision = policy.evaluate(PolicyRequest {
            session_id,
            capability_id: manifest.id.clone(),
            capability_kind: manifest.kind,
            risk_tier: manifest.risk_tier,
            args: args.clone(),
            target_host: host.to_string(),
            timestamp: chrono::Utc::now(),
            session_phase: Some("RollingBack".into()),
        });
        if let PolicyEffect::Denied { reason } = &decision.effect {
            record(
                audit,
                AuditEventType::PolicyDenied {
                    capability_id: id.clone(),
                    reason: format!("rollback refused: {reason}"),
                },
            )
            .await?;
            steps[i].rollback = Some(format!("refused by policy: {reason}"));
            continue;
        }

        let ctx = ExecutionContext::new(session_id, host);
        match cap.invoke_inverse(args, &ctx).await {
            Some(CapabilityResult::Success { .. }) => {
                record(
                    audit,
                    AuditEventType::CapabilityRolledBack {
                        capability_id: id.clone(),
                    },
                )
                .await?;
                plan.steps[i].status = StepStatus::RolledBack;
                steps[i].state = StepState::RolledBack;
                steps[i].rollback = Some("rolled back".into());
                info!(capability_id = %id, "rollback succeeded");
            }
            Some(CapabilityResult::Failure { error, .. }) => {
                record(
                    audit,
                    AuditEventType::CapabilityFailed {
                        capability_id: id.clone(),
                        error: format!("rollback failed: {error}"),
                    },
                )
                .await?;
                steps[i].rollback = Some(format!("failed: {error}"));
                warn!(capability_id = %id, %error, "rollback failed; step stays Completed");
            }
            Some(CapabilityResult::DryRun { .. }) | None => {
                steps[i].rollback = Some("not available: capability has no inverse".into());
            }
        }
    }
    Ok(())
}

async fn record(audit: &dyn AuditWriter, event: AuditEventType) -> Result<(), RunError> {
    audit.record(event).await.map_err(RunError::Audit)
}

#[cfg(test)]
mod tests;
