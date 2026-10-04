//! Operator decisions on stored plans, shared by `sentinel approve` /
//! `sentinel reject` and the TUI's Gate tab so both write the same audit
//! events and apply the same checks.
//!
//! These functions are the *only* callers of [`PlanStore::approve`].  The
//! MCP server never links to them through a tool.

use std::path::Path;

use sentinel_audit::AuditEventType;
use uuid::Uuid;

use crate::audit::AuditSink;
use crate::store::{PlanStatus, PlanStore, StoreError, StoredPlan};

/// Why an operator decision was not recorded.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("plan {id} is {status}, not PendingApproval")]
    NotPending { id: Uuid, status: PlanStatus },
    #[error(
        "plan {0} failed its integrity check (content changed after proposal); refusing to approve"
    )]
    Tampered(Uuid),
    #[error("audit write failed; decision NOT recorded: {0}")]
    Audit(String),
    #[error("could not open the audit log: {0}")]
    Io(#[from] std::io::Error),
}

/// The login name recorded against a decision.  Not authenticated.
pub fn operator_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

/// Checks that must hold before an operator is even asked to confirm.
pub fn check_approvable(rec: &StoredPlan) -> Result<(), OperatorError> {
    if rec.status != PlanStatus::PendingApproval {
        return Err(OperatorError::NotPending {
            id: rec.plan.id,
            status: rec.status,
        });
    }
    if !rec.integrity_ok() {
        return Err(OperatorError::Tampered(rec.plan.id));
    }
    Ok(())
}

/// Approve a pending plan: audit first, then the locked status transition.
///
/// `via` names the surface the operator used (`operator_cli`, `operator_tui`)
/// and is written into the audit event.
pub async fn approve_plan(
    store: &PlanStore,
    state_dir: &Path,
    plan_id: Uuid,
    who: &str,
    via: &str,
) -> Result<(StoredPlan, AuditSink), OperatorError> {
    let rec = store.load(plan_id)?;
    check_approvable(&rec)?;
    let audit = AuditSink::create(state_dir, "approve")?;
    audit
        .record(AuditEventType::PlanApproved {
            plan_id,
            approval_mode: format!(
                "{via}:{who}:{}",
                &rec.content_hash[..12.min(rec.content_hash.len())]
            ),
        })
        .await
        .map_err(|e| OperatorError::Audit(e.to_string()))?;
    let rec = store.approve(plan_id, who, Some(audit.path_string()))?;
    Ok((rec, audit))
}

/// Reject a pending plan.
pub async fn reject_plan(
    store: &PlanStore,
    state_dir: &Path,
    plan_id: Uuid,
    who: &str,
    reason: &str,
) -> Result<StoredPlan, OperatorError> {
    let audit = AuditSink::create(state_dir, "reject")?;
    audit
        .record(AuditEventType::PlanRejected {
            plan_id,
            reason: reason.to_string(),
        })
        .await
        .map_err(|e| OperatorError::Audit(e.to_string()))?;
    Ok(store.reject(plan_id, who, reason, Some(audit.path_string()))?)
}
