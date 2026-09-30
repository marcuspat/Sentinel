//! File-backed plan store.
//!
//! Plans proposed over MCP are persisted as one JSON document per plan under
//! `<state_dir>/plans/<plan_id>.json`.  The store is the hand-off point
//! between the agent-facing MCP server (which can only *create* plans in
//! [`PlanStatus::PendingApproval`]) and the operator-facing CLI (which is the
//! only code path that calls [`PlanStore::approve`]).
//!
//! Every stored plan carries a SHA-256 `content_hash` over the fields that
//! determine what will run (goal, host, and each step's capability, args and
//! risk tier).  Approval pins that hash; execution refuses to run a plan whose
//! current content no longer matches the approved hash.
//!
//! Writes are atomic (write to a temp file in the same directory, then
//! `rename`).  The store is not a lock manager: two operators approving and
//! executing the same plan concurrently is guarded only by the status
//! transition check, which is read-modify-write on a single file.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use sentinel_core::Plan;

/// Lifecycle of a plan proposed through the MCP gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanStatus {
    /// Stored by `sentinel_propose_plan`; waiting for an operator.
    PendingApproval,
    /// Approved out-of-band by an operator (`sentinel approve`).
    Approved,
    /// Rejected out-of-band by an operator (`sentinel reject`).
    Rejected,
    /// `sentinel execute` has claimed the plan and is running it.
    Executing,
    /// Every step ran successfully.
    Executed,
    /// Execution stopped on a denied or failed step.
    ExecutionFailed,
}

impl std::fmt::Display for PlanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PlanStatus::PendingApproval => "PendingApproval",
            PlanStatus::Approved => "Approved",
            PlanStatus::Rejected => "Rejected",
            PlanStatus::Executing => "Executing",
            PlanStatus::Executed => "Executed",
            PlanStatus::ExecutionFailed => "ExecutionFailed",
        };
        f.write_str(s)
    }
}

/// Operator decision recorded against a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorDecision {
    /// Free-form operator identity (e.g. `$USER`).  Not authenticated.
    pub by: String,
    pub at: DateTime<Utc>,
    /// Content hash the operator saw and approved (`None` for rejections).
    pub approved_hash: Option<String>,
    /// Rejection reason (`None` for approvals).
    pub reason: Option<String>,
    /// Audit log file that recorded the decision.
    pub audit_file: Option<String>,
}

/// Outcome of `sentinel execute`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub steps_completed: u32,
    pub steps_failed: u32,
    pub steps_skipped: u32,
    pub audit_file: Option<String>,
    pub error: Option<String>,
}

/// A plan plus its gate metadata, as persisted on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPlan {
    pub plan: Plan,
    pub host: String,
    pub status: PlanStatus,
    pub content_hash: String,
    /// Always `"mcp"` today; kept so other proposers can be added later.
    pub proposed_via: String,
    /// MCP server session that proposed the plan (matches its audit log).
    pub proposer_session: Uuid,
    pub proposed_at: DateTime<Utc>,
    /// Audit log file of the proposing MCP session.
    pub proposal_audit_file: Option<String>,
    pub decision: Option<OperatorDecision>,
    pub execution: Option<ExecutionRecord>,
}

#[derive(Serialize)]
struct HashedStep<'a> {
    sequence: u32,
    capability_id: &'a str,
    args: &'a serde_json::Value,
    risk_tier: sentinel_core::RiskTier,
}

#[derive(Serialize)]
struct HashedPlan<'a> {
    plan_id: Uuid,
    goal: &'a str,
    host: &'a str,
    steps: Vec<HashedStep<'a>>,
}

/// SHA-256 over the fields of a plan that determine what will execute.
pub fn plan_content_hash(plan: &Plan, host: &str) -> String {
    let hashed = HashedPlan {
        plan_id: plan.id,
        goal: &plan.goal,
        host,
        steps: plan
            .steps
            .iter()
            .map(|s| HashedStep {
                sequence: s.sequence,
                capability_id: &s.capability_id,
                args: &s.args,
                risk_tier: s.risk_tier,
            })
            .collect(),
    };
    let json = serde_json::to_string(&hashed).expect("HashedPlan is always serialisable");
    hex::encode(Sha256::digest(json.as_bytes()))
}

impl StoredPlan {
    /// Wrap a freshly proposed plan in `PendingApproval` state.
    pub fn new_pending(
        plan: Plan,
        host: impl Into<String>,
        proposer_session: Uuid,
        proposal_audit_file: Option<String>,
    ) -> Self {
        let host = host.into();
        let content_hash = plan_content_hash(&plan, &host);
        Self {
            plan,
            host,
            status: PlanStatus::PendingApproval,
            content_hash,
            proposed_via: "mcp".into(),
            proposer_session,
            proposed_at: Utc::now(),
            proposal_audit_file,
            decision: None,
            execution: None,
        }
    }

    /// Recompute the content hash from the current plan body.
    pub fn recompute_hash(&self) -> String {
        plan_content_hash(&self.plan, &self.host)
    }

    /// `true` when the stored hash and the recomputed hash agree and, if the
    /// plan was approved, the approved hash agrees too.
    pub fn integrity_ok(&self) -> bool {
        let current = self.recompute_hash();
        if current != self.content_hash {
            return false;
        }
        match &self.decision {
            Some(OperatorDecision {
                approved_hash: Some(h),
                ..
            }) => *h == current,
            _ => true,
        }
    }
}

/// Errors from the plan store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("plan {0} not found")]
    NotFound(Uuid),
    #[error("plan {id} is {actual}, expected {expected}")]
    InvalidTransition {
        id: Uuid,
        expected: PlanStatus,
        actual: PlanStatus,
    },
    #[error("plan {0} failed integrity check: content does not match the recorded/approved hash")]
    IntegrityMismatch(Uuid),
    #[error("plan store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("plan store serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Directory-backed store of [`StoredPlan`] documents.
#[derive(Debug, Clone)]
pub struct PlanStore {
    dir: PathBuf,
}

impl PlanStore {
    /// Open (creating if needed) `<state_dir>/plans`.
    pub fn open(state_dir: &Path) -> Result<Self, StoreError> {
        let dir = state_dir.join("plans");
        std::fs::create_dir_all(&dir)?;
        restrict_dir_permissions(&dir);
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Persist a record atomically.
    pub fn save(&self, rec: &StoredPlan) -> Result<(), StoreError> {
        let final_path = self.path_for(rec.plan.id);
        let tmp_path = self
            .dir
            .join(format!(".{}.{}.tmp", rec.plan.id, Uuid::new_v4()));
        let body = serde_json::to_vec_pretty(rec)?;
        std::fs::write(&tmp_path, body)?;
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Load a record.  Does *not* check integrity; callers that are about to
    /// act on the plan must call [`StoredPlan::integrity_ok`].
    pub fn load(&self, id: Uuid) -> Result<StoredPlan, StoreError> {
        let path = self.path_for(id);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(id))
            }
            Err(e) => return Err(e.into()),
        };
        let rec: StoredPlan = serde_json::from_slice(&bytes)?;
        if rec.plan.id != id {
            return Err(StoreError::IntegrityMismatch(id));
        }
        Ok(rec)
    }

    /// All stored plans, newest first.
    pub fn list(&self) -> Result<Vec<StoredPlan>, StoreError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(stem) else {
                continue;
            };
            out.push(self.load(id)?);
        }
        out.sort_by_key(|p| std::cmp::Reverse(p.proposed_at));
        Ok(out)
    }

    /// Transition `PendingApproval -> Approved`, pinning the content hash.
    ///
    /// This is deliberately **not** reachable from the MCP server: only the
    /// operator CLI (`sentinel approve`) calls it.
    pub fn approve(
        &self,
        id: Uuid,
        by: &str,
        audit_file: Option<String>,
    ) -> Result<StoredPlan, StoreError> {
        let mut rec = self.load(id)?;
        expect_status(&rec, PlanStatus::PendingApproval)?;
        if !rec.integrity_ok() {
            return Err(StoreError::IntegrityMismatch(id));
        }
        rec.status = PlanStatus::Approved;
        rec.plan.approve();
        rec.decision = Some(OperatorDecision {
            by: by.to_string(),
            at: Utc::now(),
            approved_hash: Some(rec.content_hash.clone()),
            reason: None,
            audit_file,
        });
        self.save(&rec)?;
        Ok(rec)
    }

    /// Transition `PendingApproval -> Rejected`.
    pub fn reject(
        &self,
        id: Uuid,
        by: &str,
        reason: &str,
        audit_file: Option<String>,
    ) -> Result<StoredPlan, StoreError> {
        let mut rec = self.load(id)?;
        expect_status(&rec, PlanStatus::PendingApproval)?;
        rec.status = PlanStatus::Rejected;
        rec.plan.reject(reason);
        rec.decision = Some(OperatorDecision {
            by: by.to_string(),
            at: Utc::now(),
            approved_hash: None,
            reason: Some(reason.to_string()),
            audit_file,
        });
        self.save(&rec)?;
        Ok(rec)
    }
}

pub(crate) fn expect_status(rec: &StoredPlan, expected: PlanStatus) -> Result<(), StoreError> {
    if rec.status != expected {
        return Err(StoreError::InvalidTransition {
            id: rec.plan.id,
            expected,
            actual: rec.status,
        });
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn restrict_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Best effort: plan and audit files may contain host details.
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
pub(crate) fn restrict_dir_permissions(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{PlanStep, RiskTier};

    fn sample_plan() -> Plan {
        let mut p = Plan::new(Uuid::new_v4(), "free disk".into(), "because".into());
        p.add_step(PlanStep::new(
            1,
            "log_vacuum",
            serde_json::json!({"log_dir": "/var/log/app", "older_than_days": 7}),
            "vacuum",
            RiskTier::Medium,
        ));
        p
    }

    #[test]
    fn save_load_roundtrip_preserves_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        store.save(&rec).unwrap();
        let back = store.load(rec.plan.id).unwrap();
        assert_eq!(back.status, PlanStatus::PendingApproval);
        assert_eq!(back.content_hash, rec.content_hash);
        assert!(back.integrity_ok());
    }

    #[test]
    fn load_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        assert!(matches!(
            store.load(Uuid::new_v4()),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn approve_pins_hash_and_is_single_shot() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        store.save(&rec).unwrap();
        let approved = store.approve(rec.plan.id, "alice", None).unwrap();
        assert_eq!(approved.status, PlanStatus::Approved);
        assert!(approved.plan.is_approved());
        assert_eq!(
            approved.decision.as_ref().unwrap().approved_hash.as_deref(),
            Some(rec.content_hash.as_str())
        );
        // Second approval is an invalid transition.
        assert!(matches!(
            store.approve(rec.plan.id, "alice", None),
            Err(StoreError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn reject_then_approve_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        store.save(&rec).unwrap();
        store.reject(rec.plan.id, "bob", "nope", None).unwrap();
        assert!(store.approve(rec.plan.id, "bob", None).is_err());
    }

    #[test]
    fn edited_pending_plan_cannot_be_approved() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let mut rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        store.save(&rec).unwrap();
        // Simulate someone editing the JSON on disk without updating the hash.
        rec.plan.steps[0].args = serde_json::json!({"log_dir": "/", "older_than_days": 0});
        store.save(&rec).unwrap();
        assert!(matches!(
            store.approve(rec.plan.id, "alice", None),
            Err(StoreError::IntegrityMismatch(_))
        ));
    }

    #[test]
    fn edit_after_approval_breaks_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        store.save(&rec).unwrap();
        let mut approved = store.approve(rec.plan.id, "alice", None).unwrap();
        approved.plan.steps[0].capability_id = "cache_prune".into();
        // Even if the attacker also rewrites content_hash, approved_hash differs.
        approved.content_hash = approved.recompute_hash();
        assert!(!approved.integrity_ok());
    }

    #[test]
    fn list_returns_all_plans() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        for _ in 0..3 {
            let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
            store.save(&rec).unwrap();
        }
        assert_eq!(store.list().unwrap().len(), 3);
    }
}
