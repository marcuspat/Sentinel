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
//! Writes are atomic and durable (write to a temp file in the same directory,
//! `fsync`, `rename`, `fsync` the directory).
//!
//! Every status transition is read-modify-write, so it runs under an
//! exclusive `flock` on a per-plan lock file (`.<plan_id>.lock`).  Two
//! `sentinel execute` processes racing for the same approved plan therefore
//! cannot both claim it: the second one sees `Executing` and is refused.
//! The lock file is separate from the plan document because `rename`
//! replaces the document's inode, which would silently drop a lock held on
//! it.

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

/// Exclusive advisory lock on one plan, released when dropped (or when the
/// process dies, which is why this is `flock` and not a marker file).
#[derive(Debug)]
pub struct PlanLock {
    _file: std::fs::File,
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

    /// Take the exclusive lock for plan `id`, blocking until it is free.
    ///
    /// Critical sections are a few small file operations, so waiting is
    /// brief.  On non-Unix targets this is a no-op handle.
    pub fn lock(&self, id: Uuid) -> Result<PlanLock, StoreError> {
        let path = self.dir.join(format!(".{id}.lock"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            loop {
                // SAFETY: `file` is an open descriptor owned by this scope.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    return Err(err.into());
                }
            }
        }
        Ok(PlanLock { _file: file })
    }

    /// Persist a record atomically and durably.
    ///
    /// This does not take the plan lock.  Use it for a brand-new plan, or
    /// while holding [`PlanStore::lock`]; for a status change use
    /// [`PlanStore::update`] or one of the transition methods.
    pub fn save(&self, rec: &StoredPlan) -> Result<(), StoreError> {
        use std::io::Write;
        let final_path = self.path_for(rec.plan.id);
        let tmp_path = self
            .dir
            .join(format!(".{}.{}.tmp", rec.plan.id, Uuid::new_v4()));
        let body = serde_json::to_vec_pretty(rec)?;
        let write = || -> std::io::Result<()> {
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(&body)?;
            // Data must be on disk before the rename makes it the plan of
            // record; otherwise a crash can leave an empty document.
            tmp.sync_all()?;
            std::fs::rename(&tmp_path, &final_path)?;
            // Make the rename itself durable.
            #[cfg(unix)]
            std::fs::File::open(&self.dir)?.sync_all()?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }
        Ok(())
    }

    /// Load, modify and save a plan under its lock.  `change` sees the
    /// current on-disk record; returning an error leaves the plan untouched.
    pub fn update<F>(&self, id: Uuid, change: F) -> Result<StoredPlan, StoreError>
    where
        F: FnOnce(&mut StoredPlan) -> Result<(), StoreError>,
    {
        let _lock = self.lock(id)?;
        let mut rec = self.load(id)?;
        change(&mut rec)?;
        self.save(&rec)?;
        Ok(rec)
    }

    /// Atomically transition `Approved -> Executing`.
    ///
    /// Exactly one caller wins.  Everyone else gets
    /// [`StoreError::InvalidTransition`] (or `IntegrityMismatch` when the
    /// plan body no longer matches the approved hash) and must not run it.
    pub fn claim_for_execution(
        &self,
        id: Uuid,
        audit_file: Option<String>,
    ) -> Result<StoredPlan, StoreError> {
        self.update(id, |rec| {
            expect_status(rec, PlanStatus::Approved)?;
            if !rec.integrity_ok() {
                return Err(StoreError::IntegrityMismatch(id));
            }
            rec.status = PlanStatus::Executing;
            rec.execution = Some(ExecutionRecord {
                started_at: Utc::now(),
                finished_at: None,
                steps_completed: 0,
                steps_failed: 0,
                steps_skipped: 0,
                audit_file,
                error: None,
            });
            Ok(())
        })
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
        self.update(id, |rec| {
            expect_status(rec, PlanStatus::PendingApproval)?;
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
            Ok(())
        })
    }

    /// Transition `PendingApproval -> Rejected`.
    pub fn reject(
        &self,
        id: Uuid,
        by: &str,
        reason: &str,
        audit_file: Option<String>,
    ) -> Result<StoredPlan, StoreError> {
        self.update(id, |rec| {
            expect_status(rec, PlanStatus::PendingApproval)?;
            rec.status = PlanStatus::Rejected;
            rec.plan.reject(reason);
            rec.decision = Some(OperatorDecision {
                by: by.to_string(),
                at: Utc::now(),
                approved_hash: None,
                reason: Some(reason.to_string()),
                audit_file,
            });
            Ok(())
        })
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

    /// Many threads race to claim the same approved plan.  Each opens its own
    /// store handle (its own file descriptors), as separate processes would.
    #[test]
    fn only_one_claimant_wins_the_race() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        let id = rec.plan.id;
        store.save(&rec).unwrap();
        store.approve(id, "alice", None).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let state = dir.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let store = PlanStore::open(&state).unwrap();
                    barrier.wait();
                    store.claim_for_execution(id, Some(format!("audit-{i}")))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "exactly one execution may start");
        for r in results.iter().filter(|r| r.is_err()) {
            assert!(
                matches!(
                    r,
                    Err(StoreError::InvalidTransition {
                        actual: PlanStatus::Executing,
                        ..
                    })
                ),
                "{r:?}"
            );
        }
        assert_eq!(store.load(id).unwrap().status, PlanStatus::Executing);
    }

    #[test]
    fn approve_and_reject_cannot_both_succeed() {
        for _ in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let store = PlanStore::open(dir.path()).unwrap();
            let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
            let id = rec.plan.id;
            store.save(&rec).unwrap();

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let (s1, b1) = (store.clone(), barrier.clone());
            let approve = std::thread::spawn(move || {
                b1.wait();
                s1.approve(id, "alice", None).is_ok()
            });
            let (s2, b2) = (store.clone(), barrier.clone());
            let reject = std::thread::spawn(move || {
                b2.wait();
                s2.reject(id, "bob", "no", None).is_ok()
            });
            let (approved, rejected) = (approve.join().unwrap(), reject.join().unwrap());
            assert!(approved ^ rejected, "exactly one decision is recorded");

            let stored = store.load(id).unwrap();
            let expected = if approved {
                PlanStatus::Approved
            } else {
                PlanStatus::Rejected
            };
            assert_eq!(stored.status, expected);
            // The recorded decision matches the status: no torn write where
            // one operator's status sits next to the other's decision.
            let by = &stored.decision.as_ref().unwrap().by;
            assert_eq!(by, if approved { "alice" } else { "bob" });
        }
    }

    #[test]
    fn claim_refuses_unapproved_and_tampered_plans() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        let id = rec.plan.id;
        store.save(&rec).unwrap();

        assert!(matches!(
            store.claim_for_execution(id, None),
            Err(StoreError::InvalidTransition {
                actual: PlanStatus::PendingApproval,
                ..
            })
        ));

        let mut approved = store.approve(id, "alice", None).unwrap();
        approved.plan.steps[0].args = serde_json::json!({"log_dir": "/", "older_than_days": 0});
        store.save(&approved).unwrap();
        assert!(matches!(
            store.claim_for_execution(id, None),
            Err(StoreError::IntegrityMismatch(_))
        ));
        assert_eq!(
            store.load(id).unwrap().status,
            PlanStatus::Approved,
            "a refused claim leaves the plan untouched"
        );
    }

    #[test]
    fn failed_update_leaves_no_temp_files_and_list_ignores_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlanStore::open(dir.path()).unwrap();
        let rec = StoredPlan::new_pending(sample_plan(), "localhost", Uuid::new_v4(), None);
        let id = rec.plan.id;
        store.save(&rec).unwrap();
        let _ = store.claim_for_execution(id, None); // refused: takes the lock
        assert_eq!(store.list().unwrap().len(), 1);
        let leftovers: Vec<_> = std::fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
