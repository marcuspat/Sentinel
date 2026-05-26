use std::path::PathBuf;

use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use uuid::Uuid;

use crate::{
    error::AuditError,
    events::{AuditEvent, AuditEventType},
    verifier::AuditVerifier,
};

/// Result returned by full chain verification.
#[derive(Debug)]
pub struct ChainVerificationResult {
    pub valid: bool,
    pub events_checked: usize,
    /// Sequence number of the first event whose hash is wrong.
    pub first_broken_at: Option<u64>,
    pub error: Option<String>,
}

/// Append-only, hash-chained audit log.
///
/// Events are stored in memory and, if `file_path` is provided, written
/// immediately to a JSONL file (one JSON object per line).
pub struct AuditLog {
    session_id: Uuid,
    events: Vec<AuditEvent>,
    next_sequence: u64,
    last_hash: String,
    file_path: Option<PathBuf>,
}

impl AuditLog {
    /// Genesis hash — 64 hex zeros, matching SHA-256 of a zero-length input
    /// represented as a 64-zero hex string per spec.
    pub const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// Create a new log for `session_id`.  If `file_path` is `Some`, every
    /// appended event is immediately flushed to that path in JSONL format.
    pub fn new(session_id: Uuid, file_path: Option<PathBuf>) -> Self {
        Self {
            session_id,
            events: Vec::new(),
            next_sequence: 0,
            last_hash: Self::GENESIS_HASH.to_string(),
            file_path,
        }
    }

    /// Append an event, computing its hash automatically.
    ///
    /// Returns a reference to the newly created `AuditEvent`.
    pub async fn append(
        &mut self,
        event_type: AuditEventType,
    ) -> Result<&AuditEvent, AuditError> {
        let event_id = Uuid::new_v4();
        let sequence = self.next_sequence;
        let timestamp = Utc::now();
        let prev_hash = self.last_hash.clone();

        let this_hash = AuditEvent::compute_hash(
            &prev_hash,
            &event_type,
            event_id,
            sequence,
            &timestamp,
            self.session_id,
        );

        let event = AuditEvent {
            event_id,
            session_id: self.session_id,
            sequence,
            timestamp,
            event_type,
            prev_hash,
            this_hash: this_hash.clone(),
        };

        // Persist to JSONL file before updating in-memory state so that
        // a write failure leaves the log in a consistent state.
        if let Some(ref path) = self.file_path {
            let line = serde_json::to_string(&event)?;
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            let line_with_newline = format!("{}\n", line);
            file.write_all(line_with_newline.as_bytes()).await?;
            file.flush().await?;
            debug!(sequence, "audit event persisted to {:?}", path);
        }

        self.last_hash = this_hash;
        self.next_sequence += 1;
        self.events.push(event);

        Ok(self.events.last().unwrap())
    }

    /// Verify the entire hash chain from genesis.
    pub fn verify_chain(&self) -> ChainVerificationResult {
        AuditVerifier::verify_events(&self.events)
    }

    /// All events in append order.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Total number of events recorded so far.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Hex hash of the most recently appended event (or genesis hash if empty).
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Serialise all events as JSONL (one JSON object per line, no trailing newline).
    pub fn export_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Produce a human-readable text report of the audit log.
    pub fn export_text_report(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "=== Sentinel Audit Log ===\n\
             Session : {}\n\
             Events  : {}\n\
             Valid   : {}\n\
             ========================\n\n",
            self.session_id,
            self.events.len(),
            self.verify_chain().valid,
        ));

        for ev in &self.events {
            out.push_str(&format!(
                "[{seq:>6}] {ts}  {kind}\n         event_id={eid}  prev={prev}  hash={hash}\n\n",
                seq = ev.sequence,
                ts = ev.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                kind = event_type_label(&ev.event_type),
                eid = ev.event_id,
                prev = &ev.prev_hash[..8],
                hash = &ev.this_hash[..8],
            ));
        }

        out
    }
}

/// Short human-readable label for each event variant.
fn event_type_label(et: &AuditEventType) -> String {
    match et {
        AuditEventType::GoalSubmitted { goal, host } => {
            format!("GoalSubmitted goal=\"{goal}\" host=\"{host}\"")
        }
        AuditEventType::InvestigationStarted => "InvestigationStarted".into(),
        AuditEventType::ObservationRecorded { capability_id, .. } => {
            format!("ObservationRecorded capability={capability_id}")
        }
        AuditEventType::PlanProposed {
            plan_id,
            step_count,
            overall_risk,
        } => format!(
            "PlanProposed plan={plan_id} steps={step_count} risk={overall_risk}"
        ),
        AuditEventType::PlanApproved {
            plan_id,
            approval_mode,
        } => format!("PlanApproved plan={plan_id} mode={approval_mode}"),
        AuditEventType::PlanRejected { plan_id, reason } => {
            format!("PlanRejected plan={plan_id} reason=\"{reason}\"")
        }
        AuditEventType::PlanEdited { plan_id, changes } => {
            format!("PlanEdited plan={plan_id} changes=\"{changes}\"")
        }
        AuditEventType::CapabilityInvoked {
            capability_id,
            risk_tier,
            ..
        } => format!("CapabilityInvoked cap={capability_id} tier={risk_tier}"),
        AuditEventType::CapabilitySucceeded {
            capability_id,
            duration_ms,
        } => format!("CapabilitySucceeded cap={capability_id} duration={duration_ms}ms"),
        AuditEventType::CapabilityFailed {
            capability_id,
            error,
        } => format!("CapabilityFailed cap={capability_id} error=\"{error}\""),
        AuditEventType::CapabilityRolledBack { capability_id } => {
            format!("CapabilityRolledBack cap={capability_id}")
        }
        AuditEventType::PolicyEvaluated {
            capability_id,
            effect,
            rule_id,
        } => format!(
            "PolicyEvaluated cap={capability_id} effect={effect} rule={rule_id:?}"
        ),
        AuditEventType::PolicyDenied {
            capability_id,
            reason,
        } => format!("PolicyDenied cap={capability_id} reason=\"{reason}\""),
        AuditEventType::KillSwitchActivated { reason } => {
            format!("KillSwitchActivated reason=\"{reason}\"")
        }
        AuditEventType::SessionCompleted {
            duration_ms,
            capabilities_executed,
        } => format!(
            "SessionCompleted duration={duration_ms}ms caps={capabilities_executed}"
        ),
        AuditEventType::SessionAborted { reason } => {
            format!("SessionAborted reason=\"{reason}\"")
        }
        AuditEventType::SessionCheckpointed { checkpoint_id } => {
            format!("SessionCheckpointed checkpoint={checkpoint_id}")
        }
        AuditEventType::HostRegistered { host_id, hostname } => {
            format!("HostRegistered host_id={host_id} hostname={hostname}")
        }
        AuditEventType::FleetCommandDispatched {
            command_id,
            host_count,
        } => format!(
            "FleetCommandDispatched cmd={command_id} hosts={host_count}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn empty_log_has_genesis_hash() {
        let log = AuditLog::new(Uuid::new_v4(), None);
        assert_eq!(log.last_hash(), AuditLog::GENESIS_HASH);
        assert_eq!(log.event_count(), 0);
    }

    #[tokio::test]
    async fn single_event_chain_valid() {
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        let res = log.verify_chain();
        assert!(res.valid);
        assert_eq!(res.events_checked, 1);
        assert!(res.first_broken_at.is_none());
    }

    #[tokio::test]
    async fn multi_event_chain_valid() {
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        for _ in 0..10 {
            log.append(AuditEventType::InvestigationStarted)
                .await
                .unwrap();
        }
        assert!(log.verify_chain().valid);
        assert_eq!(log.event_count(), 10);
    }

    #[tokio::test]
    async fn tampered_event_detected() {
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        log.append(AuditEventType::GoalSubmitted {
            goal: "original".into(),
            host: "h1".into(),
        })
        .await
        .unwrap();

        // Tamper with the first event.
        log.events[0].event_type = AuditEventType::KillSwitchActivated {
            reason: "injected".into(),
        };

        let res = log.verify_chain();
        assert!(!res.valid);
        assert_eq!(res.first_broken_at, Some(0));
    }

    #[tokio::test]
    async fn jsonl_export_round_trips() {
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        log.append(AuditEventType::SessionCompleted {
            duration_ms: 500,
            capabilities_executed: 2,
        })
        .await
        .unwrap();

        let jsonl = log.export_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line must parse back to AuditEvent.
        for line in &lines {
            serde_json::from_str::<AuditEvent>(line).expect("must deserialize");
        }
    }

    #[tokio::test]
    async fn text_report_contains_session_id() {
        let sid = Uuid::new_v4();
        let mut log = AuditLog::new(sid, None);
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        let report = log.export_text_report();
        assert!(report.contains(&sid.to_string()));
        assert!(report.contains("InvestigationStarted"));
    }

    #[tokio::test]
    async fn file_persistence_writes_jsonl() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut log = AuditLog::new(Uuid::new_v4(), Some(path.clone()));
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        log.append(AuditEventType::SessionCompleted {
            duration_ms: 100,
            capabilities_executed: 1,
        })
        .await
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            serde_json::from_str::<AuditEvent>(line).expect("each line is valid JSON");
        }
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonic() {
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        for i in 0u64..5 {
            let ev = log
                .append(AuditEventType::InvestigationStarted)
                .await
                .unwrap();
            assert_eq!(ev.sequence, i);
        }
    }

    #[tokio::test]
    async fn prev_hash_links_correctly() {
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();

        assert_eq!(log.events[0].prev_hash, AuditLog::GENESIS_HASH);
        assert_eq!(log.events[1].prev_hash, log.events[0].this_hash);
    }
}
