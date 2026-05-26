use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// All structured event variants captured in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AuditEventType {
    GoalSubmitted {
        goal: String,
        host: String,
    },
    InvestigationStarted,
    ObservationRecorded {
        capability_id: String,
        args: serde_json::Value,
        result_summary: String,
    },
    PlanProposed {
        plan_id: Uuid,
        step_count: usize,
        overall_risk: String,
    },
    PlanApproved {
        plan_id: Uuid,
        approval_mode: String,
    },
    PlanRejected {
        plan_id: Uuid,
        reason: String,
    },
    PlanEdited {
        plan_id: Uuid,
        changes: String,
    },
    CapabilityInvoked {
        capability_id: String,
        args: serde_json::Value,
        risk_tier: String,
    },
    CapabilitySucceeded {
        capability_id: String,
        duration_ms: u64,
    },
    CapabilityFailed {
        capability_id: String,
        error: String,
    },
    CapabilityRolledBack {
        capability_id: String,
    },
    PolicyEvaluated {
        capability_id: String,
        effect: String,
        rule_id: Option<String>,
    },
    PolicyDenied {
        capability_id: String,
        reason: String,
    },
    KillSwitchActivated {
        reason: String,
    },
    SessionCompleted {
        duration_ms: u64,
        capabilities_executed: u64,
    },
    SessionAborted {
        reason: String,
    },
    SessionCheckpointed {
        checkpoint_id: Uuid,
    },
    HostRegistered {
        host_id: String,
        hostname: String,
    },
    FleetCommandDispatched {
        command_id: Uuid,
        host_count: usize,
    },
}

/// A single entry in the audit log, carrying its position in the hash chain.
///
/// `this_hash = SHA-256(prev_hash_bytes || canonical_json_without_this_hash)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub session_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    /// Hex-encoded SHA-256 of the *previous* event (or 64 zeros for genesis).
    pub prev_hash: String,
    /// Hex-encoded SHA-256 of `prev_hash || canonical_json_of_this_event_without_this_hash`.
    pub this_hash: String,
}

/// Intermediate struct used for hashing — identical to `AuditEvent` but without `this_hash`.
#[derive(Serialize)]
struct AuditEventForHash<'a> {
    event_id: Uuid,
    session_id: Uuid,
    sequence: u64,
    timestamp: &'a DateTime<Utc>,
    event_type: &'a AuditEventType,
    prev_hash: &'a str,
}

impl AuditEvent {
    /// Compute `SHA-256(prev_hash_bytes || canonical_json_of_event_without_this_hash)`.
    ///
    /// `prev_hash` must be the lowercase hex string of the previous hash
    /// (64 zeros for genesis).
    pub fn compute_hash(
        prev_hash: &str,
        event_type: &AuditEventType,
        event_id: Uuid,
        sequence: u64,
        timestamp: &DateTime<Utc>,
        session_id: Uuid,
    ) -> String {
        let partial = AuditEventForHash {
            event_id,
            session_id,
            sequence,
            timestamp,
            event_type,
            prev_hash,
        };

        // Canonical JSON (keys in insertion order via serde_json).
        let json = serde_json::to_string(&partial)
            .expect("AuditEventForHash is always serialisable");

        let mut hasher = Sha256::new();
        // Prepend raw bytes of the hex prev_hash string (not decoded bytes —
        // the spec says SHA-256(hex(prev_hash_bytes) || canonical_json)).
        hasher.update(prev_hash.as_bytes());
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Return `true` iff `this_hash` matches what `compute_hash` would produce.
    pub fn verify_hash(&self) -> bool {
        let expected = Self::compute_hash(
            &self.prev_hash,
            &self.event_type,
            self.event_id,
            self.sequence,
            &self.timestamp,
            self.session_id,
        );
        expected == self.this_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(seq: u64, prev_hash: &str) -> AuditEvent {
        let session_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let event_type = AuditEventType::InvestigationStarted;

        let this_hash = AuditEvent::compute_hash(
            prev_hash,
            &event_type,
            event_id,
            seq,
            &timestamp,
            session_id,
        );

        AuditEvent {
            event_id,
            session_id,
            sequence: seq,
            timestamp,
            event_type,
            prev_hash: prev_hash.to_string(),
            this_hash,
        }
    }

    #[test]
    fn genesis_hash_is_valid() {
        let genesis_prev = "0".repeat(64);
        let ev = make_event(0, &genesis_prev);
        assert!(ev.verify_hash(), "genesis event hash should verify");
    }

    #[test]
    fn chained_hash_is_valid() {
        let genesis_prev = "0".repeat(64);
        let ev0 = make_event(0, &genesis_prev);
        let ev1 = make_event(1, &ev0.this_hash);
        assert!(ev1.verify_hash());
    }

    #[test]
    fn tampered_event_fails_verification() {
        let genesis_prev = "0".repeat(64);
        let mut ev = make_event(0, &genesis_prev);
        // Mutate the event after hashing.
        ev.event_type = AuditEventType::KillSwitchActivated {
            reason: "injected".into(),
        };
        assert!(!ev.verify_hash(), "tampered event should fail hash check");
    }

    #[test]
    fn tampered_prev_hash_fails_verification() {
        let genesis_prev = "0".repeat(64);
        let mut ev = make_event(0, &genesis_prev);
        ev.prev_hash = "a".repeat(64);
        assert!(!ev.verify_hash());
    }

    #[test]
    fn hash_is_deterministic() {
        let session_id = Uuid::nil();
        let event_id = Uuid::nil();
        let ts = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event_type = AuditEventType::InvestigationStarted;
        let prev = "0".repeat(64);

        let h1 = AuditEvent::compute_hash(&prev, &event_type, event_id, 0, &ts, session_id);
        let h2 = AuditEvent::compute_hash(&prev, &event_type, event_id, 0, &ts, session_id);
        assert_eq!(h1, h2);
    }

    #[test]
    fn all_event_types_serialize() {
        let variants: Vec<AuditEventType> = vec![
            AuditEventType::GoalSubmitted {
                goal: "fix nginx".into(),
                host: "web1".into(),
            },
            AuditEventType::InvestigationStarted,
            AuditEventType::ObservationRecorded {
                capability_id: "read_file".into(),
                args: serde_json::json!({"path": "/etc/nginx.conf"}),
                result_summary: "ok".into(),
            },
            AuditEventType::PlanProposed {
                plan_id: Uuid::new_v4(),
                step_count: 3,
                overall_risk: "low".into(),
            },
            AuditEventType::PlanApproved {
                plan_id: Uuid::new_v4(),
                approval_mode: "auto".into(),
            },
            AuditEventType::PlanRejected {
                plan_id: Uuid::new_v4(),
                reason: "too risky".into(),
            },
            AuditEventType::PlanEdited {
                plan_id: Uuid::new_v4(),
                changes: "removed step 2".into(),
            },
            AuditEventType::CapabilityInvoked {
                capability_id: "exec".into(),
                args: serde_json::json!({}),
                risk_tier: "high".into(),
            },
            AuditEventType::CapabilitySucceeded {
                capability_id: "exec".into(),
                duration_ms: 42,
            },
            AuditEventType::CapabilityFailed {
                capability_id: "exec".into(),
                error: "exit 1".into(),
            },
            AuditEventType::CapabilityRolledBack {
                capability_id: "exec".into(),
            },
            AuditEventType::PolicyEvaluated {
                capability_id: "exec".into(),
                effect: "allow".into(),
                rule_id: Some("r1".into()),
            },
            AuditEventType::PolicyDenied {
                capability_id: "exec".into(),
                reason: "blocked".into(),
            },
            AuditEventType::KillSwitchActivated {
                reason: "operator".into(),
            },
            AuditEventType::SessionCompleted {
                duration_ms: 1000,
                capabilities_executed: 5,
            },
            AuditEventType::SessionAborted {
                reason: "timeout".into(),
            },
            AuditEventType::SessionCheckpointed {
                checkpoint_id: Uuid::new_v4(),
            },
            AuditEventType::HostRegistered {
                host_id: "h1".into(),
                hostname: "web1".into(),
            },
            AuditEventType::FleetCommandDispatched {
                command_id: Uuid::new_v4(),
                host_count: 10,
            },
        ];

        for variant in &variants {
            let json = serde_json::to_string(variant).expect("must serialize");
            let _back: AuditEventType = serde_json::from_str(&json).expect("must deserialize");
        }
    }
}
