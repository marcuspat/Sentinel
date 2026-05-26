use crate::{
    error::AuditError,
    events::AuditEvent,
    log::{AuditLog, ChainVerificationResult},
};

/// Stateless verifier for audit logs loaded from external JSONL sources.
pub struct AuditVerifier;

impl AuditVerifier {
    /// Parse a JSONL string (one `AuditEvent` JSON per line) and verify that
    /// the complete hash chain is intact.
    ///
    /// Empty input is considered valid (zero events, zero checks).
    pub fn verify_jsonl(jsonl: &str) -> Result<ChainVerificationResult, AuditError> {
        let mut events: Vec<AuditEvent> = Vec::new();

        for (line_no, line) in jsonl.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(trimmed).map_err(|e| {
                AuditError::InvalidEvent(format!("line {}: {e}", line_no + 1))
            })?;
            events.push(event);
        }

        Ok(Self::verify_events(&events))
    }

    /// Verify that `events` forms a valid hash chain.
    ///
    /// Rules checked:
    /// 1. The first event's `prev_hash` must equal the genesis hash (64 zeros).
    /// 2. Every event's `this_hash` must equal `compute_hash(prev_hash, ...)`.
    /// 3. Each event's `prev_hash` must equal the previous event's `this_hash`.
    /// 4. Sequence numbers must be consecutive starting from 0.
    pub fn verify_events(events: &[AuditEvent]) -> ChainVerificationResult {
        if events.is_empty() {
            return ChainVerificationResult {
                valid: true,
                events_checked: 0,
                first_broken_at: None,
                error: None,
            };
        }

        // Verify genesis prev_hash
        if events[0].prev_hash != AuditLog::GENESIS_HASH {
            return ChainVerificationResult {
                valid: false,
                events_checked: 0,
                first_broken_at: Some(events[0].sequence),
                error: Some(format!(
                    "genesis event has prev_hash '{}' but expected all-zeros",
                    events[0].prev_hash
                )),
            };
        }

        let mut expected_prev = AuditLog::GENESIS_HASH.to_string();

        for (idx, event) in events.iter().enumerate() {
            // Check sequence number is monotonically increasing from 0.
            if event.sequence != idx as u64 {
                return ChainVerificationResult {
                    valid: false,
                    events_checked: idx,
                    first_broken_at: Some(event.sequence),
                    error: Some(format!(
                        "sequence gap: expected {idx}, got {}",
                        event.sequence
                    )),
                };
            }

            // Check prev_hash linkage.
            if event.prev_hash != expected_prev {
                return ChainVerificationResult {
                    valid: false,
                    events_checked: idx,
                    first_broken_at: Some(event.sequence),
                    error: Some(format!(
                        "seq {}: prev_hash mismatch (expected {}, got {})",
                        event.sequence, expected_prev, event.prev_hash
                    )),
                };
            }

            // Check this_hash is correct.
            if !event.verify_hash() {
                let expected_hash = AuditEvent::compute_hash(
                    &event.prev_hash,
                    &event.event_type,
                    event.event_id,
                    event.sequence,
                    &event.timestamp,
                    event.session_id,
                );
                return ChainVerificationResult {
                    valid: false,
                    events_checked: idx,
                    first_broken_at: Some(event.sequence),
                    error: Some(format!(
                        "seq {}: hash mismatch (expected {}, got {})",
                        event.sequence, expected_hash, event.this_hash
                    )),
                };
            }

            expected_prev = event.this_hash.clone();
        }

        ChainVerificationResult {
            valid: true,
            events_checked: events.len(),
            first_broken_at: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AuditEventType;
    use uuid::Uuid;

    async fn make_log_events(count: usize) -> Vec<AuditEvent> {
        use crate::log::AuditLog;
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        for _ in 0..count {
            log.append(AuditEventType::InvestigationStarted)
                .await
                .unwrap();
        }
        log.events().to_vec()
    }

    #[tokio::test]
    async fn verify_empty_is_valid() {
        let result = AuditVerifier::verify_events(&[]);
        assert!(result.valid);
        assert_eq!(result.events_checked, 0);
        assert!(result.first_broken_at.is_none());
    }

    #[tokio::test]
    async fn verify_valid_chain() {
        let events = make_log_events(5).await;
        let result = AuditVerifier::verify_events(&events);
        assert!(result.valid);
        assert_eq!(result.events_checked, 5);
        assert!(result.first_broken_at.is_none());
    }

    #[tokio::test]
    async fn verify_detects_tampered_event_type() {
        let mut events = make_log_events(3).await;
        // Tamper with event 1's data (but leave its hash unchanged).
        events[1].event_type = AuditEventType::KillSwitchActivated {
            reason: "tampered".into(),
        };
        let result = AuditVerifier::verify_events(&events);
        assert!(!result.valid);
        assert_eq!(result.first_broken_at, Some(1));
    }

    #[tokio::test]
    async fn verify_detects_tampered_prev_hash() {
        let mut events = make_log_events(3).await;
        events[1].prev_hash = "a".repeat(64);
        let result = AuditVerifier::verify_events(&events);
        assert!(!result.valid);
        assert_eq!(result.first_broken_at, Some(1));
    }

    #[tokio::test]
    async fn verify_detects_wrong_genesis_prev_hash() {
        let mut events = make_log_events(2).await;
        events[0].prev_hash = "1".repeat(64);
        let result = AuditVerifier::verify_events(&events);
        assert!(!result.valid);
        assert_eq!(result.first_broken_at, Some(0));
    }

    #[tokio::test]
    async fn verify_jsonl_round_trip() {
        use crate::log::AuditLog;
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        log.append(AuditEventType::GoalSubmitted {
            goal: "test".into(),
            host: "localhost".into(),
        })
        .await
        .unwrap();
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        log.append(AuditEventType::SessionCompleted {
            duration_ms: 100,
            capabilities_executed: 1,
        })
        .await
        .unwrap();

        let jsonl = log.export_jsonl();
        let result = AuditVerifier::verify_jsonl(&jsonl).unwrap();
        assert!(result.valid);
        assert_eq!(result.events_checked, 3);
    }

    #[tokio::test]
    async fn verify_jsonl_invalid_json_returns_error() {
        let bad = "not-json\n";
        let result = AuditVerifier::verify_jsonl(bad);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_jsonl_empty_string_is_valid() {
        let result = AuditVerifier::verify_jsonl("").unwrap();
        assert!(result.valid);
        assert_eq!(result.events_checked, 0);
    }

    #[tokio::test]
    async fn verify_jsonl_detects_tampered_event() {
        use crate::log::AuditLog;
        let mut log = AuditLog::new(Uuid::new_v4(), None);
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
        log.append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();

        // Build JSONL manually with a tampered first event.
        let mut events = log.events().to_vec();
        events[0].event_type = AuditEventType::KillSwitchActivated {
            reason: "injected".into(),
        };
        let jsonl = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let result = AuditVerifier::verify_jsonl(&jsonl).unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_broken_at, Some(0));
    }
}
