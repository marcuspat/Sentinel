//! Property tests for audit-chain verification.
//!
//! The claim under test: a log written by `AuditLog` verifies, and *any*
//! edit to it afterwards — changing a field, dropping, duplicating,
//! reordering or inserting a line — is detected.

use proptest::prelude::*;
use sentinel_audit::{AuditEvent, AuditEventType, AuditLog, AuditVerifier};
use serde_json::{json, Value};
use uuid::Uuid;

fn event_type() -> impl Strategy<Value = AuditEventType> {
    prop_oneof![
        (".{0,40}", "[a-z0-9.-]{1,20}")
            .prop_map(|(goal, host)| AuditEventType::GoalSubmitted { goal, host }),
        Just(AuditEventType::InvestigationStarted),
        ("[a-z_]{1,16}", ".{0,40}", ".{0,60}").prop_map(|(capability_id, arg, result_summary)| {
            AuditEventType::ObservationRecorded {
                capability_id,
                args: json!({ "path": arg }),
                result_summary,
            }
        }),
        (any::<u128>(), 0usize..20, "(low|medium|high)").prop_map(|(id, step_count, risk)| {
            AuditEventType::PlanProposed {
                plan_id: Uuid::from_u128(id),
                step_count,
                overall_risk: risk,
            }
        }),
        (any::<u128>(), ".{0,40}").prop_map(|(id, reason)| AuditEventType::PlanRejected {
            plan_id: Uuid::from_u128(id),
            reason,
        }),
    ]
}

fn build(types: Vec<AuditEventType>) -> Vec<AuditEvent> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut log = AuditLog::new(Uuid::from_u128(7), None);
        for t in types {
            log.append(t).await.unwrap();
        }
        log.events().to_vec()
    })
}

fn to_jsonl(events: &[AuditEvent]) -> String {
    events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every leaf value in a JSON document, as a path of keys/indices.
fn leaf_paths(v: &Value, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                prefix.push(k.clone());
                leaf_paths(child, prefix, out);
                prefix.pop();
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                prefix.push(i.to_string());
                leaf_paths(child, prefix, out);
                prefix.pop();
            }
        }
        _ => out.push(prefix.clone()),
    }
}

fn leaf_mut<'a>(v: &'a mut Value, path: &[String]) -> &'a mut Value {
    let mut cur = v;
    for key in path {
        cur = match cur {
            Value::Object(m) => m.get_mut(key).unwrap(),
            Value::Array(a) => &mut a[key.parse::<usize>().unwrap()],
            _ => unreachable!(),
        };
    }
    cur
}

/// Change a leaf to a different value of the same type.
fn mutate(leaf: &mut Value) {
    *leaf = match &*leaf {
        Value::String(s) => {
            // Flip the first character so hashes, uuids and timestamps stay
            // the same length; the result may or may not still parse.
            let mut chars: Vec<char> = s.chars().collect();
            match chars.first_mut() {
                Some(c) => *c = if *c == '1' { '2' } else { '1' },
                None => chars.push('x'),
            }
            Value::String(chars.into_iter().collect())
        }
        Value::Number(n) => json!(n.as_u64().unwrap_or(0) + 1),
        Value::Bool(b) => json!(!b),
        _ => json!("tampered"),
    };
}

/// A tampered log is acceptable only if it is rejected: either it no longer
/// parses as audit events, or the chain is reported broken.
fn rejected(jsonl: &str) -> bool {
    match AuditVerifier::verify_jsonl(jsonl) {
        Err(_) => true,
        Ok(result) => !result.valid,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn untouched_log_verifies(types in prop::collection::vec(event_type(), 0..12)) {
        let events = build(types);
        let result = AuditVerifier::verify_jsonl(&to_jsonl(&events)).unwrap();
        prop_assert!(result.valid, "{:?}", result.error);
        prop_assert_eq!(result.events_checked, events.len());
        prop_assert!(result.first_broken_at.is_none());
    }

    /// Changing any single leaf value of any event breaks verification.
    #[test]
    fn any_single_field_edit_is_detected(
        types in prop::collection::vec(event_type(), 1..8),
        which_event in any::<prop::sample::Index>(),
        which_leaf in any::<prop::sample::Index>(),
    ) {
        let events = build(types);
        let mut docs: Vec<Value> = events.iter().map(|e| serde_json::to_value(e).unwrap()).collect();
        let i = which_event.index(docs.len());
        let mut paths = Vec::new();
        leaf_paths(&docs[i], &mut Vec::new(), &mut paths);
        let path = paths[which_leaf.index(paths.len())].clone();
        mutate(leaf_mut(&mut docs[i], &path));

        let jsonl = docs.iter().map(|d| d.to_string()).collect::<Vec<_>>().join("\n");
        prop_assert!(rejected(&jsonl), "edit to event {} at {:?} went undetected", i, path);
    }

    /// Dropping any event except the last is detected. (Dropping the tail is
    /// truncation: the hash chain alone cannot see it — the signed
    /// checkpoint in ADR-015 is the control for that.)
    #[test]
    fn dropping_a_non_final_event_is_detected(
        types in prop::collection::vec(event_type(), 2..8),
        which in any::<prop::sample::Index>(),
    ) {
        let mut events = build(types);
        let i = which.index(events.len() - 1);
        events.remove(i);
        prop_assert!(rejected(&to_jsonl(&events)), "dropping event {} went undetected", i);
    }

    #[test]
    fn duplicating_or_swapping_events_is_detected(
        types in prop::collection::vec(event_type(), 2..8),
        which in any::<prop::sample::Index>(),
        swap in any::<bool>(),
    ) {
        let mut events = build(types);
        let i = which.index(events.len() - 1);
        if swap {
            events.swap(i, i + 1);
        } else {
            let copy = events[i].clone();
            events.insert(i, copy);
        }
        prop_assert!(rejected(&to_jsonl(&events)));
    }

    /// Splicing in an event from a different log is detected, even though
    /// that event is internally consistent.
    #[test]
    fn splicing_in_a_foreign_event_is_detected(
        types in prop::collection::vec(event_type(), 2..6),
        foreign in prop::collection::vec(event_type(), 2..6),
        at in any::<prop::sample::Index>(),
        from in any::<prop::sample::Index>(),
    ) {
        let mut events = build(types);
        let other = build(foreign);
        let i = at.index(events.len());
        let donor = other[from.index(other.len())].clone();
        prop_assume!(donor.this_hash != events[i].this_hash);
        events[i] = donor;
        prop_assert!(rejected(&to_jsonl(&events)));
    }

    /// Numbers survive the trip to disk and back. A float that parsed back
    /// one bit off used to make an untouched log fail verification — and the
    /// float can come straight from an MCP client's arguments.
    #[test]
    fn numeric_arguments_do_not_break_the_chain(
        floats in prop::collection::vec(any::<f64>().prop_filter("finite", |f| f.is_finite()), 1..6),
        ints in prop::collection::vec(any::<i64>(), 0..4),
        big in any::<u64>(),
    ) {
        let types = vec![
            AuditEventType::ObservationRecorded {
                capability_id: "disk_usage".into(),
                args: json!({ "floats": floats, "ints": ints, "big": big, "nested": { "f": floats[0] } }),
                result_summary: String::new(),
            },
            AuditEventType::InvestigationStarted,
        ];
        let events = build(types);
        let result = AuditVerifier::verify_jsonl(&to_jsonl(&events)).unwrap();
        prop_assert!(result.valid, "{:?}", result.error);
    }

    /// The verifier never panics on arbitrary text.
    #[test]
    fn verifier_never_panics_on_garbage(text in any::<String>()) {
        let _ = AuditVerifier::verify_jsonl(&text);
    }
}
