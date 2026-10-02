//! Property tests for the policy evaluator and resource guards.
//!
//! Example-based tests show the cases someone thought of. These state the
//! invariants and let `proptest` look for a request that breaks them.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use sentinel_core::{CapabilityKind, RiskTier};
use sentinel_policy::resource_guard::{default_resource_guards, normalise_path, normalise_unit};
use sentinel_policy::{
    default_policy, KillSwitch, PolicyEffect, PolicyEvaluator, PolicyRequest, PolicyRule,
    RuleCondition, RuleEffect,
};
use serde_json::{json, Value};
use uuid::Uuid;

fn request(
    id: &str,
    kind: CapabilityKind,
    risk: RiskTier,
    args: Value,
    host: &str,
) -> PolicyRequest {
    PolicyRequest {
        session_id: Uuid::nil(),
        capability_id: id.to_string(),
        capability_kind: kind,
        risk_tier: risk,
        args,
        target_host: host.to_string(),
        timestamp: Utc.with_ymd_and_hms(2026, 1, 15, 10, 0, 0).unwrap(),
        session_phase: None,
    }
}

fn kind() -> impl Strategy<Value = CapabilityKind> {
    prop_oneof![
        Just(CapabilityKind::ReadOnly),
        Just(CapabilityKind::Mutating)
    ]
}

fn risk() -> impl Strategy<Value = RiskTier> {
    prop_oneof![
        Just(RiskTier::Low),
        Just(RiskTier::Medium),
        Just(RiskTier::High),
        Just(RiskTier::Critical),
    ]
}

fn effect() -> impl Strategy<Value = RuleEffect> {
    prop_oneof![
        Just(RuleEffect::Allow),
        Just(RuleEffect::Deny),
        Just(RuleEffect::RequireApproval),
        Just(RuleEffect::AuditOnly),
    ]
}

/// Arbitrary JSON, a few levels deep.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        ".{0,24}".prop_map(Value::from),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            prop::collection::btree_map("[a-z_]{1,8}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn strictness(e: &PolicyEffect) -> u8 {
    match e {
        PolicyEffect::Allowed => 0,
        PolicyEffect::AuditOnly => 1,
        PolicyEffect::RequiresApproval => 2,
        PolicyEffect::Denied { .. } => 3,
    }
}

/// A rule that matches every request, with the given effect.
fn catch_all(id: &str, effect: RuleEffect) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        name: id.into(),
        description: String::new(),
        effect,
        conditions: vec![],
        priority: 1,
        enabled: true,
    }
}

/// Respell an absolute path without changing what it refers to.
fn respell(path: &str, noise: &[u8]) -> String {
    let mut out = String::new();
    let mut n = noise.iter().cycle();
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        match n.next().unwrap() % 5 {
            0 => out.push('/'),
            1 => out.push_str("//"),
            2 => out.push_str("/./"),
            3 => out.push_str("/tmp/../"),
            _ => out.push_str("/a/b/../../"),
        }
        out.push_str(segment);
    }
    if n.next().unwrap() & 1 == 0 {
        out.push('/');
    }
    out
}

const PROTECTED_FILES: [&str; 10] = [
    "/etc",
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/boot/grub/grub.cfg",
    "/proc/sys/kernel/panic",
    "/sys/kernel/mm",
    "/usr/bin/sudo",
    "/lib/systemd/system/ssh.service",
    "/dev/sda",
    "/run/systemd/system",
];

const PROTECTED_UNITS: [&str; 6] = [
    "sshd",
    "ssh",
    "docker",
    "systemd",
    "systemd-journald",
    "containerd",
];

proptest! {
    /// With no rules at all, nothing is ever allowed.
    #[test]
    fn deny_by_default_holds_for_arbitrary_requests(
        id in ".{0,40}", k in kind(), r in risk(), args in json_value(), host in ".{0,30}",
    ) {
        let evaluator = PolicyEvaluator::new(vec![], KillSwitch::new(), vec![]);
        let decision = evaluator.evaluate(request(&id, k, r, args, &host));
        prop_assert!(!decision.is_allowed());
        prop_assert!(matches!(decision.effect, PolicyEffect::Denied { .. }), "expected Denied");
    }

    /// Rules that cannot match leave the default in place.
    #[test]
    fn non_matching_and_disabled_rules_never_allow(
        id in "[a-z_]{1,20}", k in kind(), r in risk(), args in json_value(),
    ) {
        let mut disabled = catch_all("disabled", RuleEffect::Allow);
        disabled.enabled = false;
        let mut other = catch_all("other", RuleEffect::Allow);
        other.conditions = vec![RuleCondition::CapabilityId { matches: format!("{id}-not") }];
        let evaluator = PolicyEvaluator::new(vec![disabled, other], KillSwitch::new(), vec![]);
        prop_assert!(!evaluator.evaluate(request(&id, k, r, args, "h")).is_allowed());
    }

    /// The kill switch beats every rule set, including allow-everything.
    #[test]
    fn kill_switch_denies_everything(
        id in ".{0,40}", k in kind(), r in risk(), args in json_value(), reason in ".{0,40}",
    ) {
        let switch = KillSwitch::new();
        let evaluator = PolicyEvaluator::new(
            vec![catch_all("allow-all", RuleEffect::Allow)],
            Arc::clone(&switch),
            vec![],
        );
        switch.activate(reason);
        let decision = evaluator.evaluate(request(&id, k, r, args, "h"));
        prop_assert!(matches!(decision.effect, PolicyEffect::Denied { .. }), "expected Denied");
    }

    /// A tightening rule (ADR-018) can only make the outcome stricter, for any
    /// combination of base effect and overlay effect.
    #[test]
    fn tightening_rules_never_weaken_a_decision(
        base in effect(), overlay in effect(),
        id in "[a-z_]{1,20}", k in kind(), r in risk(), args in json_value(),
    ) {
        let plain = PolicyEvaluator::new(vec![catch_all("base", base.clone())], KillSwitch::new(), vec![]);
        let tightened = PolicyEvaluator::new(vec![catch_all("base", base)], KillSwitch::new(), vec![])
            .with_tightening_rules(vec![catch_all("overlay", overlay.clone())]);
        let req = request(&id, k, r, args, "h");
        let before = plain.evaluate(req.clone()).effect;
        let after = tightened.evaluate(req).effect;
        prop_assert!(strictness(&after) >= strictness(&before), "{:?} -> {:?}", before, after);
        // …and it is at least as strict as the overlay asked for.
        let asked = match overlay {
            RuleEffect::Allow => 0,
            RuleEffect::AuditOnly => 1,
            RuleEffect::RequireApproval => 2,
            RuleEffect::Deny => 3,
        };
        prop_assert!(strictness(&after) >= asked);
    }

    /// Evaluation is a pure function of the request.
    #[test]
    fn default_policy_is_deterministic(
        id in "[a-z_]{1,20}", k in kind(), r in risk(), args in json_value(),
    ) {
        let evaluator = default_policy();
        let req = request(&id, k, r, args, "localhost");
        let a = evaluator.evaluate(req.clone());
        let b = evaluator.evaluate(req);
        prop_assert_eq!(a.effect, b.effect);
        prop_assert_eq!(a.matched_rule, b.matched_rule);
    }

    /// Critical-risk requests are never allowed by the built-in policy.
    #[test]
    fn default_policy_never_allows_critical(
        id in "[a-z_]{1,20}", k in kind(), args in json_value(),
    ) {
        let decision = default_policy().evaluate(request(&id, k, RiskTier::Critical, args, "localhost"));
        prop_assert!(!decision.is_allowed());
    }

    /// A mutating request naming a protected path is denied whatever the
    /// argument is called, however deeply it is nested, and however the path
    /// is spelled (`//`, `/./`, `/x/../`, trailing slash).
    #[test]
    fn protected_paths_are_denied_under_any_spelling_and_argument_name(
        file in prop::sample::select(PROTECTED_FILES.to_vec()),
        noise in prop::collection::vec(any::<u8>(), 1..8),
        key in "[a-z_]{1,12}",
        shape in 0u8..4,
        id in "[a-z_]{1,20}",
        r in risk(),
    ) {
        let spelled = respell(file, &noise);
        let args = match shape {
            0 => json!({ key: spelled }),
            1 => json!({ key: [ "/var/tmp/ok", spelled ] }),
            2 => json!({ "options": { key: spelled } }),
            _ => json!({ key: [ { "target": spelled } ] }),
        };
        let evaluator = PolicyEvaluator::new(
            vec![catch_all("allow-all", RuleEffect::Allow)],
            KillSwitch::new(),
            default_resource_guards(),
        );
        let decision = evaluator.evaluate(request(&id, CapabilityKind::Mutating, r, args.clone(), "h"));
        prop_assert!(
            matches!(decision.effect, PolicyEffect::Denied { .. }),
            "mutating request with args {} was {:?}", args, decision.effect
        );
    }

    /// Protected services are denied under any unit spelling.
    #[test]
    fn protected_services_are_denied_under_any_unit_spelling(
        unit in prop::sample::select(PROTECTED_UNITS.to_vec()),
        suffix in prop::sample::select(vec!["", ".service", ".socket", ".SERVICE", "@tty1.service"]),
        upper in any::<bool>(),
        pad in any::<bool>(),
        key in prop::sample::select(vec!["service", "unit"]),
        as_list in any::<bool>(),
    ) {
        let mut spelled = format!("{unit}{suffix}");
        if upper { spelled = spelled.to_uppercase(); }
        if pad { spelled = format!(" {spelled} "); }
        let args = if as_list {
            json!({ format!("{key}s"): ["cron", spelled] })
        } else {
            json!({ key: spelled })
        };
        let evaluator = PolicyEvaluator::new(
            vec![catch_all("allow-all", RuleEffect::Allow)],
            KillSwitch::new(),
            default_resource_guards(),
        );
        let decision = evaluator.evaluate(request(
            "service_restart", CapabilityKind::Mutating, RiskTier::Medium, args.clone(), "h",
        ));
        prop_assert!(
            matches!(decision.effect, PolicyEffect::Denied { .. }),
            "args {} was {:?}", args, decision.effect
        );
    }

    /// The guards do not fire on paths and services outside the protected
    /// set, so the fix above has not turned them into deny-everything.
    #[test]
    fn unprotected_targets_are_not_blocked_by_guards(
        segments in prop::collection::vec("[a-z0-9_]{1,10}", 1..5),
        root in prop::sample::select(vec!["/var", "/home", "/tmp", "/opt", "/srv", "/etcetera", "/bootstrap", "/usr/local", "/run/user", "/library"]),
        service in "(nginx|cron|postgres|redis|myapp|sshguard|dockerize)[a-z0-9]{0,4}",
    ) {
        let path = format!("{root}/{}", segments.join("/"));
        let args = json!({ "path": path, "cache_dirs": [path], "service": service });
        let evaluator = PolicyEvaluator::new(
            vec![catch_all("allow-all", RuleEffect::Allow)],
            KillSwitch::new(),
            default_resource_guards(),
        );
        let decision = evaluator.evaluate(request(
            "x", CapabilityKind::Mutating, RiskTier::Medium, args.clone(), "h",
        ));
        prop_assert_eq!(decision.effect, PolicyEffect::Allowed, "args {}", args);
    }

    /// Guards with `allow_read` leave read-only requests alone.
    #[test]
    fn default_guards_never_block_reads(args in json_value(), id in "[a-z_]{1,20}") {
        for guard in default_resource_guards() {
            let req = request(&id, CapabilityKind::ReadOnly, RiskTier::Low, args.clone(), "h");
            prop_assert!(guard.blocks(&req).is_none());
        }
    }

    /// Normalisation is idempotent, never escapes the root, and produces no
    /// `.`/`..`/empty segments.
    #[test]
    fn path_normalisation_is_canonical(raw in "(/|\\.\\./|\\./|[a-z]{1,4}/?){0,12}") {
        let raw = format!("/{raw}");
        let once = normalise_path(&raw).expect("absolute path");
        prop_assert!(once.starts_with('/'));
        let twice = normalise_path(&once);
        prop_assert_eq!(twice.as_deref(), Some(once.as_str()));
        if once != "/" {
            prop_assert!(!once.ends_with('/'));
            for segment in once[1..].split('/') {
                prop_assert!(!segment.is_empty() && segment != "." && segment != "..", "{}", once);
            }
        }
    }

    #[test]
    fn relative_strings_are_not_treated_as_paths(raw in "[a-zA-Z0-9 ._-]{0,30}") {
        prop_assert!(normalise_path(&raw).is_none());
    }

    #[test]
    fn unit_normalisation_is_idempotent(raw in "[a-zA-Z0-9@._-]{0,30}") {
        let once = normalise_unit(&raw);
        prop_assert_eq!(normalise_unit(&once), once.clone());
    }
}

/// The four concrete bypasses listed in the roadmap (item 14b), as examples.
#[test]
fn roadmap_14b_bypasses_are_closed() {
    let evaluator = PolicyEvaluator::new(
        vec![catch_all("allow-all", RuleEffect::Allow)],
        KillSwitch::new(),
        default_resource_guards(),
    );
    let cases = [
        ("log_vacuum", json!({ "log_dir": "/etc" })),
        (
            "cache_prune",
            json!({ "cache_dirs": ["/var/cache/apt", "/boot"] }),
        ),
        ("service_restart", json!({ "service": "sshd.service" })),
        ("service_restart", json!({ "service": "ssh" })),
        ("write_file", json!({ "path": "/var/../etc/passwd" })),
        ("write_file", json!({ "path": "//etc//passwd" })),
    ];
    for (id, args) in cases {
        let decision = evaluator.evaluate(request(
            id,
            CapabilityKind::Mutating,
            RiskTier::Medium,
            args.clone(),
            "h",
        ));
        assert!(
            matches!(decision.effect, PolicyEffect::Denied { .. }),
            "{id} {args} was {:?}",
            decision.effect
        );
    }
}
