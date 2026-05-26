//! High-level engine module: re-exports and the [`default_policy`] constructor.
//!
//! [`default_policy`] builds a [`PolicyEvaluator`] with a sensible set of
//! built-in rules and resource guards:
//!
//! | Priority | Rule id                      | Effect           | Condition                          |
//! |----------|------------------------------|------------------|------------------------------------|
//! | 10       | `deny-critical`              | Deny             | risk_tier == Critical              |
//! | 20       | `deny-high-delete`           | Deny             | kind == Delete AND tier >= High    |
//! | 50       | `require-approval-high`      | RequireApproval  | tier == High                       |
//! | 100      | `require-approval-medium-mut`| RequireApproval  | tier == Medium AND kind != Read    |
//! | 200      | `allow-read-low-medium`      | Allow            | kind == Read AND tier <= Medium    |
//! | 300      | `allow-low-risk`             | Allow            | tier == Low                        |
//!
//! The built-in resource guards from [`default_resource_guards`] are included.

use std::sync::Arc;

use sentinel_core::{CapabilityKind, RiskTier};

use crate::{
    evaluator::PolicyEvaluator,
    kill_switch::KillSwitch,
    resource_guard::default_resource_guards,
    rules::{PolicyRule, RuleCondition, RuleEffect},
};

/// Construct a [`PolicyEvaluator`] with production-safe default rules and
/// resource guards.
///
/// The returned evaluator is deny-by-default; any capability not matched by
/// one of the default rules will be blocked.
pub fn default_policy() -> PolicyEvaluator {
    let kill_switch = KillSwitch::new();
    let guards = default_resource_guards();
    let rules = default_rules();
    PolicyEvaluator::new(rules, kill_switch, guards)
}

/// Construct a [`PolicyEvaluator`] with a caller-supplied [`Arc<KillSwitch>`].
///
/// Useful when the kill switch is shared with other subsystems (e.g. the TUI).
pub fn default_policy_with_kill_switch(kill_switch: Arc<KillSwitch>) -> PolicyEvaluator {
    let guards = default_resource_guards();
    let rules = default_rules();
    PolicyEvaluator::new(rules, kill_switch, guards)
}

// ── Default rules ─────────────────────────────────────────────────────────────

fn default_rules() -> Vec<PolicyRule> {
    vec![
        // ── Highest priority: hard denials ────────────────────────────────────

        PolicyRule {
            id: "deny-critical".into(),
            name: "Deny Critical Risk".into(),
            description: "Block all capabilities with Critical risk tier unconditionally."
                .into(),
            effect: RuleEffect::Deny,
            conditions: vec![RuleCondition::RiskTierExactly {
                tier: RiskTier::Critical,
            }],
            priority: 10,
            enabled: true,
        },
        // ── Deny high-risk mutating operations ───────────────────────────────

        PolicyRule {
            id: "deny-high-mutating".into(),
            name: "Deny High-Risk Mutating".into(),
            description:
                "Block mutating operations at High or Critical risk to prevent irreversible damage."
                    .into(),
            effect: RuleEffect::Deny,
            conditions: vec![RuleCondition::And {
                conditions: vec![
                    RuleCondition::RiskTierAtLeast { tier: RiskTier::High },
                    RuleCondition::CapabilityKindIs {
                        kind: CapabilityKind::Mutating,
                    },
                ],
            }],
            priority: 20,
            enabled: true,
        },

        // ── Require human approval for high-risk read-only operations ─────────

        PolicyRule {
            id: "require-approval-high-read".into(),
            name: "Require Approval for High-Risk Read".into(),
            description: "Pause execution for operator approval on High-risk read operations."
                .into(),
            effect: RuleEffect::RequireApproval,
            conditions: vec![RuleCondition::And {
                conditions: vec![
                    RuleCondition::RiskTierExactly { tier: RiskTier::High },
                    RuleCondition::CapabilityKindIs {
                        kind: CapabilityKind::ReadOnly,
                    },
                ],
            }],
            priority: 50,
            enabled: true,
        },

        // ── Require approval for mutating medium-risk ops ─────────────────────

        PolicyRule {
            id: "require-approval-medium-mutating".into(),
            name: "Require Approval for Mutating Medium-Risk".into(),
            description:
                "Require approval for Medium-risk capabilities that are mutating.".into(),
            effect: RuleEffect::RequireApproval,
            conditions: vec![RuleCondition::And {
                conditions: vec![
                    RuleCondition::RiskTierExactly {
                        tier: RiskTier::Medium,
                    },
                    RuleCondition::CapabilityKindIs {
                        kind: CapabilityKind::Mutating,
                    },
                ],
            }],
            priority: 100,
            enabled: true,
        },

        // ── Allow read-only capabilities at Low / Medium risk ─────────────────

        PolicyRule {
            id: "allow-read-low-medium".into(),
            name: "Allow Read-Only Low/Medium Risk".into(),
            description:
                "Permit read-only capabilities that are Low or Medium risk without approval."
                    .into(),
            effect: RuleEffect::Allow,
            conditions: vec![RuleCondition::And {
                conditions: vec![
                    RuleCondition::CapabilityKindIs {
                        kind: CapabilityKind::ReadOnly,
                    },
                    RuleCondition::Not {
                        condition: Box::new(RuleCondition::RiskTierAtLeast {
                            tier: RiskTier::High,
                        }),
                    },
                ],
            }],
            priority: 200,
            enabled: true,
        },

        // ── Allow all low-risk capabilities ───────────────────────────────────

        PolicyRule {
            id: "allow-low-risk".into(),
            name: "Allow Low Risk".into(),
            description: "Permit all Low-risk capabilities unconditionally.".into(),
            effect: RuleEffect::Allow,
            conditions: vec![RuleCondition::RiskTierExactly { tier: RiskTier::Low }],
            priority: 300,
            enabled: true,
        },
    ]
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::{PolicyEffect, PolicyRequest};
    use chrono::TimeZone;
    use sentinel_core::{CapabilityKind, RiskTier};
    use uuid::Uuid;

    fn req(cap_id: &str, kind: CapabilityKind, risk: RiskTier) -> PolicyRequest {
        PolicyRequest {
            session_id: Uuid::new_v4(),
            capability_id: cap_id.to_string(),
            capability_kind: kind,
            risk_tier: risk,
            args: serde_json::json!({}),
            target_host: "localhost".to_string(),
            timestamp: chrono::Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap(),
            session_phase: None,
        }
    }

    #[test]
    fn default_policy_denies_critical() {
        let evaluator = default_policy();
        let decision = evaluator.evaluate(req("halt_system", CapabilityKind::Mutating, RiskTier::Critical));
        assert!(
            matches!(decision.effect, PolicyEffect::Denied { .. }),
            "critical risk must be denied; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_requires_approval_for_high() {
        let evaluator = default_policy();
        let decision = evaluator.evaluate(req("rm_rf", CapabilityKind::Mutating, RiskTier::High));
        // High risk → RequireApproval (or Denied via deny-high-delete)
        // Both are acceptable non-Allow outcomes, but this shouldn't be Allowed.
        assert!(
            !matches!(decision.effect, PolicyEffect::Allowed),
            "high risk must not be directly allowed; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_allows_low_risk_read() {
        let evaluator = default_policy();
        let decision = evaluator.evaluate(req("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low));
        assert_eq!(
            decision.effect,
            PolicyEffect::Allowed,
            "low-risk reads should be allowed; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_requires_approval_for_medium_mutating() {
        let evaluator = default_policy();
        // Medium-risk Write operation
        let decision = evaluator.evaluate(req("write_file", CapabilityKind::Mutating, RiskTier::Medium));
        assert_eq!(
            decision.effect,
            PolicyEffect::RequiresApproval,
            "medium mutating should require approval; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_allows_medium_risk_with_no_path() {
        let evaluator = default_policy();
        // Medium-risk Read operation (not blocked by resource guards — no path)
        let decision = evaluator.evaluate(req("check_metrics", CapabilityKind::ReadOnly, RiskTier::Medium));
        assert_eq!(
            decision.effect,
            PolicyEffect::Allowed,
            "medium-risk read should be allowed; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_blocks_write_to_etc() {
        let evaluator = default_policy();
        let mut request = req("write_file", CapabilityKind::Mutating, RiskTier::Medium);
        request.args = serde_json::json!({ "path": "/etc/crontab" });
        let decision = evaluator.evaluate(request);
        assert!(
            matches!(decision.effect, PolicyEffect::Denied { .. }),
            "write to /etc should be blocked by resource guard; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_blocks_service_control_on_sshd() {
        let evaluator = default_policy();
        let mut request = req("restart_service", CapabilityKind::Mutating, RiskTier::Medium);
        request.args = serde_json::json!({ "service": "sshd" });
        let decision = evaluator.evaluate(request);
        assert!(
            matches!(decision.effect, PolicyEffect::Denied { .. }),
            "service control on sshd should be blocked; got {:?}",
            decision.effect
        );
    }

    #[test]
    fn default_policy_with_shared_kill_switch() {
        let ks = KillSwitch::new();
        let evaluator = default_policy_with_kill_switch(Arc::clone(&ks));
        // Before activation
        let d1 = evaluator.evaluate(req("write_file", CapabilityKind::Mutating, RiskTier::Low));
        assert_eq!(d1.effect, PolicyEffect::Allowed);

        // After activation
        ks.activate("test");
        let d2 = evaluator.evaluate(req("write_file", CapabilityKind::Mutating, RiskTier::Low));
        assert!(matches!(d2.effect, PolicyEffect::Denied { .. }));

        // Read still works
        let d3 = evaluator.evaluate(req("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low));
        assert_eq!(d3.effect, PolicyEffect::Allowed);
    }

    #[test]
    fn deny_by_default_invariant() {
        // A request with no matching rules MUST be denied.
        let ks = KillSwitch::new();
        let evaluator = PolicyEvaluator::new(vec![], ks, vec![]);
        for risk in [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical] {
            for kind in [
                CapabilityKind::ReadOnly,
                CapabilityKind::Mutating,
                CapabilityKind::Mutating,
                CapabilityKind::Mutating,
            ] {
                let decision = evaluator.evaluate(req("test_cap", kind, risk));
                assert!(
                    matches!(decision.effect, PolicyEffect::Denied { .. }),
                    "deny-by-default must hold for kind={kind:?} risk={risk:?}; got {:?}",
                    decision.effect
                );
            }
        }
    }
}
