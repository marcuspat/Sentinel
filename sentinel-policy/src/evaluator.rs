//! Policy evaluation engine.
//!
//! [`PolicyEvaluator`] is the central gatekeeper.  Every capability invocation
//! must pass through [`PolicyEvaluator::evaluate`] before execution.
//!
//! Evaluation order:
//! 1. Kill switch — immediate deny if activated.
//! 2. Resource guards — deny if any guard blocks the request.
//! 3. Rules — sorted ascending by priority; first matching rule wins.
//! 4. Deny-by-default — if no rule matched, the request is denied.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sentinel_core::{CapabilityKind, RiskTier};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::kill_switch::KillSwitch;
use crate::resource_guard::ResourceGuard;
use crate::rules::{PolicyRule, RuleEffect};

// ── PolicyRequest ─────────────────────────────────────────────────────────────

/// Input to policy evaluation — everything the engine needs to decide.
#[derive(Debug, Clone)]
pub struct PolicyRequest {
    /// The session this request belongs to.
    pub session_id: Uuid,
    /// Stable capability identifier (e.g. `"disk_usage"`).
    pub capability_id: String,
    /// High-level action category of the capability.
    pub capability_kind: CapabilityKind,
    /// Risk tier assigned to the capability.
    pub risk_tier: RiskTier,
    /// Arguments passed to the capability (JSON object).
    pub args: Value,
    /// The host that would be targeted by the capability.
    pub target_host: String,
    /// When the request was created.
    pub timestamp: DateTime<Utc>,
    /// Optional current session phase label (e.g. `"Executing"`).
    pub session_phase: Option<String>,
}

// ── PolicyEffect / PolicyDecision ─────────────────────────────────────────────

/// The outcome of evaluating a single [`PolicyRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEffect {
    /// The capability may proceed.
    Allowed,
    /// The capability is blocked.
    Denied { reason: String },
    /// The capability may not proceed until an operator approves it.
    RequiresApproval,
    /// The capability may proceed but will be recorded in the audit log.
    AuditOnly,
}

/// A complete evaluation result, including provenance.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The original request.
    pub request: PolicyRequest,
    /// The determined effect.
    pub effect: PolicyEffect,
    /// Id of the rule that produced this decision, if any.
    pub matched_rule: Option<String>,
    /// Human-readable explanation.
    pub rationale: String,
    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
}

impl PolicyDecision {
    /// Returns `true` when the capability is permitted to run.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self.effect,
            PolicyEffect::Allowed | PolicyEffect::AuditOnly
        )
    }
}

// ── PolicyEvaluator ───────────────────────────────────────────────────────────

/// The policy evaluation engine.
///
/// Holds an ordered list of [`PolicyRule`]s, a shared [`KillSwitch`], and
/// zero or more [`ResourceGuard`]s.
pub struct PolicyEvaluator {
    /// Rules sorted ascending by `priority` (lower = evaluated first).
    rules: Vec<PolicyRule>,
    kill_switch: Arc<KillSwitch>,
    resource_guards: Vec<ResourceGuard>,
}

impl PolicyEvaluator {
    /// Create a new evaluator from an explicit list of rules, a kill switch,
    /// and resource guards.  Rules are sorted by priority on construction.
    pub fn new(
        mut rules: Vec<PolicyRule>,
        kill_switch: Arc<KillSwitch>,
        resource_guards: Vec<ResourceGuard>,
    ) -> Self {
        rules.sort_by_key(|r| r.priority);
        Self {
            rules,
            kill_switch,
            resource_guards,
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Evaluate a policy request.
    ///
    /// Evaluation order:
    /// 1. Kill switch
    /// 2. Resource guards
    /// 3. Rules (ascending priority; first match wins)
    /// 4. Deny-by-default
    pub fn evaluate(&self, request: PolicyRequest) -> PolicyDecision {
        debug!(
            capability = %request.capability_id,
            risk = ?request.risk_tier,
            host = %request.target_host,
            "evaluating policy request"
        );

        // Step 1 — kill switch
        if let Some(decision) = self.check_kill_switch(&request) {
            warn!(
                capability = %request.capability_id,
                "policy: kill switch blocked request"
            );
            return decision;
        }

        // Step 2 — resource guards
        if let Some(decision) = self.check_resource_guards(&request) {
            warn!(
                capability = %request.capability_id,
                "policy: resource guard blocked request"
            );
            return decision;
        }

        // Step 3 + 4 — rules (deny-by-default inside apply_rules)
        self.apply_rules(&request)
    }

    /// Add a rule to the evaluator, keeping the list sorted by priority.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by id.  Returns the removed rule if found.
    pub fn remove_rule(&mut self, rule_id: &str) -> Option<PolicyRule> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            Some(self.rules.remove(pos))
        } else {
            None
        }
    }

    /// Return all enabled rules that match `req`, in priority order.
    pub fn get_applicable_rules<'a>(&'a self, req: &PolicyRequest) -> Vec<&'a PolicyRule> {
        self.rules.iter().filter(|r| r.matches(req)).collect()
    }

    /// Expose a reference to the kill switch so callers can activate it.
    pub fn kill_switch(&self) -> &Arc<KillSwitch> {
        &self.kill_switch
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn check_kill_switch(&self, req: &PolicyRequest) -> Option<PolicyDecision> {
        if !self.kill_switch.is_activated() {
            return None;
        }

        // Kill switch blocks all capabilities, regardless of kind.
        let reason = self
            .kill_switch
            .reason()
            .unwrap_or_else(|| "no reason provided".to_string());

        Some(PolicyDecision {
            request: req.clone(),
            effect: PolicyEffect::Denied {
                reason: format!("Kill switch activated: {reason}"),
            },
            matched_rule: None,
            rationale: format!("Global kill switch is active: {reason}"),
            decided_at: Utc::now(),
        })
    }

    fn check_resource_guards(&self, req: &PolicyRequest) -> Option<PolicyDecision> {
        for guard in &self.resource_guards {
            if let Some(blocked_reason) = guard.blocks(req) {
                return Some(PolicyDecision {
                    request: req.clone(),
                    effect: PolicyEffect::Denied {
                        reason: format!("Resource guard '{}': {}", guard.name, blocked_reason),
                    },
                    matched_rule: None,
                    rationale: format!(
                        "Resource guard '{}' protects: {}",
                        guard.name, blocked_reason
                    ),
                    decided_at: Utc::now(),
                });
            }
        }
        None
    }

    fn apply_rules(&self, req: &PolicyRequest) -> PolicyDecision {
        for rule in &self.rules {
            if rule.matches(req) {
                debug!(rule_id = %rule.id, effect = ?rule.effect, "rule matched");

                let (effect, rationale) = match &rule.effect {
                    RuleEffect::Allow => (
                        PolicyEffect::Allowed,
                        format!("Allowed by rule '{}': {}", rule.id, rule.description),
                    ),
                    RuleEffect::Deny => (
                        PolicyEffect::Denied {
                            reason: format!(
                                "Denied by rule '{}': {}",
                                rule.id, rule.description
                            ),
                        },
                        format!("Denied by rule '{}': {}", rule.id, rule.description),
                    ),
                    RuleEffect::RequireApproval => (
                        PolicyEffect::RequiresApproval,
                        format!(
                            "Approval required by rule '{}': {}",
                            rule.id, rule.description
                        ),
                    ),
                    RuleEffect::AuditOnly => (
                        PolicyEffect::AuditOnly,
                        format!(
                            "Audit-only by rule '{}': {}",
                            rule.id, rule.description
                        ),
                    ),
                };

                return PolicyDecision {
                    request: req.clone(),
                    effect,
                    matched_rule: Some(rule.id.clone()),
                    rationale,
                    decided_at: Utc::now(),
                };
            }
        }

        // Step 4 — deny-by-default
        warn!(
            capability = %req.capability_id,
            "policy: deny-by-default (no matching rule)"
        );
        PolicyDecision {
            request: req.clone(),
            effect: PolicyEffect::Denied {
                reason: "No matching allow rule (deny by default)".to_string(),
            },
            matched_rule: None,
            rationale: "Deny-by-default: no rule matched this request".to_string(),
            decided_at: Utc::now(),
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleCondition;
    use chrono::TimeZone;
    use sentinel_core::{CapabilityKind, RiskTier};
    use uuid::Uuid;

    fn make_request(cap_id: &str, kind: CapabilityKind, risk: RiskTier) -> PolicyRequest {
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

    fn allow_all_low_rule() -> PolicyRule {
        PolicyRule {
            id: "allow-low".into(),
            name: "Allow Low Risk".into(),
            description: "Allow all low-risk capabilities".into(),
            effect: RuleEffect::Allow,
            conditions: vec![RuleCondition::RiskTierExactly { tier: RiskTier::Low }],
            priority: 100,
            enabled: true,
        }
    }

    fn deny_critical_rule() -> PolicyRule {
        PolicyRule {
            id: "deny-critical".into(),
            name: "Deny Critical".into(),
            description: "Block all critical-risk operations".into(),
            effect: RuleEffect::Deny,
            conditions: vec![RuleCondition::RiskTierExactly {
                tier: RiskTier::Critical,
            }],
            priority: 10,
            enabled: true,
        }
    }

    #[test]
    fn deny_by_default_when_no_rules() {
        let ks = KillSwitch::new();
        let evaluator = PolicyEvaluator::new(vec![], ks, vec![]);
        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let decision = evaluator.evaluate(req);

        assert_eq!(
            decision.effect,
            PolicyEffect::Denied {
                reason: "No matching allow rule (deny by default)".to_string()
            }
        );
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn deny_by_default_when_no_matching_rule() {
        let ks = KillSwitch::new();
        let evaluator = PolicyEvaluator::new(vec![deny_critical_rule()], ks, vec![]);
        // Low risk — no rule matches → deny by default
        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let decision = evaluator.evaluate(req);
        assert!(matches!(decision.effect, PolicyEffect::Denied { .. }));
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn allow_rule_permits() {
        let ks = KillSwitch::new();
        let evaluator = PolicyEvaluator::new(vec![allow_all_low_rule()], ks, vec![]);
        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let decision = evaluator.evaluate(req);
        assert_eq!(decision.effect, PolicyEffect::Allowed);
        assert_eq!(decision.matched_rule.as_deref(), Some("allow-low"));
    }

    #[test]
    fn rule_priority_lower_wins() {
        let ks = KillSwitch::new();
        // priority 5 deny wins over priority 100 allow — both match Low risk
        let deny_low = PolicyRule {
            id: "deny-low-prio5".into(),
            name: "Deny Low (prio 5)".into(),
            description: "Deny low risk with high priority".into(),
            effect: RuleEffect::Deny,
            conditions: vec![RuleCondition::RiskTierExactly { tier: RiskTier::Low }],
            priority: 5,
            enabled: true,
        };
        let evaluator =
            PolicyEvaluator::new(vec![allow_all_low_rule(), deny_low], ks, vec![]);
        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let decision = evaluator.evaluate(req);
        // deny-low-prio5 (priority=5) should win over allow-low (priority=100)
        assert!(matches!(decision.effect, PolicyEffect::Denied { .. }));
        assert_eq!(decision.matched_rule.as_deref(), Some("deny-low-prio5"));
    }

    #[test]
    fn kill_switch_blocks_mutating() {
        let ks = KillSwitch::new();
        ks.activate("emergency stop");
        let evaluator = PolicyEvaluator::new(vec![allow_all_low_rule()], ks, vec![]);
        // Write capability is mutating → blocked
        let req = make_request("write_file", CapabilityKind::Mutating, RiskTier::Low);
        let decision = evaluator.evaluate(req);
        assert!(matches!(decision.effect, PolicyEffect::Denied { .. }));
    }

    #[test]
    fn kill_switch_blocks_read() {
        let ks = KillSwitch::new();
        ks.activate("emergency stop");
        let evaluator = PolicyEvaluator::new(vec![allow_all_low_rule()], ks, vec![]);
        // Kill switch blocks all capabilities regardless of kind.
        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let decision = evaluator.evaluate(req);
        assert!(matches!(decision.effect, PolicyEffect::Denied { .. }));
    }

    #[test]
    fn require_approval_effect() {
        let ks = KillSwitch::new();
        let approval_rule = PolicyRule {
            id: "approval-medium".into(),
            name: "Approval for Medium".into(),
            description: "Require approval for medium risk".into(),
            effect: RuleEffect::RequireApproval,
            conditions: vec![RuleCondition::RiskTierExactly {
                tier: RiskTier::Medium,
            }],
            priority: 50,
            enabled: true,
        };
        let evaluator = PolicyEvaluator::new(vec![approval_rule], ks, vec![]);
        let req = make_request("write_file", CapabilityKind::Mutating, RiskTier::Medium);
        let decision = evaluator.evaluate(req);
        assert_eq!(decision.effect, PolicyEffect::RequiresApproval);
    }

    #[test]
    fn audit_only_effect() {
        let ks = KillSwitch::new();
        let audit_rule = PolicyRule {
            id: "audit-low".into(),
            name: "Audit Low".into(),
            description: "Audit-only for low risk".into(),
            effect: RuleEffect::AuditOnly,
            conditions: vec![RuleCondition::RiskTierExactly { tier: RiskTier::Low }],
            priority: 100,
            enabled: true,
        };
        let evaluator = PolicyEvaluator::new(vec![audit_rule], ks, vec![]);
        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let decision = evaluator.evaluate(req);
        assert_eq!(decision.effect, PolicyEffect::AuditOnly);
        assert!(decision.is_allowed());
    }

    #[test]
    fn add_and_remove_rule() {
        let ks = KillSwitch::new();
        let mut evaluator = PolicyEvaluator::new(vec![], ks, vec![]);
        assert!(evaluator.rules.is_empty());

        evaluator.add_rule(allow_all_low_rule());
        assert_eq!(evaluator.rules.len(), 1);

        let removed = evaluator.remove_rule("allow-low");
        assert!(removed.is_some());
        assert!(evaluator.rules.is_empty());

        let not_found = evaluator.remove_rule("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn get_applicable_rules() {
        let ks = KillSwitch::new();
        let evaluator =
            PolicyEvaluator::new(vec![allow_all_low_rule(), deny_critical_rule()], ks, vec![]);

        let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);
        let applicable = evaluator.get_applicable_rules(&req);
        assert_eq!(applicable.len(), 1);
        assert_eq!(applicable[0].id, "allow-low");
    }
}
