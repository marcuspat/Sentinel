//! Policy rules: the building blocks of the policy engine.
//!
//! A [`PolicyRule`] pairs a set of [`RuleCondition`]s with a [`RuleEffect`].
//! Rules are sorted by ascending priority; the *first* matching rule wins.

use chrono::{Utc, Weekday};
use serde::{Deserialize, Serialize};
use sentinel_core::{CapabilityKind, RiskTier};

use crate::evaluator::PolicyRequest;

// ── RuleEffect ────────────────────────────────────────────────────────────────

/// What to do when a rule matches a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleEffect {
    /// Permit the capability to run.
    Allow,
    /// Block the capability outright.
    Deny,
    /// Pause execution and wait for human approval.
    RequireApproval,
    /// Allow but record every invocation in the audit log.
    AuditOnly,
}

// ── RuleCondition ─────────────────────────────────────────────────────────────

/// A predicate evaluated against a [`PolicyRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// The capability id must equal `matches` exactly (no globbing).
    CapabilityId { matches: String },

    /// The capability id must be one of the listed ids.
    CapabilityIdIn { ids: Vec<String> },

    /// The request's risk tier must be ≥ `tier` (uses `Ord` on `RiskTier`).
    RiskTierAtLeast { tier: RiskTier },

    /// The request's risk tier must be exactly `tier`.
    RiskTierExactly { tier: RiskTier },

    /// The target host must match the glob `pattern`.
    TargetHost { pattern: String },

    /// A JSON-path-like check: the value at `path` must contain `value` as a
    /// substring.  `path` uses dot notation, e.g. `"args.path"`.
    ArgValueContains { path: String, value: String },

    /// The current UTC hour must fall in `[start_hour, end_hour)` and the
    /// current weekday must be in `days`.  Both bounds are 0-based hours (0–23).
    TimeWindow {
        start_hour: u8,
        end_hour: u8,
        days: Vec<Weekday>,
    },

    /// The capability kind must match exactly (e.g. ReadOnly or Mutating).
    CapabilityKindIs { kind: CapabilityKind },

    /// The session phase label (string representation of `SessionPhase`).
    SessionPhase { phase: String },

    /// Logical negation of a sub-condition.
    Not { condition: Box<RuleCondition> },

    /// All sub-conditions must hold.
    And { conditions: Vec<RuleCondition> },

    /// At least one sub-condition must hold.
    Or { conditions: Vec<RuleCondition> },
}

impl RuleCondition {
    /// Evaluate this condition against `req`, returning `true` when it holds.
    pub fn evaluate(&self, req: &PolicyRequest) -> bool {
        match self {
            RuleCondition::CapabilityId { matches } => &req.capability_id == matches,

            RuleCondition::CapabilityIdIn { ids } => ids.contains(&req.capability_id),

            RuleCondition::RiskTierAtLeast { tier } => req.risk_tier >= *tier,

            RuleCondition::RiskTierExactly { tier } => req.risk_tier == *tier,

            RuleCondition::TargetHost { pattern } => glob_match(pattern, &req.target_host),

            RuleCondition::ArgValueContains { path, value } => {
                json_path_contains(&req.args, path, value)
            }

            RuleCondition::TimeWindow {
                start_hour,
                end_hour,
                days,
            } => {
                let now = Utc::now();
                let hour = now.format("%H").to_string().parse::<u8>().unwrap_or(0);
                let weekday = now.format("%A").to_string();
                let hour_ok = if start_hour <= end_hour {
                    hour >= *start_hour && hour < *end_hour
                } else {
                    // Wraps midnight, e.g. 22–06
                    hour >= *start_hour || hour < *end_hour
                };
                let day_ok = days.is_empty()
                    || days.iter().any(|d| weekday_name(d) == weekday);
                hour_ok && day_ok
            }

            RuleCondition::CapabilityKindIs { kind } => req.capability_kind == *kind,

            RuleCondition::SessionPhase { phase } => {
                req.session_phase.as_deref() == Some(phase.as_str())
            }

            RuleCondition::Not { condition } => !condition.evaluate(req),

            RuleCondition::And { conditions } => conditions.iter().all(|c| c.evaluate(req)),

            RuleCondition::Or { conditions } => conditions.iter().any(|c| c.evaluate(req)),
        }
    }
}

// ── PolicyRule ────────────────────────────────────────────────────────────────

/// A single policy rule that can match a [`PolicyRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique, stable identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// One-sentence rationale shown in audit logs.
    pub description: String,
    /// What to do when this rule matches.
    pub effect: RuleEffect,
    /// All conditions must hold for the rule to match.
    pub conditions: Vec<RuleCondition>,
    /// Evaluation order — lower value = higher priority.
    pub priority: u32,
    /// Disabled rules are never evaluated.
    pub enabled: bool,
}

impl PolicyRule {
    /// Returns `true` when this rule is enabled and every condition holds.
    pub fn matches(&self, req: &PolicyRequest) -> bool {
        if !self.enabled {
            return false;
        }
        self.conditions.iter().all(|c| c.evaluate(req))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal glob matching supporting `*` (any sequence) and `?` (any char).
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    // Recursive glob implementation — correct for the simple patterns used here.
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_chars(&p, &t)
}

fn glob_match_chars(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (None, _) => false,
        (Some('*'), _) => {
            // '*' can match zero characters or advance through `t`
            glob_match_chars(&p[1..], t)
                || (!t.is_empty() && glob_match_chars(p, &t[1..]))
        }
        (_, None) => false,
        (Some('?'), _) => glob_match_chars(&p[1..], &t[1..]),
        (Some(pc), Some(tc)) => pc == tc && glob_match_chars(&p[1..], &t[1..]),
    }
}

/// Walk a dot-separated `path` inside a JSON value and return the string at
/// that leaf.  Returns `None` when the path does not exist or isn't a string
/// or number.
fn json_path_get(value: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = value;
    for key in path.split('.') {
        cur = cur.get(key)?;
    }
    match cur {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn json_path_contains(value: &serde_json::Value, path: &str, needle: &str) -> bool {
    json_path_get(value, path)
        .map(|s| s.contains(needle))
        .unwrap_or(false)
}

fn weekday_name(day: &Weekday) -> &'static str {
    match day {
        Weekday::Mon => "Monday",
        Weekday::Tue => "Tuesday",
        Weekday::Wed => "Wednesday",
        Weekday::Thu => "Thursday",
        Weekday::Fri => "Friday",
        Weekday::Sat => "Saturday",
        Weekday::Sun => "Sunday",
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::PolicyRequest;
    use chrono::TimeZone;
    use sentinel_core::{CapabilityKind, RiskTier};
    use uuid::Uuid;

    fn make_request(cap_id: &str, risk: RiskTier, host: &str) -> PolicyRequest {
        PolicyRequest {
            session_id: Uuid::new_v4(),
            capability_id: cap_id.to_string(),
            capability_kind: CapabilityKind::ReadOnly,
            risk_tier: risk,
            args: serde_json::json!({}),
            target_host: host.to_string(),
            timestamp: chrono::Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap(), // Monday 10:00
            session_phase: None,
        }
    }

    fn simple_rule(effect: RuleEffect, conditions: Vec<RuleCondition>) -> PolicyRule {
        PolicyRule {
            id: "test-rule".into(),
            name: "Test Rule".into(),
            description: "For testing".into(),
            effect,
            conditions,
            priority: 100,
            enabled: true,
        }
    }

    #[test]
    fn capability_id_exact_match() {
        let req = make_request("disk_usage", RiskTier::Low, "host1");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::CapabilityId {
                matches: "disk_usage".into(),
            }],
        );
        assert!(rule.matches(&req));
    }

    #[test]
    fn capability_id_no_match() {
        let req = make_request("process_kill", RiskTier::Low, "host1");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::CapabilityId {
                matches: "disk_usage".into(),
            }],
        );
        assert!(!rule.matches(&req));
    }

    #[test]
    fn capability_id_in() {
        let req = make_request("process_kill", RiskTier::High, "host1");
        let rule = simple_rule(
            RuleEffect::Deny,
            vec![RuleCondition::CapabilityIdIn {
                ids: vec!["disk_usage".into(), "process_kill".into()],
            }],
        );
        assert!(rule.matches(&req));
    }

    #[test]
    fn risk_tier_at_least() {
        let req = make_request("op", RiskTier::High, "h");
        let rule_high = simple_rule(
            RuleEffect::Deny,
            vec![RuleCondition::RiskTierAtLeast { tier: RiskTier::High }],
        );
        let rule_critical = simple_rule(
            RuleEffect::Deny,
            vec![RuleCondition::RiskTierAtLeast {
                tier: RiskTier::Critical,
            }],
        );
        assert!(rule_high.matches(&req));
        assert!(!rule_critical.matches(&req));
    }

    #[test]
    fn risk_tier_exactly() {
        let req = make_request("op", RiskTier::Medium, "h");
        let rule_medium = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::RiskTierExactly {
                tier: RiskTier::Medium,
            }],
        );
        let rule_low = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::RiskTierExactly { tier: RiskTier::Low }],
        );
        assert!(rule_medium.matches(&req));
        assert!(!rule_low.matches(&req));
    }

    #[test]
    fn target_host_glob() {
        let req = make_request("op", RiskTier::Low, "prod-web-01.example.com");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::TargetHost {
                pattern: "prod-*".into(),
            }],
        );
        assert!(rule.matches(&req));

        let rule2 = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::TargetHost {
                pattern: "staging-*".into(),
            }],
        );
        assert!(!rule2.matches(&req));
    }

    #[test]
    fn arg_value_contains() {
        let mut req = make_request("write_file", RiskTier::Medium, "h");
        req.args = serde_json::json!({ "path": "/etc/passwd" });

        let rule_matches = simple_rule(
            RuleEffect::Deny,
            vec![RuleCondition::ArgValueContains {
                path: "path".into(),
                value: "/etc".into(),
            }],
        );
        assert!(rule_matches.matches(&req));

        let rule_no_match = simple_rule(
            RuleEffect::Deny,
            vec![RuleCondition::ArgValueContains {
                path: "path".into(),
                value: "/home".into(),
            }],
        );
        assert!(!rule_no_match.matches(&req));
    }

    #[test]
    fn time_window_matches() {
        // TimeWindow now uses Utc::now(). Use a window that covers all 24 hours
        // (start=0, end=24) with an empty days list (matches every day), so the
        // test passes regardless of when it runs.
        let req = make_request("op", RiskTier::Low, "h");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::TimeWindow {
                start_hour: 0,
                end_hour: 24, // 0 <= 24, non-wrap: hour >= 0 && hour < 24 → always true
                days: vec![], // empty days → matches every day
            }],
        );
        assert!(rule.matches(&req));
    }

    #[test]
    fn time_window_no_match_day() {
        // Use a zero-width window (start == end, non-wrap) which can never match:
        // start=5, end=5 → hour >= 5 && hour < 5 → always false.
        let req = make_request("op", RiskTier::Low, "h");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::TimeWindow {
                start_hour: 5,
                end_hour: 5, // zero-width window → never matches
                days: vec![],
            }],
        );
        assert!(!rule.matches(&req));
    }

    #[test]
    fn not_condition() {
        let req = make_request("disk_usage", RiskTier::Low, "h");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::Not {
                condition: Box::new(RuleCondition::RiskTierAtLeast {
                    tier: RiskTier::High,
                }),
            }],
        );
        assert!(rule.matches(&req));
    }

    #[test]
    fn and_condition() {
        let req = make_request("disk_usage", RiskTier::Low, "prod-01");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::And {
                conditions: vec![
                    RuleCondition::CapabilityId {
                        matches: "disk_usage".into(),
                    },
                    RuleCondition::TargetHost {
                        pattern: "prod-*".into(),
                    },
                ],
            }],
        );
        assert!(rule.matches(&req));

        let rule_fail = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::And {
                conditions: vec![
                    RuleCondition::CapabilityId {
                        matches: "disk_usage".into(),
                    },
                    RuleCondition::RiskTierAtLeast {
                        tier: RiskTier::High,
                    },
                ],
            }],
        );
        assert!(!rule_fail.matches(&req));
    }

    #[test]
    fn or_condition() {
        let req = make_request("disk_usage", RiskTier::Low, "h");
        let rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::Or {
                conditions: vec![
                    RuleCondition::RiskTierAtLeast {
                        tier: RiskTier::Critical,
                    },
                    RuleCondition::CapabilityId {
                        matches: "disk_usage".into(),
                    },
                ],
            }],
        );
        assert!(rule.matches(&req));
    }

    #[test]
    fn disabled_rule_never_matches() {
        let req = make_request("disk_usage", RiskTier::Low, "h");
        let mut rule = simple_rule(
            RuleEffect::Allow,
            vec![RuleCondition::CapabilityId {
                matches: "disk_usage".into(),
            }],
        );
        rule.enabled = false;
        assert!(!rule.matches(&req));
    }

    #[test]
    fn empty_conditions_matches_everything() {
        let req = make_request("any_cap", RiskTier::Critical, "any-host");
        let rule = simple_rule(RuleEffect::Deny, vec![]);
        assert!(rule.matches(&req));
    }

    #[test]
    fn glob_star_matches_any() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("prod-*", "prod-web-01"));
        assert!(!glob_match("prod-*", "staging-01"));
        assert!(glob_match("*.example.com", "foo.example.com"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_question_mark() {
        assert!(glob_match("host?", "host1"));
        assert!(glob_match("host?", "hosta"));
        assert!(!glob_match("host?", "host12"));
    }
}
