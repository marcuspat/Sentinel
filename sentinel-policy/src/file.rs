//! Policy files (ADR-018): operator rules loaded from TOML.
//!
//! ```toml
//! version = 1
//! # mode = "tighten"   # default; "replace" swaps out the built-in rules
//!
//! [[rule]]
//! id = "no-restarts-on-prod"
//! description = "Production services are restarted by the on-call human"
//! effect = "deny"            # deny | require_approval | audit_only | allow
//! priority = 10
//! [rule.when]                # every listed field must match
//! capability_id_in = ["service_restart", "service_stop"]
//! target_host = "prod-*"
//!
//! [[guard]]
//! id = "app-data"
//! protected_paths = ["/srv/app/data"]
//! protected_services = ["postgresql"]
//! ```
//!
//! Two modes:
//!
//! * **tighten** (default).  The built-in rules still decide every request;
//!   file rules can only make the outcome stricter.  `allow` is rejected at
//!   load time because it could never take effect.
//! * **replace**.  The file's rules replace the built-in rules.  This is the
//!   only way to loosen policy, and it is loud on purpose.
//!
//! In both modes the kill switch and the built-in resource guards stay in
//! force, guards from the file are added to them, and anything no rule
//! matches is denied.

use std::path::Path;

use sentinel_core::{CapabilityKind, RiskTier};
use serde::Deserialize;

use crate::error::PolicyError;
use crate::evaluator::PolicyEvaluator;
use crate::kill_switch::KillSwitch;
use crate::resource_guard::{default_resource_guards, ResourceGuard};
use crate::rules::{PolicyRule, RuleCondition, RuleEffect};

/// Upper bound on a policy file.  A policy is a few kilobytes; anything
/// larger is a mistake or an attempt to stall start-up.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// How file rules combine with the built-in rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    Tighten,
    Replace,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    mode: PolicyMode,
    #[serde(default, rename = "rule")]
    rules: Vec<FileRule>,
    #[serde(default, rename = "guard")]
    guards: Vec<FileGuard>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRule {
    id: String,
    name: Option<String>,
    #[serde(default)]
    description: String,
    effect: FileEffect,
    priority: u32,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    when: When,
}

fn enabled_by_default() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileEffect {
    Allow,
    Deny,
    RequireApproval,
    AuditOnly,
}

/// Flat conjunction: every field present must match.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct When {
    capability_id: Option<String>,
    capability_id_in: Option<Vec<String>>,
    risk_at_least: Option<RiskTier>,
    risk: Option<RiskTier>,
    kind: Option<CapabilityKind>,
    target_host: Option<String>,
    phase: Option<String>,
    arg_contains: Option<ArgContains>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgContains {
    path: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGuard {
    id: String,
    name: Option<String>,
    #[serde(default)]
    protected_paths: Vec<String>,
    #[serde(default)]
    protected_services: Vec<String>,
}

/// A parsed, validated policy file.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub mode: PolicyMode,
    pub rules: Vec<PolicyRule>,
    pub guards: Vec<ResourceGuard>,
}

impl LoadedPolicy {
    /// Parse and validate TOML text.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile =
            toml::from_str(text).map_err(|e| PolicyError::InvalidRule(e.to_string()))?;

        if file.version != 1 {
            return Err(invalid(format!(
                "unsupported policy file version {} (this build understands 1)",
                file.version
            )));
        }

        let mut seen = std::collections::HashSet::new();
        let mut rules = Vec::with_capacity(file.rules.len());
        for r in file.rules {
            check_id("rule", &r.id)?;
            if !seen.insert(r.id.clone()) {
                return Err(invalid(format!("duplicate rule id '{}'", r.id)));
            }
            let effect = match r.effect {
                FileEffect::Deny => RuleEffect::Deny,
                FileEffect::RequireApproval => RuleEffect::RequireApproval,
                FileEffect::AuditOnly => RuleEffect::AuditOnly,
                FileEffect::Allow => RuleEffect::Allow,
            };
            if file.mode == PolicyMode::Tighten && effect == RuleEffect::Allow {
                return Err(invalid(format!(
                    "rule '{}' has effect \"allow\", which cannot take effect in the default \
                     \"tighten\" mode: file rules can only make the built-in policy stricter. \
                     To loosen policy, set mode = \"replace\" and provide the full rule set",
                    r.id
                )));
            }
            rules.push(PolicyRule {
                name: r.name.unwrap_or_else(|| r.id.clone()),
                id: r.id,
                description: r.description,
                effect,
                conditions: r.when.into_conditions(),
                priority: r.priority,
                enabled: r.enabled,
            });
        }

        let builtin_guard_ids: Vec<String> = default_resource_guards()
            .into_iter()
            .map(|g| g.id)
            .collect();
        let mut seen = std::collections::HashSet::new();
        let mut guards = Vec::with_capacity(file.guards.len());
        for g in file.guards {
            check_id("guard", &g.id)?;
            if builtin_guard_ids.contains(&g.id) || !seen.insert(g.id.clone()) {
                return Err(invalid(format!(
                    "guard id '{}' is already in use; built-in guards cannot be redefined",
                    g.id
                )));
            }
            if g.protected_paths.is_empty() && g.protected_services.is_empty() {
                return Err(invalid(format!("guard '{}' protects nothing", g.id)));
            }
            if let Some(p) = g.protected_paths.iter().find(|p| !p.starts_with('/')) {
                return Err(invalid(format!(
                    "guard '{}': protected path '{p}' must be absolute",
                    g.id
                )));
            }
            guards.push(ResourceGuard {
                name: g.name.unwrap_or_else(|| g.id.clone()),
                id: g.id,
                protected_paths: g.protected_paths,
                protected_services: g.protected_services,
                // File guards always block mutation and never block reads,
                // matching the built-in guards.
                block_mutating: true,
                allow_read: true,
            });
        }

        if file.mode == PolicyMode::Replace && rules.is_empty() {
            return Err(invalid(
                "mode = \"replace\" with no rules would deny every request; \
                 remove the mode line or add rules"
                    .to_string(),
            ));
        }

        Ok(Self {
            mode: file.mode,
            rules,
            guards,
        })
    }

    /// Read and validate a policy file.
    ///
    /// On Unix the file must not be writable by group or other: a policy
    /// anyone can edit is not a policy.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| invalid(format!("cannot read policy file {}: {e}", path.display())))?;
        if meta.len() > MAX_FILE_BYTES {
            return Err(invalid(format!(
                "policy file {} is {} bytes; the limit is {MAX_FILE_BYTES}",
                path.display(),
                meta.len()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o022 != 0 {
                return Err(invalid(format!(
                    "policy file {} has mode {mode:o}; it must not be writable by group or other \
                     (chmod go-w)",
                    path.display()
                )));
            }
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| invalid(format!("cannot read policy file {}: {e}", path.display())))?;
        Self::parse(&text).map_err(|e| match e {
            PolicyError::InvalidRule(msg) => invalid(format!("{}: {msg}", path.display())),
            other => other,
        })
    }

    /// Build the evaluator: built-in guards plus the file's guards, and the
    /// file's rules combined with the built-in rules according to the mode.
    pub fn into_evaluator(self) -> PolicyEvaluator {
        let mut guards = default_resource_guards();
        guards.extend(self.guards);
        match self.mode {
            PolicyMode::Tighten => {
                PolicyEvaluator::new(crate::engine::default_rules(), KillSwitch::new(), guards)
                    .with_tightening_rules(self.rules)
            }
            PolicyMode::Replace => PolicyEvaluator::new(self.rules, KillSwitch::new(), guards),
        }
    }
}

impl When {
    fn into_conditions(self) -> Vec<RuleCondition> {
        let mut c = Vec::new();
        if let Some(matches) = self.capability_id {
            c.push(RuleCondition::CapabilityId { matches });
        }
        if let Some(ids) = self.capability_id_in {
            c.push(RuleCondition::CapabilityIdIn { ids });
        }
        if let Some(tier) = self.risk_at_least {
            c.push(RuleCondition::RiskTierAtLeast { tier });
        }
        if let Some(tier) = self.risk {
            c.push(RuleCondition::RiskTierExactly { tier });
        }
        if let Some(kind) = self.kind {
            c.push(RuleCondition::CapabilityKindIs { kind });
        }
        if let Some(pattern) = self.target_host {
            c.push(RuleCondition::TargetHost { pattern });
        }
        if let Some(phase) = self.phase {
            c.push(RuleCondition::SessionPhase { phase });
        }
        if let Some(a) = self.arg_contains {
            c.push(RuleCondition::ArgValueContains {
                path: a.path,
                value: a.value,
            });
        }
        c
    }
}

fn invalid(msg: String) -> PolicyError {
    PolicyError::InvalidRule(msg)
}

fn check_id(what: &str, id: &str) -> Result<(), PolicyError> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what} id {id:?} must be 1-64 characters of [A-Za-z0-9._-]"
        )))
    }
}

/// The evaluator for an optional policy file: the built-in policy when
/// `path` is `None`, otherwise the file applied on top of it.
pub fn load_policy(path: Option<&Path>) -> Result<PolicyEvaluator, PolicyError> {
    match path {
        None => Ok(crate::engine::default_policy()),
        Some(p) => Ok(LoadedPolicy::load(p)?.into_evaluator()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::{PolicyEffect, PolicyRequest};
    use serde_json::json;
    use uuid::Uuid;

    fn req(
        id: &str,
        kind: CapabilityKind,
        tier: RiskTier,
        host: &str,
        args: serde_json::Value,
    ) -> PolicyRequest {
        PolicyRequest {
            session_id: Uuid::new_v4(),
            capability_id: id.into(),
            capability_kind: kind,
            risk_tier: tier,
            args,
            target_host: host.into(),
            timestamp: chrono::Utc::now(),
            session_phase: None,
        }
    }

    fn read_low(id: &str, host: &str) -> PolicyRequest {
        req(id, CapabilityKind::ReadOnly, RiskTier::Low, host, json!({}))
    }

    const TIGHTEN: &str = r#"
version = 1

[[rule]]
id = "no-prod-process-list"
description = "Process listings on prod leak customer job names"
effect = "deny"
priority = 10
[rule.when]
capability_id = "process_list"
target_host = "prod-*"

[[rule]]
id = "approve-all-metrics"
effect = "require_approval"
priority = 20
[rule.when]
capability_id_in = ["system_metrics"]

[[guard]]
id = "app-data"
protected_paths = ["/srv/app/data"]
protected_services = ["postgresql"]
"#;

    #[test]
    fn tighten_mode_can_deny_what_the_default_allows() {
        let policy = LoadedPolicy::parse(TIGHTEN).unwrap().into_evaluator();

        let d = policy.evaluate(read_low("process_list", "prod-db1"));
        assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");
        assert_eq!(d.matched_rule.as_deref(), Some("no-prod-process-list"));

        // Same capability elsewhere: the built-in allow still applies.
        let d = policy.evaluate(read_low("process_list", "staging-1"));
        assert_eq!(d.effect, PolicyEffect::Allowed);

        let d = policy.evaluate(read_low("system_metrics", "anything"));
        assert_eq!(d.effect, PolicyEffect::RequiresApproval);
    }

    #[test]
    fn tighten_mode_can_never_loosen_a_builtin_decision() {
        // A file rule that is *weaker* than the built-in outcome must lose.
        let text = r#"
version = 1
[[rule]]
id = "audit-everything"
effect = "audit_only"
priority = 1
"#;
        let policy = LoadedPolicy::parse(text).unwrap().into_evaluator();

        // Built-in: Critical is denied.  audit_only must not override it.
        let d = policy.evaluate(req(
            "x",
            CapabilityKind::Mutating,
            RiskTier::Critical,
            "h",
            json!({}),
        ));
        assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");

        // Built-in: Medium mutating needs approval.  Still does.
        let d = policy.evaluate(req(
            "log_vacuum",
            CapabilityKind::Mutating,
            RiskTier::Medium,
            "h",
            json!({}),
        ));
        assert_eq!(d.effect, PolicyEffect::RequiresApproval);

        // Built-in: Low read is allowed; audit_only is stricter, so it wins.
        let d = policy.evaluate(read_low("disk_usage", "h"));
        assert_eq!(d.effect, PolicyEffect::AuditOnly);
        assert_eq!(d.matched_rule.as_deref(), Some("audit-everything"));
    }

    #[test]
    fn allow_is_rejected_in_tighten_mode() {
        let text = r#"
version = 1
[[rule]]
id = "let-it-through"
effect = "allow"
priority = 1
"#;
        let err = LoadedPolicy::parse(text).unwrap_err().to_string();
        assert!(err.contains("replace"), "{err}");
    }

    #[test]
    fn file_guards_add_to_builtin_guards_in_both_modes() {
        for text in [
            TIGHTEN.to_string(),
            format!("{TIGHTEN}\n").replace("version = 1", "version = 1\nmode = \"replace\""),
        ] {
            let policy = LoadedPolicy::parse(&text).unwrap().into_evaluator();
            let mutate = |args| {
                req(
                    "service_restart",
                    CapabilityKind::Mutating,
                    RiskTier::Medium,
                    "h",
                    args,
                )
            };

            // From the file.
            let d = policy.evaluate(mutate(json!({"service": "postgresql"})));
            assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");
            // Built-in, still there.
            let d = policy.evaluate(mutate(json!({"service": "sshd"})));
            assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");
            let d = policy.evaluate(mutate(json!({"path": "/etc/passwd"})));
            assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");
        }
    }

    #[test]
    fn replace_mode_swaps_rules_and_stays_deny_by_default() {
        let text = r#"
version = 1
mode = "replace"

[[rule]]
id = "allow-disk-usage-only"
effect = "allow"
priority = 10
[rule.when]
capability_id = "disk_usage"
"#;
        let policy = LoadedPolicy::parse(text).unwrap().into_evaluator();
        assert_eq!(policy.rules().len(), 1);
        assert_eq!(
            policy.evaluate(read_low("disk_usage", "h")).effect,
            PolicyEffect::Allowed
        );
        // Everything else, including what the default policy allowed.
        let d = policy.evaluate(read_low("process_list", "h"));
        assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");
        // The kill switch still wins.
        policy.kill_switch().activate("test");
        let d = policy.evaluate(read_low("disk_usage", "h"));
        assert!(matches!(d.effect, PolicyEffect::Denied { .. }), "{d:?}");
    }

    #[test]
    fn strict_parsing_rejects_mistakes() {
        let cases: &[(&str, &str)] = &[
            ("version = 2", "unsupported policy file version"),
            ("", "version"),
            ("version = 1\nmood = \"tighten\"", "unknown field"),
            (
                "version = 1\n[[rule]]\nid = \"a\"\neffect = \"deny\"\npriority = 1\nenabeld = false",
                "unknown field",
            ),
            (
                "version = 1\n[[rule]]\nid = \"a\"\neffect = \"deny\"\npriority = 1\n[rule.when]\nhost = \"x\"",
                "unknown field",
            ),
            (
                "version = 1\n[[rule]]\nid = \"a\"\neffect = \"permit\"\npriority = 1",
                "unknown variant",
            ),
            (
                "version = 1\n[[rule]]\nid = \"a\"\neffect = \"deny\"\npriority = 1\n[[rule]]\nid = \"a\"\neffect = \"deny\"\npriority = 2",
                "duplicate rule id",
            ),
            (
                "version = 1\n[[rule]]\nid = \"bad id\"\neffect = \"deny\"\npriority = 1",
                "must be 1-64 characters",
            ),
            (
                "version = 1\n[[guard]]\nid = \"system-paths\"\nprotected_paths = [\"/x\"]",
                "built-in guards cannot be redefined",
            ),
            ("version = 1\n[[guard]]\nid = \"g\"", "protects nothing"),
            (
                "version = 1\n[[guard]]\nid = \"g\"\nprotected_paths = [\"relative\"]",
                "must be absolute",
            ),
            ("version = 1\nmode = \"replace\"", "would deny every request"),
        ];
        for (text, expected) in cases {
            let err = LoadedPolicy::parse(text).unwrap_err().to_string();
            assert!(err.contains(expected), "input {text:?}\n  got: {err}");
        }
    }

    #[test]
    fn empty_tighten_file_is_the_default_policy() {
        let policy = LoadedPolicy::parse("version = 1").unwrap().into_evaluator();
        let default = crate::engine::default_policy();
        assert_eq!(policy.rules().len(), default.rules().len());
        assert_eq!(
            policy.evaluate(read_low("disk_usage", "h")).effect,
            default.evaluate(read_low("disk_usage", "h")).effect
        );
    }

    #[test]
    fn disabled_rules_and_arg_conditions() {
        let text = r#"
version = 1
[[rule]]
id = "off"
effect = "deny"
priority = 1
enabled = false

[[rule]]
id = "no-var-lib"
effect = "deny"
priority = 2
[rule.when]
kind = "ReadOnly"
risk = "Low"
arg_contains = { path = "path", value = "/var/lib" }
"#;
        let policy = LoadedPolicy::parse(text).unwrap().into_evaluator();
        let d = policy.evaluate(req(
            "disk_usage",
            CapabilityKind::ReadOnly,
            RiskTier::Low,
            "h",
            json!({"path": "/tmp"}),
        ));
        assert_eq!(
            d.effect,
            PolicyEffect::Allowed,
            "disabled rule must not fire"
        );
        let d = policy.evaluate(req(
            "disk_usage",
            CapabilityKind::ReadOnly,
            RiskTier::Low,
            "h",
            json!({"path": "/var/lib/x"}),
        ));
        assert!(matches!(d.effect, PolicyEffect::Denied { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn load_checks_permissions_size_and_reports_the_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sentinel-policy-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");

        std::fs::write(&path, TIGHTEN).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_policy(Some(&path)).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = LoadedPolicy::load(&path).unwrap_err().to_string();
        assert!(err.contains("chmod go-w"), "{err}");

        std::fs::write(&path, "version = 1\nnope = true").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = LoadedPolicy::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("policy.toml") && err.contains("unknown field"),
            "{err}"
        );

        let err = LoadedPolicy::load(&dir.join("missing.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot read policy file"), "{err}");

        assert!(load_policy(None).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
