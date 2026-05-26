//! Resource guards that protect critical system paths and services.
//!
//! A [`ResourceGuard`] holds a list of protected path globs and/or service
//! name patterns.  Before any capability is executed, every registered guard
//! is checked.  If a guard matches and would be violated, it returns a human-
//! readable reason string which the evaluator turns into a [`PolicyDecision`]
//! with effect `Denied`.
//!
//! [`PolicyDecision`]: crate::evaluator::PolicyDecision

use serde::{Deserialize, Serialize};
use sentinel_core::CapabilityKind;

use crate::evaluator::PolicyRequest;
use crate::rules::glob_match;

// ── ResourceGuard ─────────────────────────────────────────────────────────────

/// Protects a set of paths and/or services from modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGuard {
    /// Unique, stable identifier.
    pub id: String,
    /// Human-readable name used in denial messages and audit logs.
    pub name: String,
    /// Glob patterns for filesystem paths that should be protected.
    /// Matched against `args["path"]` in the request.
    pub protected_paths: Vec<String>,
    /// Glob patterns for service names that should be protected.
    /// Matched against `args["service"]` in the request.
    pub protected_services: Vec<String>,
    /// When `true`, any mutating capability (Write, Delete, Execute,
    /// ServiceControl, PackageManagement, NetworkConfig, UserManagement)
    /// targeting a protected resource is blocked.
    pub block_mutating: bool,
    /// When `true`, read operations are permitted even if the resource is
    /// protected.  When `false`, even reads are blocked.
    pub allow_read: bool,
}

impl ResourceGuard {
    /// Check whether this guard should block `req`.
    ///
    /// Returns `Some(reason)` when the request is blocked, `None` when it
    /// is permitted.
    pub fn blocks(&self, req: &PolicyRequest) -> Option<String> {
        let is_read = matches!(req.capability_kind, CapabilityKind::ReadOnly);

        // If it's a read and reads are allowed, nothing to check.
        if is_read && self.allow_read {
            return None;
        }

        // If it's a mutating op and we don't block mutating, nothing to check.
        if !is_read && !self.block_mutating {
            return None;
        }

        // Check protected paths.
        if let Some(path) = req.args.get("path").and_then(|v| v.as_str()) {
            for pattern in &self.protected_paths {
                if path_matches(pattern, path) {
                    return Some(format!("path '{}' is protected by guard '{}'", path, self.name));
                }
            }
        }

        // Check protected services.
        if let Some(service) = req.args.get("service").and_then(|v| v.as_str()) {
            for pattern in &self.protected_services {
                if glob_match(pattern, service) {
                    return Some(format!(
                        "service '{}' is protected by guard '{}'",
                        service, self.name
                    ));
                }
            }
        }

        None
    }
}

/// Match a path against a guard pattern.
///
/// Two forms are supported:
/// * Prefix pattern: `/etc` blocks `/etc`, `/etc/passwd`, `/etc/ssh/sshd_config`, etc.
/// * Glob pattern containing `*` or `?`.
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        glob_match(pattern, path)
    } else {
        // Prefix match: path must equal pattern OR start with "pattern/"
        path == pattern || path.starts_with(&format!("{}/", pattern))
    }
}

// ── Built-in guards ───────────────────────────────────────────────────────────

/// Return the default set of resource guards that protect critical system
/// paths and services.
///
/// | Guard              | Protects                                     |
/// |--------------------|----------------------------------------------|
/// | `system-paths`     | `/etc`, `/boot`, `/sys`, `/proc`             |
/// | `critical-services`| `sshd`, `systemd`, `docker`                  |
pub fn default_resource_guards() -> Vec<ResourceGuard> {
    vec![
        ResourceGuard {
            id: "system-paths".into(),
            name: "System Paths Guard".into(),
            protected_paths: vec![
                "/etc".into(),
                "/boot".into(),
                "/sys".into(),
                "/proc".into(),
            ],
            protected_services: vec![],
            block_mutating: true,
            allow_read: true,
        },
        ResourceGuard {
            id: "critical-services".into(),
            name: "Critical Services Guard".into(),
            protected_paths: vec![],
            protected_services: vec![
                "sshd".into(),
                "systemd".into(),
                "docker".into(),
            ],
            block_mutating: true,
            allow_read: true,
        },
    ]
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sentinel_core::{CapabilityKind, RiskTier};
    use uuid::Uuid;

    fn make_request_with_args(
        cap_id: &str,
        kind: CapabilityKind,
        args: serde_json::Value,
    ) -> PolicyRequest {
        PolicyRequest {
            session_id: Uuid::new_v4(),
            capability_id: cap_id.to_string(),
            capability_kind: kind,
            risk_tier: RiskTier::Medium,
            args,
            target_host: "localhost".to_string(),
            timestamp: chrono::Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap(),
            session_phase: None,
        }
    }

    fn system_path_guard() -> ResourceGuard {
        ResourceGuard {
            id: "system-paths".into(),
            name: "System Paths Guard".into(),
            protected_paths: vec!["/etc".into(), "/boot".into()],
            protected_services: vec![],
            block_mutating: true,
            allow_read: true,
        }
    }

    fn service_guard() -> ResourceGuard {
        ResourceGuard {
            id: "critical-services".into(),
            name: "Critical Services Guard".into(),
            protected_paths: vec![],
            protected_services: vec!["sshd".into(), "systemd".into()],
            block_mutating: true,
            allow_read: true,
        }
    }

    #[test]
    fn blocks_write_to_etc() {
        let guard = system_path_guard();
        let req = make_request_with_args(
            "write_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "path": "/etc/passwd" }),
        );
        assert!(guard.blocks(&req).is_some());
    }

    #[test]
    fn blocks_write_to_etc_root() {
        let guard = system_path_guard();
        let req = make_request_with_args(
            "write_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "path": "/etc" }),
        );
        assert!(guard.blocks(&req).is_some());
    }

    #[test]
    fn allows_read_from_etc() {
        let guard = system_path_guard();
        let req = make_request_with_args(
            "read_file",
            CapabilityKind::ReadOnly,
            serde_json::json!({ "path": "/etc/hostname" }),
        );
        // allow_read = true → reads should pass through
        assert!(guard.blocks(&req).is_none());
    }

    #[test]
    fn allows_write_outside_protected() {
        let guard = system_path_guard();
        let req = make_request_with_args(
            "write_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "path": "/home/user/file.txt" }),
        );
        assert!(guard.blocks(&req).is_none());
    }

    #[test]
    fn blocks_service_control_on_sshd() {
        let guard = service_guard();
        let req = make_request_with_args(
            "service_restart",
            CapabilityKind::Mutating,
            serde_json::json!({ "service": "sshd" }),
        );
        assert!(guard.blocks(&req).is_some());
    }

    #[test]
    fn allows_read_of_protected_service() {
        let guard = service_guard();
        let req = make_request_with_args(
            "service_status",
            CapabilityKind::ReadOnly,
            serde_json::json!({ "service": "sshd" }),
        );
        assert!(guard.blocks(&req).is_none());
    }

    #[test]
    fn allows_control_of_unprotected_service() {
        let guard = service_guard();
        let req = make_request_with_args(
            "service_restart",
            CapabilityKind::Mutating,
            serde_json::json!({ "service": "nginx" }),
        );
        assert!(guard.blocks(&req).is_none());
    }

    #[test]
    fn blocks_delete_of_boot() {
        let guard = system_path_guard();
        let req = make_request_with_args(
            "delete_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "path": "/boot/grub/grub.cfg" }),
        );
        assert!(guard.blocks(&req).is_some());
    }

    #[test]
    fn no_path_arg_does_not_block() {
        let guard = system_path_guard();
        // No path in args — guard cannot determine the target, passes through.
        let req = make_request_with_args(
            "write_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "content": "hello" }),
        );
        assert!(guard.blocks(&req).is_none());
    }

    #[test]
    fn allow_read_false_blocks_reads() {
        let mut guard = system_path_guard();
        guard.allow_read = false;
        let req = make_request_with_args(
            "read_file",
            CapabilityKind::ReadOnly,
            serde_json::json!({ "path": "/etc/passwd" }),
        );
        assert!(guard.blocks(&req).is_some());
    }

    #[test]
    fn default_resource_guards_are_sensible() {
        let guards = default_resource_guards();
        assert_eq!(guards.len(), 2);
        assert_eq!(guards[0].id, "system-paths");
        assert_eq!(guards[1].id, "critical-services");
        // System paths guard protects /etc
        let req = make_request_with_args(
            "write_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "path": "/etc/shadow" }),
        );
        assert!(guards[0].blocks(&req).is_some());
    }

    #[test]
    fn path_prefix_does_not_match_partial_dir_name() {
        // /etcfoo must NOT match the /etc guard
        let guard = system_path_guard();
        let req = make_request_with_args(
            "write_file",
            CapabilityKind::Mutating,
            serde_json::json!({ "path": "/etcfoo/file.conf" }),
        );
        assert!(guard.blocks(&req).is_none());
    }
}
