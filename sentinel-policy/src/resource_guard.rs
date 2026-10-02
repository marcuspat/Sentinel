//! Resource guards that protect critical system paths and services.
//!
//! A [`ResourceGuard`] holds a list of protected path globs and/or service
//! name patterns.  Before any capability is executed, every registered guard
//! is checked.  If a guard matches and would be violated, it returns a human-
//! readable reason string which the evaluator turns into a [`PolicyDecision`]
//! with effect `Denied`.
//!
//! [`PolicyDecision`]: crate::evaluator::PolicyDecision

use sentinel_core::CapabilityKind;
use serde::{Deserialize, Serialize};

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
    /// Matched against every absolute path found anywhere in the request's
    /// arguments, after lexical normalisation.
    pub protected_paths: Vec<String>,
    /// Glob patterns for service names that should be protected.
    /// Matched against the `service` / `services` / `unit` / `units`
    /// arguments, with the unit-type suffix and instance removed.
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

        // Every string anywhere in the arguments is a candidate: guards used
        // to read only `args.path` / `args.service`, so `log_dir`,
        // `cache_dirs[]` and any future argument name went unchecked.
        let mut strings = Vec::new();
        collect_strings(None, &req.args, &mut strings);

        for (key, value) in &strings {
            if let Some(normalised) = normalise_path(value) {
                for pattern in &self.protected_paths {
                    if path_matches(pattern, &normalised) || path_matches(pattern, value) {
                        return Some(format!(
                            "path '{}' is protected by guard '{}'",
                            value, self.name
                        ));
                    }
                }
            }

            if key.is_some_and(is_service_key) {
                let unit = normalise_unit(value);
                for pattern in &self.protected_services {
                    if glob_match(pattern, &unit) || glob_match(pattern, value) {
                        return Some(format!(
                            "service '{}' is protected by guard '{}'",
                            value, self.name
                        ));
                    }
                }
            }
        }

        None
    }
}

/// Argument names whose values name a service / systemd unit.
fn is_service_key(key: &str) -> bool {
    matches!(key, "service" | "services" | "unit" | "units")
}

/// Collect every string in `value`, with the name of the nearest enclosing
/// object key (array elements inherit the key of their array).
fn collect_strings<'a>(
    key: Option<&'a str>,
    value: &'a serde_json::Value,
    out: &mut Vec<(Option<&'a str>, &'a str)>,
) {
    match value {
        serde_json::Value::String(s) => out.push((key, s)),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_strings(key, item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_strings(Some(k), v, out);
            }
        }
        _ => {}
    }
}

/// Lexically normalise an absolute path: collapse `//`, drop `.`, resolve
/// `..` (never above `/`), drop a trailing slash.
///
/// Returns `None` for anything that is not an absolute path.  This is purely
/// textual — a symlink that points into a protected directory is **not**
/// resolved here; the Landlock profile in `sentinel-exec` is the control that
/// holds for those.
pub fn normalise_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in trimmed.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// Reduce a systemd unit spelling to its base name: lower-cased, without a
/// unit-type suffix (`sshd.service` → `sshd`) or an instance
/// (`getty@tty1` → `getty`).
pub fn normalise_unit(raw: &str) -> String {
    const SUFFIXES: [&str; 11] = [
        ".service",
        ".socket",
        ".target",
        ".timer",
        ".mount",
        ".automount",
        ".path",
        ".slice",
        ".scope",
        ".swap",
        ".device",
    ];
    let mut unit = raw.trim().to_ascii_lowercase();
    if let Some((base, _instance)) = unit.split_once('@') {
        unit = base.to_string();
    }
    // Repeat so a doubled suffix cannot hide the base name.
    while let Some(stripped) = SUFFIXES.iter().find_map(|s| unit.strip_suffix(s)) {
        unit = stripped.trim().to_string();
    }
    unit
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
/// | `system-paths`     | `/etc`, `/boot`, `/sys`, `/proc`, `/dev`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/run/systemd` |
/// | `critical-services`| `sshd`, `ssh`, `systemd`, `systemd-*`, `docker`, `containerd` |
pub fn default_resource_guards() -> Vec<ResourceGuard> {
    vec![
        ResourceGuard {
            id: "system-paths".into(),
            name: "System Paths Guard".into(),
            protected_paths: [
                "/etc",
                "/boot",
                "/sys",
                "/proc",
                "/dev",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                "/usr/bin",
                "/usr/sbin",
                "/usr/lib",
                "/run/systemd",
            ]
            .map(String::from)
            .to_vec(),
            protected_services: vec![],
            block_mutating: true,
            allow_read: true,
        },
        ResourceGuard {
            id: "critical-services".into(),
            name: "Critical Services Guard".into(),
            protected_paths: vec![],
            // `ssh` is the unit name on Debian/Ubuntu; `systemd-*` covers
            // journald, logind, networkd, resolved and friends.
            protected_services: vec![
                "sshd".into(),
                "ssh".into(),
                "systemd".into(),
                "systemd-*".into(),
                "docker".into(),
                "containerd".into(),
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
