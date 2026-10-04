//! JSON Schemas for the built-in capabilities' arguments.
//!
//! These are handed to LLM providers as tool input schemas.  They describe
//! the arguments; `validate_args` on each capability still enforces them.

use serde_json::{json, Value};

/// Schema for the capability `id`, or `None` for an unknown id.
pub fn args_schema(id: &str) -> Option<Value> {
    let service = || {
        json!({
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "systemd unit name, e.g. \"nginx\""}
            },
            "required": ["service"]
        })
    };
    Some(match id {
        "disk_usage" => json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to measure"},
                "depth": {"type": "integer", "minimum": 0, "description": "Directory depth to report"}
            },
            "required": ["path"]
        }),
        "log_vacuum" => json!({
            "type": "object",
            "properties": {
                "log_dir": {"type": "string", "description": "Absolute directory holding *.log files"},
                "older_than_days": {"type": "number", "minimum": 0, "description": "Remove logs older than this many days"},
                "dry_run": {"type": "boolean"}
            },
            "required": ["log_dir", "older_than_days"]
        }),
        "cache_prune" => json!({
            "type": "object",
            "properties": {
                "cache_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Absolute cache directories to empty"
                }
            },
            "required": ["cache_dirs"]
        }),
        "system_metrics" => json!({
            "type": "object",
            "properties": {
                "include": {
                    "type": "array",
                    "items": {"type": "string", "enum": crate::metrics::VALID_METRICS},
                    "description": "Metrics to collect; all when omitted"
                }
            }
        }),
        "network_connections" => json!({
            "type": "object",
            "properties": {
                "state": {"type": "string", "description": "Only connections in this state, e.g. \"LISTEN\""}
            }
        }),
        "network_interfaces" => json!({"type": "object", "properties": {}}),
        "package_list" | "process_list" => json!({
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Substring to match"}
            }
        }),
        "package_upgrade" => json!({
            "type": "object",
            "properties": {
                "all": {"type": "boolean", "description": "Upgrade every package. Give either this or `packages`"},
                "packages": {"type": "array", "items": {"type": "string"}, "description": "Specific packages to upgrade"}
            }
        }),
        "process_kill" => json!({
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "minimum": 2},
                "signal": {
                    "type": "string",
                    "enum": ["TERM", "KILL", "HUP", "INT", "QUIT", "USR1", "USR2", "CONT", "STOP"]
                }
            },
            "required": ["pid"]
        }),
        "service_status" | "service_restart" | "service_stop" | "service_start" => service(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_exec::RealCommandExecutor;
    use std::sync::Arc;

    #[test]
    fn every_builtin_capability_has_a_real_schema() {
        for cap in crate::all_capabilities(Arc::new(RealCommandExecutor)) {
            let id = &cap.manifest().id;
            let schema = cap.args_schema();
            assert_eq!(schema, args_schema(id).unwrap(), "{id}");
            assert_eq!(schema["type"], "object", "{id}");
            assert!(schema["properties"].is_object(), "{id}: no properties");
            // `required` names must exist in `properties`.
            if let Some(required) = schema["required"].as_array() {
                for name in required {
                    assert!(
                        schema["properties"].get(name.as_str().unwrap()).is_some(),
                        "{id}: required {name} not declared"
                    );
                }
            }
        }
    }

    #[test]
    fn required_fields_match_validate_args() {
        // An empty object must be rejected exactly when the schema has
        // required fields, so the schema and the validator cannot drift apart
        // on what is mandatory.
        for cap in crate::all_capabilities(Arc::new(RealCommandExecutor)) {
            let id = cap.manifest().id.clone();
            let has_required = cap.args_schema()["required"]
                .as_array()
                .is_some_and(|r| !r.is_empty());
            let empty_ok = cap.validate_args(&json!({})).is_ok();
            if id == "package_upgrade" {
                // Needs `all` *or* `packages`: an either-or that provider
                // tool schemas cannot express at the top level.  It is
                // stated in the field description instead.
                assert!(!empty_ok && !has_required);
                continue;
            }
            assert_eq!(!empty_ok, has_required, "{id}");
        }
    }

    #[test]
    fn unknown_id_has_no_schema() {
        assert!(args_schema("nope").is_none());
    }
}
