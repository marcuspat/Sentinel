use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

fn validate_safe_path(path: &str) -> Result<(), CoreError> {
    if path.is_empty() {
        return Err(CoreError::InvalidArgs("path must not be empty".into()));
    }
    // Must be absolute
    if !path.starts_with('/') {
        return Err(CoreError::InvalidArgs("path must be absolute".into()));
    }
    // Block traversal sequences
    if path.contains("..") {
        return Err(CoreError::InvalidArgs("path must not contain '..'".into()));
    }
    // Block critical system directories
    const BLOCKED_PREFIXES: &[&str] = &[
        "/etc", "/boot", "/sys", "/proc", "/dev",
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64",
        "/run/systemd",
    ];
    for blocked in BLOCKED_PREFIXES {
        if path == *blocked || path.starts_with(&format!("{}/", blocked)) {
            return Err(CoreError::InvalidArgs(
                format!("path '{}' is in a protected system directory", path)
            ));
        }
    }
    Ok(())
}

use sentinel_core::{
    Capability, CapabilityKind, CapabilityManifest, CapabilityResult, CoreError, ExecutionContext,
    RiskTier,
};
use sentinel_exec::CommandExecutorTrait;

// ─── DiskUsage ───────────────────────────────────────────────────────────────

pub struct DiskUsage {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl DiskUsage {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "disk_usage".into(),
                name: "Disk Usage".into(),
                description: "Reports disk space usage for a path using df and du.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: sentinel_core::capability::ResourceImpact {
                    io_intensive: true,
                    ..Default::default()
                },
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for DiskUsage {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        args.get("path")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CoreError::InvalidArgs("'path' must be a non-empty string".into()))?;
        if let Some(depth) = args.get("depth") {
            if !depth.is_number() {
                return Err(CoreError::InvalidArgs("'depth' must be a number".into()));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let path = args["path"].as_str().unwrap();

        debug!("DiskUsage: running df -h on {}", path);
        let df_out = match self
            .executor
            .run("df", &["-h", path], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        debug!("DiskUsage: running du -sh on {}", path);
        let du_out = match self
            .executor
            .run("du", &["-sh", path], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        CapabilityResult::success(json!({
            "path": path,
            "df_output": df_out.stdout,
            "du_output": du_out.stdout
        }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let path = args["path"].as_str().unwrap_or("/");
        CapabilityResult::dry_run(json!({
            "path": path,
            "predicted_structure": {
                "total_gb": 100.0,
                "used_gb": 45.0,
                "available_gb": 55.0,
                "percent_used": "45%",
                "top_directories": [
                    { "path": format!("{}/var", path), "size": "10G" },
                    { "path": format!("{}/usr", path), "size": "8G" }
                ]
            },
            "note": "Dry-run: no commands were executed"
        }))
    }
}

// ─── LogVacuum ───────────────────────────────────────────────────────────────

pub struct LogVacuum {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl LogVacuum {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "log_vacuum".into(),
                name: "Log Vacuum".into(),
                description: "Removes log files older than a given number of days.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::Medium,
                resource_impact: sentinel_core::capability::ResourceImpact {
                    io_intensive: true,
                    ..Default::default()
                },
                has_inverse: true,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for LogVacuum {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        let log_dir = args.get("log_dir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CoreError::InvalidArgs("'log_dir' must be a non-empty string".into()))?;
        validate_safe_path(log_dir)?;
        let days = args
            .get("older_than_days")
            .ok_or_else(|| CoreError::InvalidArgs("'older_than_days' is required".into()))?;
        if !days.is_number() {
            return Err(CoreError::InvalidArgs("'older_than_days' must be a number".into()));
        }
        if let Some(v) = days.as_f64() {
            if v < 0.0 {
                return Err(CoreError::InvalidArgs(
                    "'older_than_days' must be non-negative".into(),
                ));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let log_dir = args["log_dir"].as_str().unwrap();
        let days = args["older_than_days"].as_f64().unwrap() as i64;
        let explicit_dry = args.get("dry_run").and_then(Value::as_bool).unwrap_or(false);

        if explicit_dry || ctx.dry_run {
            return self.dry_run(args, ctx).await;
        }

        // Discover files
        let find_out = match self
            .executor
            .run(
                "find",
                &[log_dir, "-name", "*.log", "-mtime", &format!("+{}", days)],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        let files: Vec<String> = find_out
            .stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();

        let mut removed = 0usize;
        let mut backup_manifest: Vec<String> = Vec::new();
        for f in &files {
            match self
                .executor
                .run("rm", &["-f", f], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
                .await
            {
                Ok(r) if r.success() => {
                    removed += 1;
                    backup_manifest.push(f.clone());
                }
                _ => {}
            }
        }

        CapabilityResult::success(json!({
            "files_removed": removed,
            "bytes_freed": 0,
            "backup_manifest": backup_manifest
        }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let log_dir = args["log_dir"].as_str().unwrap_or("/var/log");
        let days = args["older_than_days"].as_f64().unwrap_or(7.0);
        CapabilityResult::dry_run(json!({
            "log_dir": log_dir,
            "older_than_days": days,
            "predicted": {
                "files_to_remove": ["<files matching *.log older than N days>"],
                "bytes_freed": 0
            },
            "note": "Dry-run: no files removed"
        }))
    }

    async fn invoke_inverse(
        &self,
        _args: Value,
        _ctx: &ExecutionContext,
    ) -> Option<CapabilityResult> {
        Some(CapabilityResult::failure(
            "LogVacuum: deleted files cannot be automatically restored. \
             Use the backup_manifest from the invoke output to identify affected files.",
            false,
        ))
    }
}

// ─── CachePrune ──────────────────────────────────────────────────────────────

pub struct CachePrune {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl CachePrune {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "cache_prune".into(),
                name: "Cache Prune".into(),
                description: "Clears package manager and user-specified cache directories.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::Medium,
                resource_impact: sentinel_core::capability::ResourceImpact {
                    io_intensive: true,
                    ..Default::default()
                },
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }

    async fn detect_pkg_manager(
        &self,
        env: &std::collections::HashMap<String, String>,
    ) -> Option<(&'static str, Vec<&'static str>)> {
        let candidates: &[(&str, &[&str])] = &[
            ("apt-get", &["clean"]),
            ("yum", &["clean", "all"]),
            ("dnf", &["clean", "all"]),
            ("pacman", &["-Sc", "--noconfirm"]),
        ];
        for (prog, args) in candidates {
            if let Ok(out) = self.executor.run("which", &[prog], env, 4096).await {
                if out.success() {
                    return Some((prog, args.to_vec()));
                }
            }
        }
        None
    }
}

#[async_trait]
impl Capability for CachePrune {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        let dirs = args
            .get("cache_dirs")
            .ok_or_else(|| CoreError::InvalidArgs("'cache_dirs' is required".into()))?;
        if !dirs.is_array() {
            return Err(CoreError::InvalidArgs("'cache_dirs' must be an array".into()));
        }
        for (i, dir) in dirs.as_array().unwrap().iter().enumerate() {
            let path = dir.as_str().ok_or_else(|| CoreError::InvalidArgs(
                format!("cache_dirs[{}] must be a string", i)
            ))?;
            validate_safe_path(path)?;
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let explicit_dry = args.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
        if explicit_dry || ctx.dry_run {
            return self.dry_run(args, ctx).await;
        }

        let cache_dirs = args["cache_dirs"].as_array().unwrap().clone();
        let mut actions: Vec<Value> = Vec::new();

        if let Some((prog, pm_args)) = self.detect_pkg_manager(&ctx.env_overrides).await {
            let arg_refs: Vec<&str> = pm_args.to_vec();
            match self
                .executor
                .run(prog, &arg_refs, &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
                .await
            {
                Ok(out) => actions.push(json!({
                    "action": format!("{} {}", prog, pm_args.join(" ")),
                    "success": out.success()
                })),
                Err(e) => actions.push(json!({ "action": prog, "error": e.to_string() })),
            }
        }

        for dir in &cache_dirs {
            if let Some(d) = dir.as_str() {
                match self
                    .executor
                    .run(
                        "find",
                        &[d, "-mindepth", "1", "-delete"],
                        &ctx.env_overrides,
                        ctx.resource_limits.max_output_bytes,
                    )
                    .await
                {
                    Ok(out) => actions.push(json!({ "cache_dir": d, "success": out.success() })),
                    Err(e) => actions.push(json!({ "cache_dir": d, "error": e.to_string() })),
                }
            }
        }

        CapabilityResult::success(json!({ "actions": actions, "bytes_freed": 0 }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let cache_dirs = args["cache_dirs"].as_array().cloned().unwrap_or_default();
        CapabilityResult::dry_run(json!({
            "cache_dirs": cache_dirs,
            "predicted_bytes_freed": 0,
            "note": "Dry-run: no caches cleared"
        }))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sentinel_exec::{CommandExecutorTrait, CommandOutput};

    struct DummyExecutor;
    #[async_trait::async_trait]
    impl CommandExecutorTrait for DummyExecutor {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _env: &HashMap<String, String>,
            _max_output_bytes: usize,
        ) -> Result<CommandOutput, sentinel_exec::ExecError> {
            panic!("DummyExecutor::run should not be called in validate_args tests")
        }
    }

    fn make_executor() -> Arc<dyn CommandExecutorTrait> {
        Arc::new(DummyExecutor)
    }

    // DiskUsage validate_args
    #[test]
    fn disk_usage_valid_args() {
        let cap = DiskUsage::new(make_executor());
        assert!(cap.validate_args(&json!({ "path": "/" })).is_ok());
        assert!(cap.validate_args(&json!({ "path": "/var", "depth": 2 })).is_ok());
    }

    #[test]
    fn disk_usage_missing_path() {
        let cap = DiskUsage::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }

    #[test]
    fn disk_usage_empty_path() {
        let cap = DiskUsage::new(make_executor());
        assert!(cap.validate_args(&json!({ "path": "" })).is_err());
    }

    #[test]
    fn disk_usage_bad_depth_type() {
        let cap = DiskUsage::new(make_executor());
        assert!(cap.validate_args(&json!({ "path": "/", "depth": "two" })).is_err());
    }

    // LogVacuum validate_args
    #[test]
    fn log_vacuum_valid_args() {
        let cap = LogVacuum::new(make_executor());
        assert!(cap
            .validate_args(&json!({ "log_dir": "/var/log", "older_than_days": 7 }))
            .is_ok());
    }

    #[test]
    fn log_vacuum_missing_log_dir() {
        let cap = LogVacuum::new(make_executor());
        assert!(cap.validate_args(&json!({ "older_than_days": 7 })).is_err());
    }

    #[test]
    fn log_vacuum_missing_days() {
        let cap = LogVacuum::new(make_executor());
        assert!(cap.validate_args(&json!({ "log_dir": "/var/log" })).is_err());
    }

    #[test]
    fn log_vacuum_negative_days() {
        let cap = LogVacuum::new(make_executor());
        assert!(cap
            .validate_args(&json!({ "log_dir": "/var/log", "older_than_days": -1 }))
            .is_err());
    }

    // CachePrune validate_args
    #[test]
    fn cache_prune_valid_args() {
        let cap = CachePrune::new(make_executor());
        assert!(cap
            .validate_args(&json!({ "cache_dirs": ["/tmp/cache"] }))
            .is_ok());
    }

    #[test]
    fn cache_prune_missing_dirs() {
        let cap = CachePrune::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }

    #[test]
    fn cache_prune_dirs_not_array() {
        let cap = CachePrune::new(make_executor());
        assert!(cap.validate_args(&json!({ "cache_dirs": "/tmp/cache" })).is_err());
    }
}
