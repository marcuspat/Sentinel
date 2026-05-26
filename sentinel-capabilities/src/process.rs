use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use sentinel_core::{
    capability::ResourceImpact, Capability, CapabilityKind, CapabilityManifest, CapabilityResult,
    CoreError, ExecutionContext, RiskTier,
};
use sentinel_exec::CommandExecutorTrait;

// ─── ProcessList ─────────────────────────────────────────────────────────────

pub struct ProcessList {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl ProcessList {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "process_list".into(),
                name: "Process List".into(),
                description: "Lists running processes, optionally filtered by name.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: ResourceImpact::default(),
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for ProcessList {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        if let Some(f) = args.get("filter") {
            if !f.is_string() {
                return Err(CoreError::InvalidArgs("'filter' must be a string".into()));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }

        let ps_out = match self
            .executor
            .run("ps", &["aux"], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        let filter = args.get("filter").and_then(Value::as_str);
        let processes: Vec<Value> = ps_out
            .stdout
            .lines()
            .skip(1)
            .filter(|line| {
                if let Some(f) = filter {
                    line.to_lowercase().contains(&f.to_lowercase())
                } else {
                    true
                }
            })
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 11 {
                    json!({
                        "user":        parts[0],
                        "pid":         parts[1].parse::<u64>().unwrap_or(0),
                        "cpu_percent": parts[2],
                        "mem_percent": parts[3],
                        "command":     parts[10..].join(" ")
                    })
                } else {
                    json!({ "raw": line })
                }
            })
            .collect();

        let count = processes.len();
        CapabilityResult::success(json!({ "processes": processes, "count": count }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        CapabilityResult::dry_run(json!({
            "predicted_structure": {
                "processes": [
                    { "user": "root",   "pid": 1,    "cpu_percent": "0.0", "mem_percent": "0.1", "command": "/sbin/init" },
                    { "user": "nobody", "pid": 1234, "cpu_percent": "0.2", "mem_percent": "0.5", "command": "/usr/bin/example" }
                ],
                "count": 2
            },
            "note": "Dry-run: no commands executed"
        }))
    }
}

// ─── ProcessKill ─────────────────────────────────────────────────────────────

pub struct ProcessKill {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl ProcessKill {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "process_kill".into(),
                name: "Process Kill".into(),
                description: "Sends a signal to a process by PID.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::High,
                resource_impact: ResourceImpact::default(),
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for ProcessKill {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        let pid = args
            .get("pid")
            .ok_or_else(|| CoreError::InvalidArgs("'pid' is required".into()))?;
        if !pid.is_number() {
            return Err(CoreError::InvalidArgs("'pid' must be a number".into()));
        }
        if pid.as_f64().map(|v| v <= 1.0).unwrap_or(true) {
            return Err(CoreError::InvalidArgs("'pid' must be > 1 (PID 1 is reserved)".into()));
        }
        const ALLOWED_SIGNALS: &[&str] = &[
            "TERM", "KILL", "HUP", "INT", "QUIT", "USR1", "USR2", "CONT", "STOP",
        ];
        if let Some(sig) = args.get("signal") {
            if !sig.is_string() {
                return Err(CoreError::InvalidArgs("'signal' must be a string".into()));
            }
            let sig_str = sig.as_str().unwrap();
            if !ALLOWED_SIGNALS.contains(&sig_str) {
                return Err(CoreError::InvalidArgs(
                    format!("'signal' must be one of: {}", ALLOWED_SIGNALS.join(", "))
                ));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let pid = args["pid"].as_u64().unwrap();
        let signal = args.get("signal").and_then(Value::as_str).unwrap_or("TERM");
        let pid_str = pid.to_string();
        let sig_flag = format!("-{}", signal);

        debug!("ProcessKill: sending {} to pid {}", signal, pid);
        match self
            .executor
            .run(
                "kill",
                &[sig_flag.as_str(), pid_str.as_str()],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(out) if out.success() => CapabilityResult::success(json!({
                "pid": pid, "signal": signal, "success": true
            })),
            Ok(out) => CapabilityResult::failure(
                format!("kill returned non-zero: {}", out.stderr.trim()),
                true,
            ),
            Err(e) => CapabilityResult::failure(e.to_string(), true),
        }
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let pid = args["pid"].as_u64().unwrap_or(0);
        let signal = args.get("signal").and_then(Value::as_str).unwrap_or("TERM");
        CapabilityResult::dry_run(json!({
            "pid": pid, "signal": signal, "note": "Dry-run: no signal sent"
        }))
    }
}

// ─── ServiceStatus ───────────────────────────────────────────────────────────

pub struct ServiceStatus {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl ServiceStatus {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "service_status".into(),
                name: "Service Status".into(),
                description: "Reports systemd service status including recent log lines.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: ResourceImpact::default(),
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for ServiceStatus {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        args.get("service")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CoreError::InvalidArgs("'service' must be a non-empty string".into()))?;
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap();

        let out = match self
            .executor
            .run(
                "systemctl",
                &["status", service],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        let recent_logs: Vec<&str> = out.stdout.lines().rev().take(10).collect();
        CapabilityResult::success(json!({
            "service":     service,
            "active":      out.stdout.contains("active (running)"),
            "enabled":     out.stdout.contains("enabled"),
            "recent_logs": recent_logs
        }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap_or("unknown");
        CapabilityResult::dry_run(json!({
            "service": service,
            "predicted_structure": {
                "active": true, "enabled": true,
                "recent_logs": ["<last 10 lines of systemctl status>"]
            },
            "note": "Dry-run: no commands executed"
        }))
    }
}

// ─── ServiceRestart ──────────────────────────────────────────────────────────

pub struct ServiceRestart {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl ServiceRestart {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "service_restart".into(),
                name: "Service Restart".into(),
                description: "Restarts a systemd service.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::High,
                resource_impact: ResourceImpact::default(),
                has_inverse: true,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for ServiceRestart {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        args.get("service")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CoreError::InvalidArgs("'service' must be a non-empty string".into()))?;
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap();

        let pre_state = match self
            .executor
            .run("systemctl", &["is-active", service], &ctx.env_overrides, 4096)
            .await
        {
            Ok(o) => o.stdout.trim().to_string(),
            Err(_) => "unknown".to_string(),
        };

        match self
            .executor
            .run(
                "systemctl",
                &["restart", service],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(out) if out.success() => CapabilityResult::success(json!({
                "service":   service,
                "success":   true,
                "pre_state": pre_state
            })),
            Ok(out) => CapabilityResult::failure(
                format!("systemctl restart failed: {}", out.stderr.trim()),
                true,
            ),
            Err(e) => CapabilityResult::failure(e.to_string(), true),
        }
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap_or("unknown");
        CapabilityResult::dry_run(json!({
            "service": service,
            "note": "Dry-run: systemctl restart not executed"
        }))
    }

    async fn invoke_inverse(&self, args: Value, ctx: &ExecutionContext) -> Option<CapabilityResult> {
        if let Err(e) = self.validate_args(&args) {
            return Some(CapabilityResult::failure(e.to_string(), false));
        }
        let service = args["service"].as_str().unwrap();

        match self
            .executor
            .run(
                "systemctl",
                &["stop", service],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(o) if o.success() => Some(CapabilityResult::success(json!({
                "service": service,
                "action": "stopped",
                "note": "Stopped service as inverse of restart"
            }))),
            Ok(o) => Some(CapabilityResult::failure(
                format!("inverse stop failed: {}", o.stderr.trim()),
                true,
            )),
            Err(e) => Some(CapabilityResult::failure(e.to_string(), true)),
        }
    }
}

// ─── ServiceStop ─────────────────────────────────────────────────────────────

pub struct ServiceStop {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl ServiceStop {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "service_stop".into(),
                name: "Service Stop".into(),
                description: "Stops a systemd service.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::High,
                resource_impact: ResourceImpact::default(),
                has_inverse: true,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for ServiceStop {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        args.get("service")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CoreError::InvalidArgs("'service' must be a non-empty string".into()))?;
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap();

        match self
            .executor
            .run(
                "systemctl",
                &["stop", service],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(out) if out.success() => CapabilityResult::success(json!({
                "service": service, "success": true
            })),
            Ok(out) => CapabilityResult::failure(
                format!("systemctl stop failed: {}", out.stderr.trim()),
                true,
            ),
            Err(e) => CapabilityResult::failure(e.to_string(), true),
        }
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap_or("unknown");
        CapabilityResult::dry_run(json!({ "service": service, "note": "Dry-run: not stopped" }))
    }

    async fn invoke_inverse(&self, args: Value, ctx: &ExecutionContext) -> Option<CapabilityResult> {
        let start_cap = ServiceStart::new(Arc::clone(&self.executor));
        Some(start_cap.invoke(args, ctx).await)
    }
}

// ─── ServiceStart ────────────────────────────────────────────────────────────

pub struct ServiceStart {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl ServiceStart {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "service_start".into(),
                name: "Service Start".into(),
                description: "Starts a systemd service.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::Medium,
                resource_impact: ResourceImpact::default(),
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for ServiceStart {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        args.get("service")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CoreError::InvalidArgs("'service' must be a non-empty string".into()))?;
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap();

        let out = match self
            .executor
            .run(
                "systemctl",
                &["start", service],
                &ctx.env_overrides,
                ctx.resource_limits.max_output_bytes,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        if !out.success() {
            return CapabilityResult::failure(
                format!("systemctl start failed: {}", out.stderr.trim()),
                true,
            );
        }

        let status = match self
            .executor
            .run("systemctl", &["is-active", service], &ctx.env_overrides, 4096)
            .await
        {
            Ok(o) => o.stdout.trim().to_string(),
            Err(_) => "unknown".to_string(),
        };

        CapabilityResult::success(json!({
            "service": service, "success": true, "status": status
        }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let service = args["service"].as_str().unwrap_or("unknown");
        CapabilityResult::dry_run(json!({ "service": service, "note": "Dry-run: not started" }))
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

    // ProcessList
    #[test]
    fn process_list_no_args_ok() {
        let cap = ProcessList::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_ok());
    }

    #[test]
    fn process_list_with_string_filter() {
        let cap = ProcessList::new(make_executor());
        assert!(cap.validate_args(&json!({ "filter": "nginx" })).is_ok());
    }

    #[test]
    fn process_list_bad_filter_type() {
        let cap = ProcessList::new(make_executor());
        assert!(cap.validate_args(&json!({ "filter": 123 })).is_err());
    }

    // ProcessKill
    #[test]
    fn process_kill_valid() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({ "pid": 1234 })).is_ok());
        assert!(cap.validate_args(&json!({ "pid": 1234, "signal": "KILL" })).is_ok());
    }

    #[test]
    fn process_kill_missing_pid() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }

    #[test]
    fn process_kill_zero_pid() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({ "pid": 0 })).is_err());
    }

    #[test]
    fn process_kill_negative_pid() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({ "pid": -1 })).is_err());
    }

    #[test]
    fn process_kill_pid_1_rejected() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({ "pid": 1 })).is_err());
    }

    #[test]
    fn process_kill_bad_signal_type() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({ "pid": 1234, "signal": 9 })).is_err());
    }

    #[test]
    fn process_kill_invalid_signal_name() {
        let cap = ProcessKill::new(make_executor());
        assert!(cap.validate_args(&json!({ "pid": 1234, "signal": "INVALID" })).is_err());
    }

    // ServiceStatus
    #[test]
    fn service_status_valid() {
        let cap = ServiceStatus::new(make_executor());
        assert!(cap.validate_args(&json!({ "service": "nginx" })).is_ok());
    }

    #[test]
    fn service_status_missing_service() {
        let cap = ServiceStatus::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }

    #[test]
    fn service_status_empty_service() {
        let cap = ServiceStatus::new(make_executor());
        assert!(cap.validate_args(&json!({ "service": "" })).is_err());
    }

    // ServiceRestart
    #[test]
    fn service_restart_valid() {
        let cap = ServiceRestart::new(make_executor());
        assert!(cap.validate_args(&json!({ "service": "sshd" })).is_ok());
    }

    #[test]
    fn service_restart_empty() {
        let cap = ServiceRestart::new(make_executor());
        assert!(cap.validate_args(&json!({ "service": "" })).is_err());
    }

    // ServiceStop
    #[test]
    fn service_stop_valid() {
        let cap = ServiceStop::new(make_executor());
        assert!(cap.validate_args(&json!({ "service": "apache2" })).is_ok());
    }

    #[test]
    fn service_stop_missing() {
        let cap = ServiceStop::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }

    // ServiceStart
    #[test]
    fn service_start_valid() {
        let cap = ServiceStart::new(make_executor());
        assert!(cap.validate_args(&json!({ "service": "redis" })).is_ok());
    }

    #[test]
    fn service_start_missing() {
        let cap = ServiceStart::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }
}
