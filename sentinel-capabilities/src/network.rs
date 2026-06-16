use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use sentinel_core::{
    capability::ResourceImpact, Capability, CapabilityKind, CapabilityManifest, CapabilityResult,
    CoreError, ExecutionContext, RiskTier,
};
use sentinel_exec::CommandExecutorTrait;

// ─── NetworkConnections ──────────────────────────────────────────────────────

pub struct NetworkConnections {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl NetworkConnections {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "network_connections".into(),
                name: "Network Connections".into(),
                description: "Lists active network connections using ss or netstat.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: ResourceImpact {
                    network_required: true,
                    ..Default::default()
                },
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }

    fn parse_connection_line(line: &str) -> Value {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            json!({
                "proto":   parts[0],
                "state":   parts.get(1).copied().unwrap_or(""),
                "local":   parts.get(4).copied().unwrap_or(""),
                "foreign": parts.get(5).copied().unwrap_or(""),
                "raw":     line
            })
        } else {
            json!({ "raw": line })
        }
    }
}

#[async_trait]
impl Capability for NetworkConnections {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        if let Some(state) = args.get("state") {
            if !state.is_string() {
                return Err(CoreError::InvalidArgs("'state' must be a string".into()));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let state_filter = args.get("state").and_then(Value::as_str);

        let tool = if let Ok(out) =
            self.executor.run("which", &["ss"], &ctx.env_overrides, 4096).await
        {
            if out.success() { "ss" } else { "netstat" }
        } else {
            "netstat"
        };

        debug!("NetworkConnections: using {}", tool);
        let out = match self
            .executor
            .run(tool, &["-tuln"], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        let connections: Vec<Value> = out
            .stdout
            .lines()
            .skip(1)
            .filter(|line| {
                if let Some(s) = state_filter {
                    line.to_uppercase().contains(&s.to_uppercase())
                } else {
                    true
                }
            })
            .map(Self::parse_connection_line)
            .collect();

        let count = connections.len();
        CapabilityResult::success(json!({
            "tool": tool, "connections": connections, "count": count
        }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        CapabilityResult::dry_run(json!({
            "predicted_structure": {
                "tool": "ss",
                "connections": [
                    { "proto": "tcp", "state": "LISTEN",      "local": "0.0.0.0:22",      "foreign": "0.0.0.0:*" },
                    { "proto": "tcp", "state": "ESTABLISHED", "local": "192.168.1.1:22",   "foreign": "10.0.0.1:54321" }
                ],
                "count": 2
            },
            "note": "Dry-run: no commands executed"
        }))
    }
}

// ─── NetworkInterfaces ───────────────────────────────────────────────────────

pub struct NetworkInterfaces {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl NetworkInterfaces {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "network_interfaces".into(),
                name: "Network Interfaces".into(),
                description: "Lists network interfaces with their addresses and state.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: ResourceImpact {
                    network_required: true,
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
impl Capability for NetworkInterfaces {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, _args: &Value) -> Result<(), CoreError> {
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }

        let (tool, tool_args): (&str, &[&str]) =
            if let Ok(out) = self.executor.run("which", &["ip"], &ctx.env_overrides, 4096).await {
                if out.success() { ("ip", &["addr"]) } else { ("ifconfig", &["-a"]) }
            } else {
                ("ifconfig", &["-a"])
            };

        debug!("NetworkInterfaces: using {}", tool);
        let out = match self
            .executor
            .run(tool, tool_args, &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        let interfaces: Vec<Value> = out
            .stdout
            .split('\n')
            .fold(Vec::<(String, Vec<String>)>::new(), |mut acc, line| {
                if line.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    let name = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    acc.push((name, vec![line.to_string()]));
                } else if let Some(last) = acc.last_mut() {
                    last.1.push(line.to_string());
                }
                acc
            })
            .into_iter()
            .map(|(name, lines)| {
                let full = lines.join("\n");
                let state = if full.contains("state UP") {
                    "UP"
                } else if full.contains("state DOWN") {
                    "DOWN"
                } else {
                    "UNKNOWN"
                };
                let addresses: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.trim().starts_with("inet"))
                    .map(|l| l.trim())
                    .collect();
                json!({ "name": name, "state": state, "addresses": addresses })
            })
            .collect();

        CapabilityResult::success(json!({ "tool": tool, "interfaces": interfaces }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        CapabilityResult::dry_run(json!({
            "predicted_structure": {
                "tool": "ip",
                "interfaces": [
                    { "name": "lo",   "state": "UNKNOWN", "addresses": ["inet 127.0.0.1/8"] },
                    { "name": "eth0", "state": "UP",      "addresses": ["inet 192.168.1.10/24"] }
                ]
            },
            "note": "Dry-run: no commands executed"
        }))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use sentinel_exec::{CommandExecutorTrait, CommandOutput};
    use uuid::Uuid;

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

    /// Mock executor that records each invocation and returns canned stdout
    /// per program (always exit 0). Lets us drive `invoke()` without the OS.
    struct MockExecutor {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self { calls: Mutex::new(Vec::new()) })
        }
    }

    #[async_trait::async_trait]
    impl CommandExecutorTrait for MockExecutor {
        async fn run(
            &self,
            program: &str,
            args: &[&str],
            _env: &HashMap<String, String>,
            _max_output_bytes: usize,
        ) -> Result<CommandOutput, sentinel_exec::ExecError> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));

            let stdout = match program {
                // `which <tool>` succeeds → primary tool (ss / ip) is selected.
                "which" => "/usr/bin/tool\n",
                "ss" => {
                    "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n\
                     tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*\n\
                     tcp   ESTAB  0      0      192.168.1.1:22     10.0.0.1:54321\n"
                }
                "netstat" => "Proto Recv-Q Send-Q Local Address Foreign Address State\n",
                "ip" => {
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n    \
                     inet 127.0.0.1/8 scope host lo\n\
                     2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    \
                     inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
                }
                "ifconfig" => "",
                _ => "",
            };

            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: stdout.to_string(),
                stderr: String::new(),
                truncated: false,
            })
        }
    }

    fn ctx() -> ExecutionContext {
        ExecutionContext::new(Uuid::new_v4(), "localhost")
    }

    #[tokio::test]
    async fn network_connections_invoke_parses_ss_output() {
        let exec = MockExecutor::new();
        let cap = NetworkConnections::new(Arc::clone(&exec) as Arc<dyn CommandExecutorTrait>);

        let result = cap.invoke(json!({}), &ctx()).await;
        assert!(result.is_success());
        if let CapabilityResult::Success { output } = result {
            assert_eq!(output["tool"], "ss");
            // Two data lines (header skipped) → two connections.
            assert_eq!(output["count"], 2);
            assert_eq!(output["connections"][0]["proto"], "tcp");
            assert_eq!(output["connections"][0]["state"], "LISTEN");
        }

        // Verify it actually shelled out to `ss -tuln` (no shell, explicit args).
        let calls = exec.calls.lock().unwrap();
        assert!(calls.iter().any(|(p, a)| p == "ss" && a == &["-tuln"]));
    }

    #[tokio::test]
    async fn network_connections_invoke_state_filter() {
        let exec = MockExecutor::new();
        let cap = NetworkConnections::new(exec as Arc<dyn CommandExecutorTrait>);

        let result = cap.invoke(json!({ "state": "LISTEN" }), &ctx()).await;
        assert!(result.is_success());
        if let CapabilityResult::Success { output } = result {
            // Only the LISTEN line survives the filter.
            assert_eq!(output["count"], 1);
            assert_eq!(output["connections"][0]["state"], "LISTEN");
        }
    }

    #[tokio::test]
    async fn network_interfaces_invoke_parses_ip_output() {
        let exec = MockExecutor::new();
        let cap = NetworkInterfaces::new(Arc::clone(&exec) as Arc<dyn CommandExecutorTrait>);

        let result = cap.invoke(json!({}), &ctx()).await;
        assert!(result.is_success());
        if let CapabilityResult::Success { output } = result {
            assert_eq!(output["tool"], "ip");
            let ifaces = output["interfaces"].as_array().unwrap();
            assert_eq!(ifaces.len(), 2);
            assert_eq!(ifaces[0]["name"], "lo");
            assert_eq!(ifaces[1]["name"], "eth0");
            assert_eq!(ifaces[1]["state"], "UP");
        }

        let calls = exec.calls.lock().unwrap();
        assert!(calls.iter().any(|(p, a)| p == "ip" && a == &["addr"]));
    }

    #[test]
    fn network_connections_no_args() {
        let cap = NetworkConnections::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_ok());
    }

    #[test]
    fn network_connections_with_state() {
        let cap = NetworkConnections::new(make_executor());
        assert!(cap.validate_args(&json!({ "state": "ESTABLISHED" })).is_ok());
    }

    #[test]
    fn network_connections_bad_state_type() {
        let cap = NetworkConnections::new(make_executor());
        assert!(cap.validate_args(&json!({ "state": 42 })).is_err());
    }

    #[test]
    fn network_interfaces_empty_args() {
        let cap = NetworkInterfaces::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_ok());
    }

    #[test]
    fn network_interfaces_extra_args_ok() {
        let cap = NetworkInterfaces::new(make_executor());
        assert!(cap.validate_args(&json!({ "anything": 1 })).is_ok());
    }
}
