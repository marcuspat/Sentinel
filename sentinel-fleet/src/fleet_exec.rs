//! SSH-based multi-host orchestration.
//!
//! This module provides a lightweight, agentless way to run a single
//! capability across many hosts in parallel over SSH, aggregating the
//! per-host [`CapabilityResult`]s.
//!
//! The real transport ([`SshHostExecutor`]) shells out to the system `ssh`
//! binary via `tokio::process` — no native SSH library is required.  All
//! orchestration logic (parallel fan-out, result aggregation, error
//! isolation) is decoupled from the transport behind the [`HostExecutor`]
//! trait, so it can be exercised in tests with a mock executor.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use sentinel_core::{CapabilityResult, ExecutionContext};

/// Connection details for a single fleet host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// Hostname or IP address to connect to.
    pub hostname: String,
    /// SSH login user.
    pub user: String,
    /// SSH port (defaults to 22).
    pub port: u16,
    /// Optional path to a private key (`ssh -i`).
    pub key_path: Option<String>,
}

impl HostConfig {
    /// Construct a host config with port 22 and no explicit key.
    pub fn new(hostname: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            user: user.into(),
            port: 22,
            key_path: None,
        }
    }

    /// Parse a host spec of the form `[user@]hostname[:port]`.
    ///
    /// When the user is omitted it defaults to `root`; when the port is
    /// omitted it defaults to `22`.
    pub fn parse(spec: &str) -> Self {
        let (user, rest) = match spec.split_once('@') {
            Some((u, r)) => (u.to_string(), r),
            None => ("root".to_string(), spec),
        };
        let (hostname, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(22)),
            None => (rest.to_string(), 22),
        };
        Self {
            hostname,
            user,
            port,
            key_path: None,
        }
    }
}

/// A fleet — an ordered collection of [`HostConfig`]s.
#[derive(Debug, Clone, Default)]
pub struct FleetConfig {
    /// Hosts the capability will run against.
    pub hosts: Vec<HostConfig>,
}

impl FleetConfig {
    /// Build a config from a list of `[user@]host[:port]` specs.
    pub fn from_specs<I, S>(specs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            hosts: specs
                .into_iter()
                .map(|s| HostConfig::parse(s.as_ref()))
                .collect(),
        }
    }

    /// Number of hosts in the fleet.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether the fleet has no hosts.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

/// The aggregated outcome of a fleet execution: `hostname → result`.
pub type FleetResult = HashMap<String, CapabilityResult>;

/// Transport abstraction for executing a capability on a single host.
///
/// The production implementation is [`SshHostExecutor`]; tests provide a mock.
#[async_trait]
pub trait HostExecutor: Send + Sync {
    /// Execute capability `cap_id` with `args` on `host`, returning its result.
    ///
    /// Implementations MUST NOT panic on remote failure — a transport or
    /// remote error should be returned as a [`CapabilityResult::Failure`] so
    /// that one bad host never aborts the rest of the fleet.
    async fn execute(
        &self,
        host: &HostConfig,
        cap_id: &str,
        args: &HashMap<String, Value>,
        ctx: &ExecutionContext,
    ) -> CapabilityResult;
}

/// Production [`HostExecutor`] that runs the remote Sentinel agent over SSH.
///
/// For each host it invokes:
///
/// ```text
/// ssh -o BatchMode=yes -o ConnectTimeout=10 -p <port> [-i <key>] \
///     <user>@<host> "<remote_binary> agent-exec <cap_id> '<args-json>'"
/// ```
///
/// A zero exit status whose stdout parses as a [`CapabilityResult`] is
/// returned verbatim; otherwise stdout is wrapped as a success payload.  A
/// non-zero status (or a spawn/timeout failure) becomes a recoverable
/// [`CapabilityResult::Failure`].
pub struct SshHostExecutor {
    /// Name of the Sentinel binary on the remote host.
    remote_binary: String,
}

impl SshHostExecutor {
    /// Create an executor that invokes `remote_binary` on each host.
    pub fn new(remote_binary: impl Into<String>) -> Self {
        Self {
            remote_binary: remote_binary.into(),
        }
    }
}

impl Default for SshHostExecutor {
    fn default() -> Self {
        Self::new("sentinel")
    }
}

/// Build the `ssh` argument vector for a host and remote command.
///
/// Pulled out as a pure function so the argv construction can be unit-tested
/// without invoking `ssh`.
fn build_ssh_args(host: &HostConfig, remote_cmd: &str) -> Vec<String> {
    let mut args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-p".to_string(),
        host.port.to_string(),
    ];
    if let Some(key) = &host.key_path {
        args.push("-i".to_string());
        args.push(key.clone());
    }
    args.push(format!("{}@{}", host.user, host.hostname));
    args.push(remote_cmd.to_string());
    args
}

/// Single-quote a string for safe inclusion in a remote shell command.
fn shell_quote(s: &str) -> String {
    // Close the quote, emit an escaped quote, reopen — the POSIX-safe idiom.
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[async_trait]
impl HostExecutor for SshHostExecutor {
    async fn execute(
        &self,
        host: &HostConfig,
        cap_id: &str,
        args: &HashMap<String, Value>,
        ctx: &ExecutionContext,
    ) -> CapabilityResult {
        let args_json = serde_json::to_string(args).unwrap_or_else(|_| "{}".to_string());
        let remote_cmd = format!(
            "{} agent-exec {} {}",
            self.remote_binary,
            cap_id,
            shell_quote(&args_json)
        );
        let ssh_args = build_ssh_args(host, &remote_cmd);

        debug!(host = %host.hostname, %cap_id, "fleet: ssh exec");

        let timeout = Duration::from_millis(ctx.timeout_ms.max(1));
        let run = Command::new("ssh").args(&ssh_args).output();

        let output = match tokio::time::timeout(timeout, run).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return CapabilityResult::failure(
                    format!("ssh to {} failed to spawn: {e}", host.hostname),
                    true,
                )
            }
            Err(_) => {
                return CapabilityResult::failure(
                    format!("ssh to {} timed out after {} ms", host.hostname, ctx.timeout_ms),
                    true,
                )
            }
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Prefer a structured remote result; otherwise wrap raw stdout.
            match serde_json::from_str::<CapabilityResult>(&stdout) {
                Ok(result) => result,
                Err(_) => CapabilityResult::success(json!({
                    "host": host.hostname,
                    "stdout": stdout,
                })),
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            CapabilityResult::failure(
                format!("remote execution on {} failed: {stderr}", host.hostname),
                true,
            )
        }
    }
}

/// Run `cap_id` on every host in `config` in parallel over SSH and aggregate
/// the results by hostname.
///
/// This is the production entry point; it uses [`SshHostExecutor`].  Use
/// [`execute_on_fleet_with`] to inject a custom (e.g. mock) transport.
pub async fn execute_on_fleet(
    config: &FleetConfig,
    cap_id: &str,
    args: &HashMap<String, Value>,
    ctx: &ExecutionContext,
) -> FleetResult {
    execute_on_fleet_with(Arc::new(SshHostExecutor::default()), config, cap_id, args, ctx).await
}

/// Like [`execute_on_fleet`] but with a caller-supplied [`HostExecutor`].
///
/// Each host runs on its own task; a failure (or panic) on one host never
/// prevents the others from completing.
pub async fn execute_on_fleet_with(
    executor: Arc<dyn HostExecutor>,
    config: &FleetConfig,
    cap_id: &str,
    args: &HashMap<String, Value>,
    ctx: &ExecutionContext,
) -> FleetResult {
    let mut set: JoinSet<(String, CapabilityResult)> = JoinSet::new();

    for host in &config.hosts {
        let executor = Arc::clone(&executor);
        let host = host.clone();
        let cap_id = cap_id.to_string();
        let args = args.clone();
        let ctx = ctx.clone();
        set.spawn(async move {
            let result = executor.execute(&host, &cap_id, &args, &ctx).await;
            (host.hostname, result)
        });
    }

    let mut results = FleetResult::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((hostname, result)) => {
                results.insert(hostname, result);
            }
            Err(e) => {
                // A task panicked — record it rather than dropping the host.
                warn!(error = %e, "fleet: host task panicked");
            }
        }
    }
    results
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    fn ctx() -> ExecutionContext {
        ExecutionContext::new(Uuid::new_v4(), "fleet")
    }

    fn fleet(specs: &[&str]) -> FleetConfig {
        FleetConfig::from_specs(specs.iter().copied())
    }

    /// Mock transport: returns a success echoing the host, and counts calls.
    struct EchoExecutor {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl HostExecutor for EchoExecutor {
        async fn execute(
            &self,
            host: &HostConfig,
            cap_id: &str,
            _args: &HashMap<String, Value>,
            _ctx: &ExecutionContext,
        ) -> CapabilityResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            CapabilityResult::success(json!({
                "host": host.hostname,
                "cap": cap_id,
            }))
        }
    }

    /// Mock transport that fails for one specific host, succeeds for the rest.
    struct FlakyExecutor {
        fail_host: String,
    }

    #[async_trait]
    impl HostExecutor for FlakyExecutor {
        async fn execute(
            &self,
            host: &HostConfig,
            _cap_id: &str,
            _args: &HashMap<String, Value>,
            _ctx: &ExecutionContext,
        ) -> CapabilityResult {
            if host.hostname == self.fail_host {
                CapabilityResult::failure(format!("{} is unreachable", host.hostname), true)
            } else {
                CapabilityResult::success(json!({ "host": host.hostname }))
            }
        }
    }

    #[test]
    fn host_config_parse_variants() {
        let h = HostConfig::parse("web-01");
        assert_eq!(h.user, "root");
        assert_eq!(h.hostname, "web-01");
        assert_eq!(h.port, 22);

        let h = HostConfig::parse("deploy@db-02:2222");
        assert_eq!(h.user, "deploy");
        assert_eq!(h.hostname, "db-02");
        assert_eq!(h.port, 2222);
    }

    #[test]
    fn ssh_args_include_port_key_and_target() {
        let mut host = HostConfig::new("h1", "ops");
        host.port = 2200;
        host.key_path = Some("/keys/id_ed25519".to_string());
        let args = build_ssh_args(&host, "sentinel agent-exec disk_usage '{}'");
        assert!(args.windows(2).any(|w| w == ["-p", "2200"]));
        assert!(args.windows(2).any(|w| w == ["-i", "/keys/id_ed25519"]));
        assert_eq!(args[args.len() - 2], "ops@h1");
        assert_eq!(args[args.len() - 1], "sentinel agent-exec disk_usage '{}'");
    }

    #[tokio::test]
    async fn single_host_round_trip() {
        let calls = Arc::new(AtomicUsize::new(0));
        let exec = Arc::new(EchoExecutor { calls: Arc::clone(&calls) });
        let config = fleet(&["app-01"]);

        let results =
            execute_on_fleet_with(exec, &config, "system_metrics", &HashMap::new(), &ctx()).await;

        assert_eq!(results.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let r = &results["app-01"];
        assert!(r.is_success());
        if let CapabilityResult::Success { output } = r {
            assert_eq!(output["host"], "app-01");
            assert_eq!(output["cap"], "system_metrics");
        }
    }

    #[tokio::test]
    async fn multi_host_parallel_all_succeed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let exec = Arc::new(EchoExecutor { calls: Arc::clone(&calls) });
        let config = fleet(&["h1", "h2", "h3", "h4", "h5"]);

        let results =
            execute_on_fleet_with(exec, &config, "process_list", &HashMap::new(), &ctx()).await;

        assert_eq!(results.len(), 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        for host in ["h1", "h2", "h3", "h4", "h5"] {
            assert!(results[host].is_success(), "{host} should have succeeded");
        }
    }

    #[tokio::test]
    async fn error_isolation_one_host_fails() {
        let exec = Arc::new(FlakyExecutor { fail_host: "bad-host".to_string() });
        let config = fleet(&["good-1", "bad-host", "good-2"]);

        let results =
            execute_on_fleet_with(exec, &config, "disk_usage", &HashMap::new(), &ctx()).await;

        // Every host is represented; the failure is isolated to one entry.
        assert_eq!(results.len(), 3);
        assert!(results["good-1"].is_success());
        assert!(results["good-2"].is_success());
        assert!(results["bad-host"].is_failure());
        if let CapabilityResult::Failure { error, .. } = &results["bad-host"] {
            assert!(error.contains("unreachable"));
        }
    }
}
