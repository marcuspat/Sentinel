//! Core command executor with allowlist enforcement, sandboxing, timeouts,
//! and bounded output capture.
//!
//! This module exposes two related APIs:
//!
//! * The **trait-based** `CommandExecutorTrait` / `RealCommandExecutor` pair,
//!   intended for unit-testing via mock injection.
//! * The **struct-based** `CommandExecutor` that accepts an [`ExecutionContext`]
//!   and enforces all resource constraints end-to-end.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::Instant;
use tracing::{debug, warn};

use sentinel_core::ExecutionContext;

use crate::error::ExecError;
use crate::output_capture::OutputCapture;
use crate::sandbox::{apply_sandbox, SandboxConfig};
use crate::timeout_guard::TimeoutGuard;

// ─────────────────────────────────────────────────────────────────────────────
// Low-level trait-based API (kept for mock-injection in tests)
// ─────────────────────────────────────────────────────────────────────────────

/// The captured output from a completed process invocation.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// The process exit code.  `None` if the process was killed by a signal.
    pub exit_code: Option<i32>,
    /// Captured standard output (possibly truncated).
    pub stdout: String,
    /// Captured standard error (possibly truncated).
    pub stderr: String,
    /// `true` when either stream was truncated due to the output-byte limit.
    pub truncated: bool,
}

impl CommandOutput {
    /// `true` when the process exited with code 0.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Trait that abstracts over "run a command and return its output".
///
/// The primary implementation is [`RealCommandExecutor`].  Tests may provide a
/// mock implementation.
#[async_trait]
pub trait CommandExecutorTrait: Send + Sync {
    /// Run `program` with `args`, optional env overrides, and a byte limit on
    /// captured output.  Returns the exit code and captured stdio.
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        env: &HashMap<String, String>,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, ExecError>;
}

/// The real low-level executor that spawns OS processes via `tokio::process`.
///
/// This is the *thin* implementation used when callers manage timeouts and
/// sandboxing themselves.  For full constraint enforcement, use
/// [`CommandExecutor`] instead.
pub struct RealCommandExecutor;

#[async_trait]
impl CommandExecutorTrait for RealCommandExecutor {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        env: &HashMap<String, String>,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, ExecError> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .envs(env)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| ExecError::SpawnFailed(e.to_string()))?;

        let stdout_pipe = child
            .stdout
            .take()
            .ok_or_else(|| ExecError::SpawnFailed("failed to capture stdout".into()))?;
        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| ExecError::SpawnFailed("failed to capture stderr".into()))?;

        let capture = OutputCapture::new(max_output_bytes);
        let (stdout, stderr, truncated) = capture.capture(stdout_pipe, stderr_pipe).await;

        let status = child.wait().await.map_err(ExecError::Io)?;

        Ok(CommandOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            truncated,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level struct-based API (full constraint enforcement)
// ─────────────────────────────────────────────────────────────────────────────

/// Executor-wide configuration.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Default timeout in milliseconds, used when `ExecutionContext.timeout_ms`
    /// is zero.
    pub default_timeout_ms: u64,
    /// Maximum number of bytes to keep from stdout + stderr combined.
    pub max_output_bytes: usize,
    /// Explicit command allowlist.  `None` means **deny all** (safe default).
    /// Supply `Some(set)` to permit specific commands.
    pub allowed_commands: Option<HashSet<String>>,
    /// Override working directory for every spawned child.  When `None` the
    /// directory from `ExecutionContext.working_dir` is used if present.
    pub working_dir: Option<PathBuf>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30_000,
            max_output_bytes: 1024 * 1024, // 1 MiB
            allowed_commands: None,        // deny-all by default
            working_dir: None,
        }
    }
}

/// Detailed outcome of a command execution.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Process exit code (0 typically means success).
    pub exit_code: i32,
    /// Captured standard output (possibly truncated).
    pub stdout: String,
    /// Captured standard error (possibly truncated).
    pub stderr: String,
    /// Wall-clock time in milliseconds from spawn to reap.
    pub duration_ms: u64,
    /// `true` when the process was killed because it exceeded its time budget.
    pub timed_out: bool,
    /// `true` when at least one stream was truncated due to the output limit.
    pub truncated: bool,
}

/// Result of a dry-run validation check.
#[derive(Debug, Clone)]
pub struct DryRunResult {
    /// `true` when the command is in the allowlist and args look well-formed.
    pub valid: bool,
    /// Human-readable explanation of any validation failure.
    pub message: String,
}

/// Constrained subprocess executor.
///
/// Create one `CommandExecutor` per agent session and reuse it for all
/// capability invocations.
#[derive(Debug, Clone)]
pub struct CommandExecutor {
    config: ExecutorConfig,
}

impl CommandExecutor {
    /// Create a new executor with the given configuration.
    pub fn new(config: ExecutorConfig) -> Self {
        Self { config }
    }

    /// Execute `command` with `args` under the constraints in `ctx`.
    ///
    /// Steps performed:
    /// 1. Check command against the allowlist (if configured).
    /// 2. Build the `tokio::process::Command` without any shell expansion.
    /// 3. Apply sandbox rlimits via [`apply_sandbox`].
    /// 4. Spawn the child.
    /// 5. Read stdout and stderr concurrently, bounded by `max_output_bytes`.
    /// 6. Enforce the timeout; on expiry SIGTERM then SIGKILL the child.
    /// 7. Return a full [`ExecutionResult`].
    pub async fn execute(
        &self,
        command: &str,
        args: &[&str],
        ctx: &ExecutionContext,
    ) -> Result<ExecutionResult, ExecError> {
        // ── 1. Allowlist check ───────────────────────────────────────────────
        self.check_allowlist(command)?;

        // ── 2. Determine timeout ────────────────────────────────────────────
        let timeout_ms = if ctx.timeout_ms > 0 {
            ctx.timeout_ms
        } else {
            self.config.default_timeout_ms
        };

        debug!(command, ?args, timeout_ms, "executing command");

        // ── 3. Build Command (no shell expansion) ────────────────────────────
        let mut cmd = Command::new(command);
        cmd.args(args);

        // Environment overrides from context.
        for (k, v) in &ctx.env_overrides {
            cmd.env(k, v);
        }

        // Working directory: config override takes precedence, then context.
        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        } else if let Some(dir) = &ctx.working_dir {
            cmd.current_dir(dir);
        }

        // Pipe stdout and stderr so we can capture them.
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // Detach stdin so the child cannot block waiting for input.
        cmd.stdin(std::process::Stdio::null());

        // ── 4. Apply sandbox ─────────────────────────────────────────────────
        let sandbox = SandboxConfig::default();
        apply_sandbox(&mut cmd, &sandbox);

        // ── 5. Spawn ─────────────────────────────────────────────────────────
        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| ExecError::SpawnFailed(e.to_string()))?;

        // Take the stdio handles before handing the child to the guard.
        let stdout_handle = child
            .stdout
            .take()
            .expect("stdout was piped but not available");
        let stderr_handle = child
            .stderr
            .take()
            .expect("stderr was piped but not available");

        // ── 6. Determine output byte limit ───────────────────────────────────
        let max_bytes = self
            .config
            .max_output_bytes
            .min(ctx.resource_limits.max_output_bytes);

        let capture = OutputCapture::new(max_bytes);
        let guard = TimeoutGuard::new(child, timeout_ms);

        // Run output capture and process wait concurrently.
        let capture_fut = capture.capture(stdout_handle, stderr_handle);
        let wait_fut = guard.wait_with_timeout();

        let ((stdout, stderr, truncated), wait_result) =
            tokio::join!(capture_fut, wait_fut);

        let duration_ms = start.elapsed().as_millis() as u64;

        // ── 7. Evaluate result ────────────────────────────────────────────────
        let (exit_status, timed_out) = match wait_result {
            Ok(pair) => pair,
            Err(ExecError::Timeout { ms }) => {
                warn!(command, ms, "command timed out");
                return Err(ExecError::Timeout { ms });
            }
            Err(e) => return Err(e),
        };

        let exit_code = exit_status.code().unwrap_or(-1);

        debug!(
            command,
            exit_code,
            duration_ms,
            truncated,
            "command completed"
        );

        Ok(ExecutionResult {
            exit_code,
            stdout,
            stderr,
            duration_ms,
            timed_out,
            truncated,
        })
    }

    /// Validate `command` and `args` without executing anything.
    ///
    /// Returns a [`DryRunResult`] describing whether the invocation would be
    /// accepted by this executor.
    pub fn dry_run_validate(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<DryRunResult, ExecError> {
        match self.check_allowlist(command) {
            Ok(()) => {
                let message = format!(
                    "Command '{}' with {} arg(s) is permitted",
                    command,
                    args.len()
                );
                Ok(DryRunResult {
                    valid: true,
                    message,
                })
            }
            Err(ExecError::NotAllowed(cmd)) => Ok(DryRunResult {
                valid: false,
                message: format!("Command '{}' is not in the allowlist", cmd),
            }),
            Err(e) => Err(e),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn check_allowlist(&self, command: &str) -> Result<(), ExecError> {
        match &self.config.allowed_commands {
            // `None` means deny all.
            None => Err(ExecError::NotAllowed(command.to_string())),
            Some(set) => {
                if set.contains(command) {
                    Ok(())
                } else {
                    Err(ExecError::NotAllowed(command.to_string()))
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::ExecutionContext;
    use uuid::Uuid;

    fn make_ctx() -> ExecutionContext {
        ExecutionContext::new(Uuid::new_v4(), "localhost")
    }

    fn allow(cmds: &[&str]) -> ExecutorConfig {
        let mut set = HashSet::new();
        for c in cmds {
            set.insert(c.to_string());
        }
        ExecutorConfig {
            allowed_commands: Some(set),
            ..Default::default()
        }
    }

    // ── Allowlist enforcement ─────────────────────────────────────────────────

    #[test]
    fn deny_all_when_no_allowlist() {
        let exec = CommandExecutor::new(ExecutorConfig::default());
        let result = exec.dry_run_validate("echo", &["hello"]).unwrap();
        assert!(!result.valid);
        assert!(result.message.contains("echo"));
    }

    #[test]
    fn allows_listed_command() {
        let exec = CommandExecutor::new(allow(&["echo"]));
        let result = exec.dry_run_validate("echo", &["hello"]).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn denies_unlisted_command() {
        let exec = CommandExecutor::new(allow(&["echo"]));
        let result = exec.dry_run_validate("rm", &["-rf", "/"]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn basename_does_not_bypass_allowlist() {
        // "/usr/bin/echo" must NOT match an allowlist entry of "echo".
        let exec = CommandExecutor::new(allow(&["echo"]));
        let result = exec.dry_run_validate("/usr/bin/echo", &[]).unwrap();
        assert!(!result.valid, "full path should not match bare basename in allowlist");

        // Only the exact string is matched.
        let exec2 = CommandExecutor::new(allow(&["/usr/bin/echo"]));
        let result2 = exec2.dry_run_validate("/usr/bin/echo", &[]).unwrap();
        assert!(result2.valid, "exact full path should be allowed");
    }

    #[test]
    fn dry_run_reports_arg_count() {
        let exec = CommandExecutor::new(allow(&["ls"]));
        let result = exec.dry_run_validate("ls", &["-la", "/tmp"]).unwrap();
        assert!(result.valid);
        assert!(result.message.contains("2"));
    }

    // ── Successful execution ──────────────────────────────────────────────────

    #[tokio::test]
    async fn executes_echo_command() {
        let exec = CommandExecutor::new(allow(&["echo"]));
        let ctx = make_ctx();
        let result = exec
            .execute("echo", &["sentinel", "test"], &ctx)
            .await
            .expect("execute failed");
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("sentinel"));
        assert!(!result.timed_out);
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn captures_stderr() {
        let exec = CommandExecutor::new(allow(&["sh"]));
        let ctx = make_ctx();
        let result = exec
            .execute("sh", &["-c", "echo error_msg >&2"], &ctx)
            .await
            .expect("execute failed");
        assert_eq!(result.exit_code, 0);
        assert!(result.stderr.contains("error_msg"));
    }

    #[tokio::test]
    async fn non_zero_exit_code_returned() {
        let exec = CommandExecutor::new(allow(&["sh"]));
        let ctx = make_ctx();
        let result = exec
            .execute("sh", &["-c", "exit 42"], &ctx)
            .await
            .expect("execute failed");
        assert_eq!(result.exit_code, 42);
    }

    // ── Timeout enforcement ───────────────────────────────────────────────────

    #[tokio::test]
    async fn returns_timeout_error_for_slow_process() {
        let exec = CommandExecutor::new(allow(&["sleep"]));
        let ctx = make_ctx().with_timeout_ms(100); // 100 ms
        let result = exec.execute("sleep", &["60"], &ctx).await;
        match result {
            Err(ExecError::Timeout { ms }) => assert_eq!(ms, 100),
            other => panic!("expected Timeout, got {:?}", other),
        }
    }

    // ── Output truncation ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn truncates_large_output() {
        let exec = CommandExecutor::new(ExecutorConfig {
            allowed_commands: Some(["sh"].iter().map(|s| s.to_string()).collect()),
            max_output_bytes: 20, // very small limit
            ..Default::default()
        });
        let ctx = make_ctx();
        // Generate considerably more than 20 bytes of output.
        let result = exec
            .execute(
                "sh",
                &["-c", "python3 -c \"print('x' * 200)\" 2>/dev/null || printf '%200s' '' | tr ' ' 'x'"],
                &ctx,
            )
            .await
            .expect("execute failed");
        assert!(result.truncated, "output should have been truncated");
        assert!(result.stdout.contains("[...output truncated...]"));
    }

    // ── NotAllowed error ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn execute_returns_not_allowed_error() {
        let exec = CommandExecutor::new(ExecutorConfig::default()); // deny all
        let ctx = make_ctx();
        let result = exec.execute("bash", &[], &ctx).await;
        assert!(matches!(result, Err(ExecError::NotAllowed(_))));
    }

    // ── Environment overrides ─────────────────────────────────────────────────

    #[tokio::test]
    async fn env_override_is_passed_to_child() {
        let exec = CommandExecutor::new(allow(&["sh"]));
        let ctx = make_ctx().with_env("SENTINEL_TEST_VAR", "hello_sentinel");
        let result = exec
            .execute("sh", &["-c", "echo $SENTINEL_TEST_VAR"], &ctx)
            .await
            .expect("execute failed");
        assert!(result.stdout.contains("hello_sentinel"));
    }

    // ── Working directory ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn working_dir_from_context() {
        let exec = CommandExecutor::new(allow(&["pwd"]));
        let ctx = make_ctx().with_working_dir("/tmp");
        let result = exec
            .execute("pwd", &[], &ctx)
            .await
            .expect("execute failed");
        // /tmp may be a symlink on some systems; check prefix
        assert!(
            result.stdout.trim() == "/tmp" || result.stdout.trim().starts_with("/tmp"),
            "unexpected pwd output: {}",
            result.stdout
        );
    }

    // ── Duration is populated ─────────────────────────────────────────────────

    #[tokio::test]
    async fn duration_ms_is_populated() {
        let exec = CommandExecutor::new(allow(&["true"]));
        let ctx = make_ctx();
        let result = exec.execute("true", &[], &ctx).await.expect("execute");
        assert!(result.duration_ms < 60_000, "duration too large: {}ms", result.duration_ms);
    }

    // ── RealCommandExecutor (low-level trait) ─────────────────────────────────

    #[tokio::test]
    async fn real_executor_runs_echo() {
        let exec = RealCommandExecutor;
        let env = HashMap::new();
        let out = exec
            .run("echo", &["trait_test"], &env, 1024)
            .await
            .expect("run failed");
        assert!(out.success());
        assert!(out.stdout.contains("trait_test"));
        assert!(!out.truncated);
    }

    #[tokio::test]
    async fn real_executor_captures_stderr() {
        let exec = RealCommandExecutor;
        let env = HashMap::new();
        let out = exec
            .run("sh", &["-c", "echo err_trait >&2"], &env, 1024)
            .await
            .expect("run failed");
        assert!(out.stderr.contains("err_trait"));
    }
}
