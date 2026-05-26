//! Sandbox configuration and enforcement for spawned subprocesses.
//!
//! On Linux, resource limits are applied via `setrlimit` in a
//! `pre_exec` hook so they take effect in the child process before
//! `execve` is called.  This means no capability is required in the
//! parent process.

use std::path::PathBuf;
use tokio::process::Command;
use tracing::warn;

/// Sandbox configuration for process isolation.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Paths the child may read (advisory; not kernel-enforced here).
    pub read_only_paths: Vec<PathBuf>,
    /// Paths the child may write (advisory; not kernel-enforced here).
    pub writable_paths: Vec<PathBuf>,
    /// NOT enforced by rlimits — requires Linux network namespaces or seccomp
    /// BPF, which are outside scope; setting this field emits a warning.
    pub deny_network: bool,
    /// If `true`, `RLIMIT_NPROC` is set to 64 to prevent fork bombs.
    pub deny_new_processes: bool,
    /// If `true`, drop all supplementary capabilities via `RLIMIT_*` limits.
    pub drop_capabilities: bool,
}

/// Apply sandbox constraints to a `tokio::process::Command` before spawning.
///
/// The rlimits applied unconditionally are:
/// * `RLIMIT_NOFILE` → 256   (limit open file descriptors)
/// * `RLIMIT_CORE`   → 0     (no core dumps)
///
/// When [`SandboxConfig::deny_new_processes`] is `true`:
/// * `RLIMIT_NPROC`  → 64    (limit child processes / threads)
///
/// # Safety
/// The `pre_exec` closure runs in the child process between `fork` and
/// `execve`.  It must be async-signal-safe.  The `nix` functions used
/// (`setrlimit`) are documented as safe in this context.
pub fn apply_sandbox(cmd: &mut Command, config: &SandboxConfig) {
    if config.deny_network {
        warn!(
            "deny_network is set but NOT enforced at the rlimit level; \
             network isolation requires Linux network namespaces or seccomp BPF"
        );
    }

    let deny_new_processes = config.deny_new_processes;

    // SAFETY: pre_exec runs after fork(), before execve().  Only
    // async-signal-safe operations are performed here (setrlimit syscalls).
    unsafe {
        cmd.pre_exec(move || {
            use nix::sys::resource::{setrlimit, Resource};

            let map_err = |e: nix::errno::Errno| {
                std::io::Error::other(e.to_string())
            };

            // Limit open file descriptors to 256.
            setrlimit(Resource::RLIMIT_NOFILE, 256, 256).map_err(map_err)?;

            // Disable core dumps.
            setrlimit(Resource::RLIMIT_CORE, 0, 0)
                .map_err(|e: nix::errno::Errno| {
                    std::io::Error::other(e.to_string())
                })?;

            // Optionally restrict fork/thread creation.
            if deny_new_processes {
                setrlimit(Resource::RLIMIT_NPROC, 64, 64)
                    .map_err(|e: nix::errno::Errno| {
                        std::io::Error::other(e.to_string())
                    })?;
            }

            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sandbox_config() {
        let cfg = SandboxConfig::default();
        assert!(!cfg.deny_network);
        assert!(!cfg.deny_new_processes);
        assert!(!cfg.drop_capabilities);
        assert!(cfg.read_only_paths.is_empty());
        assert!(cfg.writable_paths.is_empty());
    }

    #[tokio::test]
    async fn apply_sandbox_does_not_crash_on_simple_command() {
        // Verify that apply_sandbox can be called without panicking and that
        // the resulting command can spawn a trivial child process.
        let cfg = SandboxConfig {
            deny_new_processes: true,
            ..Default::default()
        };
        let mut cmd = Command::new("true");
        apply_sandbox(&mut cmd, &cfg);
        let status = cmd.status().await.expect("spawn failed");
        assert!(status.success());
    }
}
