//! Async timeout guard that ensures child-process cleanup on deadline.
//!
//! When the deadline expires the guard sends SIGTERM and, after a 2-second
//! grace period, SIGKILL.  This guarantees that no zombie is left behind
//! even if the child ignores SIGTERM.

use std::process::ExitStatus;
use tokio::process::Child;
use tokio::time::{Duration, Instant};

use crate::error::ExecError;

/// Two-second grace period between SIGTERM and SIGKILL.
const SIGTERM_GRACE_MS: u64 = 2_000;

/// Wraps a spawned child and enforces a wall-clock deadline.
pub struct TimeoutGuard {
    child: Child,
    deadline: Instant,
    timeout_ms: u64,
}

impl TimeoutGuard {
    /// Create a new guard.  The deadline is `now + timeout_ms`.
    pub fn new(child: Child, timeout_ms: u64) -> Self {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        Self {
            child,
            deadline,
            timeout_ms,
        }
    }

    /// Wait for the child process, enforcing the deadline.
    ///
    /// On timeout:
    /// 1. Send SIGTERM.
    /// 2. Wait up to 2 seconds for graceful exit.
    /// 3. Send SIGKILL and wait for the process to be reaped.
    ///
    /// Returns `(exit_status, timed_out)`.
    pub async fn wait_with_timeout(mut self) -> Result<(ExitStatus, bool), ExecError> {
        let now = Instant::now();
        let remaining = self.deadline.saturating_duration_since(now);

        match tokio::time::timeout(remaining, self.child.wait()).await {
            Ok(Ok(status)) => Ok((status, false)),
            Ok(Err(e)) => Err(ExecError::Io(e)),
            Err(_elapsed) => {
                // Deadline exceeded — terminate the child gracefully.
                self.terminate_child().await?;
                Err(ExecError::Timeout {
                    ms: self.timeout_ms,
                })
            }
        }
    }

    /// Attempt graceful termination (SIGTERM → wait 2 s → SIGKILL).
    async fn terminate_child(&mut self) -> Result<(), ExecError> {
        // Obtain the PID while the child is still alive.
        let pid = match self.child.id() {
            Some(p) => p,
            // Process already exited on its own — nothing to do.
            None => return Ok(()),
        };

        // Send SIGTERM.
        send_signal(pid, nix::sys::signal::Signal::SIGTERM)?;

        // Wait for the grace period.
        let grace = Duration::from_millis(SIGTERM_GRACE_MS);
        match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(Ok(_)) => {
                // Child exited during the grace window.
                return Ok(());
            }
            Ok(Err(e)) => return Err(ExecError::Io(e)),
            Err(_) => {
                // Grace period elapsed — escalate to SIGKILL.
            }
        }

        // Send SIGKILL.  The PID might now be invalid if the process exited
        // between the timeout and here; ignore ESRCH in that case.
        match send_signal(pid, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) | Err(ExecError::Signal(_)) => {}
            Err(e) => return Err(e),
        }

        // Reap the child to avoid zombies.
        let _ = self.child.wait().await;

        Ok(())
    }
}

/// Send `signal` to the process with the given PID.
fn send_signal(pid: u32, signal: nix::sys::signal::Signal) -> Result<(), ExecError> {
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as nix::libc::pid_t);
    nix::sys::signal::kill(nix_pid, signal).map_err(|e| ExecError::Signal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::process::Command;

    #[tokio::test]
    async fn completes_before_timeout() {
        let child = Command::new("true")
            .spawn()
            .expect("spawn true");
        let guard = TimeoutGuard::new(child, 5_000);
        let (status, timed_out) = guard.wait_with_timeout().await.expect("wait failed");
        assert!(status.success());
        assert!(!timed_out);
    }

    #[tokio::test]
    async fn timeout_kills_long_running_process() {
        let child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let guard = TimeoutGuard::new(child, 100); // 100 ms timeout
        let result = guard.wait_with_timeout().await;
        match result {
            Err(ExecError::Timeout { ms }) => assert_eq!(ms, 100),
            other => panic!("expected Timeout, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fast_process_not_timed_out() {
        let child = Command::new("echo")
            .arg("hello")
            .spawn()
            .expect("spawn echo");
        let guard = TimeoutGuard::new(child, 10_000);
        let (status, timed_out) = guard.wait_with_timeout().await.expect("wait");
        assert!(status.success());
        assert!(!timed_out);
    }
}
