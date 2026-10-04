//! `sentinel-exec` — constrained subprocess execution for the Sentinel agent.
//!
//! This crate is the **single gateway** through which every capability must
//! invoke OS processes.  It enforces:
//!
//! * **Allowlist gating** – only registered commands may be run.
//! * **Timeouts** – processes that exceed their budget are killed with
//!   SIGTERM → SIGKILL.
//! * **Output limits** – stdout and stderr are truncated at a configurable
//!   byte ceiling.
//! * **Sandbox rlimits** – file-descriptor count, core-dump size, and
//!   optionally the number of child processes are restricted via `setrlimit`.
//! * **`no_new_privs` and Landlock** – children cannot gain privilege through
//!   setuid binaries, and can be confined to a filesystem allowlist.
//!
//! [`HardenedExecutor`] applies all of the above behind the
//! [`CommandExecutorTrait`] that capabilities use.

pub mod error;
pub mod executor;
pub mod output_capture;
pub mod sandbox;
pub mod timeout_guard;

// Convenience re-exports.
pub use error::ExecError;
pub use executor::{
    CommandExecutor, CommandExecutorTrait, CommandOutput, DryRunResult, ExecutionResult,
    ExecutorConfig, FsAccess, HardenedExecutor, LandlockMode, RealCommandExecutor,
    BUILTIN_COMMANDS, NETWORK_COMMANDS, SAFE_PATH,
};
pub use output_capture::OutputCapture;
pub use sandbox::{apply_sandbox, SandboxConfig, SandboxReport};
pub use timeout_guard::TimeoutGuard;
