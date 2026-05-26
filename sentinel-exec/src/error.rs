/// All errors that can be produced by `sentinel-exec`.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The requested command is not in the configured allowlist.
    #[error("Command not in allowlist: {0}")]
    NotAllowed(String),

    /// The process did not finish within its allotted time.
    #[error("Execution timed out after {ms}ms")]
    Timeout { ms: u64 },

    /// A low-level I/O error occurred (file descriptor management, pipe reads, …).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The OS rejected the `spawn` call.
    #[error("Process spawn failed: {0}")]
    SpawnFailed(String),

    /// The captured output exceeded the configured byte ceiling.
    #[error("Output limit exceeded ({max_bytes} bytes)")]
    OutputLimitExceeded { max_bytes: usize },

    /// A Unix signal operation (SIGTERM/SIGKILL) failed.
    #[error("Signal error: {0}")]
    Signal(String),
}
