/// All errors that can arise from the fleet management crate.
#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("Host already registered: {0}")]
    HostAlreadyRegistered(String),

    #[error("Host not found: {0}")]
    HostNotFound(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Connection failed to {host}: {reason}")]
    ConnectionFailed { host: String, reason: String },

    #[error("Rollout halted at stage {stage}: {reason}")]
    RolloutHalted { stage: usize, reason: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
