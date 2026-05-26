/// All errors that can arise from audit log operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Hash chain broken at sequence {sequence}: expected {expected}, got {actual}")]
    BrokenChain {
        sequence: u64,
        expected: String,
        actual: String,
    },

    #[error("IO error writing audit log: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid event data: {0}")]
    InvalidEvent(String),
}
