/// All errors that can arise from the agent LLM crate.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("LLM API error ({status}): {message}")]
    ApiError { status: u16, message: String },

    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("Invalid LLM response format: {0}")]
    InvalidResponse(String),

    #[error("Capability not found: {0}")]
    CapabilityNotFound(String),

    #[error("Policy denied execution: {0}")]
    PolicyDenied(String),

    #[error("Investigation limit reached ({max} rounds)")]
    InvestigationLimitReached { max: u32 },

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Core error: {0}")]
    Core(#[from] sentinel_core::CoreError),
}
