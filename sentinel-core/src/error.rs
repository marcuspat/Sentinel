use crate::session::SessionPhase;

/// The canonical error type for the sentinel-core crate.
///
/// All other crates in the workspace should map their internal errors into
/// `CoreError` (or a superset thereof) at API boundaries.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Capability arguments failed validation.
    #[error("Invalid capability arguments: {0}")]
    InvalidArgs(String),

    /// A capability with the given identifier was not registered.
    #[error("Capability not found: {0}")]
    CapabilityNotFound(String),

    /// A requested session phase transition is not legal from the current phase.
    #[error("Invalid session phase transition from {from:?} to {to:?}")]
    InvalidPhaseTransition { from: SessionPhase, to: SessionPhase },

    /// JSON serialisation or deserialisation failure.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The capability itself reported a non-recoverable execution failure.
    #[error("Capability execution failed: {0}")]
    ExecutionFailed(String),

    /// The active policy engine denied the operation.
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// An operation exceeded its allowed wall-clock budget.
    #[error("Timeout after {ms}ms")]
    Timeout { ms: u64 },

    /// An operator triggered the emergency kill switch.
    #[error("Kill switch activated: {reason}")]
    KillSwitchActivated { reason: String },

    /// Rollback of a previously executed step failed.
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_args() {
        let err = CoreError::InvalidArgs("missing field `host`".into());
        assert_eq!(err.to_string(), "Invalid capability arguments: missing field `host`");
    }

    #[test]
    fn display_capability_not_found() {
        let err = CoreError::CapabilityNotFound("read_file".into());
        assert_eq!(err.to_string(), "Capability not found: read_file");
    }

    #[test]
    fn display_invalid_phase_transition() {
        let err = CoreError::InvalidPhaseTransition {
            from: SessionPhase::Investigating,
            to: SessionPhase::Completed,
        };
        let msg = err.to_string();
        assert!(msg.contains("Invalid session phase transition"));
        assert!(msg.contains("Investigating"));
        assert!(msg.contains("Completed"));
    }

    #[test]
    fn display_timeout() {
        let err = CoreError::Timeout { ms: 5000 };
        assert_eq!(err.to_string(), "Timeout after 5000ms");
    }

    #[test]
    fn display_kill_switch() {
        let err = CoreError::KillSwitchActivated {
            reason: "operator request".into(),
        };
        assert_eq!(err.to_string(), "Kill switch activated: operator request");
    }

    #[test]
    fn display_policy_denied() {
        let err = CoreError::PolicyDenied("high-risk action on production host".into());
        assert_eq!(
            err.to_string(),
            "Policy denied: high-risk action on production host"
        );
    }

    #[test]
    fn display_rollback_failed() {
        let err = CoreError::RollbackFailed("step 3 left partial state".into());
        assert_eq!(err.to_string(), "Rollback failed: step 3 left partial state");
    }

    #[test]
    fn from_serde_json_error() {
        let raw = serde_json::from_str::<serde_json::Value>("{bad json");
        assert!(raw.is_err());
        let core_err: CoreError = raw.unwrap_err().into();
        assert!(matches!(core_err, CoreError::Serialization(_)));
    }

    #[test]
    fn display_execution_failed() {
        let err = CoreError::ExecutionFailed("exit code 1".into());
        assert_eq!(err.to_string(), "Capability execution failed: exit code 1");
    }
}
