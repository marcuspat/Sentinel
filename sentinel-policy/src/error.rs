/// All errors that can arise inside the policy engine.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The global kill switch has been activated; all mutating capabilities are blocked.
    #[error("Kill switch activated: {reason}")]
    KillSwitchActivated { reason: String },

    /// A resource guard blocked this request.
    #[error("Resource guard blocked: {guard_name} protects {resource}")]
    ResourceGuardBlocked { guard_name: String, resource: String },

    /// No allow rule matched and the engine is deny-by-default.
    #[error("Deny-by-default: no allow rule matched")]
    DenyByDefault,

    /// An error occurred while evaluating a rule.
    #[error("Rule evaluation error: {0}")]
    EvaluationError(String),

    /// A rule or guard has an invalid configuration.
    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),
}
