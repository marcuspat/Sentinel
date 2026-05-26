use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::execution_context::ExecutionContext;

/// Risk tier for a capability — used by the policy engine.
///
/// The ordering `Low < Medium < High < Critical` is deliberately encoded so
/// that comparisons like `step.risk_tier >= RiskTier::High` work naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    /// Read-only, no state changes.  Auto-allowed in most policies.
    Low,
    /// Narrow, reversible mutations.  May require approval in strict policies.
    Medium,
    /// Broad or hard-to-reverse mutations.  Requires explicit operator approval.
    High,
    /// System-wide or unrecoverable actions (e.g. `rm -rf /`, `halt`).
    /// Denied by default in every built-in policy.
    Critical,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskTier::Low => write!(f, "Low"),
            RiskTier::Medium => write!(f, "Medium"),
            RiskTier::High => write!(f, "High"),
            RiskTier::Critical => write!(f, "Critical"),
        }
    }
}

/// Classification of capability mutability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityKind {
    /// Reads data without any side effects.
    ReadOnly,
    /// Makes changes to system state.
    Mutating,
}

/// Resource impact declaration for a capability.
///
/// Declared statically so the policy engine and scheduler can reason about
/// contention before any capability is actually invoked.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceImpact {
    /// True if this capability is expected to saturate a CPU core.
    pub cpu_intensive: bool,
    /// True if this capability performs significant disk I/O.
    pub io_intensive: bool,
    /// True if this capability requires outbound network access.
    pub network_required: bool,
    /// Filesystem paths that may be read or written by this capability.
    pub affects_paths: Vec<String>,
    /// System service names that may be started, stopped, or restarted.
    pub affects_services: Vec<String>,
}

/// Metadata that every capability must declare.
///
/// `CapabilityManifest` is the static, compile-time description of a
/// capability.  It must be cheap to clone and must not change at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityManifest {
    /// Unique, stable identifier (e.g. `"sentinel.fs.read_file"`).
    pub id: String,
    /// Human-readable short name shown in the TUI.
    pub name: String,
    /// One-paragraph description of what the capability does.
    pub description: String,
    /// Mutability classification.
    pub kind: CapabilityKind,
    /// Risk tier used by the policy engine.
    pub risk_tier: RiskTier,
    /// Resource impact declaration.
    pub resource_impact: ResourceImpact,
    /// Whether `invoke_inverse` is implemented and can undo this capability's effects.
    pub has_inverse: bool,
    /// SemVer string (e.g. `"1.0.0"`).
    pub version: String,
}

impl CapabilityManifest {
    /// Convenience constructor for the most common fields.
    /// Sets `resource_impact` to default, `has_inverse` to `false`, and
    /// `version` to `"1.0.0"`.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        kind: CapabilityKind,
        risk_tier: RiskTier,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            kind,
            risk_tier,
            resource_impact: ResourceImpact::default(),
            has_inverse: false,
            version: "1.0.0".into(),
        }
    }
}

/// The result of invoking a capability.
///
/// Using an enum rather than a `Result<T, E>` makes dry-run a first-class
/// outcome and avoids the temptation to `unwrap()` at call sites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityResult {
    /// The capability completed successfully.
    Success {
        /// Structured output produced by the capability.
        output: serde_json::Value,
    },
    /// The capability failed.
    Failure {
        /// Human-readable error message.
        error: String,
        /// `true` if the operation can be retried without manual intervention.
        recoverable: bool,
    },
    /// Returned when `dry_run = true`.  No real changes were made.
    DryRun {
        /// Description of what *would* happen on a real invocation.
        predicted_effect: serde_json::Value,
    },
}

impl CapabilityResult {
    /// Returns `true` when the variant is `Success`.
    pub fn is_success(&self) -> bool {
        matches!(self, CapabilityResult::Success { .. })
    }

    /// Returns `true` when the variant is `DryRun`.
    pub fn is_dry_run(&self) -> bool {
        matches!(self, CapabilityResult::DryRun { .. })
    }

    /// Returns `true` when the variant is `Failure`.
    pub fn is_failure(&self) -> bool {
        matches!(self, CapabilityResult::Failure { .. })
    }

    /// Convenience constructor for a successful result carrying a JSON value.
    pub fn success(output: serde_json::Value) -> Self {
        CapabilityResult::Success { output }
    }

    /// Convenience constructor for a failure result.
    pub fn failure(error: impl Into<String>, recoverable: bool) -> Self {
        CapabilityResult::Failure {
            error: error.into(),
            recoverable,
        }
    }

    /// Convenience constructor for a dry-run result.
    pub fn dry_run(predicted_effect: serde_json::Value) -> Self {
        CapabilityResult::DryRun { predicted_effect }
    }
}

/// Core capability trait — every capability must implement this.
///
/// # Object Safety
/// This trait is `Send + Sync` so capabilities can be stored as
/// `Arc<dyn Capability>` and invoked from any async task.
#[async_trait]
pub trait Capability: Send + Sync {
    /// Return the static manifest for this capability.  Must be cheap (no I/O).
    fn manifest(&self) -> &CapabilityManifest;

    /// Execute the capability with the provided JSON arguments.
    ///
    /// Implementations MUST respect `ctx.dry_run` and delegate to `dry_run`
    /// (or return a `CapabilityResult::DryRun`) when it is set.
    async fn invoke(&self, args: serde_json::Value, ctx: &ExecutionContext) -> CapabilityResult;

    /// Predict the effect of the capability without making any real changes.
    ///
    /// The returned `CapabilityResult` should always be `DryRun { .. }`.
    async fn dry_run(&self, args: serde_json::Value, ctx: &ExecutionContext) -> CapabilityResult;

    /// Undo the effects of a previously completed `invoke`.
    ///
    /// Returns `None` when the capability has no inverse (the default).
    /// Capabilities that set `manifest().has_inverse = true` MUST override this.
    async fn invoke_inverse(
        &self,
        _args: serde_json::Value,
        _ctx: &ExecutionContext,
    ) -> Option<CapabilityResult> {
        None
    }

    /// Validate the JSON arguments before invocation.
    ///
    /// Called by the execution harness before `invoke` / `dry_run`.
    /// Return `Err(CoreError::InvalidArgs(_))` for any validation failure.
    fn validate_args(&self, args: &serde_json::Value) -> Result<(), CoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RiskTier ──────────────────────────────────────────────────────────────

    #[test]
    fn risk_tier_ordering() {
        assert!(RiskTier::Low < RiskTier::Medium);
        assert!(RiskTier::Medium < RiskTier::High);
        assert!(RiskTier::High < RiskTier::Critical);
    }

    #[test]
    fn risk_tier_max() {
        let tiers = [
            RiskTier::Low,
            RiskTier::High,
            RiskTier::Medium,
            RiskTier::Critical,
        ];
        let max = tiers.iter().copied().max().unwrap();
        assert_eq!(max, RiskTier::Critical);
    }

    #[test]
    fn risk_tier_display() {
        assert_eq!(RiskTier::Low.to_string(), "Low");
        assert_eq!(RiskTier::Medium.to_string(), "Medium");
        assert_eq!(RiskTier::High.to_string(), "High");
        assert_eq!(RiskTier::Critical.to_string(), "Critical");
    }

    #[test]
    fn risk_tier_serde_roundtrip() {
        for tier in [
            RiskTier::Low,
            RiskTier::Medium,
            RiskTier::High,
            RiskTier::Critical,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: RiskTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    // ── CapabilityKind ────────────────────────────────────────────────────────

    #[test]
    fn capability_kind_equality() {
        assert_eq!(CapabilityKind::ReadOnly, CapabilityKind::ReadOnly);
        assert_ne!(CapabilityKind::ReadOnly, CapabilityKind::Mutating);
    }

    #[test]
    fn capability_kind_serde_roundtrip() {
        for kind in [CapabilityKind::ReadOnly, CapabilityKind::Mutating] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: CapabilityKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── ResourceImpact ────────────────────────────────────────────────────────

    #[test]
    fn resource_impact_default() {
        let ri = ResourceImpact::default();
        assert!(!ri.cpu_intensive);
        assert!(!ri.io_intensive);
        assert!(!ri.network_required);
        assert!(ri.affects_paths.is_empty());
        assert!(ri.affects_services.is_empty());
    }

    #[test]
    fn resource_impact_serde_roundtrip() {
        let ri = ResourceImpact {
            cpu_intensive: true,
            io_intensive: false,
            network_required: true,
            affects_paths: vec!["/etc/hosts".into(), "/var/log".into()],
            affects_services: vec!["nginx".into()],
        };
        let json = serde_json::to_string(&ri).unwrap();
        let back: ResourceImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cpu_intensive, ri.cpu_intensive);
        assert_eq!(back.network_required, ri.network_required);
        assert_eq!(back.affects_paths, ri.affects_paths);
        assert_eq!(back.affects_services, ri.affects_services);
    }

    // ── CapabilityManifest ────────────────────────────────────────────────────

    #[test]
    fn manifest_new_sets_defaults() {
        let m = CapabilityManifest::new(
            "sentinel.test.noop",
            "No-op",
            "Does nothing",
            CapabilityKind::ReadOnly,
            RiskTier::Low,
        );
        assert_eq!(m.id, "sentinel.test.noop");
        assert_eq!(m.name, "No-op");
        assert_eq!(m.description, "Does nothing");
        assert_eq!(m.kind, CapabilityKind::ReadOnly);
        assert_eq!(m.risk_tier, RiskTier::Low);
        assert!(!m.has_inverse);
        assert_eq!(m.version, "1.0.0");
        // ResourceImpact should be default
        assert!(!m.resource_impact.cpu_intensive);
        assert!(m.resource_impact.affects_paths.is_empty());
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = CapabilityManifest {
            id: "sentinel.test.ping".into(),
            name: "Ping".into(),
            description: "Pings a host".into(),
            kind: CapabilityKind::ReadOnly,
            risk_tier: RiskTier::Low,
            resource_impact: ResourceImpact {
                network_required: true,
                ..Default::default()
            },
            has_inverse: false,
            version: "2.1.0".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: CapabilityManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.version, m.version);
        assert_eq!(back.risk_tier, m.risk_tier);
        assert_eq!(back.kind, m.kind);
        assert!(back.resource_impact.network_required);
        assert!(!back.resource_impact.cpu_intensive);
    }

    #[test]
    fn manifest_with_inverse() {
        let m = CapabilityManifest {
            id: "sentinel.svc.restart".into(),
            name: "Restart Service".into(),
            description: "Restarts a systemd service".into(),
            kind: CapabilityKind::Mutating,
            risk_tier: RiskTier::Medium,
            resource_impact: ResourceImpact {
                affects_services: vec!["nginx".into()],
                ..Default::default()
            },
            has_inverse: true,
            version: "1.0.0".into(),
        };
        assert!(m.has_inverse);
        assert_eq!(m.risk_tier, RiskTier::Medium);
        assert_eq!(m.resource_impact.affects_services, vec!["nginx"]);
    }

    // ── CapabilityResult ──────────────────────────────────────────────────────

    #[test]
    fn capability_result_success_is_success() {
        let r = CapabilityResult::success(serde_json::json!({"key": "val"}));
        assert!(r.is_success());
        assert!(!r.is_failure());
        assert!(!r.is_dry_run());
    }

    #[test]
    fn capability_result_failure_is_failure() {
        let r = CapabilityResult::failure("something went wrong", true);
        assert!(r.is_failure());
        assert!(!r.is_success());
        assert!(!r.is_dry_run());
        if let CapabilityResult::Failure { error, recoverable } = &r {
            assert_eq!(error, "something went wrong");
            assert!(*recoverable);
        } else {
            panic!("expected Failure variant");
        }
    }

    #[test]
    fn capability_result_failure_non_recoverable() {
        let r = CapabilityResult::failure("fatal error", false);
        if let CapabilityResult::Failure { recoverable, .. } = &r {
            assert!(!*recoverable);
        } else {
            panic!("expected Failure variant");
        }
    }

    #[test]
    fn capability_result_dry_run_is_dry_run() {
        let r = CapabilityResult::dry_run(serde_json::json!({"would_do": "nothing"}));
        assert!(r.is_dry_run());
        assert!(!r.is_success());
        assert!(!r.is_failure());
        if let CapabilityResult::DryRun { predicted_effect } = &r {
            assert_eq!(predicted_effect["would_do"], "nothing");
        } else {
            panic!("expected DryRun variant");
        }
    }

    #[test]
    fn capability_result_serde_roundtrip() {
        let variants: Vec<CapabilityResult> = vec![
            CapabilityResult::success(serde_json::json!(42)),
            CapabilityResult::failure("oops", false),
            CapabilityResult::dry_run(serde_json::json!({"action": "would_write"})),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CapabilityResult = serde_json::from_str(&json).unwrap();
            match (v, &back) {
                (CapabilityResult::Success { .. }, CapabilityResult::Success { .. }) => {}
                (CapabilityResult::Failure { .. }, CapabilityResult::Failure { .. }) => {}
                (CapabilityResult::DryRun { .. }, CapabilityResult::DryRun { .. }) => {}
                _ => panic!("variant mismatch after roundtrip"),
            }
        }
    }

    // ── Capability trait (concrete stub for testing) ──────────────────────────

    struct NoopCapability {
        manifest: CapabilityManifest,
    }

    impl NoopCapability {
        fn new() -> Self {
            Self {
                manifest: CapabilityManifest::new(
                    "sentinel.test.noop",
                    "No-op",
                    "Returns immediately without doing anything",
                    CapabilityKind::ReadOnly,
                    RiskTier::Low,
                ),
            }
        }
    }

    #[async_trait]
    impl Capability for NoopCapability {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }

        async fn invoke(
            &self,
            _args: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> CapabilityResult {
            CapabilityResult::success(serde_json::json!({"status": "ok"}))
        }

        async fn dry_run(
            &self,
            _args: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> CapabilityResult {
            CapabilityResult::dry_run(serde_json::json!({"would_do": "nothing"}))
        }

        fn validate_args(&self, args: &serde_json::Value) -> Result<(), CoreError> {
            if args.is_object() || args.is_null() {
                Ok(())
            } else {
                Err(CoreError::InvalidArgs("expected object or null".into()))
            }
        }
    }

    /// A capability that has a working inverse.
    struct InvertibleCapability {
        manifest: CapabilityManifest,
    }

    impl InvertibleCapability {
        fn new() -> Self {
            let mut manifest = CapabilityManifest::new(
                "sentinel.test.invertible",
                "Invertible",
                "Can be undone",
                CapabilityKind::Mutating,
                RiskTier::Medium,
            );
            manifest.has_inverse = true;
            Self { manifest }
        }
    }

    #[async_trait]
    impl Capability for InvertibleCapability {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }

        async fn invoke(
            &self,
            _args: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> CapabilityResult {
            CapabilityResult::success(serde_json::json!({"done": true}))
        }

        async fn dry_run(
            &self,
            _args: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> CapabilityResult {
            CapabilityResult::dry_run(serde_json::json!({"would_mutate": true}))
        }

        async fn invoke_inverse(
            &self,
            _args: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> Option<CapabilityResult> {
            Some(CapabilityResult::success(serde_json::json!({"undone": true})))
        }

        fn validate_args(&self, _args: &serde_json::Value) -> Result<(), CoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn noop_capability_invoke() {
        let cap = NoopCapability::new();
        let ctx = ExecutionContext::new(uuid::Uuid::new_v4(), "localhost");
        let result = cap.invoke(serde_json::json!({}), &ctx).await;
        assert!(result.is_success());
        if let CapabilityResult::Success { output } = result {
            assert_eq!(output["status"], "ok");
        }
    }

    #[tokio::test]
    async fn noop_capability_dry_run() {
        let cap = NoopCapability::new();
        let ctx = ExecutionContext::new(uuid::Uuid::new_v4(), "localhost");
        let result = cap.dry_run(serde_json::json!({}), &ctx).await;
        assert!(result.is_dry_run());
    }

    #[tokio::test]
    async fn noop_capability_invoke_inverse_returns_none() {
        let cap = NoopCapability::new();
        let ctx = ExecutionContext::new(uuid::Uuid::new_v4(), "localhost");
        let result = cap.invoke_inverse(serde_json::json!({}), &ctx).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn invertible_capability_returns_some_inverse() {
        let cap = InvertibleCapability::new();
        let ctx = ExecutionContext::new(uuid::Uuid::new_v4(), "localhost");
        let result = cap.invoke_inverse(serde_json::json!({}), &ctx).await;
        assert!(result.is_some());
        assert!(result.unwrap().is_success());
    }

    #[test]
    fn noop_capability_validate_args_ok() {
        let cap = NoopCapability::new();
        assert!(cap.validate_args(&serde_json::json!({})).is_ok());
        assert!(cap.validate_args(&serde_json::Value::Null).is_ok());
    }

    #[test]
    fn noop_capability_validate_args_err() {
        let cap = NoopCapability::new();
        let err = cap.validate_args(&serde_json::json!("not an object")).unwrap_err();
        assert!(matches!(err, CoreError::InvalidArgs(_)));
    }

    #[test]
    fn capability_manifest_id_is_accessible_via_trait() {
        let cap = NoopCapability::new();
        let cap_ref: &dyn Capability = &cap;
        assert_eq!(cap_ref.manifest().id, "sentinel.test.noop");
    }
}
