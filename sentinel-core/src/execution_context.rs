use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Hard limits applied to every capability invocation.
///
/// These are advisory for pure-Rust code but are enforced by the execution
/// harness in `sentinel-exec` when spawning OS processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum number of bytes that can be captured from a capability's
    /// stdout/stderr or structured output.
    pub max_output_bytes: usize,

    /// Wall-clock budget for the CPU-bound portion of a capability, in
    /// milliseconds.
    pub max_cpu_time_ms: u64,

    /// Optional hard memory ceiling, in bytes.  `None` means "no limit".
    pub max_memory_bytes: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 1024 * 1024, // 1 MiB
            max_cpu_time_ms: 30_000,       // 30 s
            max_memory_bytes: None,
        }
    }
}

/// Immutable runtime context threaded through every capability call.
///
/// A single `ExecutionContext` is created at the start of each plan step and
/// is passed — by reference — to both `invoke` and `dry_run`.  It must never
/// be mutated by a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// The session that owns this execution.
    pub session_id: uuid::Uuid,

    /// Fully-qualified hostname (or IP) of the target machine.
    pub host: String,

    /// When `true` the capability must predict its effects without making any
    /// real changes to the system.
    pub dry_run: bool,

    /// Maximum wall-clock time the capability is allowed to run, in
    /// milliseconds.
    pub timeout_ms: u64,

    /// Optional working directory to use when a capability spawns a subprocess.
    pub working_dir: Option<PathBuf>,

    /// Key/value pairs that override (or augment) the process environment for
    /// any subprocess the capability spawns.
    pub env_overrides: HashMap<String, String>,

    /// Resource ceilings for this invocation.
    pub resource_limits: ResourceLimits,
}

impl ExecutionContext {
    /// Construct a context with sensible defaults for the given session and
    /// host.  Sets `dry_run = false` and a 30-second timeout.
    pub fn new(session_id: uuid::Uuid, host: impl Into<String>) -> Self {
        Self {
            session_id,
            host: host.into(),
            dry_run: false,
            timeout_ms: 30_000,
            working_dir: None,
            env_overrides: HashMap::new(),
            resource_limits: ResourceLimits::default(),
        }
    }

    /// Return a copy of this context with `dry_run` forced to `true`.
    pub fn as_dry_run(&self) -> Self {
        let mut ctx = self.clone();
        ctx.dry_run = true;
        ctx
    }

    /// Return a copy of this context with a different timeout.
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Add a single environment-variable override and return `self`.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_overrides.insert(key.into(), value.into());
        self
    }

    /// Set the working directory and return `self`.
    pub fn with_working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(path.into());
        self
    }

    /// Override the resource limits and return `self`.
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> ExecutionContext {
        ExecutionContext::new(uuid::Uuid::new_v4(), "localhost")
    }

    #[test]
    fn default_resource_limits() {
        let lim = ResourceLimits::default();
        assert_eq!(lim.max_output_bytes, 1024 * 1024);
        assert_eq!(lim.max_cpu_time_ms, 30_000);
        assert!(lim.max_memory_bytes.is_none());
    }

    #[test]
    fn resource_limits_with_memory() {
        let lim = ResourceLimits {
            max_output_bytes: 512,
            max_cpu_time_ms: 5_000,
            max_memory_bytes: Some(256 * 1024 * 1024),
        };
        assert_eq!(lim.max_memory_bytes, Some(256 * 1024 * 1024));
    }

    #[test]
    fn resource_limits_serde_roundtrip() {
        let lim = ResourceLimits {
            max_output_bytes: 2048,
            max_cpu_time_ms: 10_000,
            max_memory_bytes: Some(1024),
        };
        let json = serde_json::to_string(&lim).unwrap();
        let back: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_output_bytes, lim.max_output_bytes);
        assert_eq!(back.max_cpu_time_ms, lim.max_cpu_time_ms);
        assert_eq!(back.max_memory_bytes, lim.max_memory_bytes);
    }

    #[test]
    fn new_context_defaults() {
        let ctx = make_ctx();
        assert!(!ctx.dry_run);
        assert_eq!(ctx.timeout_ms, 30_000);
        assert_eq!(ctx.host, "localhost");
        assert!(ctx.working_dir.is_none());
        assert!(ctx.env_overrides.is_empty());
        assert_eq!(ctx.resource_limits.max_output_bytes, 1024 * 1024);
    }

    #[test]
    fn as_dry_run_does_not_mutate_original() {
        let ctx = make_ctx();
        let dry = ctx.as_dry_run();
        assert!(!ctx.dry_run, "original must stay non-dry");
        assert!(dry.dry_run, "copy must be dry");
        assert_eq!(ctx.session_id, dry.session_id);
        assert_eq!(ctx.host, dry.host);
    }

    #[test]
    fn with_timeout_ms_builder() {
        let ctx = make_ctx().with_timeout_ms(5_000);
        assert_eq!(ctx.timeout_ms, 5_000);
    }

    #[test]
    fn with_env_builder() {
        let ctx = make_ctx().with_env("RUST_LOG", "debug");
        assert_eq!(
            ctx.env_overrides.get("RUST_LOG").map(|s| s.as_str()),
            Some("debug")
        );
    }

    #[test]
    fn with_working_dir_builder() {
        let ctx = make_ctx().with_working_dir("/tmp/sentinel");
        assert_eq!(ctx.working_dir, Some(PathBuf::from("/tmp/sentinel")));
    }

    #[test]
    fn multiple_env_overrides() {
        let ctx = make_ctx()
            .with_env("KEY_A", "val_a")
            .with_env("KEY_B", "val_b");
        assert_eq!(ctx.env_overrides.len(), 2);
        assert_eq!(ctx.env_overrides["KEY_A"], "val_a");
        assert_eq!(ctx.env_overrides["KEY_B"], "val_b");
    }

    #[test]
    fn with_resource_limits_builder() {
        let limits = ResourceLimits {
            max_output_bytes: 512,
            max_cpu_time_ms: 1_000,
            max_memory_bytes: Some(1024),
        };
        let ctx = make_ctx().with_resource_limits(limits.clone());
        assert_eq!(ctx.resource_limits.max_output_bytes, 512);
        assert_eq!(ctx.resource_limits.max_cpu_time_ms, 1_000);
        assert_eq!(ctx.resource_limits.max_memory_bytes, Some(1024));
    }

    #[test]
    fn serialization_roundtrip() {
        let ctx = make_ctx()
            .with_timeout_ms(1_000)
            .with_env("FOO", "bar")
            .with_working_dir("/srv");
        let json = serde_json::to_string(&ctx).expect("serialize");
        let restored: ExecutionContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ctx.session_id, restored.session_id);
        assert_eq!(ctx.host, restored.host);
        assert_eq!(ctx.timeout_ms, restored.timeout_ms);
        assert_eq!(ctx.env_overrides, restored.env_overrides);
        assert_eq!(ctx.working_dir, restored.working_dir);
        assert!(!restored.dry_run);
    }

    #[test]
    fn dry_run_context_serialization_roundtrip() {
        let ctx = make_ctx().as_dry_run();
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: ExecutionContext = serde_json::from_str(&json).unwrap();
        assert!(restored.dry_run);
    }

    #[test]
    fn session_id_is_preserved() {
        let id = uuid::Uuid::new_v4();
        let ctx = ExecutionContext::new(id, "myhost.example.com");
        assert_eq!(ctx.session_id, id);
        assert_eq!(ctx.host, "myhost.example.com");
    }
}
