//! # sentinel-capabilities
//!
//! The built-in capability library for the Sentinel agentic sysadmin tool.
//!
//! Each capability implements [`sentinel_core::Capability`] and delegates
//! process execution to [`sentinel_exec::CommandExecutor`].  All capabilities
//! are accessible via the [`CapabilityRegistry`] type or the
//! [`all_capabilities`] factory function.

pub mod filesystem;
pub mod metrics;
pub mod network;
pub mod packages;
pub mod process;
pub mod registry;

pub use registry::CapabilityRegistry;

use std::sync::Arc;
use sentinel_core::Capability;
use sentinel_exec::CommandExecutorTrait;

/// Construct a `Vec` of every built-in capability backed by the provided
/// executor.  This is the canonical way to get all capabilities for injection
/// into a policy engine, TUI, or audit layer.
pub fn all_capabilities(executor: Arc<dyn CommandExecutorTrait>) -> Vec<Box<dyn Capability>> {
    vec![
        // Filesystem
        Box::new(filesystem::DiskUsage::new(Arc::clone(&executor))),
        Box::new(filesystem::LogVacuum::new(Arc::clone(&executor))),
        Box::new(filesystem::CachePrune::new(Arc::clone(&executor))),
        // Process / service
        Box::new(process::ProcessList::new(Arc::clone(&executor))),
        Box::new(process::ProcessKill::new(Arc::clone(&executor))),
        Box::new(process::ServiceStatus::new(Arc::clone(&executor))),
        Box::new(process::ServiceRestart::new(Arc::clone(&executor))),
        Box::new(process::ServiceStop::new(Arc::clone(&executor))),
        Box::new(process::ServiceStart::new(Arc::clone(&executor))),
        // Packages
        Box::new(packages::PackageList::new(Arc::clone(&executor))),
        Box::new(packages::PackageUpgrade::new(Arc::clone(&executor))),
        // Network
        Box::new(network::NetworkConnections::new(Arc::clone(&executor))),
        Box::new(network::NetworkInterfaces::new(Arc::clone(&executor))),
        // Metrics
        Box::new(metrics::SystemMetrics::new(Arc::clone(&executor))),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sentinel_exec::{CommandExecutorTrait, CommandOutput};

    struct DummyExecutor;
    #[async_trait::async_trait]
    impl CommandExecutorTrait for DummyExecutor {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _env: &HashMap<String, String>,
            _max_output_bytes: usize,
        ) -> Result<CommandOutput, sentinel_exec::ExecError> {
            panic!("DummyExecutor::run should not be called in these tests")
        }
    }

    fn make_executor() -> Arc<dyn CommandExecutorTrait> {
        Arc::new(DummyExecutor)
    }

    #[test]
    fn all_capabilities_returns_14_items() {
        let caps = all_capabilities(make_executor());
        assert_eq!(caps.len(), 14);
    }

    #[test]
    fn all_capability_ids_are_unique() {
        let caps = all_capabilities(make_executor());
        let mut ids = std::collections::HashSet::new();
        for cap in &caps {
            let id = cap.manifest().id.clone();
            assert!(ids.insert(id.clone()), "Duplicate capability id: {}", id);
        }
    }

    #[test]
    fn all_capability_manifests_have_non_empty_names() {
        let caps = all_capabilities(make_executor());
        for cap in &caps {
            let m = cap.manifest();
            assert!(!m.name.is_empty(), "Empty name for capability '{}'", m.id);
            assert!(!m.description.is_empty(), "Empty description for '{}'", m.id);
        }
    }
}
