use std::collections::HashMap;
use std::sync::Arc;

use sentinel_core::{Capability, CapabilityManifest};
use sentinel_exec::CommandExecutorTrait;


/// A registry that maps capability IDs to capability implementations.
pub struct CapabilityRegistry {
    capabilities: HashMap<String, Box<dyn Capability>>,
}

impl CapabilityRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            capabilities: HashMap::new(),
        }
    }

    /// Register a capability. Overwrites any existing capability with the same ID.
    pub fn register(&mut self, cap: Box<dyn Capability>) {
        let id = cap.manifest().id.clone();
        self.capabilities.insert(id, cap);
    }

    /// Look up a capability by its ID.
    pub fn get(&self, id: &str) -> Option<&dyn Capability> {
        self.capabilities.get(id).map(|b| b.as_ref())
    }

    /// Return manifests for all registered capabilities.
    pub fn list(&self) -> Vec<&CapabilityManifest> {
        self.capabilities.values().map(|c| c.manifest()).collect()
    }

    /// Return all registered capability IDs.
    pub fn all_ids(&self) -> Vec<String> {
        self.capabilities.keys().cloned().collect()
    }

    /// Build a registry pre-populated with all built-in capabilities.
    pub fn from_all(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        let mut reg = Self::new();
        for cap in crate::all_capabilities(executor) {
            reg.register(cap);
        }
        reg
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sentinel_exec::{CommandExecutorTrait, CommandOutput};
    use crate::filesystem::DiskUsage;

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
            panic!("DummyExecutor::run should not be called in validate_args tests")
        }
    }

    fn make_executor() -> Arc<dyn CommandExecutorTrait> {
        Arc::new(DummyExecutor)
    }

    #[test]
    fn registry_starts_empty() {
        let reg = CapabilityRegistry::new();
        assert!(reg.all_ids().is_empty());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn register_and_get() {
        let mut reg = CapabilityRegistry::new();
        reg.register(Box::new(DiskUsage::new(make_executor())));
        assert!(reg.get("disk_usage").is_some());
        assert!(reg.get("no_such_cap").is_none());
    }

    #[test]
    fn from_all_populates_all_capabilities() {
        let reg = CapabilityRegistry::from_all(make_executor());
        let ids = reg.all_ids();
        // Ensure all 15 capabilities are registered
        let expected = [
            "disk_usage",
            "log_vacuum",
            "cache_prune",
            "process_list",
            "process_kill",
            "service_status",
            "service_restart",
            "service_stop",
            "service_start",
            "package_list",
            "package_upgrade",
            "network_connections",
            "network_interfaces",
            "system_metrics",
        ];
        for id in &expected {
            assert!(
                ids.contains(&id.to_string()),
                "Missing capability: {}",
                id
            );
        }
        assert_eq!(ids.len(), expected.len());
    }

    #[test]
    fn list_returns_manifests() {
        let reg = CapabilityRegistry::from_all(make_executor());
        let manifests = reg.list();
        assert!(!manifests.is_empty());
        // Every manifest should have a non-empty ID
        for m in manifests {
            assert!(!m.id.is_empty());
        }
    }

    #[test]
    fn register_overwrites_existing() {
        let mut reg = CapabilityRegistry::new();
        reg.register(Box::new(DiskUsage::new(make_executor())));
        reg.register(Box::new(DiskUsage::new(make_executor())));
        assert_eq!(reg.all_ids().len(), 1);
    }
}
