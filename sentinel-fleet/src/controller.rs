//! Fleet controller stub — manages lightweight agents on multiple hosts.
//! Full implementation deferred to post-MVP fleet phase.

use std::collections::HashMap;

use crate::error::FleetError;
use crate::host::{Host, HostId};
use crate::staged_rollout::StagedRollout;
use crate::topology::FleetTopology;

/// The fleet controller manages the topology and dispatches commands to agents.
pub struct FleetController {
    pub topology: FleetTopology,
    pub rollouts: HashMap<uuid::Uuid, StagedRollout>,
}

impl FleetController {
    pub fn new() -> Self {
        Self {
            topology: FleetTopology::new(),
            rollouts: HashMap::new(),
        }
    }

    /// Register a host with the fleet.
    pub fn register_host(&mut self, host: Host) -> Result<(), FleetError> {
        self.topology.register_host(host)
    }

    /// Deregister a host from the fleet.
    pub fn deregister_host(&mut self, id: &HostId) -> Option<Host> {
        self.topology.deregister_host(id)
    }

    /// Add a staged rollout plan.
    pub fn add_rollout(&mut self, rollout: StagedRollout) {
        self.rollouts.insert(rollout.id, rollout);
    }

    /// Get a rollout by ID.
    pub fn get_rollout(&self, id: &uuid::Uuid) -> Option<&StagedRollout> {
        self.rollouts.get(id)
    }
}

impl Default for FleetController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Host;

    #[test]
    fn register_and_deregister_host() {
        let mut ctrl = FleetController::new();
        let host = Host::new("web-01".into(), "192.168.1.1".into(), 9090);
        let id = host.id.clone();
        ctrl.register_host(host).unwrap();
        assert!(ctrl.topology.get_host(&id).is_some());
        let removed = ctrl.deregister_host(&id);
        assert!(removed.is_some());
        assert!(ctrl.topology.get_host(&id).is_none());
    }
}
