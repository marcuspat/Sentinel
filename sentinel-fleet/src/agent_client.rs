//! Agent-side client stub for fleet communication.
//! Full implementation deferred to post-MVP fleet phase.

use crate::error::FleetError;
use crate::host::HostId;

/// A lightweight client that connects a fleet agent to the fleet controller.
pub struct AgentClient {
    pub host_id: HostId,
    pub controller_addr: String,
}

impl AgentClient {
    pub fn new(host_id: HostId, controller_addr: impl Into<String>) -> Self {
        Self {
            host_id,
            controller_addr: controller_addr.into(),
        }
    }

    /// Register this agent with the controller.
    pub async fn register(&self) -> Result<(), FleetError> {
        // Post-MVP: establish mTLS connection and send registration message.
        Ok(())
    }

    /// Send a heartbeat to the controller.
    pub async fn heartbeat(&self) -> Result<(), FleetError> {
        // Post-MVP: send periodic heartbeat with host metrics.
        Ok(())
    }
}
