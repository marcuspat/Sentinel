//! Agent-side client for the planned mTLS controller protocol.
//!
//! **Not implemented.**  Fleet execution today is agentless over SSH
//! (`fleet_exec`).  These methods return [`FleetError::NotImplemented`]; they
//! used to return `Ok(())` without doing anything, which let a caller believe
//! a host had registered and was sending heartbeats.

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
        Err(FleetError::NotImplemented(
            "agent registration over mTLS; use the SSH fleet path",
        ))
    }

    /// Send a heartbeat to the controller.
    pub async fn heartbeat(&self) -> Result<(), FleetError> {
        Err(FleetError::NotImplemented(
            "agent heartbeats over mTLS; use the SSH fleet path",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unimplemented_protocol_does_not_report_success() {
        let client = AgentClient::new(HostId("h".into()), "controller:9090");
        assert!(matches!(
            client.register().await,
            Err(FleetError::NotImplemented(_))
        ));
        assert!(matches!(
            client.heartbeat().await,
            Err(FleetError::NotImplemented(_))
        ));
    }
}
