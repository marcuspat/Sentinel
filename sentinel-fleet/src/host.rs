use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unique, stable identifier for a fleet host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HostId(pub String);

impl HostId {
    /// Create a new `HostId` from any string-like value.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for HostId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Operational status of a fleet host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    /// The agent is reachable and responding normally.
    Online,
    /// The agent has cleanly shut down or deregistered.
    Offline,
    /// The agent cannot be reached (network or firewall issue).
    Unreachable,
    /// The host has been administratively isolated pending investigation.
    Quarantined,
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Online => write!(f, "Online"),
            HostStatus::Offline => write!(f, "Offline"),
            HostStatus::Unreachable => write!(f, "Unreachable"),
            HostStatus::Quarantined => write!(f, "Quarantined"),
        }
    }
}

/// A managed host in the Sentinel fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    /// Unique identifier assigned at registration.
    pub id: HostId,
    /// Fully-qualified hostname or short name.
    pub hostname: String,
    /// IPv4 or IPv6 address used for agent connections.
    pub ip_address: String,
    /// TCP port on which the fleet agent listens.
    pub port: u16,
    /// Logical group memberships (e.g. "production", "web-tier").
    pub groups: Vec<String>,
    /// When the host was first registered with the controller.
    pub registered_at: DateTime<Utc>,
    /// Most recent time the controller received a heartbeat from this host.
    pub last_seen: Option<DateTime<Utc>>,
    /// Current reachability / operational status.
    pub status: HostStatus,
    /// SHA-256 fingerprint of the host's mTLS certificate (hex-encoded).
    pub cert_fingerprint: Option<String>,
}

impl Host {
    /// Create a new host with `Offline` status and no group memberships.
    /// A unique ID is generated automatically from the hostname and a UUID.
    pub fn new(hostname: String, ip_address: String, port: u16) -> Self {
        let id = HostId(format!("{}_{}", hostname, uuid::Uuid::new_v4()));
        Self {
            id,
            hostname,
            ip_address,
            port,
            groups: Vec::new(),
            registered_at: Utc::now(),
            last_seen: None,
            status: HostStatus::Offline,
            cert_fingerprint: None,
        }
    }

    /// Create a host with a specific pre-determined ID (useful for testing).
    pub fn with_id(id: HostId, hostname: String, ip_address: String, port: u16) -> Self {
        Self {
            id,
            hostname,
            ip_address,
            port,
            groups: Vec::new(),
            registered_at: Utc::now(),
            last_seen: None,
            status: HostStatus::Offline,
            cert_fingerprint: None,
        }
    }

    /// Add this host to a named group.  Duplicate memberships are ignored.
    pub fn add_to_group(&mut self, group: String) {
        if !self.groups.contains(&group) {
            self.groups.push(group);
        }
    }

    /// Remove this host from a named group.  A no-op if the host is not a member.
    pub fn remove_from_group(&mut self, group: &str) {
        self.groups.retain(|g| g != group);
    }

    /// Update `last_seen` to the current wall-clock time and set status to `Online`.
    pub fn mark_seen(&mut self) {
        self.last_seen = Some(Utc::now());
        self.status = HostStatus::Online;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_host_defaults() {
        let host = Host::new("web01".into(), "10.0.0.1".into(), 9000);
        assert_eq!(host.hostname, "web01");
        assert_eq!(host.ip_address, "10.0.0.1");
        assert_eq!(host.port, 9000);
        assert_eq!(host.status, HostStatus::Offline);
        assert!(host.groups.is_empty());
        assert!(host.last_seen.is_none());
        assert!(host.cert_fingerprint.is_none());
    }

    #[test]
    fn add_and_remove_group() {
        let mut host = Host::new("db01".into(), "10.0.0.2".into(), 9001);
        host.add_to_group("production".into());
        host.add_to_group("database".into());
        assert_eq!(host.groups.len(), 2);

        // Adding same group again is a no-op
        host.add_to_group("production".into());
        assert_eq!(host.groups.len(), 2);

        host.remove_from_group("production");
        assert_eq!(host.groups, vec!["database"]);
    }

    #[test]
    fn mark_seen_sets_online_and_timestamp() {
        let mut host = Host::new("app01".into(), "10.0.0.3".into(), 9002);
        assert_eq!(host.status, HostStatus::Offline);
        host.mark_seen();
        assert_eq!(host.status, HostStatus::Online);
        assert!(host.last_seen.is_some());
    }

    #[test]
    fn host_id_display() {
        let id = HostId::new("test-host-1");
        assert_eq!(id.to_string(), "test-host-1");
    }

    #[test]
    fn remove_from_group_noop_when_absent() {
        let mut host = Host::new("cache01".into(), "10.0.0.4".into(), 9003);
        // Should not panic when group doesn't exist
        host.remove_from_group("nonexistent");
        assert!(host.groups.is_empty());
    }

    #[test]
    fn host_serialization_roundtrip() {
        let mut host = Host::new("ser01".into(), "192.168.1.1".into(), 8080);
        host.add_to_group("staging".into());
        host.mark_seen();

        let json = serde_json::to_string(&host).expect("serialize");
        let restored: Host = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(host.id, restored.id);
        assert_eq!(host.hostname, restored.hostname);
        assert_eq!(host.groups, restored.groups);
        assert_eq!(host.status, restored.status);
    }
}
