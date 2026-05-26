use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::FleetError;
use crate::host::{Host, HostId, HostStatus};

/// Flexible host selector used for targeting rollouts and commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostSelector {
    /// Target every registered host.
    All,
    /// Target a single host by its ID.
    ById(HostId),
    /// Target all hosts in a named group.
    ByGroup(String),
    /// Target a specific set of hosts by ID.
    ByIds(Vec<HostId>),
    /// Target only hosts whose status is `Online`.
    Online,
    /// Extension point: future expression-language filter.
    Custom { filter: String },
}

/// The complete topology of all registered fleet hosts.
///
/// Provides O(1) lookup by ID and efficient group-based selection.
pub struct FleetTopology {
    hosts: HashMap<HostId, Host>,
    groups: HashMap<String, HashSet<HostId>>,
}

impl Default for FleetTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl FleetTopology {
    /// Create an empty topology.
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    /// Register a host in the topology.
    ///
    /// Returns `Err(FleetError::HostAlreadyRegistered)` if a host with the
    /// same ID already exists.
    pub fn register_host(&mut self, host: Host) -> Result<(), FleetError> {
        if self.hosts.contains_key(&host.id) {
            return Err(FleetError::HostAlreadyRegistered(host.id.0.clone()));
        }

        // Update group indices.
        for group in &host.groups {
            self.groups
                .entry(group.clone())
                .or_default()
                .insert(host.id.clone());
        }

        self.hosts.insert(host.id.clone(), host);
        Ok(())
    }

    /// Deregister a host, removing it from all group indices.
    ///
    /// Returns the removed `Host` if it existed, or `None` otherwise.
    pub fn deregister_host(&mut self, id: &HostId) -> Option<Host> {
        let host = self.hosts.remove(id)?;

        // Clean up group indices.
        for group in &host.groups {
            if let Some(members) = self.groups.get_mut(group) {
                members.remove(id);
                // Prune empty group entries to keep the map clean.
                if members.is_empty() {
                    self.groups.remove(group);
                }
            }
        }

        Some(host)
    }

    /// Look up a host by its ID.
    pub fn get_host(&self, id: &HostId) -> Option<&Host> {
        self.hosts.get(id)
    }

    /// Get a mutable reference to a host by its ID.
    pub fn get_host_mut(&mut self, id: &HostId) -> Option<&mut Host> {
        self.hosts.get_mut(id)
    }

    /// All hosts that belong to the named group, in arbitrary order.
    pub fn hosts_in_group(&self, group: &str) -> Vec<&Host> {
        match self.groups.get(group) {
            None => Vec::new(),
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.hosts.get(id))
                .collect(),
        }
    }

    /// All registered hosts, in arbitrary order.
    pub fn all_hosts(&self) -> Vec<&Host> {
        self.hosts.values().collect()
    }

    /// All hosts whose status is `Online`.
    pub fn online_hosts(&self) -> Vec<&Host> {
        self.hosts
            .values()
            .filter(|h| h.status == HostStatus::Online)
            .collect()
    }

    /// Select hosts according to the given selector.
    pub fn select_hosts(&self, selector: &HostSelector) -> Vec<&Host> {
        match selector {
            HostSelector::All => self.all_hosts(),
            HostSelector::ById(id) => self
                .get_host(id)
                .into_iter()
                .collect(),
            HostSelector::ByGroup(group) => self.hosts_in_group(group),
            HostSelector::ByIds(ids) => ids
                .iter()
                .filter_map(|id| self.get_host(id))
                .collect(),
            HostSelector::Online => self.online_hosts(),
            HostSelector::Custom { .. } => {
                // Extension point: expression-language evaluation not yet implemented.
                // Falls back to all hosts so callers can at least run in degraded mode.
                self.all_hosts()
            }
        }
    }

    /// Total number of registered hosts.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Returns `true` if no hosts are registered.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Host;

    fn make_host(hostname: &str, ip: &str) -> Host {
        Host::new(hostname.into(), ip.into(), 9000)
    }

    fn make_host_with_group(hostname: &str, ip: &str, group: &str) -> Host {
        let mut h = make_host(hostname, ip);
        h.add_to_group(group.into());
        h
    }

    // ── Register / deregister ─────────────────────────────────────────────────

    #[test]
    fn register_host_succeeds() {
        let mut topo = FleetTopology::new();
        let host = make_host("web01", "10.0.0.1");
        let id = host.id.clone();
        topo.register_host(host).expect("register should succeed");
        assert!(topo.get_host(&id).is_some());
    }

    #[test]
    fn register_duplicate_host_fails() {
        let mut topo = FleetTopology::new();
        let host = make_host("web01", "10.0.0.1");
        let id = host.id.clone();
        topo.register_host(host.clone()).unwrap();

        // Build a second host with the same ID.
        let duplicate = Host::with_id(id, "web01-dup".into(), "10.0.0.2".into(), 9001);
        let err = topo.register_host(duplicate).unwrap_err();
        assert!(matches!(err, FleetError::HostAlreadyRegistered(_)));
    }

    #[test]
    fn deregister_existing_host() {
        let mut topo = FleetTopology::new();
        let host = make_host("db01", "10.0.0.5");
        let id = host.id.clone();
        topo.register_host(host).unwrap();
        let removed = topo.deregister_host(&id);
        assert!(removed.is_some());
        assert!(topo.get_host(&id).is_none());
    }

    #[test]
    fn deregister_nonexistent_host_returns_none() {
        let mut topo = FleetTopology::new();
        let id = HostId::new("ghost");
        assert!(topo.deregister_host(&id).is_none());
    }

    // ── Group management ──────────────────────────────────────────────────────

    #[test]
    fn hosts_in_group_returns_correct_set() {
        let mut topo = FleetTopology::new();
        let h1 = make_host_with_group("web01", "10.0.0.1", "web");
        let h2 = make_host_with_group("web02", "10.0.0.2", "web");
        let h3 = make_host_with_group("db01", "10.0.0.3", "db");

        topo.register_host(h1).unwrap();
        topo.register_host(h2).unwrap();
        topo.register_host(h3).unwrap();

        let web_hosts = topo.hosts_in_group("web");
        assert_eq!(web_hosts.len(), 2);

        let db_hosts = topo.hosts_in_group("db");
        assert_eq!(db_hosts.len(), 1);

        let empty = topo.hosts_in_group("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn deregister_removes_from_group_index() {
        let mut topo = FleetTopology::new();
        let h = make_host_with_group("web01", "10.0.0.1", "web");
        let id = h.id.clone();
        topo.register_host(h).unwrap();
        topo.deregister_host(&id);
        assert!(topo.hosts_in_group("web").is_empty());
    }

    // ── Select operations ─────────────────────────────────────────────────────

    #[test]
    fn select_all_returns_all_hosts() {
        let mut topo = FleetTopology::new();
        topo.register_host(make_host("a", "1.1.1.1")).unwrap();
        topo.register_host(make_host("b", "1.1.1.2")).unwrap();
        assert_eq!(topo.select_hosts(&HostSelector::All).len(), 2);
    }

    #[test]
    fn select_by_id_returns_single_host() {
        let mut topo = FleetTopology::new();
        let h = make_host("solo", "2.2.2.2");
        let id = h.id.clone();
        topo.register_host(h).unwrap();

        let selected = topo.select_hosts(&HostSelector::ById(id.clone()));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, id);
    }

    #[test]
    fn select_online_returns_only_online() {
        let mut topo = FleetTopology::new();
        let mut h1 = make_host("on", "3.3.3.1");
        h1.mark_seen(); // sets Online
        let h2 = make_host("off", "3.3.3.2"); // stays Offline

        topo.register_host(h1).unwrap();
        topo.register_host(h2).unwrap();

        let online = topo.select_hosts(&HostSelector::Online);
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].hostname, "on");
    }

    #[test]
    fn select_by_ids_returns_subset() {
        let mut topo = FleetTopology::new();
        let h1 = make_host("h1", "4.4.4.1");
        let h2 = make_host("h2", "4.4.4.2");
        let h3 = make_host("h3", "4.4.4.3");
        let id1 = h1.id.clone();
        let id3 = h3.id.clone();
        topo.register_host(h1).unwrap();
        topo.register_host(h2).unwrap();
        topo.register_host(h3).unwrap();

        let selected = topo.select_hosts(&HostSelector::ByIds(vec![id1, id3]));
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn host_count_tracks_registrations() {
        let mut topo = FleetTopology::new();
        assert_eq!(topo.host_count(), 0);
        assert!(topo.is_empty());

        topo.register_host(make_host("x", "5.5.5.5")).unwrap();
        assert_eq!(topo.host_count(), 1);
        assert!(!topo.is_empty());
    }
}
