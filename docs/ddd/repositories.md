# Repositories — Sentinel Persistence Interfaces

This document defines the repository interfaces in the Sentinel domain. Repositories are the abstraction layer between the domain model and the persistence infrastructure. Each repository defines the interface that the domain layer expects; concrete implementations live in infrastructure modules and are injected at application startup.

---

## Repository Design Principles

Sentinel's repositories follow these conventions:

1. **Domain-centric interfaces.** Repository methods use domain types (aggregates, value objects, domain IDs) as inputs and outputs, not raw database rows or file paths.
2. **Async-first.** All repository methods that perform I/O return `impl Future` (via `async fn` or `async-trait`). The domain layer does not block.
3. **Error types are domain errors.** Repository methods return `Result<T, RepositoryError>` where `RepositoryError` is a domain-level error type, not a database driver error. Infrastructure-specific errors are wrapped and translated.
4. **No query language in the interface.** Repository interfaces do not expose SQL, filter DSLs, or query builders. If a query is needed, it is expressed as a named method (e.g., `find_by_phase` rather than `find_where("phase = ?")`).
5. **Collections are bounded.** Methods that return multiple records specify a `limit` or return a `Page<T>` to prevent unbounded memory allocation.

---

## 1. SessionRepository

**Crate:** `sentinel-agent-llm`  
**Manages:** `Session` aggregate

### Interface

```
trait SessionRepository: Send + Sync {
    async fn save(&self, session: &Session) -> Result<(), RepositoryError>;
    async fn load(&self, id: &SessionId) -> Result<Option<Session>, RepositoryError>;
    async fn delete(&self, id: &SessionId) -> Result<(), RepositoryError>;

    async fn find_by_phase(&self, phase: SessionPhase) -> Result<Vec<SessionSummary>, RepositoryError>;
    async fn find_active_for_host(&self, host: &str) -> Result<Vec<SessionSummary>, RepositoryError>;
    async fn find_checkpointable(&self) -> Result<Vec<SessionId>, RepositoryError>;
    async fn list_recent(&self, limit: usize) -> Result<Vec<SessionSummary>, RepositoryError>;
}
```

### Method Semantics

**`save`** — Upserts the full `Session` aggregate. If the session does not exist, creates it. If it exists, replaces the stored version. The implementation must perform this as an atomic operation. For the checkpoint-based implementation, this writes a `SessionCheckpoint` JSON file atomically using rename-based replacement (see ADR-012).

**`load`** — Retrieves the full `Session` aggregate by ID. Returns `None` if no session with the given ID exists. The loaded session should include all observations, plan, approval decision, and execution state.

**`delete`** — Removes the session from storage. Called when a completed session's checkpoint is past its retention window and eligible for cleanup.

**`find_by_phase`** — Returns lightweight `SessionSummary` records for all sessions currently in a given phase. Used by the TUI's session list view and by the fleet controller's active session monitor. Returns summaries (not full aggregates) to avoid loading large LLM context blobs for list display.

**`find_active_for_host`** — Returns sessions in non-terminal phases targeting a specific host. Used to enforce single-active-session-per-host invariants in some policy configurations.

**`find_checkpointable`** — Returns session IDs for sessions that are in an active phase (Investigating / Planning / Executing / Verifying) and have been modified since their last checkpoint. Used by the checkpoint scheduler.

**`list_recent`** — Returns the most recent `N` sessions (by `updated_at`) as summaries. Used for the TUI's session history view.

### SessionSummary (view type)

A lightweight projection of the `Session` aggregate for list display:
- `session_id: SessionId`
- `goal_text: String` — truncated to 120 characters
- `phase: SessionPhase`
- `host: String`
- `created_at: Timestamp`
- `updated_at: Timestamp`
- `step_count: u32` — total plan steps
- `steps_completed: u32`

### Concrete Implementations

**`FileSystemSessionRepository`** — Stores sessions as JSON checkpoint files in `~/.sentinel/sessions/<session_id>.checkpoint.json`. Suitable for single-host deployments. Default implementation.

**`InMemorySessionRepository`** — Stores sessions in a `HashMap` in process memory. Used in tests and for ephemeral sessions that should not persist across restarts.

---

## 2. CapabilityRepository

**Crate:** `sentinel-capabilities`  
**Manages:** `CapabilityManifest` aggregate (specifically the registry of `CapabilityEntry` records)

### Interface

```
trait CapabilityRepository: Send + Sync {
    async fn load_manifest(&self) -> Result<CapabilityManifest, RepositoryError>;
    async fn save_manifest(&self, manifest: &CapabilityManifest) -> Result<(), RepositoryError>;

    async fn get_entry(&self, id: &CapabilityId) -> Result<Option<CapabilityEntry>, RepositoryError>;
    async fn list_entries(&self, filter: &CapabilityFilter) -> Result<Vec<CapabilityEntry>, RepositoryError>;
    async fn enable(&self, id: &CapabilityId) -> Result<(), RepositoryError>;
    async fn disable(&self, id: &CapabilityId) -> Result<(), RepositoryError>;
}
```

### Method Semantics

**`load_manifest`** — Loads the current `CapabilityManifest` from configuration storage. Called at startup by the `CapabilityRegistry` to initialize the registry. The manifest includes all registered capability metadata.

**`save_manifest`** — Persists the current manifest state after a capability is registered, enabled, or disabled. For the default TOML implementation, writes the manifest to `sentinel-capabilities.toml`.

**`get_entry`** — Returns the `CapabilityEntry` for a specific capability ID, or `None` if not found. Does not return the `Box<dyn Capability>` implementation — that is managed by the in-memory `CapabilityRegistry`, not the repository.

**`list_entries`** — Returns `CapabilityEntry` records matching a `CapabilityFilter`. Filters supported:
- `enabled_only: bool` — exclude disabled capabilities
- `risk_tier_max: Option<RiskTier>` — exclude capabilities above this tier
- `tags: Vec<String>` — include only capabilities with all specified tags

**`enable` / `disable`** — Toggle the `enabled` flag on a `CapabilityEntry` and persist. Enabling a capability that does not exist in the manifest returns `RepositoryError::NotFound`.

### CapabilityFilter (value type)

```
struct CapabilityFilter {
    enabled_only: bool,
    risk_tier_max: Option<RiskTier>,
    tags: Vec<String>,           // All specified tags must match (AND semantics)
    id_pattern: Option<String>,  // Glob pattern for capability ID filtering
}
```

### Concrete Implementations

**`TomlCapabilityRepository`** — Stores capability metadata in a TOML configuration file. The `Box<dyn Capability>` implementations are registered in code; the TOML file stores only metadata overrides (enabled/disabled, custom descriptions). Default implementation.

**`InMemoryCapabilityRepository`** — Used in tests. All capability entries are pre-loaded at construction time.

---

## 3. PolicyRepository

**Crate:** `sentinel-policy`  
**Manages:** `PolicyRuleset` aggregate

### Interface

```
trait PolicyRepository: Send + Sync {
    async fn load_ruleset(&self, id: &RulesetId) -> Result<PolicyRuleset, RepositoryError>;
    async fn save_ruleset(&self, ruleset: &PolicyRuleset) -> Result<(), RepositoryError>;
    async fn reload_ruleset(&self, id: &RulesetId) -> Result<PolicyRuleset, RepositoryError>;

    async fn list_rulesets(&self) -> Result<Vec<RulesetSummary>, RepositoryError>;
    async fn get_kill_switch_state(&self, name: &str) -> Result<Option<KillSwitchState>, RepositoryError>;
    async fn set_kill_switch(&self, name: &str, active: bool, actor: &ActorId) -> Result<(), RepositoryError>;
}
```

### Method Semantics

**`load_ruleset`** — Loads a `PolicyRuleset` from configuration storage. Called at startup and after a SIGHUP-triggered configuration reload. The `RulesetId` typically maps to an environment name (`"production"`, `"staging"`).

**`save_ruleset`** — Persists a modified `PolicyRuleset`. Used when policy rules are dynamically updated via the management API (not standard operational flow — rule changes are normally made via configuration files and `reload_ruleset`).

**`reload_ruleset`** — Reloads the ruleset from its backing configuration file, picking up any changes made since the last load. Returns the newly loaded ruleset. The calling code is responsible for swapping the active ruleset in the `PolicyEngine`.

**`list_rulesets`** — Returns summaries of all available rulesets. Used by the TUI's policy configuration view to show which rulesets are available and which is currently active.

**`get_kill_switch_state`** — Returns the current activation state of a named kill switch, or `None` if no kill switch with that name exists. Used by the `PolicyEngine` to check kill switch state before evaluation.

**`set_kill_switch`** — Activates or deactivates a named kill switch. Records the activating actor's identity and timestamp. This method has immediate effect — the next policy evaluation will reflect the new kill switch state. Emits `KillSwitchActivated` domain event.

### RulesetSummary (view type)

- `ruleset_id: RulesetId`
- `rule_count: u32`
- `kill_switch_count: u32`
- `default_effect: PolicyEffect`
- `loaded_at: Timestamp`
- `version: String`

### Concrete Implementations

**`TomlPolicyRepository`** — Loads policy rules from TOML configuration files. Supports hot-reload via `reload_ruleset`. Kill switch state is persisted to a separate state file to survive process restarts. Default implementation.

**`InMemoryPolicyRepository`** — Stores rulesets and kill switch state in memory. Used in tests and for default-allow development mode (single rule: allow everything).

---

## 4. AuditRepository

**Crate:** `sentinel-audit`  
**Manages:** `AuditLog` aggregate

### Interface

```
trait AuditRepository: Send + Sync {
    async fn append(&self, event: AuditEvent) -> Result<(), RepositoryError>;
    async fn get_event(&self, id: &EventId) -> Result<Option<AuditEvent>, RepositoryError>;
    async fn get_events_for_session(
        &self,
        session_id: &SessionId,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditEvent>, RepositoryError>;
    async fn get_recent_events(
        &self,
        limit: usize,
        filter: &AuditEventFilter,
    ) -> Result<Vec<AuditEvent>, RepositoryError>;
    async fn verify_chain(
        &self,
        start_event_id: Option<&EventId>,
        end_event_id: Option<&EventId>,
    ) -> Result<ChainVerificationResult, RepositoryError>;
    async fn export(
        &self,
        config: &ExportConfig,
        start_event_id: Option<&EventId>,
    ) -> Result<(), RepositoryError>;
    async fn get_head_hash(&self) -> Result<Hash, RepositoryError>;
    async fn entry_count(&self) -> Result<u64, RepositoryError>;
}
```

### Method Semantics

**`append`** — Appends a new `AuditEvent` to the log. Computes the `entry_hash` (SHA-256 of the canonical serialization including `prev_hash`) and updates the `head_hash`. This operation must be atomic — either the event is fully written with correct hashes, or it is not written at all. Concurrent append calls must be serialized.

**`get_event`** — Retrieves a single event by ID. Used for event-level audit queries and forensic investigation.

**`get_events_for_session`** — Returns paginated `AuditEvent` records for a given session, ordered by `occurred_at`. Used by the TUI's audit log browser and for session-scoped forensic analysis.

**`get_recent_events`** — Returns the most recent `N` events matching an `AuditEventFilter`. Used by the TUI's live audit event stream and SIEM export monitoring.

**`verify_chain`** — Recomputes the hash chain over a range of events and verifies integrity. Returns a `ChainVerificationResult` indicating whether the chain is intact, and if not, which entries have hash mismatches. If `start_event_id = None`, verification starts from the genesis entry. If `end_event_id = None`, verification runs to the most recent entry.

**`export`** — Streams events to the configured `ExportDestination` in the configured `ExportFormat`. Resumes from `start_event_id` if provided (for incremental SIEM export). Handles connection errors with exponential backoff for TCP/UDP destinations.

**`get_head_hash`** — Returns the hash of the most recently written entry. Used by `AuditLog` to compute `prev_hash` for new entries, and by monitoring to detect unexpected modifications.

**`entry_count`** — Returns the total number of entries in the log. Used for Prometheus metrics and for estimating chain verification time.

### AuditEventFilter (value type)

```
struct AuditEventFilter {
    event_types: Option<Vec<AuditEventType>>, // Include only these event types
    session_id: Option<SessionId>,            // Scope to a specific session
    actor: Option<ActorId>,                   // Filter by actor
    since: Option<Timestamp>,                 // Events after this time
    until: Option<Timestamp>,                 // Events before this time
    risk_tier_min: Option<RiskTier>,          // For capability events: minimum risk tier
}
```

### ChainVerificationResult

```
struct ChainVerificationResult {
    verified_entry_count: u64,
    is_intact: bool,
    first_violation: Option<ChainViolation>,
    violations: Vec<ChainViolation>,
}

struct ChainViolation {
    event_id: EventId,
    entry_index: u64,
    violation_type: ViolationType, // HashMismatch / MissingEntry / UnexpectedEntry
    expected_hash: Hash,
    actual_hash: Hash,
}
```

### Concrete Implementations

**`AppendFileAuditRepository`** — Writes events as newline-delimited JSON to an append-only file. Uses atomic writes (write to `.tmp`, then `rename`). Maintains an in-memory index of event IDs to file offsets for `get_event` lookups. Default implementation.

**`InMemoryAuditRepository`** — Stores events in a `Vec<AuditEvent>` in memory. Used in tests. Hash chain is computed correctly but is lost on process exit.

---

## 5. FleetRepository

**Crate:** `sentinel-fleet`  
**Manages:** `Fleet` aggregate

### Interface

```
trait FleetRepository: Send + Sync {
    async fn load_fleet(&self) -> Result<Fleet, RepositoryError>;
    async fn save_fleet(&self, fleet: &Fleet) -> Result<(), RepositoryError>;

    async fn get_host(&self, id: &HostId) -> Result<Option<Host>, RepositoryError>;
    async fn get_host_by_hostname(&self, hostname: &str) -> Result<Option<Host>, RepositoryError>;
    async fn list_hosts(&self, filter: &HostFilter) -> Result<Vec<Host>, RepositoryError>;
    async fn save_host(&self, host: &Host) -> Result<(), RepositoryError>;
    async fn delete_host(&self, id: &HostId) -> Result<(), RepositoryError>;

    async fn get_group(&self, name: &GroupName) -> Result<Option<HostGroup>, RepositoryError>;
    async fn list_groups(&self) -> Result<Vec<HostGroup>, RepositoryError>;
    async fn save_group(&self, group: &HostGroup) -> Result<(), RepositoryError>;

    async fn get_rollout(&self, id: &RolloutId) -> Result<Option<StagedRollout>, RepositoryError>;
    async fn list_active_rollouts(&self) -> Result<Vec<StagedRollout>, RepositoryError>;
    async fn save_rollout(&self, rollout: &StagedRollout) -> Result<(), RepositoryError>;
    async fn complete_rollout(&self, id: &RolloutId) -> Result<(), RepositoryError>;
}
```

### Method Semantics

**`load_fleet` / `save_fleet`** — Load and save the full `Fleet` aggregate. The fleet state is loaded at controller startup and saved after any host registration, deregistration, or group change.

**`get_host` / `get_host_by_hostname`** — Retrieve a `Host` entity by ID or by hostname. The `get_host_by_hostname` query is used during certificate pinning verification to look up the expected fingerprint for a connecting agent.

**`list_hosts`** — Returns hosts matching a `HostFilter`. Filters include:
- `status: Option<HostStatus>` — filter by current status
- `group: Option<GroupName>` — filter by group membership
- `tags: Vec<String>` — filter by host tags (AND semantics)

**`save_host`** — Upserts a `Host` entity. Called after registration, status update, or certificate rotation.

**`delete_host`** — Removes a `Host` from the fleet registry. Only valid for hosts in `Disconnected` or `Registered` (never connected) status.

**`get_group` / `list_groups` / `save_group`** — Manage `HostGroup` entities within the `Fleet` aggregate.

**`get_rollout` / `list_active_rollouts` / `save_rollout` / `complete_rollout`** — Manage `StagedRollout` entities. `list_active_rollouts` returns rollouts in `InProgress` or `Paused` status. `complete_rollout` transitions a rollout to `Completed` status and archives it.

### HostFilter (value type)

```
struct HostFilter {
    status: Option<HostStatus>,
    group: Option<GroupName>,
    tags: Vec<String>,
    hostname_pattern: Option<String>, // glob
}
```

### Concrete Implementations

**`JsonFileFleetRepository`** — Stores the fleet registry as a JSON file (`~/.sentinel/fleet.json`). Host status is updated in-place (the fleet file is fully rewritten on each save, atomically). Default implementation for single-controller deployments.

**`InMemoryFleetRepository`** — Stores fleet state in memory. Used in tests and for ephemeral fleet configurations that do not need to survive process restarts.

---

## Repository Error Types

All repositories share a common `RepositoryError` type:

```
enum RepositoryError {
    NotFound { entity: String, id: String },
    Conflict { entity: String, id: String, reason: String },
    IoError { operation: String, source: std::io::Error },
    SerializationError { source: serde_json::Error },
    StorageFull,
    PermissionDenied { path: String },
    InvalidState { message: String },
}
```

Infrastructure-specific error types (filesystem errors, network errors) are translated into `RepositoryError::IoError` at the implementation boundary. The domain layer never handles raw `std::io::Error` or storage driver errors.
