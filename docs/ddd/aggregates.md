# Aggregates — Sentinel Domain Model

This document defines the aggregates in the Sentinel domain. Each aggregate has a clearly identified root entity, associated entities, and value objects. Aggregates enforce their own consistency rules and are the unit of transactional consistency.

---

## Aggregate Design Principles

In Sentinel's domain model, aggregates follow these rules:

1. **One transaction, one aggregate.** State changes are applied to exactly one aggregate at a time. Cross-aggregate operations are coordinated via domain events, not direct method calls.
2. **External references by identity only.** Aggregates reference each other by ID (e.g., `SessionId`, `HostId`), never by direct object reference. This prevents cascading loads and enforces boundary integrity.
3. **The root owns consistency.** Only the aggregate root's methods may modify the aggregate's internal state. Internal entities and value objects are not exposed as mutable references.
4. **Value objects are immutable.** All value objects are immutable structs. Changing a value object means creating a new one.

---

## Aggregate 1: Session

**Aggregate Root:** `Session`  
**Bounded Context:** Agent / Reasoning Context (`sentinel-agent-llm`), with serialized state stored via checkpointing  
**Repository:** `SessionRepository`

### Purpose

The Session aggregate represents a complete unit of agent work from goal submission to completion. It is the top-level domain object that owns the lifecycle of a single operator-directed task.

### Root Entity: Session

**Identity:** `SessionId` (UUID v4)

**State fields:**
- `session_id: SessionId` — immutable identity
- `goal: Goal` — the operator-stated objective (immutable after creation)
- `phase: SessionPhase` — current lifecycle phase (mutable, transitions are validated)
- `created_at: Timestamp` — session creation time (immutable)
- `updated_at: Timestamp` — time of last state change
- `host: HostRef` — target host identity (immutable after creation)
- `observations: Vec<Observation>` — read-only facts gathered during investigation
- `plan: Option<Plan>` — the proposed execution plan (set during Planning phase)
- `approval: Option<ApprovalDecision>` — operator approval record (set during Approve phase)
- `execution_state: ExecutionState` — per-step execution status and results
- `checkpoint: Option<SessionCheckpoint>` — most recent checkpoint reference
- `llm_context: LlmContext` — accumulated LLM conversation state

**Invariants:**
- `phase` can only advance through the defined `SessionPhase` state machine (Investigating → Planning → Executing → Verifying → Completed; or any phase → Failed/Aborted)
- `plan` must be `Some` before phase can advance to Executing
- `approval` must be `Some(Approved)` before phase can advance to Executing
- `observations` are append-only — existing observations cannot be removed
- Phase transition to Executing fires `PlanApproved` domain event; transition to Failed fires `SessionAborted`

### Child Entity: Observation

**Identity:** `ObservationId` (UUID v4)

- `observation_id: ObservationId`
- `session_id: SessionId` — parent reference
- `capability_id: CapabilityId` — which capability produced this observation
- `result: CapabilityResult` — the raw result from the read-only capability
- `summary: String` — LLM-generated or structured summary of the observation
- `observed_at: Timestamp`

### Child Entity: ExecutionState

Tracks the per-step status of plan execution.

- `steps: Vec<StepStatus>` — one entry per PlanStep, in order
- `current_step_index: Option<usize>` — index of currently executing step

**StepStatus (value object):**
- `step_index: usize`
- `capability_id: CapabilityId`
- `status: ExecutionStatus` (Pending / InProgress / Completed / Failed / Skipped / RolledBack)
- `result: Option<CapabilityResult>` — set when status is Completed or Failed
- `started_at: Option<Timestamp>`
- `completed_at: Option<Timestamp>`

### Value Objects

**Goal:**
- `text: String` — operator-stated goal text
- `submitted_by: ActorId` — identity of the submitting operator
- `submitted_at: Timestamp`

**Plan:**
- `plan_id: PlanId` (UUID v4) — unique identifier for this plan version
- `steps: Vec<PlanStep>` — ordered list of capability invocations
- `generated_at: Timestamp`
- `policy_preflight_result: PolicyPreflightResult` — result of pre-flight policy evaluation

**PlanStep:**
- `step_index: usize`
- `capability_id: CapabilityId`
- `parameters: serde_json::Value` — validated against capability schema
- `description: String`
- `depends_on: Vec<usize>` — indices of prerequisite steps
- `risk_tier: RiskTier`
- `dry_run_result: Option<CapabilityResult>` — pre-flight dry-run result

**ApprovalDecision:**
- `outcome: ApprovalOutcome` (Approved / Rejected / EditedAndApproved)
- `actor_id: ActorId`
- `approved_at: Timestamp`
- `edits: Vec<PlanEdit>` — parameter changes made during approval
- `rejection_reason: Option<String>`

**LlmContext:**
- `backend: String` — name of the active LlmBackend
- `messages: Vec<LlmMessage>` — accumulated conversation (truncated to context window)
- `total_tokens_used: u64`

---

## Aggregate 2: CapabilityManifest

**Aggregate Root:** `CapabilityManifest`  
**Bounded Context:** Core Domain / Capabilities Context (`sentinel-core`, `sentinel-capabilities`)  
**Repository:** `CapabilityRepository`

### Purpose

The CapabilityManifest aggregate owns the registry of all available capabilities. It is the authoritative source for what actions the agent can take, their schemas, risk classifications, and inverse relationships.

### Root Entity: CapabilityManifest

**Identity:** Singleton per deployment (manifest version is the identity)

**State fields:**
- `version: ManifestVersion` — semantic version of this manifest
- `entries: HashMap<CapabilityId, CapabilityEntry>` — registered capabilities by ID
- `loaded_at: Timestamp`

**Invariants:**
- `capability_id` values are unique within the manifest
- A capability can only be registered once per manifest version
- Disabling a capability in the manifest does not remove it — it sets `enabled = false`, preventing invocation while preserving the schema for audit log reference

### Child Entity: CapabilityEntry

**Identity:** `CapabilityId` (string, e.g., `"fs.write_file"`)

- `capability_id: CapabilityId`
- `name: String` — human-readable display name
- `description: String` — detailed description for operator presentation
- `risk_tier: RiskTier` — Low / Medium / High / Critical
- `schema: serde_json::Value` — JSON Schema for capability parameters
- `has_inverse: bool` — whether `inverse()` is implemented
- `resource_impact: ResourceImpact` — expected CPU/memory/disk impact classification
- `enabled: bool` — whether this capability is currently available for invocation
- `tags: Vec<String>` — categories for filtering (e.g., "filesystem", "networking", "package-management")

### Value Objects

**CapabilityId:**
- Dot-namespaced string identifier: `"<domain>.<action>"` format (e.g., `"fs.read_file"`, `"process.kill"`)
- Immutable once registered

**ResourceImpact:**
- `cpu_intensity: Intensity` (Negligible / Low / Medium / High)
- `memory_delta_mb: Option<i64>` — expected memory change (positive = increase)
- `disk_writes_mb: Option<u64>` — expected disk write volume
- `network_calls: bool` — whether this capability makes network connections

**ManifestVersion:**
- `major: u32`
- `minor: u32`
- `patch: u32`

---

## Aggregate 3: PolicyRuleset

**Aggregate Root:** `PolicyRuleset`  
**Bounded Context:** Policy Context (`sentinel-policy`)  
**Repository:** `PolicyRepository`

### Purpose

The PolicyRuleset aggregate owns the complete set of policy rules, kill switch configurations, and resource guards that determine which capability invocations are permitted.

### Root Entity: PolicyRuleset

**Identity:** `RulesetId` — typically scoped to an environment name (e.g., `"production"`, `"staging"`)

**State fields:**
- `ruleset_id: RulesetId`
- `rules: Vec<PolicyRule>` — ordered list; earlier rules have higher precedence
- `kill_switches: Vec<KillSwitchConfig>` — named kill switch definitions
- `resource_guards: Vec<ResourceGuard>` — resource threshold rules
- `default_effect: PolicyEffect` — Deny (always Deny in production; Allow only in development mode)
- `loaded_at: Timestamp`
- `version: String` — for audit log reference (git SHA or config file hash)

**Invariants:**
- `default_effect` must be `Deny` unless development mode is explicitly configured
- Rule precedence is determined by list order — rules are evaluated in sequence; first match wins
- Kill switch configurations are named and can be activated/deactivated without modifying the rule list

### Child Entity: PolicyRule

**Identity:** `RuleId` (UUID v4)

- `rule_id: RuleId`
- `name: String` — descriptive name for audit log references
- `capability_pattern: CapabilityPattern` — exact ID or glob (e.g., `"fs.*"`, `"pkg.install_*"`)
- `path_pattern: Option<PathPattern>` — target path constraint (e.g., `"/etc/**"`, `"/var/log/*"`)
- `risk_tier_threshold: Option<RiskTier>` — minimum tier to apply this rule
- `effect: PolicyEffect` (Allow / Deny)
- `conditions: Vec<RuleCondition>` — time-of-day, operator role, session tags

### Child Entity: KillSwitchConfig

- `name: String` — human-readable name (e.g., `"emergency-stop"`)
- `risk_tier_threshold: RiskTier` — deny all capabilities at or above this tier when active
- `scope: KillSwitchScope` (Session / Global)
- `active: bool` — current activation state
- `activated_by: Option<ActorId>`
- `activated_at: Option<Timestamp>`

### Value Objects

**PolicyEffect:**
- `Allow` — permit the capability invocation
- `Deny` — reject with a reason

**CapabilityPattern:**
- `pattern: String` — glob pattern matching capability IDs
- `is_glob: bool`

**ResourceGuard:**
- `metric: SystemMetric` (DiskUsagePercent / MemoryUsagePercent / LoadAverage)
- `threshold: f64`
- `effect: PolicyEffect`
- `message: String` — denial message when threshold exceeded

**RuleCondition:**
- Time window: `allowed_hours: Option<(u8, u8)>` — (start_hour, end_hour)
- Role requirement: `required_role: Option<String>`
- Tag requirement: `required_session_tag: Option<String>`

---

## Aggregate 4: Fleet

**Aggregate Root:** `Fleet`  
**Bounded Context:** Fleet Context (`sentinel-fleet`)  
**Repository:** `FleetRepository`

### Purpose

The Fleet aggregate owns the topology of the managed host network, host registration, group membership, and staged rollout state. It is the authoritative source for which hosts are registered, trusted, and in which groups.

### Root Entity: Fleet

**Identity:** `FleetId` — typically the controller's hostname or a configured fleet name

**State fields:**
- `fleet_id: FleetId`
- `hosts: HashMap<HostId, Host>` — all registered hosts
- `host_groups: HashMap<GroupName, HostGroup>` — named groups of hosts
- `active_rollouts: Vec<StagedRollout>` — in-progress staged deployments
- `canary_configs: HashMap<GroupName, CanaryConfig>` — per-group canary configuration
- `created_at: Timestamp`

**Invariants:**
- A `Host` can belong to multiple `HostGroup` records
- A `Host` must be registered (fingerprint verified) before any Plan can be dispatched to it
- `StagedRollout` progression requires either manual approval or passing `CanaryConfig` health criteria
- Deregistering a `Host` while it is executing a Plan requires explicit force flag

### Child Entity: Host

**Identity:** `HostId` (UUID v4)

- `host_id: HostId`
- `hostname: String` — FQDN or IP address
- `certificate_fingerprint: CertificateFingerprint` — SHA-256 fingerprint for mTLS pinning
- `status: HostStatus` (Registered / Connected / Disconnected / Executing / Unreachable)
- `groups: Vec<GroupName>` — group memberships
- `registered_at: Timestamp`
- `last_seen_at: Option<Timestamp>`
- `platform: HostPlatform` — OS/architecture information

### Child Entity: HostGroup

**Identity:** `GroupName` (string)

- `name: GroupName`
- `description: String`
- `host_ids: Vec<HostId>` — member hosts
- `tags: Vec<String>` — metadata tags for policy scoping

### Child Entity: StagedRollout

- `rollout_id: RolloutId` (UUID v4)
- `plan_id: PlanId` — the plan being rolled out
- `stages: Vec<RolloutStage>` — ordered deployment stages
- `current_stage: usize`
- `status: RolloutStatus` (Pending / InProgress / Paused / Completed / Aborted)
- `created_at: Timestamp`

**RolloutStage (value object):**
- `stage_index: usize`
- `target_group: GroupName`
- `host_subset: Option<f32>` — percentage of group hosts (None = all)
- `advancement_criteria: AdvancementCriteria`
- `status: StageStatus`

### Value Objects

**CertificateFingerprint:**
- `algorithm: HashAlgorithm` (SHA256)
- `hex_digest: String` — 64-character hex SHA-256 digest

**CanaryConfig:**
- `canary_group: GroupName` — group receiving changes first
- `baseline_group: GroupName` — control group for comparison
- `observation_window_seconds: u64`
- `success_threshold: f64` — minimum success rate to advance
- `rollback_on_failure: bool`

**HostPlatform:**
- `os: String` (e.g., `"linux"`)
- `arch: String` (e.g., `"x86_64"`, `"aarch64"`)
- `distro: Option<String>` (e.g., `"ubuntu-22.04"`)

---

## Aggregate 5: AuditLog

**Aggregate Root:** `AuditLog`  
**Bounded Context:** Audit Context (`sentinel-audit`)  
**Repository:** `AuditRepository`

### Purpose

The AuditLog aggregate owns the append-only, hash-chained record of all domain events. It is the authoritative, tamper-evident history of everything Sentinel has done.

### Root Entity: AuditLog

**Identity:** `AuditLogId` — typically scoped to a deployment (instance-level singleton)

**State fields:**
- `log_id: AuditLogId`
- `entry_count: u64` — monotonically increasing entry counter
- `head_hash: Hash` — SHA-256 hash of the most recently written entry
- `storage_path: PathBuf` — location of the log file
- `export_config: ExportConfig` — current SIEM export configuration

**Invariants:**
- Entries are append-only — no update or delete operations exist
- Each new entry's `prev_hash` must equal the current `head_hash` before write
- `head_hash` is updated atomically with the file write (via rename-based atomic write)
- `entry_count` is monotonically increasing and cannot be decremented

### Child Entity: AuditEvent

**Identity:** `EventId` (UUID v4)

- `event_id: EventId`
- `session_id: SessionId` — session this event belongs to
- `event_type: AuditEventType` — typed enum of event kinds
- `payload: serde_json::Value` — event-specific structured data
- `timestamp: Timestamp` — RFC 3339 with nanosecond precision
- `actor: ActorId` — operator identity or `"agent"` for autonomous actions
- `prev_hash: Hash` — SHA-256 of the preceding entry
- `entry_hash: Hash` — SHA-256 of this entry's canonical serialization

### Value Objects

**Hash:**
- `algorithm: HashAlgorithm` (SHA256)
- `hex_digest: String` — 64-character hex digest

**ExportConfig:**
- `format: ExportFormat` (JsonLines / Cef / Syslog)
- `destination: ExportDestination` (Stdout / File(PathBuf) / Tcp(SocketAddr) / Udp(SocketAddr))
- `filter: Option<EventTypeFilter>` — optional subset of event types to export

**AuditEventType** (enum):
```
GoalSubmitted | InvestigationStarted | ObservationRecorded |
PlanProposed | PlanApproved | PlanRejected | PlanEdited |
CapabilityInvoked | CapabilitySucceeded | CapabilityFailed | CapabilityRolledBack |
PolicyEvaluated | PolicyDenied | PolicyApproved | KillSwitchActivated |
SessionCompleted | SessionAborted | SessionCheckpointed |
HostRegistered | HostDeregistered | FleetCommandDispatched |
StagedRolloutStarted | CanaryDeploymentStarted
```
