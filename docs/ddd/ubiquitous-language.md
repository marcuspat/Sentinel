# Ubiquitous Language — Sentinel Domain Glossary

This glossary defines the canonical terms used throughout the Sentinel codebase, documentation, and team communication. All code, ADRs, design discussions, and user-facing text must use these terms precisely and consistently. When a term has a specific, bounded meaning in Sentinel's domain, that domain meaning takes precedence over colloquial usage.

---

## Core Terms

### Session

A single end-to-end unit of agent work, scoped to one operator-stated **Goal** on one target host (or one fleet **HostGroup**). A Session progresses through the phases: **Investigating → Planning → Executing → Verifying → Completed** (or **Failed** / **Aborted**). Every capability invocation, policy decision, and approval decision is associated with exactly one Session. Sessions are the top-level unit of auditability: a `SessionId` (UUID v4) links together all `AuditEvent` records for a given piece of work.

A Session is the root aggregate of the domain. Its state is durable via **Session Checkpointing**.

### Goal

The natural language statement provided by the operator at the start of a Session, describing the desired end state or problem to diagnose. A Goal is unstructured text (e.g., "Ensure the nginx service is running and serving traffic on port 443"). The **Agent** interprets the Goal to drive the **Investigation** and **Planning** phases. A Goal does not prescribe specific actions — that is the **Plan**'s responsibility. Goals are immutable once a Session starts.

### Capability

The atomic unit of action in Sentinel. A Capability is a typed, self-describing unit of work that the agent can invoke against a target system. Every capability implements the `Capability` Rust trait, which requires a unique `capability_id`, a `risk_tier` classification, `invoke` and `dry_run` methods, a JSON parameter schema, and an optional `inverse` method. A Capability is not a shell command — it is a strongly-typed, policy-gatable, auditable action with known side effects and a defined undo procedure.

**Examples:** `fs.read_file`, `fs.write_file`, `process.restart_service`, `network.check_port`, `pkg.install_package`.

### CapabilityResult

The outcome of a single **Capability** invocation. Contains: a `success` boolean, a human-readable `message`, optional structured `output` (JSON), optional captured `stdout`/`stderr` from subprocesses, and the wall-clock `duration_ms`. A `CapabilityResult` is recorded in the **AuditLog** as the payload of a `CapabilityInvoked` or `CapabilityFailed` **AuditEvent**.

### Plan

A structured, ordered sequence of **PlanStep** records produced by the **Agent** during the **Planning** phase. A Plan is machine-readable (serialized as JSON), not a narrative description. A Plan must pass **Policy** pre-flight validation before being presented to the operator for **Approval**. Plans are immutable after **ApprovalDecision** is recorded — any modification (even minor parameter changes) requires a new approval cycle.

### PlanStep

A single step within a **Plan**. Each PlanStep identifies:
- A `capability_id` from the **CapabilityManifest**.
- A `parameters` map (JSON), validated against the capability's schema.
- A human-readable `description` of the expected effect.
- An `ExecutionStatus` (Pending / InProgress / Completed / Failed / Skipped / RolledBack).
- Zero or more `depends_on` step indices, enabling the **PlanOptimizer** to identify parallelism opportunities.

### RiskTier

A four-level classification of the potential harm of a **Capability** invocation. Assigned by the capability author and enforced by the **PolicyEngine**. The tiers are:

| Value | Label | Meaning |
|-------|-------|---------|
| 1 | `Low` | Read-only, no persistent side effects. Safe to execute without explicit approval. |
| 2 | `Medium` | Writes to non-critical paths, service restarts, non-sensitive configuration changes. |
| 3 | `High` | System path writes, data deletion, security-sensitive configuration, user management. |
| 4 | `Critical` | Irreversible destructive operations: drop database, remove system users, kernel parameter changes. Always requires explicit operator confirmation. |

### PolicyRule

A single declarative rule in the **PolicyRuleset** that specifies conditions under which a **Capability** invocation is allowed or denied. A PolicyRule contains: a `capability_id` pattern (exact or glob), an optional target path pattern, a `risk_tier` threshold, an `effect` (Allow / Deny), and optional conditions (time-of-day range, operator role, session context tags).

### PolicyDecision

The output of evaluating a **PolicyRule** set against a proposed capability invocation. A PolicyDecision is either `Allow` or `Deny`, accompanied by the matching rule(s) that produced the decision and a human-readable `reason` string. PolicyDecisions are recorded as `PolicyEvaluated` **AuditEvent** records.

### ApprovalDecision

The operator's response to a proposed **Plan** during the **Approve** phase. An ApprovalDecision captures: the `outcome` (Approved / Rejected / EditedAndApproved), the `operator_id` of the approving or rejecting party, a `timestamp`, and any `edits` made to the plan before approval. An ApprovalDecision is immutable once recorded. For plans containing only Low/Medium-tier steps and with auto-approve policy configured, the ApprovalDecision is synthetic (recorded as `"system"` actor).

### AuditEvent

A single, immutable record in the **AuditLog** capturing a domain event that occurred during a **Session**. Every AuditEvent contains: a UUID `event_id`, a `session_id`, an `event_type` (from the `AuditEventType` enum), a JSON `payload` with event-specific data, a precise `timestamp`, an `actor` identity, a `prev_hash` (the SHA-256 hash of the preceding entry), and an `entry_hash` (the SHA-256 hash of this entry's canonical serialization). AuditEvents are append-only and cannot be modified after writing.

### Agent

The autonomous reasoning component implemented by `sentinel-agent-llm`. The Agent accepts a **Goal**, drives the **Investigate → Plan → Approve → Act** workflow, interacts with the configured **LlmBackend** to generate plans and interpret observations, and emits domain events for logging. The Agent does not execute capabilities directly — it submits **Plans** to `sentinel-exec` after approval.

---

## Execution and Context Terms

### ExecutionContext

An immutable bundle of runtime context passed to every **Capability** invocation. Contains: the `session_id`, the target `host`, a `dry_run` flag, a `timeout_ms`, an optional `working_dir`, environment variable overrides, and **ResourceLimits**. A Capability must not modify its `ExecutionContext` — the context is owned by the execution harness. The `ExecutionContext` is serialized and recorded with each `CapabilityInvoked` **AuditEvent**.

### ResourceLimits

Hard constraints applied to every capability invocation: `max_output_bytes` (maximum captured stdout/stderr/output size), `max_cpu_time_ms` (wall-clock budget), and `max_memory_bytes` (optional memory ceiling). Enforced by `sentinel-exec` when spawning OS processes. Violations cause the capability to be terminated and a `CapabilityFailed` event to be emitted.

### CapabilityManifest

The registry of all **Capability** implementations available in a Sentinel deployment. The CapabilityManifest maps `capability_id` strings to `Capability` trait objects and their associated metadata: display name, description, parameter JSON schema, `RiskTier`, and availability (enabled / disabled). The **PolicyEngine** and the **Agent**'s prompt construction both depend on the CapabilityManifest to know what actions are available.

### InverseCapability

A **Capability** that reverses the side effects of another capability. Returned by the `inverse()` method of a Capability implementation. Used by the **PlanOptimizer** to automatically construct rollback chains. Not all capabilities have inverses — capabilities that produce irreversible effects (e.g., `pkg.remove_package` after data has been uninstalled) do not implement `inverse()`. The absence of an inverse is communicated to the operator during plan approval.

### RollbackCapability

A `PlanStep` in a dynamically constructed rollback plan, generated by invoking `inverse()` on each completed step in reverse order. RollbackCapability steps are subject to the same **PolicyDecision** process as forward plan steps, but are expedited (Human approval is recommended but can be configured as automatic for rollback to minimize recovery time).

---

## Policy and Safety Terms

### KillSwitch

A named policy override that, when activated, immediately denies all **Capability** invocations at or above a specified **RiskTier** for the current **Session** or globally (all sessions on all connected fleet hosts). Kill switches are activated by: operator keyboard shortcut in the TUI, REST API call, or automated anomaly detection trigger. Kill switch activation is recorded as a `KillSwitchActivated` **AuditEvent** with the activating actor's identity.

### PolicyRuleset

The complete set of **PolicyRule** records loaded by the **PolicyEngine** for evaluation. A PolicyRuleset is scoped to an environment (production, staging, development) and version-controlled. PolicyRulesets are loaded from TOML configuration files at Sentinel startup and can be reloaded without restarting the process.

### DryRun

A mode of **Capability** invocation where the capability's `dry_run(ctx)` method is called instead of `invoke(ctx)`. In dry-run mode, the capability must predict its effects and return a descriptive `CapabilityResult` without making any real changes to the target system. Every capability must implement `dry_run`. The **Planning** phase always uses dry-run invocations to populate the plan preview. Policy pre-flight evaluation uses dry-run mode.

---

## Fleet Terms

### Fleet

A collection of managed **Host** records under the control of a single Sentinel controller instance. A Fleet is represented by the `Fleet` aggregate in `sentinel-fleet`. Fleet operations dispatch **Plan** execution across multiple hosts with staged rollout support.

### Host

A single managed Linux machine registered with the Sentinel fleet controller. Each Host has: a unique `host_id`, a `hostname`/IP address, a pinned certificate fingerprint (for mTLS authentication), a set of **HostGroup** memberships, and a current operational status (connected/disconnected/executing/idle).

### HostGroup

A named set of **Host** records used to target fleet operations. HostGroups are used for staged rollouts (e.g., "canary" group gets changes first) and for policy scoping (policies can be group-specific). HostGroups can overlap — a host can belong to multiple groups.

### StagedRollout

A fleet deployment strategy where a **Plan** is applied to **Host** records in sequential stages rather than simultaneously. Each stage applies to a subset of hosts (defined by **HostGroup** or percentage). Progression between stages requires either manual approval or automated health verification. A StagedRollout that encounters failures in an early stage halts and does not proceed to later stages.

### CanaryDeployment

A special case of **StagedRollout** where a small subset of hosts ("canary" hosts) receive a change before the full fleet, and automated metrics analysis determines whether the rollout should proceed. The **FleetOrchestrator** collects health indicators from canary hosts after each stage and compares them against baseline metrics.

---

## Session Lifecycle Terms

### Observation

A structured fact about the target system gathered during the **Investigate** phase via a read-only **Capability** invocation. Observations are accumulated in the **Session** aggregate and form the LLM reasoning context for the **Planning** phase. Observations include the capability that produced them, the raw `CapabilityResult`, and a structured summary.

### SessionCheckpoint

A serialized snapshot of the complete **Session** aggregate state, written to durable storage after each significant state transition. A SessionCheckpoint enables crash recovery and session resumption without re-executing completed **PlanStep** records or re-running the investigation phase.

### SessionPhase

The current lifecycle phase of a **Session**: `Investigating`, `Planning`, `Executing`, `Verifying`, `Completed`, or `Failed`. Phase transitions are recorded as **AuditEvent** records. The `Verifying` phase is a read-only re-evaluation of system state after execution to confirm the **Goal** has been achieved.
