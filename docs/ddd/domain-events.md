# Domain Events — Sentinel Event Taxonomy

This document defines all domain events in the Sentinel system. Domain events record significant state changes and occurrences within the domain. They are the basis for the audit log, cross-context integration, and event-driven UI updates.

## Event Conventions

All domain events follow these conventions:

- **Named in past tense:** Events record what has happened, not what is requested.
- **Immutable:** Once emitted, an event's content never changes.
- **Carry sufficient context:** Events contain enough information to be useful without re-querying the source aggregate.
- **Strongly typed:** Each event type has a defined payload schema.
- **Audit-logged:** All domain events listed here are written to the `AuditLog` as `AuditEvent` records.

**Common envelope fields** (present on all events):
- `event_id: EventId` — UUID v4 unique to this event
- `session_id: SessionId` — the session context (or a nil UUID for session-independent events)
- `occurred_at: Timestamp` — RFC 3339 timestamp with nanosecond precision
- `actor: ActorId` — `"agent"` for autonomous actions, operator identity for human actions

---

## Session Lifecycle Events

### GoalSubmitted

**Emitted by:** Agent / Reasoning Context  
**Trigger:** Operator provides a goal to start a new session

**Payload:**
- `goal_text: String` — the operator-stated goal
- `host: String` — target hostname or IP
- `llm_backend: String` — configured LLM backend name
- `policy_ruleset_id: String` — active policy ruleset identifier

**Significance:** Marks the beginning of a Session. The `session_id` in the event envelope is the newly created Session's ID. This event anchors all subsequent events in the session's audit chain.

---

### InvestigationStarted

**Emitted by:** Agent / Reasoning Context  
**Trigger:** Session phase transitions from Planning (or initial state) to Investigating

**Payload:**
- `investigation_number: u32` — 1 for initial investigation; > 1 for re-investigation after plan rejection

**Significance:** Signals the beginning of a read-only context gathering phase. All `CapabilityInvoked` events following this event (until `PlanProposed`) are read-only observations.

---

### ObservationRecorded

**Emitted by:** Agent / Reasoning Context  
**Trigger:** A read-only capability completes successfully during the Investigation phase

**Payload:**
- `observation_id: ObservationId` — unique ID for this observation
- `capability_id: CapabilityId` — the capability that produced this observation
- `summary: String` — LLM-generated or structured summary
- `observation_index: u32` — sequential index within this investigation phase

**Significance:** Documents the evidence base used by the LLM to generate the plan. In forensic analysis, the set of `ObservationRecorded` events explains why the agent proposed what it did.

---

### PlanProposed

**Emitted by:** Agent / Reasoning Context  
**Trigger:** The LLM generates a plan that passes policy pre-flight validation

**Payload:**
- `plan_id: PlanId` — unique ID for this plan version
- `step_count: u32` — number of steps in the plan
- `risk_tier_distribution: HashMap<String, u32>` — count of steps per risk tier
- `has_critical_steps: bool` — convenience flag for alerting
- `plan_summary: String` — LLM-generated plain-language plan summary
- `policy_preflight_status: String` — "passed" or details of any warnings

**Significance:** The plan is now visible to the operator for approval. If the plan is subsequently edited or rejected, this event documents the original proposal.

---

### PlanApproved

**Emitted by:** Presentation Context (forwarded from operator action)  
**Trigger:** Operator approves the proposed plan (with or without edits)

**Payload:**
- `plan_id: PlanId` — the approved plan ID
- `operator_id: ActorId` — identity of the approving operator
- `auto_approved: bool` — true if approval was automated per policy configuration
- `edits_made: bool` — true if the operator modified any steps before approving
- `edit_count: u32` — number of step modifications made

**Significance:** This event is the authorization record for execution. The `operator_id` and timestamp provide non-repudiation for the decision to execute. Auto-approval is recorded distinctly from manual approval for compliance purposes.

---

### PlanRejected

**Emitted by:** Presentation Context (forwarded from operator action)  
**Trigger:** Operator rejects the proposed plan

**Payload:**
- `plan_id: PlanId` — the rejected plan ID
- `operator_id: ActorId`
- `reason: String` — operator-provided rejection reason
- `return_to_planning: bool` — true if a new planning cycle should begin; false if session is aborted

**Significance:** Documents that a human reviewed and explicitly rejected a proposed plan. If `return_to_planning = true`, the rejection reason is fed back to the LLM as context for plan revision.

---

### PlanEdited

**Emitted by:** Presentation Context  
**Trigger:** Operator modifies one or more plan steps during the approval workflow

**Payload:**
- `plan_id: PlanId`
- `operator_id: ActorId`
- `edits: Vec<PlanEdit>` — list of step modifications
  - `step_index: usize`
  - `field_changed: String` — e.g., `"parameters.path"`, `"description"`
  - `old_value: serde_json::Value`
  - `new_value: serde_json::Value`

**Note:** This event is emitted for each editing session during plan review. A plan submitted after editing emits `PlanApproved` with `edits_made: true`.

---

### SessionCompleted

**Emitted by:** Agent / Reasoning Context  
**Trigger:** All plan steps complete successfully and verification (if configured) passes

**Payload:**
- `steps_executed: u32`
- `steps_succeeded: u32`
- `steps_failed: u32`
- `total_duration_ms: u64`
- `verification_passed: Option<bool>` — null if no verification phase was run

**Significance:** Marks the clean conclusion of a Session. Used for session-level SLO metrics and as the signal to archive the checkpoint.

---

### SessionAborted

**Emitted by:** Agent / Reasoning Context or Presentation Context  
**Trigger:** Session is terminated before completion (operator abort, unrecoverable error, kill switch activation)

**Payload:**
- `reason: AbortReason` — Operator / UnrecoverableError / KillSwitch / PolicyDenied / Timeout
- `phase_at_abort: SessionPhase` — the phase the session was in when aborted
- `steps_completed: u32` — number of successfully completed steps before abort
- `rollback_initiated: bool` — whether a rollback sequence was started
- `error_detail: Option<String>` — machine-readable error information

---

### SessionCheckpointed

**Emitted by:** Agent / Reasoning Context  
**Trigger:** A session checkpoint is written to durable storage

**Payload:**
- `checkpoint_file: String` — path to the checkpoint file (sanitized)
- `phase: SessionPhase` — session phase at checkpoint time
- `steps_completed: u32`
- `checkpoint_size_bytes: u64`
- `trigger: CheckpointTrigger` — PhaseTransition / StepCompletion / PeriodicInterval / Operator

---

## Capability Execution Events

### CapabilityInvoked

**Emitted by:** Execution Context  
**Trigger:** A capability invocation begins (both invoke and dry_run paths)

**Payload:**
- `capability_id: CapabilityId`
- `risk_tier: RiskTier`
- `parameters: serde_json::Value` — the (potentially redacted) parameter set
- `dry_run: bool`
- `step_index: Option<usize>` — plan step index, if invoked as part of a plan
- `timeout_ms: u64`

**Note:** Parameter redaction is applied to fields tagged `sensitive` in the capability's JSON Schema before logging.

---

### CapabilitySucceeded

**Emitted by:** Execution Context  
**Trigger:** A capability completes with `CapabilityResult::success = true`

**Payload:**
- `capability_id: CapabilityId`
- `step_index: Option<usize>`
- `duration_ms: u64`
- `output_summary: Option<String>` — truncated/summarized output for log readability
- `dry_run: bool`

---

### CapabilityFailed

**Emitted by:** Execution Context  
**Trigger:** A capability completes with `CapabilityResult::success = false`, or is terminated by timeout/resource limit

**Payload:**
- `capability_id: CapabilityId`
- `step_index: Option<usize>`
- `duration_ms: u64`
- `failure_reason: FailureReason` — Timeout / ResourceLimit / ProcessError / CapabilityError / ValidationError
- `error_message: String`
- `dry_run: bool`
- `rollback_available: bool` — whether an inverse capability exists

---

### CapabilityRolledBack

**Emitted by:** Execution Context  
**Trigger:** An inverse capability is successfully invoked to undo a previously completed step

**Payload:**
- `original_capability_id: CapabilityId` — the capability being undone
- `inverse_capability_id: CapabilityId` — the inverse that was invoked
- `original_step_index: usize`
- `rollback_step_index: usize` — index in the rollback sequence
- `duration_ms: u64`
- `success: bool`

---

## Policy Events

### PolicyEvaluated

**Emitted by:** Policy Context  
**Trigger:** The policy engine evaluates a capability invocation (or plan step)

**Payload:**
- `capability_id: CapabilityId`
- `risk_tier: RiskTier`
- `decision: PolicyEffect` — Allow or Deny
- `matching_rule_id: Option<RuleId>` — which rule produced the decision (None = default deny)
- `matching_rule_name: Option<String>` — human-readable rule name
- `evaluation_duration_us: u64` — microseconds for performance monitoring

---

### PolicyDenied

**Emitted by:** Policy Context  
**Trigger:** The policy engine denies a capability invocation

**Payload:**
- `capability_id: CapabilityId`
- `risk_tier: RiskTier`
- `reason: String` — human-readable denial reason
- `rule_id: Option<RuleId>` — rule that caused the denial (None = default deny)
- `kill_switch_active: bool` — true if denial was caused by an active kill switch
- `resource_guard_triggered: bool` — true if denial was caused by a resource threshold

**Note:** `PolicyDenied` is emitted in addition to `PolicyEvaluated` (which is always emitted) for clarity in SIEM alerting rules. Monitoring on `PolicyDenied` alone is sufficient for security alerting.

---

### PolicyApproved

**Emitted by:** Policy Context  
**Trigger:** The policy engine allows a capability invocation

**Payload:**
- `capability_id: CapabilityId`
- `risk_tier: RiskTier`
- `matching_rule_id: RuleId`
- `matching_rule_name: String`

**Note:** For Low-tier capabilities, `PolicyApproved` events may be suppressed in the audit log to reduce volume (configurable). `PolicyEvaluated` with decision=Allow is always written.

---

### KillSwitchActivated

**Emitted by:** Policy Context (triggered by Presentation Context command or API)  
**Trigger:** A kill switch is activated

**Payload:**
- `kill_switch_name: String`
- `risk_tier_threshold: RiskTier` — capabilities at this tier and above are now denied
- `scope: KillSwitchScope` — Session / Global
- `activated_by: ActorId`
- `active_sessions_affected: u32` — number of in-progress sessions affected

**Significance:** This is a high-priority security event that should trigger immediate alerting in SIEM integrations. A global kill switch activation affects all fleet hosts.

---

## Audit Infrastructure Events

### AuditEventRecorded

This is a meta-event emitted for monitoring purposes only — it is NOT written to the audit log itself (which would create infinite recursion). Instead, it increments the `sentinel_audit_events_written_total` Prometheus counter.

---

## Fleet Events

### HostRegistered

**Emitted by:** Fleet Context  
**Trigger:** A new host is registered with the fleet controller

**Payload:**
- `host_id: HostId`
- `hostname: String`
- `certificate_fingerprint: String`
- `platform: HostPlatform`
- `groups: Vec<GroupName>`

---

### HostDeregistered

**Emitted by:** Fleet Context  
**Trigger:** A host is removed from the fleet registry

**Payload:**
- `host_id: HostId`
- `hostname: String`
- `reason: DeregistrationReason` — Operator / Expired / Unreachable
- `sessions_affected: u32` — active sessions on this host at deregistration time

---

### FleetCommandDispatched

**Emitted by:** Fleet Context  
**Trigger:** The fleet controller dispatches a Plan to one or more agents

**Payload:**
- `plan_id: PlanId`
- `target_host_ids: Vec<HostId>`
- `target_group: Option<GroupName>` — if dispatched to a group
- `dispatch_mode: DispatchMode` — Parallel / Sequential / Staged
- `session_ids: Vec<SessionId>` — one session ID per target host

---

### StagedRolloutStarted

**Emitted by:** Fleet Context  
**Trigger:** A staged rollout begins (first stage dispatched)

**Payload:**
- `rollout_id: RolloutId`
- `plan_id: PlanId`
- `stage_count: u32` — total number of stages
- `first_stage_group: GroupName`
- `first_stage_host_count: u32`

---

### CanaryDeploymentStarted

**Emitted by:** Fleet Context  
**Trigger:** A canary deployment stage begins

**Payload:**
- `rollout_id: RolloutId`
- `canary_group: GroupName`
- `canary_host_count: u32`
- `baseline_group: GroupName`
- `observation_window_seconds: u64`
- `success_threshold: f64`

---

## Event Ordering and Consistency

Within a single **Session**, domain events are strictly ordered by their `occurred_at` timestamp and their position in the **AuditLog** hash chain. The expected event sequence for a successful session is:

```
GoalSubmitted
InvestigationStarted
  ObservationRecorded (× N)
  CapabilityInvoked (read-only) (× N)
  CapabilitySucceeded (× N)
PlanProposed
  PolicyEvaluated (× N, one per plan step, dry-run)
PlanApproved
  CapabilityInvoked (× N, executing phase)
    PolicyEvaluated (Allow)
    PolicyApproved
    CapabilitySucceeded
  SessionCheckpointed (periodically)
SessionCompleted
```

For a failed session with rollback:
```
... (as above through Executing phase)
CapabilityFailed
  CapabilityRolledBack (× M, where M = completed steps before failure)
SessionAborted (reason=UnrecoverableError, rollback_initiated=true)
```
