# Domain Services — Sentinel Cross-Aggregate Logic

This document defines the domain services in the Sentinel system. Domain services encapsulate domain logic that spans multiple aggregates or that does not naturally belong to a single aggregate root. Each service has a clearly defined responsibility, inputs, outputs, and the aggregates it coordinates.

---

## Service Design Principles

Domain services in Sentinel follow these rules:

1. **Stateless.** Domain services do not hold mutable state between invocations. They operate on aggregate instances passed in or retrieved from repositories.
2. **Domain logic only.** Services contain domain logic, not infrastructure concerns. Database access, network calls, and file I/O are handled by repositories and infrastructure adapters, not service implementations.
3. **Named with domain verbs.** Service method names describe meaningful domain operations, not technical operations (e.g., `evaluate_risk` not `compute_score`).
4. **Emit domain events.** When a service produces a significant state change, it emits the appropriate domain event rather than returning a raw data structure.

---

## 1. CapabilityRegistry

**Crate:** `sentinel-capabilities` (concrete implementations), `sentinel-core` (registry interface)  
**Type:** Application / Domain Service  
**Coordinates:** `CapabilityManifest` aggregate, `CapabilityRepository`

### Responsibility

The CapabilityRegistry is the service through which all **Capability** implementations are discovered, registered, validated, and looked up. It maintains the live `CapabilityManifest` and provides query methods used by the Agent, Policy, and Execution contexts.

### Core Operations

**`register(capability: Box<dyn Capability>) -> Result<(), RegistrationError>`**

Registers a new capability implementation. Validates:
- The `capability_id` is unique within the current manifest.
- The `capability_id` follows the `<domain>.<action>` naming convention.
- The parameter schema is valid JSON Schema (draft-07 or later).
- The `risk_tier` is explicitly declared.
- If `has_inverse = true`, the `inverse()` method returns a non-None value when called with a stub context.

Emits: No domain event (registration is a startup/configuration concern, not a runtime event).

**`deregister(capability_id: &CapabilityId) -> Result<(), RegistrationError>`**

Marks a capability as disabled in the manifest. Does not remove it from the manifest (preserving schema references for audit log entries). Capabilities invoked while disabled are treated as if the capability were absent.

**`lookup(capability_id: &CapabilityId) -> Option<&dyn Capability>`**

Returns a reference to the registered capability implementation, or `None` if not found or disabled.

**`validate_parameters(capability_id: &CapabilityId, params: &serde_json::Value) -> Result<(), ValidationError>`**

Validates a JSON parameter set against the capability's declared schema. Used by the `PlanExtractor` to validate LLM-generated plan steps before policy evaluation.

**`manifest() -> &CapabilityManifest`**

Returns the current `CapabilityManifest` for use by the Agent's prompt construction and the Policy Context's rule evaluation.

**`capabilities_for_llm_context() -> Vec<CapabilityDescription>`**

Returns a formatted list of capability summaries (ID, description, schema, risk tier) suitable for injection into the LLM's system prompt. Excludes disabled capabilities and optionally filters by allowed risk tiers based on the current policy configuration.

### Integration Points

- **Agent / Reasoning Context:** Calls `manifest()` and `capabilities_for_llm_context()` to build LLM prompts.
- **Policy Context:** Calls `lookup()` to verify that plan steps reference valid, enabled capabilities.
- **Execution Context:** Calls `lookup()` to retrieve the `Box<dyn Capability>` to invoke.
- **`sentinel-capabilities` crate:** Calls `register()` at startup to install all baseline capabilities.

---

## 2. RiskEvaluator

**Crate:** `sentinel-policy`  
**Type:** Domain Service  
**Coordinates:** `PolicyRuleset` aggregate, `CapabilityManifest` aggregate

### Responsibility

The RiskEvaluator computes a composite risk assessment for a proposed capability invocation, considering not only the capability's declared `RiskTier` but also contextual factors: the target path, session history, time of day, system resource state, and invocation patterns. It produces an advisory `RiskScore` and a `PolicyDecision`.

The RiskEvaluator is the core computational component of the Policy Context. The `PolicyEngine` delegates evaluation to the RiskEvaluator for each candidate invocation.

### Core Operations

**`evaluate(invocation: &CapabilityInvocation, context: &EvaluationContext) -> PolicyEvaluation`**

The primary evaluation method. Takes a proposed capability invocation and the current evaluation context, and returns a `PolicyEvaluation` containing:
- `decision: PolicyDecision` — Allow or Deny
- `matching_rule: Option<PolicyRule>` — the rule that produced the decision
- `risk_score: RiskScore` — composite risk score (0.0–1.0)
- `risk_factors: Vec<RiskFactor>` — individual factors contributing to the score
- `reason: String` — human-readable explanation of the decision

**`evaluate_plan(plan: &Plan, context: &EvaluationContext) -> PlanEvaluation`**

Evaluates all steps in a plan, returning per-step decisions and an aggregate plan-level risk assessment. Used for pre-flight policy evaluation. Short-circuits on the first `Deny` decision unless `evaluation_mode = Full` (which evaluates all steps and collects all violations).

**`compute_composite_score(invocation: &CapabilityInvocation, context: &EvaluationContext) -> RiskScore`**

Computes the numerical risk score independently of the binary Allow/Deny decision. Used for advisory risk display in the TUI and for canary deployment health assessment.

### Risk Factors

The RiskEvaluator considers the following factors when computing the composite score:

| Factor | Description | Weight |
|--------|-------------|--------|
| `CapabilityTierFactor` | The capability's declared `RiskTier` | High |
| `PathSensitivityFactor` | How sensitive the target path is (`/etc/ssh` > `/tmp`) | Medium |
| `TimeOfDayFactor` | Higher risk during off-hours or change freeze windows | Low |
| `SessionHistoryFactor` | Whether this session has already invoked many High-tier capabilities | Low |
| `FrequencyFactor` | Whether this capability type is being invoked at an unusual rate | Medium |
| `ResourceStateFactor` | Whether current system resource usage is near thresholds | Medium |

**`EvaluationContext`** (input to evaluation):
- `session: &Session` — current session state
- `ruleset: &PolicyRuleset` — active policy rules
- `manifest: &CapabilityManifest` — capability metadata
- `system_metrics: &SystemMetrics` — current CPU, memory, disk usage
- `timestamp: Timestamp` — evaluation time

---

## 3. PlanOptimizer

**Crate:** `sentinel-agent-llm`  
**Type:** Domain Service  
**Coordinates:** `Session` aggregate (Plan entity), `CapabilityManifest` aggregate

### Responsibility

The PlanOptimizer takes a raw `Plan` generated by the LLM and applies domain-level transformations:

1. **Dependency analysis:** Identifies the dependency graph from `PlanStep::depends_on` declarations and the capability's resource impact metadata.
2. **Parallelism detection:** Identifies steps that can be executed in parallel (no dependencies, no conflicting resource impact).
3. **Rollback chain construction:** For each step that has an `inverse()`, pre-computes the inverse capability and parameter set for the rollback sequence.
4. **Step ordering validation:** Verifies that the declared dependency order is consistent (no cycles) and that all `depends_on` indices refer to valid step indices.

### Core Operations

**`optimize(plan: &Plan, manifest: &CapabilityManifest) -> OptimizedPlan`**

Returns an `OptimizedPlan` that augments the original plan with:
- `execution_groups: Vec<ExecutionGroup>` — groups of steps that can execute in parallel
- `rollback_chain: Vec<RollbackStep>` — pre-computed inverse sequence
- `dependency_graph: DependencyGraph` — directed acyclic graph of step dependencies
- `estimated_duration_ms: u64` — estimated total execution time based on parallel grouping and capability `ResourceImpact`

**`build_rollback_chain(plan: &Plan, completed_steps: &[usize], manifest: &CapabilityManifest) -> RollbackChain`**

Constructs the rollback sequence for a set of completed steps. Called after a step failure to prepare for operator-approved rollback. Steps without an `inverse()` are flagged as `ManualRollbackRequired`.

**`validate_dependencies(plan: &Plan) -> Result<(), DependencyError>`**

Validates the dependency graph for cycles and invalid references. Returns an error if the plan has a circular dependency, which would make execution ordering impossible.

### Output Types

**`ExecutionGroup`:**
- `steps: Vec<usize>` — step indices that can execute in parallel
- `must_complete_before: Vec<usize>` — groups that must complete before this group starts

**`RollbackStep`:**
- `original_step_index: usize`
- `inverse_capability_id: CapabilityId`
- `inverse_parameters: serde_json::Value`
- `requires_manual_intervention: bool` — true if no `inverse()` exists

---

## 4. ApprovalWorkflow

**Crate:** `sentinel-agent-llm` (orchestration), `sentinel-tui` (presentation)  
**Type:** Application Service (spans Presentation and Agent contexts)  
**Coordinates:** `Session` aggregate, `PolicyRuleset` aggregate

### Responsibility

The ApprovalWorkflow service manages the human-in-the-loop plan approval process. It receives a validated plan from the PolicyEngine, presents it to the operator via the Presentation Context, handles operator interactions (edit, approve, reject), enforces approval requirements based on risk tier, and records the final `ApprovalDecision` in the Session aggregate.

### Core Operations

**`request_approval(plan: &Plan, evaluation: &PlanEvaluation, session: &mut Session) -> impl Future<Output = ApprovalResult>`**

Initiates the approval workflow for a given plan. Performs the following steps:

1. Checks `PolicyRuleset` for auto-approval eligibility (only if all steps are Low/Medium tier and the ruleset permits auto-approval).
2. If auto-approval is permitted, records a synthetic `ApprovalDecision` with `actor = "system"` and returns `ApprovalResult::AutoApproved`.
3. Otherwise, sends a `PlanReadyForApproval` notification to the Presentation Context and waits for an operator response.
4. Handles a timeout (configurable, default: no timeout) that, if exceeded, returns `ApprovalResult::Timeout`.

**`handle_edit(plan: &Plan, edit: &PlanEdit, manifest: &CapabilityManifest) -> Result<Plan, EditError>`**

Applies an operator's parameter edit to a plan step and re-validates the modified step against the capability schema. If the edit changes a step's risk tier (e.g., editing a path from `/tmp` to `/etc`), triggers re-evaluation of the full plan against the PolicyRuleset.

**`record_decision(session: &mut Session, decision: ApprovalDecision) -> AuditEvent`**

Applies the `ApprovalDecision` to the Session aggregate and emits either `PlanApproved` or `PlanRejected` domain events.

**`handle_rejection(session: &mut Session, reason: &str, return_to_planning: bool) -> RejectionOutcome`**

Processes an operator's plan rejection. If `return_to_planning = true`, formats the rejection reason into an LLM message and re-engages the `ReasoningLoop` for plan revision. If `return_to_planning = false`, transitions the session to `Failed`.

### Approval Requirements

| Condition | Approval Mode |
|-----------|--------------|
| All steps `Low` tier + auto-approve configured | Auto-approve |
| All steps `Low`/`Medium` tier + no auto-approve config | Manual approval required |
| Any step `High` tier | Manual approval mandatory (cannot be configured away) |
| Any step `Critical` tier | Explicit operator confirmation with typed confirmation string |

---

## 5. FleetOrchestrator

**Crate:** `sentinel-fleet`  
**Type:** Domain Service  
**Coordinates:** `Fleet` aggregate, `Session` aggregate (indirectly via session IDs)

### Responsibility

The FleetOrchestrator manages the dispatch of plans to multiple hosts, coordinates staged rollouts, monitors canary deployment health, and makes advancement decisions for multi-stage fleet operations.

### Core Operations

**`dispatch_to_fleet(plan: &Plan, targets: &FleetTargets, fleet: &Fleet) -> Result<DispatchResult, FleetError>`**

Dispatches an approved plan to a set of fleet hosts. Selects the appropriate dispatch mode:
- `Parallel`: Send to all target hosts simultaneously.
- `Sequential`: Send to hosts one at a time in order.
- `Staged`: Use the `StagedRollout` state machine.

For each target host, creates a per-host `Session` with a host-specific `ExecutionContext` and dispatches via the `FleetProtocol`.

**`run_staged_rollout(rollout: &mut StagedRollout, fleet: &Fleet) -> impl Future<Output = RolloutResult>`**

Drives a `StagedRollout` through its stages. For each stage:
1. Dispatches the plan to the stage's target `HostGroup`.
2. Monitors execution status from all target hosts.
3. Upon stage completion, evaluates advancement criteria (manual approval or automated health check).
4. If criteria pass, advances to the next stage. If they fail, pauses the rollout and notifies the operator.

**`evaluate_canary_health(rollout_id: RolloutId, canary_metrics: &HostMetrics, baseline_metrics: &HostMetrics, config: &CanaryConfig) -> CanaryHealthDecision`**

Compares health metrics from canary hosts against the baseline group. Metrics considered:
- Capability success rate
- Average capability execution duration
- System resource usage (CPU, memory, disk) post-execution
- Application-level health signals (if provided via a health capability)

Returns `CanaryHealthDecision::Advance` if metrics meet the `CanaryConfig::success_threshold`, or `CanaryHealthDecision::Abort` if they fall below it.

**`select_hosts(targets: &FleetTargets, fleet: &Fleet) -> Vec<HostId>`**

Resolves a `FleetTargets` specification (which may reference `HostGroup` names, individual `HostId` values, or tag-based selectors) to a concrete list of `HostId` values that are currently connected.

**`abort_rollout(rollout_id: RolloutId, fleet: &mut Fleet, reason: &str) -> Result<(), FleetError>`**

Halts all in-progress stage dispatches for a staged rollout, sends cancellation messages to executing agents, and records `SessionAborted` events for all affected sessions. Does not automatically initiate rollback — rollback is a separate operator-initiated action.

### Host Selection Logic

The `select_hosts` method resolves targets using the following precedence:

1. Explicit `HostId` list — used as-is after connectivity verification.
2. `GroupName` — resolved to all `connected` hosts in the named group.
3. Tag selector — resolved to all hosts whose tag set matches the selector expression.
4. Percentage selector — resolved to `N%` of hosts in the target group, selected deterministically by host registration order (to ensure reproducible stage composition).

If any selected host is in `Disconnected` or `Unreachable` status, dispatch to that host fails, and the overall dispatch result reflects the partial failure. Whether partial failures cause the full rollout to abort is configurable per rollout.
