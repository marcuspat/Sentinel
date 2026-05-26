# ADR-005: Investigate → Plan → Approve → Act Workflow

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Architecture, Workflow, Safety, Human-in-the-Loop

---

## Context

Autonomous agents that interact with production infrastructure must balance operational speed against the risk of unrecoverable mistakes. Two failure modes must be avoided:

1. **Action without understanding.** An agent that immediately starts making changes without first gathering system state context will likely make incorrect or destructive changes, because it is operating on assumptions rather than facts.
2. **Action without oversight.** An agent that takes irreversible actions without giving a human the opportunity to review and approve the proposed changes creates unacceptable risk for production systems.

Traditional automation tools (Ansible, Salt, Terraform) address this partially with dry-run modes and plan previews. However, they do not have a reasoning loop that generates plans from natural language goals — they require the operator to write the automation themselves. Sentinel's LLM-driven reasoning loop introduces a new category of risk: the LLM may propose a technically valid but contextually wrong plan.

The workflow model must address:

- **Context gathering before planning.** The LLM needs accurate system state to generate a correct plan. Observations gathered in a read-only phase provide this without risk.
- **Structured plan representation.** The plan must be machine-readable (for policy evaluation, dry-run, and audit) rather than just a textual description.
- **Human approval gate.** The operator must be able to review, edit, and approve or reject the plan before any changes are made.
- **Constrained execution.** Once approved, execution must be limited strictly to the approved plan steps and must not allow the LLM to deviate based on new observations during execution.

The workflow model is also reflected in the `SessionPhase` enum in `sentinel-core`: `Investigating`, `Planning`, `Executing`, `Verifying`, `Completed`, `Failed`.

---

## Decision

Sentinel enforces a four-phase workflow for every agent session:

### Phase 1: Investigate (Read-Only)

The LLM reasoning loop issues read-only capabilities to gather system state. All capabilities invoked in this phase must be declared with `RiskTier::Low` and must implement `dry_run` returning the same result as `invoke` (since reads are by definition non-mutating). The policy engine enforces the read-only constraint: any capability with `RiskTier > Low` is automatically denied during the Investigation phase.

The investigation produces a structured set of `Observation` records — system facts gathered via capability results — which form the context for the Planning phase.

### Phase 2: Plan

The LLM reasoning loop, given the goal and the gathered observations, constructs a `Plan`: a serialized, ordered list of `PlanStep` values. Each step specifies:
- A `capability_id` from the registered manifest.
- A JSON-serialized parameter set, validated against the capability's schema.
- A human-readable `description` of what this step will do.
- A reference to the preceding step(s) it depends on (for parallel execution planning).
- The `RiskTier` of the capability (copied from the manifest for plan display).

The plan is evaluated against the policy engine in dry-run mode. Any step that would be denied produces a pre-flight violation report, and the plan is returned to the LLM for revision. The plan is not surfaced to the operator until it passes pre-flight policy validation.

### Phase 3: Approve

The validated plan is presented to the human operator via the TUI (or an external API for headless use). The operator may:
- **Approve** the plan as-is, advancing to execution.
- **Reject** the plan, terminating the session or returning to the Planning phase with rejection feedback.
- **Edit** individual steps (modify parameters, remove steps, reorder steps) and resubmit for policy re-evaluation.

For plans containing any `High` or `Critical` risk steps, approval is mandatory and cannot be bypassed by configuration. For plans containing only `Low` and `Medium` steps, a policy rule can be configured to auto-approve, enabling fully automated operation for low-risk tasks.

The `ApprovalDecision` (with timestamp, operator identity, and any edits made) is recorded as a domain event in the audit log.

### Phase 4: Act (Constrained Execution)

`sentinel-exec` executes the approved plan steps in order (or in parallel where dependency analysis permits). The LLM reasoning loop is **not** consulted during execution. Each step invokes its capability via the typed `Capability` trait, and the result is recorded in the audit log.

If a step fails, execution halts and the rollback chain (built from `inverse()` capabilities) is offered to the operator. The LLM may be re-engaged for a Verification or Recovery phase after the fact, but it cannot inject new steps into the approved plan mid-execution.

---

## Rationale

**Read-only investigation prevents early mistakes.** By enforcing that Phase 1 is strictly read-only, the agent cannot accidentally modify system state while gathering context. This provides a safe "look before you leap" guarantee that is built into the workflow, not dependent on operator discipline.

**Structured plan enables policy pre-flight and transparent approval.** A machine-readable plan can be evaluated against the full policy rule set before any execution begins, catching violations before they become mid-execution surprises. The TUI can render the plan in a human-readable format with risk tier indicators, giving the operator a clear picture of what will happen.

**Human approval gate provides meaningful oversight.** The approval gate is not a simple "press Enter to continue" — it presents the full plan with dry-run results and risk tiers, and allows step-level editing. This gives operators the information they need to make an informed decision, not just a rubber-stamp prompt.

**Constrained execution prevents plan deviation.** Once a plan is approved, execution is strictly bound to that plan. The LLM cannot observe the results of step N and decide to add step N+1 based on what it sees — that would require a new Investigate → Plan → Approve cycle. This "no new actions without approval" constraint is critical for maintaining operator oversight over multi-step operations.

**Verifying phase closes the loop.** After execution, a Verification phase re-engages the LLM in read-only mode to confirm that the desired state has been achieved. This provides automated validation of success without opening a new action window.

---

## Consequences

**Positive:**

- The read-only investigation phase prevents accidental early modification of system state.
- The structured plan representation enables policy pre-flight, dry-run preview, TUI rendering, and complete audit records.
- The approval gate ensures that every plan containing significant risk operations has human sign-off before execution.
- Constrained execution ensures that the approved plan is exactly what gets executed — no surprises from LLM mid-flight plan changes.
- The four-phase structure maps naturally to the `SessionPhase` enum, enabling clean state machine management and checkpointing.
- Auto-approval configuration for Low/Medium plans enables automated use cases (CI/CD, scheduled maintenance) while preserving oversight for high-risk operations.

**Negative:**

- The four-phase workflow introduces latency for simple tasks. A task that could in principle be done with a single capability invocation still goes through Investigation, Planning, and Approval phases. For interactive use, this is acceptable; for very high-frequency automation, it may be a bottleneck.
- The "no new actions without approval" constraint means that an agent cannot adaptively respond to unexpected conditions during execution (e.g., discovering mid-execution that a service is in an unexpected state). It must halt, surface the situation, and start a new cycle.
- Plan editing during the Approve phase requires re-running policy pre-flight validation, which adds latency to the approval step.
- Auto-approval configuration for Low/Medium plans reduces oversight but is a necessary feature for headless/automated deployments. Clear documentation and default-off configuration are required to prevent misuse.

---

## Alternatives Considered

**Continuous action loop (ReAct-style).** Allow the LLM to take actions interleaved with observations in a continuous loop (Reason → Act → Observe → Reason → Act). This is the model used by many LLM agent frameworks (LangChain, AutoGPT). It was rejected because it provides no natural point for human approval, makes the full action plan non-inspectable before execution begins, and allows the LLM to take unbounded numbers of actions before completing a goal. For production infrastructure management, this is too unconstrained.

**Two-phase: Plan then Execute (no Investigate).** Skip the dedicated Investigation phase and let the LLM immediately generate a plan from the stated goal, with a human approval gate before execution. This is simpler but degrades plan quality significantly: the LLM does not have accurate system state and will generate plans based on assumptions. The read-only investigation phase is low-cost (read operations are fast) and dramatically improves plan quality.

**Fully automatic execution for all tiers.** Auto-approve all plans regardless of risk tier, relying solely on the policy engine to prevent dangerous operations. This would support faster end-to-end execution for automation use cases. It was rejected because it removes the human oversight layer for High/Critical operations that may have correct but destructive effects — "delete all logs older than 7 days" may be policy-compliant but still require a human to confirm it is the right action in the current context.

**Plan-as-text rather than Plan-as-structured-data.** Allow the LLM to generate the plan as a natural language description or a shell script rather than a structured list of capability invocations. This was rejected for the same reasons as shell command generation (ADR-003): it makes policy evaluation, dry-run, and audit impossible, and opens the prompt injection attack surface.

**Streaming step-by-step approval.** Instead of approving the full plan at once, present each step to the operator one at a time as it is about to be executed. This provides fine-grained control but introduces significant latency between steps for interactive operations. The full-plan approval model is preferred because it gives the operator a complete view of what is going to happen, enabling them to reject the plan if a later step is problematic even if the early steps are fine.
