# ADR-019: One Plan Executor

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Execution, Policy, Correctness

---

## Context

Two code paths executed plans: `ReasoningLoop::execute_plan` (`sentinel run`,
the TUI) and `execute_approved_plan` (`sentinel execute`, the MCP gate). They
had drifted, and the differences were not cosmetic.

| | Loop (`run`, TUI) | Gate (`execute`) |
|---|---|---|
| Policy says `RequiresApproval` for a step of an approved plan | **Step skipped and counted as failed** | Step runs |
| Capability returns `Failure` | **Step marked `Completed`** | Step fails |
| After a failed step | Later steps still run unless they declare `depends_on` | Halt |
| Risk tier used for the policy check | Tier written in the plan | Current manifest |
| Per-step timeout | None | Yes |
| Rollback | Yes, but a step was marked `RolledBack` even when its inverse failed or did not exist | None |
| Capability with no implementation | Stub success | Failure |

The first row is the one the MCP spec recorded (A.7 #2): with the default
policy every Medium-risk mutating capability answers `RequiresApproval`, so
`sentinel run` could approve a plan and then never perform its mutating steps.
The second row meant a failed step was reported as a success and execution
carried on.

## Decision

A new crate, `sentinel-runner`, holds the only executor, `run_plan`. Both
paths call it. It needs policy and audit, which `sentinel-core` cannot depend
on, and neither `sentinel-agent-llm` nor `sentinel-mcp` should depend on the
other; hence a crate of its own.

The rules, each pinned by a test:

1. **Approval covers the plan.** `RequiresApproval` on a step of an approved
   plan runs. `Denied` never runs.
2. **Policy uses the capability's current manifest**, so a plan cannot
   understate a step's risk.
3. **A `Failure` result is a failure.**
4. **Halt on the first denied or failed step**; later steps are `Skipped`.
5. **Rollback** (on by default): completed steps with `can_rollback` are undone
   newest-first. A step becomes `RolledBack` only if its inverse reports
   success; otherwise it stays `Completed` and the report says why. The inverse
   is checked against policy and refused on `Denied`, so the kill switch stops
   rollback as well.
6. **Audit before action.** A failed audit write stops execution before the
   capability is invoked.

Stub results for capabilities without an implementation remain only when the
loop is built with no implementations at all (test harnesses). A real session
missing one capability now fails that step.

`--no-rollback` (or `SENTINEL_NO_ROLLBACK`) turns rule 5 off for `run`, the TUI
and `execute`. `ExecutionRecord` gained `steps_rolled_back`.

## Consequences

- **Behaviour change for `sentinel run` and the TUI:** approved Medium-risk
  mutating steps now execute. That is the fix, and it is also the first time
  those steps run from this path; they go through the sandbox added in
  ADR-016.
- **Behaviour change for `sentinel execute`:** it now rolls back by default.
- A plan no longer continues past a failed step, even when later steps do not
  depend on it. `depends_on` is currently unused by the executor.
- One more workspace crate.

## Not covered

- Rollback is best effort. Of the built-in capabilities only the service
  operations have a real inverse; `log_vacuum` and `package_upgrade` cannot be
  undone.
- Rollback is not re-entrant: a crash during rollback is not resumed.
- Step-level approval (`ApprovalDecision::StepByStep`) is still treated as
  whole-plan approval by the executor.
