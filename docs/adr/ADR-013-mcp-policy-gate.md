# ADR-013: MCP Policy Gate for Coding Agents

**Status:** Proposed  
**Date:** 2026-09-25  
**Deciders:** Marcus Patman  
**Categories:** Architecture, Safety, Human-in-the-Loop, Integration

---

## Context

Coding agents (Claude Code, Cursor, and similar) increasingly touch the machines they run on: they inspect disk usage, restart services, clean caches. Today they do this through a raw shell tool, so the only control points are the agent's own judgement and whatever per-command prompt the client shows.

Sentinel already has the pieces an agent should be forced through: a typed capability catalogue with risk tiers (ADR-003), a deny-by-default policy engine (ADR-004), an Investigate → Plan → Approve → Act workflow (ADR-005), and a hash-chained audit log (ADR-007). What it lacks is a way for an *external* agent to use them. The Model Context Protocol (MCP) is the integration surface those clients speak, and its stdio transport needs no network listener.

The property that matters: **an agent must be able to propose changes but never approve them.** If the agent can approve its own plan, the approval step is theatre.

## Decision

### 1. New crate `sentinel-mcp`, exposed as `sentinel serve --mcp`

A new workspace crate owns the gate. It depends on `sentinel-core`, `sentinel-policy` and `sentinel-audit` only; concrete capabilities are injected by the binary (so tests inject the real capabilities over a fake executor). The transport is MCP stdio: newline-delimited JSON-RPC 2.0 with `initialize`, `notifications/initialized`, `ping`, `tools/list` and `tools/call`. Protocol revisions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05 are accepted; an unknown requested revision gets the newest. JSON-RPC batches are rejected. Lines over 1 MiB are discarded with an error. Logs go to stderr for every subcommand, since stdout carries the protocol.

### 2. Exactly five tools, none of which can approve or execute

| Tool | Host effect |
|---|---|
| `sentinel_capabilities` | none |
| `sentinel_policy_check` | none; calls `PolicyEvaluator::evaluate`, which has no side effects |
| `sentinel_investigate` | runs one capability whose manifest kind is `ReadOnly`, **and** only if policy returns `Allowed`/`AuditOnly` in phase `Investigating` |
| `sentinel_propose_plan` | writes one `PendingApproval` plan to the store |
| `sentinel_plan_status` | none |

The `ReadOnly` check in `sentinel_investigate` is structural and independent of the rules in force, so a permissive custom policy cannot turn investigation into mutation. Unknown tool names (for example `sentinel_approve`) are a JSON-RPC `-32602` error, and they are still audited.

`sentinel_propose_plan` validates each step with the capability's own `validate_args`, evaluates policy per step in phase `Executing`, and **refuses the whole plan (stores nothing)** if any step is unknown, has invalid arguments or is `Denied`. Risk tiers are copied from the manifest, never from agent input. Every step is marked `requires_approval = true` whatever its tier: in this mode, any plan from an agent needs a human.

### 3. File-backed plan store with content-hash pinning

Plans live at `<state_dir>/plans/<plan_id>.json` (state dir: `--state-dir`, `$SENTINEL_STATE_DIR`, `$XDG_STATE_HOME/sentinel` or `~/.local/state/sentinel`; directories are created `0700`). Each record carries `content_hash = SHA-256(plan_id, goal, host, [sequence, capability_id, args, risk_tier]…)`. Status moves `PendingApproval → Approved | Rejected`, then `Approved → Executing → Executed | ExecutionFailed`. Writes go to a temp file and are then renamed into place.

`approve` pins `approved_hash`. `execute` refuses unless the status is `Approved` and the recomputed hash equals both `content_hash` and `approved_hash`, so editing a plan after approval, even with a recomputed `content_hash`, blocks execution. Execution claims the plan (`Executing`) before running, so an approved plan runs at most once.

### 4. Approval is out-of-band and operator-only

The gate process has no code path to `PlanStore::approve`. Approval happens through `sentinel approve <plan_id>`, which prints the plan for review, requires stdin to be a terminal, and asks the operator to type the first 8 characters of the plan id. `sentinel reject` needs no TTY, because rejecting is always safe. TUI approval of stored plans is specified but not yet built (see the spec).

### 5. Execution re-checks policy; operator approval satisfies `RequireApproval`

`sentinel execute` re-evaluates every step against the current policy. `Denied` halts execution: policy may have tightened since the proposal. `RequireApproval` is treated as satisfied by the operator's approval of this exact plan content. Execution stops at the first denied or failed step, and the remaining steps are marked `Skipped`.

This deliberately differs from `ReasoningLoop::execute_plan`, which treats `RequiresApproval` as not allowed and skips the step even after plan approval. Under the default policy that means Medium-risk mutating capabilities (`log_vacuum`, `cache_prune`, `service_start`) never run through `sentinel run`. That is a pre-existing behaviour, recorded here as a follow-up rather than changed in this ADR.

### 6. Every call is audited, in separate chains per process

Each process (`serve`, `approve`, `reject`, `execute`) writes its own session-scoped chain `<state_dir>/audit/<kind>-<session>.jsonl`, so every chain stays linear and verifiable with `sentinel verify-audit`. A new event variant, `AuditEventType::McpToolCalled { tool, arguments }`, is appended **before** dispatch on every `tools/call`, and the existing `PolicyEvaluated` / `PolicyDenied` / `CapabilityInvoked` / `CapabilitySucceeded` / `CapabilityFailed` / `ObservationRecorded` / `PlanProposed` / `PlanApproved` / `PlanRejected` events follow. Stored plans record which audit files hold their proposal, decision and execution. If an audit write fails before an action, the action is refused.

## Threat model and limits

In scope: an agent that can only speak MCP to the gate. It cannot approve, execute, run mutating capabilities, downgrade a step's risk tier, or smuggle a denied step into a stored plan, and everything it tries is logged.

**Not a boundary: same-UID shell access.** An agent that also has a shell as the same OS user can:
- allocate a pseudo-terminal and pass the TTY check (checked while writing this ADR: `script -qec "sentinel approve <id>"` with the id prefix on stdin approves the plan);
- edit the plan store or audit files directly. Hash pinning stops edits *after* approval from executing, but a same-UID process could rewrite both the plan and its decision.

Mitigations, strongest first:
1. Run the gate and own `state_dir` as a dedicated user. The agent reaches it only through MCP, for example a stdio wrapper via `sudo -u sentinel`. Operators approve as that user or via group-write on a socket (future).
2. Deny `Bash(sentinel approve:*)` and `Bash(sentinel execute:*)` in the agent client's permission settings.
3. Treat the audit chains as tamper-*evident*, not tamper-*proof*. Ship them off-host (ADR-007 exporter) if that matters.

Operator identity in approvals is `$USER`/`$LOGNAME` and is not authenticated.

## Known gaps (this iteration)

- No automatic rollback in `sentinel execute`. It halts on the first failure instead.
- No TUI approval of stored plans. The CLI only.
- The store has no locking beyond the status-transition check. Two concurrent `execute` calls on the same plan can race between load and claim.
- Policy is `default_policy()`. There is no policy file loading yet, which is true of the rest of Sentinel too.
- `sentinel_investigate` runs locally only. `--host` is a label for policy and audit, not a remote target.

## Consequences

- Positive: Sentinel becomes usable as a guardrail by any MCP client with no network exposure; the propose/approve split is enforced by the absence of a code path rather than by a flag.
- Positive: The plan store and executor are reusable for a future HTTP/Arena front end and for TUI approval.
- Negative: A second plan executor now exists alongside `ReasoningLoop::execute_plan`. Follow-up: extract a shared executor into `sentinel-agent-llm` or a new crate, and settle one `RequireApproval` semantic.
- Negative: `AuditEventType` gained a variant. Older binaries cannot deserialize logs that contain it. Chains written by older binaries still verify.

## Alternatives considered

- **Expose approve as an MCP tool gated by a secret.** Rejected: the secret would sit in the agent's environment or config.
- **HTTP/SSE transport.** Deferred: it adds a network listener and auth surface, and stdio covers local coding agents.
- **One shared audit file across processes.** Rejected for now: concurrent appenders would interleave and break the linear chain. Per-process chains plus cross-references in the plan record are simpler and verifiable today.
