# SPEC: Sentinel as the Policy Gate for Coding Agents, plus Sentinel Arena

**Status:** Draft. Part A is implemented in this PR; B, C and D are plan only.  
**Date:** 2026-09-25  
**Owner:** Marcus Patman  
**Related:** ADR-003 (capabilities), ADR-004 (deny-by-default), ADR-005 (IPAA workflow), ADR-007 (audit chain), ADR-010 (static binary), **ADR-013 (MCP gate)**

---

## Summary

Sentinel already decides what an LLM may do to a host. This spec makes that decision point available to *other people's* agents over MCP, and describes a public demo ("Arena") that lets anyone try to talk an agent past it. It also recommends a crates.io naming strategy, because the current release workflow cannot publish as written.

| Part | Scope | In this PR |
|---|---|---|
| A | `sentinel serve --mcp`, five tools, file-backed plan store, operator `approve`/`reject`/`execute` | **Implemented and tested** |
| B | Sentinel Arena: per-visitor sandboxes, jailbreak feed, verifiable chains | Design only; nothing deployed |
| C | crates.io naming | Availability checked; recommendation only; nothing renamed or published |
| D | Milestones and acceptance criteria | Plan |

---

## Part A: MCP policy gate (`sentinel serve --mcp`)

### A.1 Goals

1. Any MCP client (Claude Code, Cursor, …) can ask Sentinel "would this be allowed?", run **read-only** diagnostics, and **propose** plans.
2. An MCP client can never approve or execute. Approval is an operator action taken out-of-band.
3. Every call lands in a SHA-256 hash-chained audit log.

Non-goals for A: network transports (HTTP/SSE), multi-tenant auth, remote-host execution, a policy file format.

### A.2 Transport

- MCP stdio: one JSON-RPC 2.0 message per line on stdin/stdout. Logs go to stderr for **all** subcommands; this PR changes the tracing writer globally.
- Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`. All others get `-32601`. Tool methods before `initialize` get `-32600`.
- Protocol revisions accepted: `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`. The server echoes the client's revision if supported, otherwise it answers with the newest.
- Batches (JSON arrays) are rejected (`-32600`). Lines over 1 MiB are discarded (`-32600`) and the stream continues.
- `tools/call` results carry both `content[0].text` (pretty JSON) and `structuredContent` (the same object), with `isError` set for tool-level failures. An unknown tool name is a protocol error (`-32602`).
- Requests are processed sequentially. No server→client requests (sampling, elicitation) are used.

### A.3 Tools

| Tool | Input | Behaviour | Audit events |
|---|---|---|---|
| `sentinel_capabilities` | `{}` | Manifests: id, name, description, kind, risk tier, has_inverse, `investigable` | `McpToolCalled` |
| `sentinel_policy_check` | `capability_id`, `args?`, `phase?` (`Investigating`\|`Executing`, default `Executing`) | `PolicyEvaluator::evaluate` only. Returns `decision` (allow/deny/require_approval/audit_only), `matched_rule`, `rationale`, `reason`, `args_valid`, `executed:false`. Unknown capability → `deny` (deny-by-default), not an error | `McpToolCalled`, `PolicyEvaluated`, `PolicyDenied` on deny |
| `sentinel_investigate` | `capability_id`, `args?` | Refuses unless manifest kind is `ReadOnly` (structural check) **and** policy allows in phase `Investigating`. Validates args, invokes with a timeout (default 30 s), returns `CapabilityResult` | `McpToolCalled`, `PolicyEvaluated`, `CapabilityInvoked`, `CapabilitySucceeded`/`Failed`, `ObservationRecorded` (summary ≤256 chars); `PolicyDenied` on refusal |
| `sentinel_propose_plan` | `goal`, `rationale?`, `steps[1..=16]: {capability_id, args?, description?}` | Validates every step (exists, `validate_args`, policy in phase `Executing`). **Any** unknown, invalid or denied step → the whole plan is refused and nothing is stored. Risk tier comes from the manifest. Every step gets `requires_approval=true`. Stores `PendingApproval`, returns `plan_id`, `content_hash`, per-step decisions, `executed:false`. **Never executes.** | `McpToolCalled`, `PolicyEvaluated`×n, `PolicyDenied` as needed, `PlanProposed` |
| `sentinel_plan_status` | `plan_id` | Stored record: status, steps, hashes, `integrity_ok`, decision, execution | `McpToolCalled` |

There is no approve tool and no execute tool. The gate has no code path to `PlanStore::approve`.

### A.4 Plan store

- `<state_dir>/plans/<uuid>.json`. The state dir comes from `--state-dir`, then `$SENTINEL_STATE_DIR`, then `$XDG_STATE_HOME/sentinel`, then `~/.local/state/sentinel`. Directories are created `0700` on Unix.
- Record: `Plan` (existing `sentinel-core` type), `host`, `status`, `content_hash`, `proposed_via`, `proposer_session`, `proposal_audit_file`, `decision {by, at, approved_hash, reason, audit_file}`, `execution {started_at, finished_at, counts, audit_file, error}`.
- `content_hash = SHA-256(json{plan_id, goal, host, steps:[{sequence, capability_id, args, risk_tier}]})`.
- Transitions: `PendingApproval → Approved|Rejected`; `Approved → Executing → Executed|ExecutionFailed`. Anything else is an error.
- Writes go to a temp file in the same directory, then a rename.

### A.5 Operator CLI

| Command | Rules |
|---|---|
| `sentinel plans` / `show-plan <id>` | Read-only |
| `sentinel approve <id>` | Status must be `PendingApproval` and the integrity check must pass. **stdin must be a TTY.** The operator types the first 8 chars of the id. Writes `PlanApproved` to `approve-<session>.jsonl`, then pins `approved_hash` |
| `sentinel reject <id> [--reason]` | No TTY required. Writes `PlanRejected` |
| `sentinel execute <id>` | Refuses unless `Approved` and recomputed hash == `content_hash` == `approved_hash`. Claims the plan (`Executing`), re-evaluates policy per step (`Denied` halts; `RequireApproval` counts as satisfied by the operator's approval), halts on first failure, writes `execute-<session>.jsonl`. Exit code 2 if not fully `Executed` |

### A.6 Threat model

Covered in ADR-013. In short: the boundary is the MCP protocol. A same-UID shell can pass the TTY check with a PTY (verified with `script`) and can edit the state dir. The hard fix is a dedicated OS user for the gate and state dir. The README documents Claude Code `permissions.deny` rules as defence in depth.

### A.7 Follow-ups (not in this PR)

1. TUI tab listing `PendingApproval` plans with approve/reject (reuse `PlanStore`).
2. Extract one plan executor shared by `ReasoningLoop::execute_plan` and `sentinel execute`, and decide one `RequireApproval` semantic. Today `sentinel run` skips Medium-risk mutating steps even after approval.
3. Rollback in `sentinel execute`, using `invoke_inverse` for completed steps.
4. Policy file loading (TOML/JSON of `PolicyRule`), so gate operators can tighten rules without rebuilding.
5. Store locking (`flock` on the plan file) to close the concurrent-execute race.
6. Add `sentinel-mcp` to the `CRATES` list in `.github/workflows/release.yml` (publish order: after `sentinel-audit`, before `sentinel-tui`) and add a `cargo fmt --all --check` step to `ci.yml`. **Not done here: this PR does not touch workflows.** CI currently runs check, test and clippy but not fmt, and `main` does not pass `cargo fmt --all --check` today (45 pre-existing files differ). A formatting-only commit should land separately before the CI step is added.

---

## Part B: Sentinel Arena (design only)

### B.1 What the visitor sees

A web page: "Here is a real Linux VM with an AI sysadmin on it. It answers to Sentinel. Give it a goal, or try to make it do something it shouldn't."

- A chat pane. The visitor types goals or jailbreak attempts. An LLM agent acts on the visitor's own sandbox **only through the Sentinel MCP gate**.
- A **live blocked-attempt feed** (global, anonymised): each `PolicyDenied` / unknown-tool / investigate refusal shows capability, rule id, reason and time. Visitor free text is never shown publicly.
- A **verifiable audit chain** per session: download the JSONL, and an in-browser verifier (the `sentinel-audit` verifier compiled to WASM) shows `VALID` / the first broken sequence. The chain head hash is shown live.
- Plans the agent proposes appear as cards. The visitor may approve them **for their own throwaway VM** (see B.4 for how that works without breaking the "agent cannot self-approve" property).

### B.2 Runtime choice

Requirements: strong isolation (visitors *will* try to escape), fast create/destroy (seconds), per-second billing or a flat ceiling, and a real enough Linux userland for `df`, `ps`, `ss`, `find`.

| Option | Isolation | Ops burden | Cost model | Fit |
|---|---|---|---|---|
| **Fly Machines** | Firecracker microVM per machine | Low: REST Machines API, images from a registry | Per-second while running; stopped machines billed for rootfs | **Recommended for v1** |
| E2B | Managed sandboxes built for AI agents | Lowest | Per-second vCPU + RAM; plan caps on session length and concurrency | Strong alternative; less control over image, networking and egress; the vendor's session caps shape the product |
| Self-hosted Firecracker (`jailer`) on KVM bare metal | Firecracker microVM, fully under our control | High: host provisioning, networking, image pipeline, patching | Flat monthly host cost | v2 option if Arena traffic justifies it; best for egress control and cost at scale |
| Containers (Docker/gVisor on a VM) | Shared kernel (gVisor narrows it) | Medium | Flat | Rejected: an adversarial public demo should not share a kernel between visitors |

Why Fly Machines for v1: microVM isolation without running KVM hosts; the Machines API maps one-to-one onto "one VM per visitor session"; ADR-010's static musl binary makes the image tiny; per-second billing fits short sessions.

Prices, as read from the vendors' pricing pages on 2026-09-25 (re-check before budgeting):
- Fly.io: `shared-cpu-1x` with 256 MB is listed at $0.00000078/s (about $0.0028/h, about $2.02/month). Stopped machines are billed $0.15 per GB of rootfs per 30 days.
- E2B: 1 vCPU is $0.000014/s, 1 GiB RAM is $0.0000045/s. The Hobby tier caps sessions at 1 h and 20 concurrent sandboxes; Pro ($150/month) allows 24 h sessions and 100 concurrent.

Known v1 constraint: Fly Machines do not run systemd as PID 1 by default, so `service_*` capabilities will return failures inside the Arena VM unless the image boots an init that supports them. That is acceptable for v1: the demo is about the gate. The VM image seeds `/var/log/arena/*` and cache directories so `disk_usage`, `log_vacuum` and `cache_prune` have real, harmless targets.

**Spike before commitment (M4):** confirm how to block egress on a Fly Machine. If the platform has no per-machine egress policy, apply in-VM `nftables` at boot with default-drop output except the 6PN control-plane address, and confirm a visitor cannot undo it (Sentinel runs as a non-root user; the fixture is owned by that user; no sudo in the image).

### B.3 Architecture

```
Browser ──HTTPS──► arena-web (static) ──► arena-control (Rust, new crate `sentinel-arena`, not in this PR)
                                            │  • Turnstile verify, rate limits, budget meter
                                            │  • runs the LLM agent loop (API key lives ONLY here)
                                            │  • MCP client ──(private network)──► per-visitor VM
                                            │  • SSE: public blocked-attempt feed + per-session chain head
                                            ▼
                                   Fly Machines API: create / destroy
                                            ▼
                     visitor VM: `sentinel serve --mcp` behind a stdio↔TCP bridge,
                                 seeded fixture, no egress, hard TTL
```

- The LLM key never enters the visitor VM, so a successful jailbreak inside the VM cannot exfiltrate it.
- The control plane is the MCP client. The agent's tool calls are forwarded to the VM's gate.
- Audit JSONL is pulled from the VM at session end (and streamed during it) and kept for N days for the verifier download.

### B.4 Approval in the Arena

The core property stays: **the agent cannot approve.** The visitor, acting as the operator of their own throwaway VM, can. The approve button calls arena-control, which calls a new non-TTY operator path in the VM: `sentinel approve --operator-token-file /run/arena/op.token <id>`. The token is written at boot by arena-control via the Machines API, readable only by a separate `operator` user, and never exposed over MCP. That flag does not exist yet (milestone M5). It must be designed so the token is not readable by the UID that runs `serve --mcp`.

### B.5 Abuse controls

| Threat | Control |
|---|---|
| Bot floods / VM exhaustion | Cloudflare Turnstile before a VM is allocated; per-IP and per-/24 (per-/48 v6) session rate limit; global max concurrent VMs (config, start at 20); queue with a position indicator once full |
| Long-lived sessions | Hard TTL (start at 10 min) enforced by arena-control (destroy call) **and** in the VM (`timeout` wrapper on PID 1) as a second line |
| LLM cost abuse | Per-session caps: max turns, max input chars per message, max output tokens, max tool calls; per-IP daily token cap; global daily token budget |
| Using the VM as an attack platform | No egress (B.2 spike); no inbound except from arena-control; no sudo; non-root Sentinel |
| Public feed abuse (slurs, doxxing via free text) | The feed shows only structured fields (capability id, rule id, fixed reason strings); visitor text is never published |
| Escape attempts | microVM boundary; image rebuilt weekly with patched kernel/userland; VMs never reused |
| Kill switch | `ARENA_ALLOCATE=false` stops new sessions; destroy-all admin endpoint; Sentinel's own `KillSwitch` in each VM |
| Data retention | Keep audit JSONL and structured feed only, for 30 days by default; store no IP addresses at rest beyond rate-limit windows |

### B.6 Cost ceiling

A hard ceiling enforced in arena-control, not only by dashboards:

```
monthly_compute_max = max_concurrent_vms × 730 h × vm_price_per_hour
monthly_llm_max     = global_daily_token_budget × 30 × blended_price_per_token
ceiling             = monthly_compute_max + monthly_llm_max + fixed (control plane, DNS)
```

Worked compute bound using the Fly price quoted above: 20 concurrent × 730 h × $0.0028/h ≈ **$41/month**, assuming VMs ran 24/7 (they don't: TTL plus destroy on idle). The LLM term depends on the model chosen and its price at launch. Fill it in then, and set the provider-side spend limit to the same number.

Enforcement: arena-control keeps a running meter (VM-seconds × rate + tokens × rate). At 80% of the monthly ceiling it halves `max_concurrent_vms`; at 100% it stops allocating and shows "Arena is resting".

### B.7 Infrastructure as code

- Long-lived infra (DNS, Turnstile site, Fly app, arena-control deployment) is defined in OpenTofu/Terraform where a maintained provider exists. Otherwise it is a checked-in `fly.toml` plus a script.
- **A plan step always comes before apply:** CI runs `tofu plan -out=tfplan` and attaches the plan to the PR; apply is manual, from the saved plan, after review. For `flyctl`-managed pieces, the equivalent is config validation plus a reviewed diff of `fly.toml`; confirm the exact flyctl dry-run/validate flags during M4. No auto-apply on merge.
- Per-visitor VMs are runtime objects created by arena-control under the caps above, not IaC.
- Secrets (LLM key, Fly token, Turnstile secret) live in the platform secret store and are never committed. The Fly token is scoped to the Arena app/org.

---

## Part C: crates.io naming

The API was checked on 2026-09-25 via `GET https://crates.io/api/v1/crates/<name>` (200 = taken, 404 = available); `cargo search` agreed.

| Name | Status | Notes |
|---|---|---|
| `sentinel` | **taken** | nils-mathieu/sentinel, 0.5.4 |
| `sentinel-core` | **taken** | sentinel-group/sentinel-rust, 0.1.3 |
| `sentinel-tui` | **taken** | mateusdcc/code-sentinel, 0.1.0 (updated 2026-07-29) |
| `sentinel-rs` | **taken** | ayushbindlish/sentinel-rs, 0.1.0 |
| `sentinelctl` | available | |
| `sentinel-ops` | available | |
| `sentinel-agent` | available | |
| `sentinel-sysadmin` | available | |
| `sentinel-gate`, `sentinel-mcp` | available | |
| `sentinel-exec`, `-policy`, `-capabilities`, `-audit`, `-agent-llm`, `-fleet` | available | |
| `sentinelctl-core`, `-policy`, `-audit`, `-mcp` | available | |
| `sentinel-ops-core`, `sentinel-ops-policy` | available | |

**Consequence:** the opt-in publish job in `release.yml` publishes `sentinel-core` first. That name belongs to another project, so a real publish would fail at step one, and the `sentinel-tui` step would fail too.

**Recommendation:** `sentinelctl` as the published package name for the binary crate (currently `sentinel-tui`). Keep the installed binary named `sentinel`. `sentinelctl` is short, reads as "the thing you run", follows `kubectl`/`systemctl` convention, and has no near-collision. For the libraries, either:
1. prefix them `sentinelctl-*` (all checked names are free), or
2. publish only `sentinelctl` and mark the libraries `publish = false`, which avoids reserving eight or nine names for crates nobody consumes independently yet.

Option 2 is preferred until there is an external consumer of the libraries. **Decision needed from Marcus.** Nothing was renamed or published in this PR. Names can be taken at any time, so re-check before acting.

---

## Part D: Milestones

| # | Milestone | Acceptance criteria |
|---|---|---|
| M1 | **MCP gate core** *(this PR)* | `sentinel serve --mcp` passes the stdio integration test: initialize, tools/list (exactly 5 tools), policy check deny with `matched_rule`, mutating investigate refused, propose returns `PendingApproval` with no `CapabilityInvoked` in the chain, and `sentinel_approve` is `-32602`. `sentinel execute` on a pending plan exits non-zero. Piped (non-TTY) `sentinel approve` exits non-zero. Edited-after-approval plans are refused. Every MCP chain verifies with `sentinel verify-audit`. fmt, clippy `-D warnings` and tests are green |
| M2 | **Gate hardening** | Store `flock`; policy file loading; `sentinel-mcp` in release `CRATES`; `cargo fmt --check` in CI; a documented dedicated-user deployment (`sudo -u sentinel` wrapper) with a test showing the agent UID cannot write the state dir |
| M3 | **Operator UX** | TUI tab for pending plans with approve/reject; a shared plan executor used by both `run` and `execute` with one `RequireApproval` semantic and rollback via `invoke_inverse`; regression tests for both paths |
| M4 | **Arena spike** | One Fly Machine created and destroyed via API from a local script. Egress blocked (demonstrated by a failing `curl` from inside); the gate reachable over the private network through the stdio↔TCP bridge; measured cold-start time and per-session VM-seconds recorded in the spike notes (measured, not estimated); flyctl/OpenTofu plan-before-apply flow written down |
| M5 | **Arena alpha (private)** | `sentinel-arena` control plane; Turnstile; all B.5 caps enforced with tests; budget meter with 80%/100% behaviour tested against a fake clock; `approve --operator-token-file` with a test that the MCP-serving UID cannot read the token; WASM verifier validates a downloaded chain in the browser |
| M6 | **Arena public** | Red-team pass against B.5 (written findings); public feed shows only structured fields; provider spend limits set equal to the B.6 ceiling; runbook for kill switch and destroy-all |
| M7 | **crates.io** | Naming decision from Part C applied; `cargo publish --dry-run` green for every crate that will publish; publish job run manually |
