# Sentinel

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/marcuspat/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/marcuspat/Sentinel/actions)

> ⭐ If Sentinel gives your AI agents a safety net, [a star helps others find it](https://github.com/marcuspat/Sentinel).

Sentinel is a safe, auditable agentic system administration tool written in Rust.
It drives an **Investigate → Plan → Approve → Act** workflow: the LLM gathers
read-only observations, proposes a structured plan, waits for explicit operator
approval, then executes under a strict deny-by-default policy engine with a
hash-chained audit log.

## 🎬 Demo

![sentinel listing capabilities and the deny-by-default policy](demo.gif)

*The capability catalog and the deny-by-default policy engine — no API key needed for either. Recorded from the actual binary with [asciinema](https://asciinema.org) + [agg](https://github.com/asciinema/agg).*

## Features

- **Deny-by-default policy engine** — kill switch, resource guards, risk-tiered rules
- **Operator approval gate** — no mutating action runs without explicit approval
- **Hash-chained audit log** — SHA-256 chain, JSONL export, tamper detection
- **14 built-in capabilities** — filesystem, process, packages, network, metrics
- **Pluggable LLM backends** — Anthropic Claude, OpenAI, Ollama
- **Fleet mode** — mutual TLS (rcgen + rustls 0.23), staged rollouts
- **Interactive TUI** — ratatui 0.30, full keyboard navigation

## Install

Build from source — `sentinel` isn't published to crates.io (the crate name is already taken by an unrelated project):

```bash
git clone https://github.com/marcuspat/Sentinel
cd Sentinel
cargo build --release
# binary at target/release/sentinel
```

## Quick Start

```bash
# Interactive TUI (default)
sentinel

# With a goal on the command line
sentinel run "Ensure nginx is running and serving traffic"

# Target a specific host
sentinel tui --host web-01.prod

# With Anthropic backend
ANTHROPIC_API_KEY=sk-... sentinel run "Fix high disk usage on /var"

# With Ollama (local)
sentinel --backend ollama --model llama3 run "Check CPU load"
```

## Build

```bash
# Requires Rust 1.75+
cargo build --release

# Run all tests
cargo test --workspace

# Static analysis
cargo clippy --workspace --all-targets -- -D warnings

# Security audit
cargo audit
```

### Static musl binary (for container / bare-metal deployment)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## CLI Reference

| Command | Description |
|---|---|
| `sentinel` | Launch interactive TUI (default) |
| `sentinel tui [--host HOST]` | Launch TUI targeting HOST |
| `sentinel run GOAL [--host HOST] [--dry-run]` | Non-interactive run |
| `sentinel capabilities` | List all built-in capabilities |
| `sentinel policy` | Show default policy rules |
| `sentinel verify-audit PATH` | Verify audit log chain integrity |
| `sentinel serve --mcp [--state-dir DIR] [--host HOST]` | Run as an MCP policy gate for coding agents (stdio) |
| `sentinel plans` / `sentinel show-plan ID` | List / inspect plans proposed through the gate |
| `sentinel approve ID` | Operator approval of a proposed plan (interactive terminal required) |
| `sentinel reject ID [--reason TEXT]` | Reject a proposed plan |
| `sentinel execute ID` | Execute an approved plan; refuses unapproved or modified plans |

## Policy gate for coding agents (MCP)

`sentinel serve --mcp` exposes Sentinel's capability catalogue, deny-by-default
policy engine and hash-chained audit log to any MCP client (Claude Code,
Cursor, …) over stdio. The agent can **ask** and **propose**; it cannot
**approve** or **execute**:

| Tool | What it does | Touches the host? |
|---|---|---|
| `sentinel_capabilities` | List capabilities with kind and risk tier | No |
| `sentinel_policy_check` | Dry-run a policy decision; returns allow/deny/require_approval + matching rule | No |
| `sentinel_investigate` | Run one **read-only** capability after a policy check | Read-only |
| `sentinel_propose_plan` | Validate + store a plan as `PendingApproval`, return `plan_id` | Writes the plan store only |
| `sentinel_plan_status` | Read a stored plan's status | No |

There is no approve or execute tool. An operator reviews the plan and runs
`sentinel approve <plan_id>` (interactive terminal required) and then
`sentinel execute <plan_id>`. Execution re-evaluates policy per step and
refuses any plan whose content changed after approval. Every MCP call, policy
decision, approval and capability invocation is written to a per-process
hash-chained JSONL log under `<state-dir>/audit/`, verifiable with
`sentinel verify-audit`.

Claude Code — project `.mcp.json`:

```json
{
  "mcpServers": {
    "sentinel": {
      "type": "stdio",
      "command": "sentinel",
      "args": ["serve", "--mcp"],
      "env": { "SENTINEL_STATE_DIR": "/var/lib/sentinel" }
    }
  }
}
```

If the agent also has a shell, deny it the operator commands in
`.claude/settings.json` as defence in depth:

```json
{
  "permissions": {
    "deny": ["Bash(sentinel approve:*)", "Bash(sentinel execute:*)"]
  }
}
```

The TTY check on `approve` and these deny rules are speed bumps, not a
security boundary: a process running as the same OS user can allocate a
pseudo-terminal or edit the state directory. For a hard boundary, run the gate
and own the state directory as a separate user. See
[ADR-013](docs/adr/ADR-013-mcp-policy-gate.md) for the threat model and
[plans/SPEC-mcp-gate-and-arena.md](plans/SPEC-mcp-gate-and-arena.md) for the
roadmap.

## Architecture

```
sentinel-core          — Capability trait, RiskTier, CapabilityResult, Plan types
sentinel-exec          — Sandboxed command executor (allowlist, timeout, rlimits)
sentinel-policy        — PolicyEvaluator: kill switch -> resource guards -> rules
sentinel-audit         — SHA-256 hash-chained audit log, JSONL, Prometheus metrics
sentinel-capabilities  — 14 concrete capabilities (fs, process, packages, net, metrics)
sentinel-agent-llm     — Investigate/Plan/Act reasoning loop, LLM backends
sentinel-fleet         — mTLS fleet management, staged rollouts
sentinel-tui           — ratatui TUI: 5 tabs, approval workflow, clap CLI
sentinel-mcp           — MCP stdio policy gate: tools, plan store, approved-plan executor
```

## Security Model

- **Kill switch** — blocks all capabilities (ReadOnly and Mutating) when activated
- **Resource guards** — protect /etc, /boot, /sys, /proc, /dev, sshd, systemd, docker
- **Command allowlist** — exact-match only; basename fallback is intentionally absent
- **PID guard** — ProcessKill rejects PID <= 1 (init/systemd is protected)
- **Signal allowlist** — only TERM/KILL/HUP/INT/QUIT/USR1/USR2/CONT/STOP accepted
- **Path validation** — destructive capabilities reject system directories
- **Time restrictions** — evaluated against server wall-clock, not client timestamp
- **mTLS** — all fleet communication uses mutual TLS with certificate pinning

See [docs/adr/](docs/adr/) for full Architecture Decision Records and
[docs/ddd/](docs/ddd/) for Domain-Driven Design documentation.

## Sentinel vs. Ansible / plain SSH

Ansible and hand-rolled SSH scripts run what you tell them to, without judgment. Sentinel's LLM proposes the fix from a live investigation, but nothing mutates until an operator approves it — every action still passes through the same deny-by-default policy engine, resource guards, and hash-chained audit log regardless of who or what proposed it. Reach for Ansible/SSH when the fix is a known, repeatable playbook; reach for Sentinel when the fix isn't known ahead of time and you want a verifiable record of exactly what an agent was allowed to do about it.

## Ecosystem

| Repo | What it does |
|------|-------------|
| [**codescope**](https://github.com/adventurewave-labs/codescope) | Rust code-intelligence engine for AI agents — no cloud, no DB |
| [**secret-scan**](https://github.com/adventurewave-labs/secret-scan) | Rust secret scanner — obfuscation detection |
| [**turbo-flow**](https://github.com/marcuspat/turbo-flow) | Agentic dev environment — Ruflo v3.5 orchestration (by [ruvnet](https://github.com/ruvnet)), 215+ MCP tools |

## License

MIT — see [LICENSE](LICENSE).
