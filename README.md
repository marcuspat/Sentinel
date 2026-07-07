# Sentinel

[![Crates.io](https://img.shields.io/crates/v/sentinel-agent.svg)](https://crates.io/crates/sentinel-agent)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://github.com/marcuspat/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/marcuspat/Sentinel/actions)

> ⭐ If Sentinel gives your AI agents a safety net, [a star helps others find it](https://github.com/marcuspat/Sentinel).

Sentinel is a safe, auditable agentic system administration tool written in Rust.
It drives an **Investigate → Plan → Approve → Act** workflow: the LLM gathers
read-only observations, proposes a structured plan, waits for explicit operator
approval, then executes under a strict deny-by-default policy engine with a
hash-chained audit log.

## Features

- **Deny-by-default policy engine** — kill switch, resource guards, risk-tiered rules
- **Operator approval gate** — no mutating action runs without explicit approval
- **Hash-chained audit log** — SHA-256 chain, JSONL export, tamper detection
- **14 built-in capabilities** — filesystem, process, packages, network, metrics
- **Pluggable LLM backends** — Anthropic Claude, OpenAI, Ollama
- **Fleet mode** — mutual TLS (rcgen + rustls 0.23), staged rollouts
- **Interactive TUI** — ratatui 0.30, full keyboard navigation

## Demo

> 📹 **Demo GIF coming soon.** Capture with [`vhs`](https://github.com/charmbracelet/vhs) or `asciinema` + [`agg`](https://github.com/asciinema/agg): run `sentinel run "Ensure nginx is running"` to show the Investigate → Plan → Approve → Act loop in the TUI.

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

## Ecosystem

| Repo | What it does |
|------|-------------|
| [**codescope**](https://github.com/adventurewave-labs/codescope) | Rust code-intelligence engine for AI agents — no cloud, no DB |
| [**spacelift-intent**](https://github.com/marcuspat/spacelift-intent) | Natural language → cloud infra via Terraform providers, no HCL |
| [**secret-scan**](https://github.com/adventurewave-labs/secret-scan) | Rust secret scanner — 51k files/sec, 99% accuracy |
| [**turbo-flow**](https://github.com/adventurewave-labs/turbo-flow) | Agentic dev environment — 600+ AI subagents, SPARC methodology |

## License

Apache-2.0
