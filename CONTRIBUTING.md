# Contributing to Sentinel

Thanks for your interest. This document covers what you need to get a change
merged.

## Scope

Sentinel executes privileged system administration actions under LLM direction.
Every change is evaluated against one question first: **does this widen what the
agent can do without an operator saying yes?** If it does, it needs an ADR and an
explicit security review in the PR description — see below.

## Development Setup

Requirements:

- Rust **1.86** or newer (stable) — set as `rust-version` in the workspace manifest;
  `ratatui 0.30` and `clap 4.6` are what put the floor there
- `cargo clippy`, `cargo fmt` (`rustup component add clippy rustfmt`)
- `cargo audit` (`cargo install cargo-audit`) for dependency checks
- Docker, only if you are changing the image
- `musl-tools` if you are building the static Linux binary

```bash
git clone https://github.com/marcuspat/Sentinel.git
cd Sentinel
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Before You Open a PR

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

The first three must pass; CI runs the same commands. `cargo audit` findings
should be resolved or explained in the PR.

## Workspace Layout

The workspace is eight crates with a unidirectional dependency graph — no
circular dependencies. Keep it that way.

| Crate | Bounded context |
|---|---|
| `sentinel-core` | Domain types, capability traits, shared errors |
| `sentinel-exec` | Sandboxed command execution (rlimits, timeouts, output caps) |
| `sentinel-policy` | Deny-by-default policy evaluation, risk tiers, kill switch |
| `sentinel-capabilities` | Concrete system capabilities |
| `sentinel-agent-llm` | Investigate–Plan–Approve–Act reasoning loop, LLM backends |
| `sentinel-audit` | SHA-256 hash-chained audit log, verification, metrics |
| `sentinel-fleet` | mTLS controller/agent fleet management |
| `sentinel-tui` | Terminal UI and the `sentinel` binary |

A new capability belongs in `sentinel-capabilities` and must be registered with a
risk tier. A capability with no risk tier is a bug.

## Code Style

- `rustfmt` defaults; `clippy` with `-D warnings`. No `#[allow(...)]` without a
  comment explaining why.
- Errors: `thiserror` for library error enums, `anyhow` at the binary boundary.
  Never `unwrap()` or `expect()` on a path reachable from LLM input or from an
  operator-supplied config.
- No `unsafe` outside of the sandbox syscall layer, and any new `unsafe` block
  carries a `// SAFETY:` comment.
- Public items get doc comments. Security-relevant invariants get them in prose,
  not just in types.

## Testing

- Unit tests live in-crate; the workspace carries 382 of them and that number
  should not go down.
- `mockall` for trait mocks, `tempfile` for filesystem tests, `wiremock` for HTTP,
  `criterion` for benchmarks (`cargo bench`, HTML reports under `target/criterion`).
- Anything touching the policy engine, the command allowlist, the sandbox, the
  audit chain, or the approval gate **needs a test that demonstrates the deny
  path**, not just the allow path.
- New risk-tier routing or resource-guard entries need a test proving the guard
  actually blocks.

## Architecture Decisions

Significant design changes get an ADR under `docs/adr/` (`ADR-013`, `ADR-014`, …)
following the existing format: context, decision, consequences. Reference the ADR
number in the PR description.

## Pull Requests

- One logical change per PR. Mechanical reformatting goes in its own commit.
- Update `CHANGELOG.md` under an `## [Unreleased]` heading using
  [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) categories.
- Update `README.md` if you add or change a CLI command or a documented capability.
- CI must be green before review.

## Security-Sensitive Changes

Do not open a public PR for a vulnerability fix. Follow [SECURITY.md](SECURITY.md)
and report it privately first.

These areas get extra scrutiny — explain your reasoning in the PR description and
expect questions:

- the deny-by-default evaluator, risk tiers, or kill switch (`sentinel-policy`)
- the exact-match command allowlist or shell-free execution path (`sentinel-exec`)
- rlimit sandbox configuration, timeouts, or output caps
- the PID guard, signal allowlist, or path validation (`sentinel-capabilities`)
- the audit hash chain, its genesis constant, or the verifier (`sentinel-audit`)
- mTLS setup or certificate pinning (`sentinel-fleet`)
- the approval gate and capability-ID validation (`sentinel-agent-llm`)

Loosening any of these defaults is a breaking change even if the types do not
change.

## License

By contributing you agree that your contributions are licensed under the MIT
License, matching [LICENSE](LICENSE).
