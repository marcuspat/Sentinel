# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- **Signed audit checkpoints (ADR-015).** The hash chain alone could not tell
  a genuine log from one rewritten wholesale: the hashes are unkeyed, so a
  forged but consistent chain verified as `VALID`. With `SENTINEL_AUDIT_KEY`
  set, every audit event is now followed by an Ed25519-signed checkpoint of
  the chain head in the sidecar `<log>.sig`. `sentinel verify-audit PATH
  --pubkey HEX|FILE` checks them against the operator's public key and fails on
  a rewritten chain, a foreign signing key, or a truncated log;
  `--require-signature` also fails on a missing sidecar or unsigned tail. New
  `sentinel audit-keygen --out FILE` (mode 0600, never overwrites). A key that
  is configured but unusable stops the process instead of logging unsigned.
  Not covered, by design and documented: an attacker who can read the signing
  key, and truncation of log and sidecar together without an off-host copy of
  the latest checkpoint
- **Prompt-injection hardening (ADR-014).** Capability output is now
  *spotlighted*: wrapped in nonce-tagged `UNTRUSTED-DATA` fences with forged
  fences neutralised, and both system prompts tell the model that fenced
  content is data, never instructions. Byte budgets apply to the raw payload
  (neutralisation runs after truncation, so padding can't evict real data).
  A heuristic tripwire scans the full rendered payload of observations and
  execution results across all phases (investigate, plan, execute) — a
  superset of the truncated prefix prompts embed; hits are logged and
  written to the hash-chained audit log as a new
  `SuspectedPromptInjection` event

### Fixed
- Investigation prompts panicked when truncating capability output whose
  2 000th byte fell inside a multi-byte UTF-8 character. Truncation is now
  char-boundary safe, and planning prompts, which previously had no limit, are
  now capped per observation

### Added
- **MCP policy gate** (`sentinel-mcp` crate, ADR-013): `sentinel serve --mcp`
  speaks MCP over stdio and exposes five tools: `sentinel_capabilities`,
  `sentinel_policy_check` (dry policy evaluation with the matching rule),
  `sentinel_investigate` (read-only capabilities only), `sentinel_propose_plan`
  (validates and stores a `PendingApproval` plan and never executes) and
  `sentinel_plan_status`. There is no approve or execute tool
- Operator commands for gate plans: `sentinel plans`, `show-plan`, `approve`
  (interactive terminal required), `reject` and `execute` (refuses unapproved
  plans and plans whose content changed after approval). File-backed plan store
  under `--state-dir` / `$SENTINEL_STATE_DIR` (default
  `$XDG_STATE_HOME/sentinel`)
- `AuditEventType::McpToolCalled`, recorded before every MCP tool call; the
  gate, `approve`, `reject` and `execute` each write their own hash-chained log
  under `<state-dir>/audit/`
- `plans/SPEC-mcp-gate-and-arena.md`: gate spec, Sentinel Arena design (not
  deployed), crates.io naming check, milestones
- `CONTRIBUTING.md` covering development setup, workspace layout and bounded
  contexts, code style, testing expectations, ADR process, and the
  security-sensitive areas that get extra review
- Tag-driven release automation: verification (fmt, clippy, tests, `cargo audit`),
  four-target binary builds (`x86_64-unknown-linux-gnu`,
  `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`)
  with SHA-256 sums, and GitHub Release creation from the CHANGELOG section
- `rust-version = "1.86"` on `workspace.package`, so cargo reports the real
  minimum supported Rust version instead of failing deep inside a dependency

### Changed
- Tracing output from every `sentinel` subcommand now goes to stderr (was
  stdout), so stdout carries only command output or, under `serve --mcp`, the
  JSON-RPC stream
- License declaration reconciled to **MIT**, matching `LICENSE` and the README
  badge — `workspace.package.license` previously declared Apache-2.0
- Workspace-internal dependencies now carry an explicit `version` alongside
  `path` (required of any crate that is ever published)
- Removed the crates.io badge and publish step. `sentinel-agent` — the crate the
  badge advertised — has never existed, and `sentinel-core` and `sentinel-tui` are
  registered to other authors, so the workspace cannot be published under these
  names. Releases ship binaries and container images only
- Documented minimum Rust version corrected from 1.75 to **1.86** in the README
  and CONTRIBUTING.md

### Fixed
- `docker build` could not succeed: the builder image was `rust:1.82-slim`, but
  `ratatui 0.30` requires Rust 1.86 and `clap 4.6` requires 1.85, so cargo refused
  the workspace before compiling anything. Builder bumped to `rust:1.86-slim`
- Terminal output and log messages in `sentinel-tui` printed mojibake: box-drawing
  rules, em dashes, arrows and ellipses had been committed as double-encoded UTF-8
  (`â` sequences), so `sentinel run` rendered `â──â──` instead of `──`. 3,096
  sequences repaired across the four TUI sources and the Dockerfile
- `cargo clippy --workspace --all-targets -- -D warnings` — the exact command the
  CI lint step runs — failed on current stable with eight `collapsible_match`
  errors in `sentinel-tui`. The TUI key handler now uses match guards. Behaviour
  is unchanged: `a`, `s` and `r` keep being swallowed off the Plan tab via an
  explicit no-op arm rather than falling through to the Goal-tab text input

## [0.1.0] - 2026-05-26

### Added

- Initial release of Sentinel — Rust agentic system administration tool
- 8-crate Cargo workspace: core, exec, policy, audit, capabilities, agent-llm, fleet, tui
- **sentinel-core**: Capability trait, RiskTier enum (Low/Medium/High/Critical), CapabilityResult
  enum, Plan/PlanStep/Session/ExecutionContext types (90 tests)
- **sentinel-exec**: Sandboxed command executor with exact-match allowlist, configurable timeout,
  output size cap, rlimit sandbox (RLIMIT_NOFILE, RLIMIT_CORE, RLIMIT_NPROC) (26 tests)
- **sentinel-policy**: Deny-by-default PolicyEvaluator — kill switch blocks all capabilities,
  resource guards for system paths/services, 6 default rules with risk-tiered routing (53 tests)
- **sentinel-audit**: SHA-256 hash-chained append-only audit log, JSONL export, chain verifier,
  Prometheus metrics integration (30 tests)
- **sentinel-capabilities**: 14 built-in capabilities across filesystem (DiskUsage, LogVacuum,
  CachePrune), process (ProcessList, ProcessKill, ServiceStatus, ServiceRestart, ServiceStop,
  ServiceStart), packages (PackageList, PackageUpgrade), network (NetworkConnections,
  NetworkInterfaces), and metrics (SystemMetrics) (60 tests)
- **sentinel-agent-llm**: Investigate/Plan/Act reasoning loop; pluggable LlmBackend trait;
  Anthropic Claude, OpenAI, and Ollama backends; PromptBuilder for structured JSON prompts (53 tests)
- **sentinel-fleet**: Mutual TLS with rcgen + rustls 0.23; SHA-256 certificate pinning;
  FleetTopology with HostSelector; StagedRollout state machine (40 tests)
- **sentinel-tui**: ratatui 0.30 interactive TUI — 5 tabs (Goal/Investigation/Plan/Execution/Audit),
  approval workflow (approve-all / step-by-step / reject), clap CLI (30 tests)
- 12 Architecture Decision Records (ADR-001 through ADR-012)
- DDD documentation: ubiquitous language, bounded contexts, aggregates, domain events,
  domain services, repositories
- Criterion benchmarks for sentinel-core, sentinel-policy, sentinel-audit

### Security

Pre-release security review identified and resolved 10 findings:

- **[Critical]** Authorization bypass: `execute_plan` approval parameter now applied to plan before
  gate check; rejected plans correctly block execution
- **[Critical]** Command allowlist basename bypass: `check_allowlist` now requires exact command
  string match; `/tmp/evil/ls` no longer matches an `ls` allowlist entry
- **[Critical]** ProcessKill PID 1 unguarded: `validate_args` now rejects PID <= 1
- **[High]** Kill switch passthrough: kill switch now blocks all capabilities regardless of
  ReadOnly/Mutating kind
- **[High]** Unbounded path destruction: LogVacuum and CachePrune validate paths against a blocked
  prefix list (/etc, /boot, /sys, /proc, /dev, /bin, /usr/bin, etc.)
- **[High]** Forgeable time restrictions: TimeWindow policy condition now reads `Utc::now()`
  instead of the caller-supplied `req.timestamp`
- **[Medium]** False network isolation: `deny_network` sandbox flag documented and warned as
  unenforced at rlimit level
- **[Medium]** Unvalidated capability IDs: `CapabilityRequestParser` now validates capability_id
  character set before returning
- **[Medium]** Unallowlisted signals: ProcessKill now accepts only
  TERM/KILL/HUP/INT/QUIT/USR1/USR2/CONT/STOP
- **[Medium]** Non-atomic audit write: JSONL append now uses a single `write_all` call

### Dependencies

- Rust edition 2021, MSRV 1.75
- tokio 1.35, serde 1.0, rustls 0.23, ratatui 0.30, reqwest 0.12, prometheus 0.14
- `cargo audit`: 0 vulnerabilities at release

[0.1.0]: https://github.com/marcuspat/Sentinel/releases/tag/v0.1.0
