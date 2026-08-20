# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `CONTRIBUTING.md` covering development setup, workspace layout and bounded
  contexts, code style, testing expectations, ADR process, and the
  security-sensitive areas that get extra review
- Tag-driven release automation: verification (fmt, clippy, tests, `cargo audit`),
  four-target binary builds (`x86_64-unknown-linux-gnu`,
  `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`)
  with SHA-256 sums, GitHub Release creation from the CHANGELOG section, and an
  opt-in crates.io publish that walks the workspace in dependency order

### Changed
- License declaration reconciled to **MIT**, matching `LICENSE` and the README
  badge — `workspace.package.license` previously declared Apache-2.0
- Workspace-internal dependencies now carry an explicit `version` alongside
  `path`; without it `cargo publish` rejects every crate in the workspace

### Fixed
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
