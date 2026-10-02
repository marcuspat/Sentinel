# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- **Resource guards could be bypassed four ways.** Guards read only
  `args.path` and `args.service`, so `log_vacuum.log_dir` and
  `cache_prune.cache_dirs` were never checked; `sshd.service` and Debian's
  `ssh` slipped past the `sshd` guard; and `/var/../etc` or `//etc` slipped
  past the `/etc` guard. Guards now inspect every string in the arguments
  (any name, any nesting), normalise paths lexically, and compare unit names
  without their type suffix or instance. The default service guard also covers
  `ssh`, `systemd-*` and `containerd`, and the default path guard now covers
  the directories `SECURITY.md` already claimed it did (`/dev`, `/bin`,
  `/sbin`, `/lib`, `/lib64`, `/usr/bin`, `/usr/sbin`, `/usr/lib`,
  `/run/systemd`) — the code had only `/etc`, `/boot`, `/sys`, `/proc`.
  Symlinks are not resolved by the guard;
  Landlock remains the control for those.
- **An MCP client could make the audit log fail verification.** A float in a
  tool call's arguments could parse back from disk one bit different from the
  value that was hashed, so an untouched log reported tampering. Found by the
  new protocol fuzzer; fixed by enabling exact float round-tripping in
  `serde_json`.

### Added
- **Property tests and protocol fuzzing** (`proptest`, 32 properties): the
  policy evaluator (deny-by-default, kill switch, tightening never weakens,
  guards hold under any path/unit spelling), the untrusted-data fence (no
  content can forge or close it), the audit chain (any edit, drop, swap or
  splice is detected) and the MCP JSON-RPC surface (no panic, well-formed
  replies, nothing mutating runs without approval, audit chain stays valid).

### Security
- **Four dependency advisories fixed, found by the new `cargo deny` check.**
  `rustls` 0.23.40 → 0.23.45 (RUSTSEC-2026-0285, TLS 1.3 handshake messages
  accepted across key changes), `h2` → 0.4.19 (RUSTSEC-2026-0258, unbounded
  empty DATA frames), `crossbeam-epoch` → 0.9.21 (RUSTSEC-2026-0204) and
  `anyhow` → 1.0.104 (RUSTSEC-2026-0190, unsound `downcast_mut`).
- **`rustls-pemfile` removed** (RUSTSEC-2025-0134, unmaintained). Fleet PEM
  parsing now uses the PEM support in `rustls-pki-types`.
- **Supply-chain controls (`docs/SUPPLY_CHAIN.md`).** `cargo deny check`
  (advisories, licences, sources, wildcard versions) runs on every push; every
  GitHub Action is pinned to a commit SHA; both workflows default to a
  read-only token; release binaries are built with the same pinned toolchain CI
  tests with, ship a CycloneDX SBOM each, and carry a build provenance
  attestation (`gh attestation verify`). `sentinel-tui/tests/supply_chain.rs`
  fails the suite if any of these is loosened.
- **`sentinel fleet` ran outside policy, approval and audit (ADR-022).** The
  fleet path consulted no policy, asked for no approval and wrote no audit
  event. It now evaluates policy per host on the controller, dispatches nothing
  when approval is required and `--approve` is absent, and audits the run; each
  host re-checks under its own policy in the new `sentinel agent-exec`
- **Local command execution via `--hosts` (ADR-022).** A host spec such as
  `-oProxyCommand=…` was passed to `ssh` as an option and ran a command on the
  controller. Hostnames, users and key paths are now validated, and `ssh` is
  called with `--` before the destination
- **Remote command injection via `--capability` (ADR-022).** The capability id
  was interpolated unquoted into the remote shell command. It is now validated
  and every part of the remote command is quoted
- **Child processes no longer inherit Sentinel's environment (ADR-016).**
  Allowlisted program names were resolved through whatever `PATH` Sentinel was
  started with, so a poisoned `PATH` decided what `rm` or `systemctl` meant.
  Children now start from an empty environment with a fixed `PATH`
  (`/usr/local/sbin:…:/bin`) and `LC_ALL=C`; caller-supplied overrides that
  change what code is loaded (`PATH`, `LD_*`, `BASH_ENV`, `PYTHONPATH`, …) are
  refused. Proxy variables are passed only to package managers
- **Network denial is enforced (ADR-016).** `deny_network` used to log a
  warning and do nothing. It now installs a seccomp filter that denies
  `AF_INET`, `AF_INET6` and `AF_PACKET` sockets (TCP and UDP) and
  `io_uring_setup`, leaving Unix and netlink sockets working. Every built-in
  command except the package managers (and `ifconfig`/`netstat`, which need an
  inet socket for local ioctls) runs with it. Linux x86_64 and aarch64
- **Arbitrary file deletion through `log_vacuum`.** The capability listed
  files with `find` and split the output on newlines. A directory named
  `evil\n` inside the log directory, holding a copy of some absolute path,
  made the second line a path anywhere on the host, which was then passed to
  `rm -f` with Sentinel's privileges. Any local user able to create files in a
  vacuumed log directory could delete any file whose name ends in `.log`.
  Output is now NUL-separated and every path must sit under `log_dir`
- **Per-capability Landlock confinement (ADR-016).** Every command a built-in
  capability spawns now states what it may write, and the kernel enforces it:
  read-only capabilities can write nothing, `log_vacuum`'s `rm` only under its
  `log_dir`, `cache_prune`'s `find -delete` only under the pruned path,
  `systemctl` only under `/run`, package queries and cache cleaning only under
  package-manager state directories. `package_upgrade` is deliberately
  unconfined. `SENTINEL_LANDLOCK=require` refuses to run on kernels without
  Landlock; `off` disables confinement; the default warns and continues
- **Production now runs commands through the constrained executor (ADR-016).**
  The command allowlist, timeouts and rlimits described in `SECURITY.md` lived
  in `CommandExecutor`, but `sentinel run`, the TUI, `serve --mcp` and
  `sentinel execute` all gave capabilities `RealCommandExecutor`, which has
  none of them. They now use the new `HardenedExecutor`: exact-match allowlist
  of the 18 programs built-in capabilities spawn, 15-minute timeout with
  SIGTERM → SIGKILL, rlimits, `PR_SET_NO_NEW_PRIVS`, and kill-on-drop
- **Landlock filesystem sandbox (ADR-016).** `SandboxConfig::read_only_paths`
  and `writable_paths` were advisory and unused. They are now enforced by a
  Landlock ruleset covering every filesystem right the kernel supports, applied
  between `fork` and `execve` and inherited by all descendants.
  `SandboxConfig::write_restricted(paths)` gives "read anywhere, write only
  here". Kernels without Landlock either refuse to spawn or warn, per
  `require_enforcement`
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
- **Goals could not contain common letters in the TUI.** On the Goal tab `q`
  quit the program, `a`, `s` and `r` were swallowed and `j`/`k` scrolled, so a
  goal such as "restart nginx" could not be typed. Printable characters on the
  Goal tab are now always text
- **Typing or deleting a non-ASCII character in the TUI goal field panicked**:
  the cursor moved one byte at a time and landed inside the character
- **`sentinel fleet` could not work.** It invoked `sentinel agent-exec` on each
  host, a subcommand that did not exist. It exists now
- Fleet `AgentClient::register` / `heartbeat` returned success without doing
  anything; they now return `NotImplemented`
- The TLS fingerprint pin is compared as raw bytes in constant time, ignoring
  case and colons; a malformed pin rejects every certificate
- **`sentinel run` never performed approved mutating steps (ADR-019).** With
  the default policy every Medium-risk mutating capability evaluates to
  `RequiresApproval`; the loop's executor treated that as a refusal even after
  the operator had approved the plan, so those steps were skipped and counted
  as failures
- **A failed step was reported as completed.** The loop's executor marked a
  step `Completed` whenever the capability returned at all, including a
  `Failure` result, and carried on with the remaining steps
- **Steps were marked `RolledBack` when nothing was rolled back**: when the
  inverse failed, or the capability had no inverse
- **An approved plan could be executed twice.** `sentinel execute` read the
  plan, checked it was `Approved`, then wrote `Executing`: two processes
  started together both passed the check and both ran every step. Status
  transitions now run under an exclusive `flock` on a per-plan lock file, and
  `Approved -> Executing` is a single atomic claim that exactly one caller
  wins. The same race between `approve` and `reject` could leave one
  operator's status next to the other's decision record; also closed. Plan
  writes are now `fsync`ed (file and directory), so a crash cannot leave an
  empty plan document
- A plan step that hit the MCP gate's per-step timeout left its child process
  running. Children are now killed when the step's future is dropped
- CI failed on untouched code when Rust 1.99 shipped a clippy lint
  (`double_must_use`) that fires inside `async-trait`'s expansion. CI and the
  release verify job now pin the toolchain (1.97.0) instead of tracking
  `stable`, and clippy failures are surfaced as check annotations
- Investigation prompts panicked when truncating capability output whose
  2 000th byte fell inside a multi-byte UTF-8 character. Truncation is now
  char-boundary safe, and planning prompts, which previously had no limit, are
  now capped per observation

### Added
- **TUI Gate tab.** Lists plans proposed through `sentinel serve --mcp`
  (pending first), shows the selected plan's steps, risk, content hash and
  integrity check, and lets the operator approve (`a`, then type the first 8
  characters of the plan id, as `sentinel approve` requires) or reject (`x`,
  then `y`). It uses the same code path as the CLI commands, so audit events
  and refusals (not pending, content changed after proposal) are identical;
  approvals are recorded as `operator_tui`
- **Working metrics (ADR-021).** `SentinelMetrics` was defined and tested but
  never incremented or exported. Counters are now derived from the audit log
  on every append, so every command is measured and the numbers cannot
  disagree with the chain. New LLM metrics: requests by outcome, tokens by
  direction, retries, request duration; plus suspected prompt injections and
  MCP tool calls. Set `SENTINEL_METRICS_FILE` to have the Prometheus text
  exposition kept up to date (for node_exporter's textfile collector)
- **GenAI spans (ADR-021).** `gen_ai.chat` per model request and
  `gen_ai.execute_tool` per capability invocation, with OpenTelemetry GenAI
  semantic-convention attributes (model, token usage, finish reason, error
  type). Prompts, completions and tool arguments are never attached. No OTLP
  exporter is bundled
- **LLM retries, deadlines and session budgets (ADR-020).** Model calls made by
  `sentinel run` and the TUI are retried up to four times on rate limits,
  `5xx`/`529` and network errors, with jittered exponential backoff and
  `Retry-After` honoured (waits over 60 s are refused). Each attempt has a
  deadline. A session is capped at 100 model calls and 2,000,000 tokens
  (`SENTINEL_MAX_LLM_CALLS`, `SENTINEL_MAX_LLM_TOKENS`; `0` = unlimited);
  beyond that no request is made. Provider response bodies are read with an
  8 MiB cap instead of being buffered without limit
- **Policy files (ADR-018).** `--policy FILE` / `$SENTINEL_POLICY` loads
  operator rules and resource guards from TOML for `run`, the TUI,
  `serve --mcp`, `execute` and `policy`. In the default `tighten` mode file
  rules can only make the built-in decision stricter (an `allow` rule is
  rejected at load time); `mode = "replace"` swaps the built-in rules and is
  announced on every start. The kill switch, the built-in resource guards and
  deny-by-default cannot be changed from a file. Unknown keys, a missing or
  group/world-writable file all stop the process; there is no fallback to the
  default policy. `sentinel policy` now prints the effective policy including
  guards
- **Provider-native tool use for Anthropic (ADR-017).** Investigation and
  planning now go through `tools` / `tool_use` instead of a JSON object dug out
  of response text: one tool per capability with its argument schema, plus
  `done_investigating` and `propose_plan`. Exactly one tool call per turn;
  text is commentary and is never executed, so JSON a model is tricked into
  *writing* is no longer an action. New `Capability::args_schema()` on all 14
  built-ins and `LlmBackend::complete_with_tools`. `SENTINEL_NATIVE_TOOLS=off`
  restores the text protocol. Tested against `wiremock` only; not yet run
  against the live API
- **Native tool use for OpenAI and Ollama (ADR-017).** OpenAI function calling
  (`tool_choice: "required"`, parallel calls off), on by default for
  api.openai.com and opt-in for OpenAI-compatible servers. Ollama tool calling
  is opt-in per backend (`with_native_tools(true)`) since it depends on the
  model. Malformed OpenAI `arguments` fail the turn. `wiremock` only
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
- **One plan executor (ADR-019).** New `sentinel-runner` crate; `sentinel run`,
  the TUI and `sentinel execute` all execute plans through it. Approval covers
  the plan (`Denied` still never runs), policy uses the capability's current
  manifest, execution halts at the first denied or failed step, and audit
  events are written before each action
- `sentinel execute` now rolls back completed, rollback-capable steps after a
  failure, newest first; the inverse is policy-checked, so the kill switch
  stops rollback too. `--no-rollback` / `SENTINEL_NO_ROLLBACK` disables it on
  every path
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
