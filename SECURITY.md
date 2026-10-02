# Security Policy

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report security issues by emailing the maintainers directly or via GitHub's
private security advisory feature:
<https://github.com/marcuspat/Sentinel/security/advisories/new>

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Proposed fix (optional)

You will receive a response within 5 business days. We target a fix within 30 days
for critical/high findings and 90 days for medium/low.

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| 0.1.x | No — several of the issues fixed in 0.2.0 are exploitable; upgrade |

## Security Architecture

Sentinel is designed to operate with elevated system privileges. Its security model
relies on multiple layers of defense:

### Policy Engine (sentinel-policy)

- **Deny-by-default**: All requests are denied unless explicitly allowed by a matching rule.
- **Kill switch**: When activated, blocks **all** capabilities regardless of risk tier or kind.
  This is an emergency stop — it does not pass ReadOnly requests through.
- **Resource guards**: System directories (/etc, /boot, /sys, /proc, /dev, /bin, /sbin, /lib,
  /lib64, /usr/bin, /usr/sbin, /usr/lib, /run/systemd) and critical services (sshd/ssh,
  systemd and systemd-*, docker, containerd) are protected from mutating capabilities by
  default. Guards check every string argument at any depth, after lexical path normalisation
  (`..`, `//`, `.`) and with unit suffixes removed (`sshd.service` → `sshd`). They do not
  resolve symlinks; the Landlock profile is the control for those.
- **Policy files (ADR-018)**: `--policy FILE` / `$SENTINEL_POLICY`. In the default
  `tighten` mode a file can only make a decision stricter (`allow` is rejected at load
  time); `mode = "replace"` is the only way to loosen policy. The kill switch and the
  built-in guards stay in force in both modes. Parsing is strict, a bad file stops the
  command, and a file writable by group or other is refused.
- **Risk tiers**: Low, Medium, High, Critical — with distinct routing (allow / require-approval / deny).
- **Time restrictions**: Evaluated against server wall-clock (`Utc::now()`), not client-supplied timestamps.

### Command Execution (sentinel-exec)

Every production path runs commands through `HardenedExecutor` (ADR-016):

- **Exact-match allowlist**: only the programs the built-in capabilities spawn
  (`BUILTIN_COMMANDS`). No shells, interpreters or `sudo`. `/tmp/evil/ls` does **not**
  match `"ls"`.
- **No shell**: Commands are spawned directly via `tokio::process::Command` with explicit
  argument vectors — no shell expansion.
- **Timeout + output cap**: 15-minute default with SIGTERM → SIGKILL; a child is also
  killed when the step that started it is cancelled.
- **rlimits**: file descriptors (256), core dumps disabled.
- **`no_new_privs`**: children cannot gain privilege via setuid/setgid binaries or file
  capabilities.
- **Clean environment**: children inherit nothing. They get a fixed `PATH` and the C
  locale, so allowlisted names always resolve to system binaries; `LD_*`, `PATH` and
  similar overrides are refused.
- **No network**: a seccomp filter denies Internet and raw sockets to every command except
  the package managers (Linux x86_64 / aarch64).
- **Landlock filesystem confinement** (Linux ≥ 5.13): each command a built-in capability
  spawns may write only where that capability needs to — nothing for read-only
  capabilities, the target directory for `log_vacuum` and `cache_prune`. `package_upgrade`
  is unconfined by design. `SENTINEL_LANDLOCK=require` fails closed on kernels without
  Landlock; the default warns and continues. See ADR-016 for the full table.

### Capabilities (sentinel-capabilities)

- **PID guard**: ProcessKill rejects PID <= 1. PID 1 (init/systemd) cannot be signalled.
- **Signal allowlist**: Only TERM, KILL, HUP, INT, QUIT, USR1, USR2, CONT, STOP are accepted.
- **Path validation**: LogVacuum and CachePrune validate paths against a blocked prefix list
  before executing find/rm operations.

### Audit Log (sentinel-audit)

- **Hash chain**: SHA-256 chained log — every event includes the hash of the prior event.
  Tampering (deletion, reordering, modification) is detectable via `sentinel verify-audit`.
- **Signed checkpoints (opt-in, ADR-015)**: the hash chain is unkeyed, so on its own it
  cannot detect a log that was rewritten wholesale with a consistent chain. Set
  `SENTINEL_AUDIT_KEY` (from `sentinel audit-keygen`) to sign the chain head after every
  event; verify with `sentinel verify-audit PATH --pubkey KEY --require-signature`.
  Keep the key readable only by a dedicated user, and ship `<log>.sig` off-host if you
  need to detect truncation of log and signatures together.
- **Atomic writes**: Each JSONL line is written in a single `write_all` call to reduce
  the crash-window for partial writes.

### Plan Execution (sentinel-runner)

- **One executor (ADR-019)**: `sentinel run`, the TUI and `sentinel execute` share it.
  Policy is re-evaluated for every step, a `Failure` result halts the plan, and completed
  steps are rolled back in reverse order through the same policy check (`--no-rollback`
  opts out). A rollback is audited only when it succeeded.

### MCP Gate and Plan Store (sentinel-mcp)

- **No approve or execute tool (ADR-013)**: an MCP client can list, dry-run policy, run
  read-only capabilities and propose plans. Approval needs an interactive terminal.
- **Content hash**: a plan modified after approval is refused.
- **Locked store**: per-plan `flock`, an atomic `Approved → Executing` claim and `fsync`ed
  writes, so an approved plan cannot be executed twice.

### Fleet (sentinel-fleet)

`sentinel fleet` runs one capability on many hosts over SSH (ADR-022):

- **Policy twice**: evaluated per host on the controller, then again on each host under
  that host's own policy by `sentinel agent-exec`. Nothing is dispatched when approval is
  required and `--approve` is absent. The run is audited.
- **Input validation**: host specs, users, key paths and capability ids are validated;
  `ssh` is called with `--` before the destination and every part of the remote command
  is quoted.
- **mTLS is not in this path.** The mutual-TLS and certificate-pinning code described in
  ADR-008 exists in the crate (pins are compared in constant time) and is exercised only
  by its tests.

### LLM Integration (sentinel-agent-llm)

- **Policy gate**: Every capability invocation in every phase (investigation and execution)
  passes through `PolicyEvaluator::evaluate` before running.
- **Approval gate**: Plan execution requires `plan.approval` to be set to an approved state
  via an explicit call before `execute_plan` will proceed.
- **Untrusted output (ADR-014)**: capability output is wrapped in a fence carrying a fresh
  random nonce and the fence marker is neutralised inside the data, so output cannot close
  or forge the fence. This lowers the odds of prompt injection; the policy and approval
  gates are what bound its effect.
- **Native tool use (ADR-017)**: with Anthropic and api.openai.com the model requests
  capabilities through the provider's tool-call channel, validated against each
  capability's argument schema; free text is not parsed for requests on that path.
  `SENTINEL_NATIVE_TOOLS=off` restores the text protocol.
- **Deadlines and budgets (ADR-020)**: 120 s per attempt, at most 4 attempts, and a
  per-session budget (default 100 calls, 2,000,000 tokens). Response bodies are capped.
- **Capability ID validation**: LLM-supplied capability IDs are validated against `[a-zA-Z0-9._-]`
  and cross-checked against the capability registry before any invocation.

### Build and Release

- Dependencies are checked against the RustSec advisory database, a permissive
  licence allow-list and a crates.io-only source policy on every push
  (`cargo deny`, `deny.toml`).
- CI actions are pinned to commit SHAs and run with a read-only token.
- Release binaries are built `--locked` with the toolchain CI tested, and are
  published with a SHA-256 file, a CycloneDX SBOM and a build provenance
  attestation: `gh attestation verify sentinel-<target> --repo marcuspat/Sentinel`.
- Details and limits: [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).

## Known Limitations

- Landlock confines writes only. It does not restrict reads, signals, or connections to
  existing Unix sockets, and on kernels without it the default is to warn, not refuse.
- Network denial blocks socket families, not a network namespace: Unix-socket access to
  local daemons remains.
- The fixed child `PATH` assumes a conventional filesystem layout (not NixOS/Guix).
- `sentinel fleet` trusts SSH authentication to carry the operator's approval to each host,
  and uses `StrictHostKeyChecking=accept-new` (trust on first use). Every approved host is
  contacted in parallel — staged rollout is not wired in — and the mTLS controller protocol
  is not implemented (roadmap 14f).
- Resource guards compare paths lexically and do not resolve symlinks.
- The audit log does not record which policy file was in force (roadmap 14c).
- A process killed mid-run leaves its plan in `Executing`; there is no operator command to
  fail it yet (roadmap 14d). The plan-store lock is advisory and does not cover NFS.
- The LLM token budget can be overshot by one response, and a provider that reports no
  usage counts as zero tokens.
- Provider wire formats are tested against mock servers only, never the live APIs.
- Spans are emitted through `tracing`; no OTLP exporter is bundled (roadmap 14e).
- Fuzzing is property-based (`proptest`); there are no coverage-guided `cargo-fuzz` targets.
- The release workflow's SBOM and attestation steps have not yet run end to end (they
  run only on a tag).
- `GENESIS_HASH` is defined as 64 zero characters (an arbitrary sentinel value), not
  `SHA-256("")`. External audit tools must use the same convention.
