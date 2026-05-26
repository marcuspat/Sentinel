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
| 0.1.x | Yes |

## Security Architecture

Sentinel is designed to operate with elevated system privileges. Its security model
relies on multiple layers of defense:

### Policy Engine (sentinel-policy)

- **Deny-by-default**: All requests are denied unless explicitly allowed by a matching rule.
- **Kill switch**: When activated, blocks **all** capabilities regardless of risk tier or kind.
  This is an emergency stop — it does not pass ReadOnly requests through.
- **Resource guards**: System directories (/etc, /boot, /sys, /proc, /dev, /bin, /usr/bin, /lib,
  /run/systemd) and critical services (sshd, systemd, docker) are protected by default.
- **Risk tiers**: Low, Medium, High, Critical — with distinct routing (allow / require-approval / deny).
- **Time restrictions**: Evaluated against server wall-clock (`Utc::now()`), not client-supplied timestamps.

### Command Execution (sentinel-exec)

- **Exact-match allowlist**: Command strings must match exactly — no basename fallback, no glob.
  `/tmp/evil/ls` does **not** match an allowlist containing `"ls"`.
- **No shell**: Commands are spawned directly via `tokio::process::Command` with explicit
  argument vectors — no shell expansion.
- **Sandbox**: `setrlimit` limits file descriptors (256), disables core dumps, optionally
  restricts process creation. Network isolation requires external namespaces/seccomp.
- **Timeout + output cap**: Configurable per-command timeout and max output bytes.

### Capabilities (sentinel-capabilities)

- **PID guard**: ProcessKill rejects PID <= 1. PID 1 (init/systemd) cannot be signalled.
- **Signal allowlist**: Only TERM, KILL, HUP, INT, QUIT, USR1, USR2, CONT, STOP are accepted.
- **Path validation**: LogVacuum and CachePrune validate paths against a blocked prefix list
  before executing find/rm operations.

### Audit Log (sentinel-audit)

- **Hash chain**: SHA-256 chained log — every event includes the hash of the prior event.
  Tampering (deletion, reordering, modification) is detectable via `sentinel verify-audit`.
- **Atomic writes**: Each JSONL line is written in a single `write_all` call to reduce
  the crash-window for partial writes.

### Fleet (sentinel-fleet)

- **Mutual TLS**: All controller-to-agent communication uses mTLS via rustls 0.23.
- **Certificate pinning**: Client verifies the server's SHA-256 fingerprint directly;
  does not rely on a CA bundle.

### LLM Integration (sentinel-agent-llm)

- **Policy gate**: Every capability invocation in every phase (investigation and execution)
  passes through `PolicyEvaluator::evaluate` before running.
- **Approval gate**: Plan execution requires `plan.approval` to be set to an approved state
  via an explicit call before `execute_plan` will proceed.
- **Capability ID validation**: LLM-supplied capability IDs are validated against `[a-zA-Z0-9._-]`
  and cross-checked against the capability registry before any invocation.

## Known Limitations

- `deny_network` in `SandboxConfig` is advisory: enforcing network isolation requires Linux
  network namespaces or seccomp BPF filters, which are outside the scope of rlimit-based
  sandboxing. A `tracing::warn!` is emitted when this flag is set.
- The TLS fingerprint comparison in `PinnedFingerprintVerifier` uses string equality on
  hex-encoded bytes. For use cases requiring constant-time comparison, replace with
  `subtle::ConstantTimeEq` on the raw digest bytes.
- `GENESIS_HASH` is defined as 64 zero characters (an arbitrary sentinel value), not
  `SHA-256("")`. External audit tools must use the same convention.
