# ADR-016: Landlock Filesystem Sandbox and the Hardened Executor

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Security, Sandboxing, Process Execution

---

## Context

Two gaps, one documented and one not.

**Documented.** `SandboxConfig::read_only_paths` and `writable_paths` were
labelled "advisory; not kernel-enforced". Nothing read them. A capability's
child process could write anywhere its UID could.

**Not documented.** `README.md` and `SECURITY.md` describe an exact-match
command allowlist, per-command timeouts and `setrlimit` sandboxing. Those live
in `CommandExecutor`. Every production path (`sentinel run`, the TUI session,
`sentinel serve --mcp`, `sentinel execute`) handed capabilities
`RealCommandExecutor` instead, which has none of them: no allowlist, no
timeout, no rlimits. The documented protections were real code with real
tests, and were not in the path that runs commands.

A related defect: the MCP gate wraps each plan step in `tokio::time::timeout`.
When that fired, the future was dropped and the child process kept running.

## Decision

### Landlock enforcement in `sentinel-exec`

- When either path list is non-empty, `apply_sandbox` builds a Landlock ruleset
  that **handles every filesystem access right the running kernel knows**
  (ABI 1 base set, plus `REFER` on ABI ≥ 2, `TRUNCATE` on ≥ 3, `IOCTL_DEV` on
  ≥ 5). Handling a right means "deny unless a rule allows it".
- `read_only_paths` are granted read-file, read-dir and execute.
  `writable_paths` are granted everything handled.
- The ruleset is built in the parent. The `pre_exec` hook issues only raw
  `prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self` and `setrlimit`
  syscalls: no allocation, no locks, async-signal-safe.
- Direct syscalls through `libc` rather than a Landlock crate. It is three
  syscalls and a bit mask, and it keeps the post-`fork` code auditable.
- `SandboxConfig::write_restricted(paths)` is the practical profile: read and
  execute anywhere, write only under `paths` (plus `/dev/null`).
- A path that does not exist is skipped. It cannot be granted, and skipping
  only makes the sandbox stricter.
- **Kernels without Landlock.** `require_enforcement = true` refuses to spawn
  (`ExecError::SandboxUnavailable`); `false` logs a warning and runs
  unconfined. `write_restricted` sets it to `true`. `apply_sandbox` returns a
  `SandboxReport` saying what is actually enforced.
- Non-Linux targets compile a stand-in that reports Landlock as unavailable.

### `no_new_privs`

New `SandboxConfig::no_new_privs`. Always on when Landlock is used (the kernel
requires it for unprivileged callers). The child and everything it execs can
no longer gain privilege through setuid/setgid binaries or file capabilities.

### `HardenedExecutor`

A `CommandExecutorTrait` implementation, so it drops in where capabilities
expect an executor:

- exact-match allowlist (`BUILTIN_COMMANDS`: the 18 programs the built-in
  capabilities spawn; no shells, interpreters or `sudo`);
- timeout with SIGTERM → SIGKILL (15 minutes by default, sized for a package
  upgrade);
- rlimits and `no_new_privs`;
- `kill_on_drop`, so a cancelled or timed-out step takes its child with it;
- an optional Landlock profile via `with_sandbox`.

All four production call sites now use `HardenedExecutor::for_builtin_capabilities()`.

## What is and is not enforced after this ADR

| Control | Before | Now |
|---|---|---|
| Command allowlist in production | No | Yes |
| Per-command timeout in production | No | Yes |
| rlimits in production | No | Yes |
| `no_new_privs` | No | Yes |
| Child killed when its step is cancelled | No | Yes |
| Landlock filesystem allowlist | Not implemented | Implemented and tested; **not yet switched on for the built-in capabilities** |
| Network isolation (`deny_network`) | No | No (next roadmap item) |
| Environment scrubbing / fixed `PATH` | No | No (next roadmap item) |

The Landlock row is deliberate. Package managers legitimately write across
`/usr`, `/var` and `/etc`, so one process-wide write allowlist would either
break `package_upgrade` or allow nearly everything. The right shape is a
profile per capability (`log_vacuum` may write only under its `log_dir`,
`disk_usage` nowhere). That is a roadmap item of its own.

Allowlisted program names are resolved through `PATH`. Until the environment
is scrubbed, an attacker who controls Sentinel's `PATH` controls what `rm`
means; `no_new_privs` and the allowlist do not help with that.

## Consequences

- New direct dependency: `libc` (already in the lock file).
- `apply_sandbox` now returns `Result<SandboxReport, ExecError>`.
- `ExecutorConfig` gained a `sandbox` field.
- A capability that spawns a program outside `BUILTIN_COMMANDS` now fails with
  `NotAllowed`. A test asserts the list contains no shells or interpreters;
  new capabilities must extend it explicitly.
- Landlock tests skip, with a printed note, on kernels that lack it.

## Alternatives considered

- **`landlock` crate.** Friendlier API, but its `restrict_self` is not
  documented as async-signal-safe, and it must run after `fork`.
- **seccomp-bpf only.** Filters syscalls, not paths; cannot express "write only
  under this directory".
- **Mount/user namespaces (bubblewrap-style).** Stronger, but needs either
  privilege or unprivileged user namespaces, which many hardened hosts disable.
- **Pin the allowlist to absolute paths.** Would close the `PATH` issue but
  breaks across distributions (`/bin` vs `/usr/bin` vs `/usr/sbin`). A fixed,
  scrubbed `PATH` is the planned fix.
