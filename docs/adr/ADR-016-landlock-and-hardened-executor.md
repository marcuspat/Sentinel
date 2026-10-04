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
| Landlock filesystem allowlist | Not implemented | Enforced per command for the built-in capabilities (see the amendment below) |
| Network isolation (`deny_network`) | No | Yes, seccomp (second amendment) |
| Environment scrubbing / fixed `PATH` | No | Yes (second amendment) |

## Amendment: per-capability profiles

`CommandExecutorTrait` gained `run_confined(…, fs: &FsAccess)`, defaulting to
`run` so mocks and the thin executor are unaffected. `HardenedExecutor` turns
the `FsAccess` into a Landlock profile for that one child. Reading and
executing stay unrestricted in every profile; only writes are confined.

| Capability / command | May write |
|---|---|
| `disk_usage`, `process_list`, `process_kill`, `service_status`, `network_*`, `system_metrics`, every `which` probe, `log_vacuum`'s `find` | nothing (`/dev/null` only) |
| `log_vacuum`'s `rm` | under its `log_dir` |
| `cache_prune`'s `find -delete` | under the pruned path |
| `service_start` / `stop` / `restart` (`systemctl`) | under `/run` |
| `package_list`, `cache_prune`'s package-manager clean | `/var/cache`, `/var/lib`, `/var/log`, `/run`, `/tmp` |
| `package_upgrade` | unconfined, on purpose: an upgrade writes across `/usr`, `/etc` and `/boot` |

`SENTINEL_LANDLOCK` selects the mode: unset is best effort (confine when the
kernel can, warn when it cannot), `require` refuses to run a confined command
on a kernel without Landlock, `off` disables confinement.

Two honest caveats:

- The `systemctl` and package-manager profiles were chosen from how those
  tools behave, not verified against a live systemd or every package manager
  in this change's tests (the CI container has neither). If one needs a path
  not listed, the command fails with "Permission denied"; `off` is the
  immediate workaround and the profile is one line to widen.
- Landlock does not mediate signals or connecting to existing Unix sockets, so
  `kill` and `systemctl` are confined in what they can *write*, not in whom
  they can signal or ask.

This already paid for itself. `log_vacuum` split `find` output on newlines, so
a crafted directory name could redirect its `rm -f` to any `*.log` path on the
host. That is fixed at the source (NUL-separated output, prefix check), and
the confined `rm` would have refused it regardless.

## Amendment 2: network denial and environment scrubbing

**Network.** `deny_network` installs a 14-instruction seccomp-BPF filter in the
child: `socket()` with `AF_INET`, `AF_INET6` or `AF_PACKET` returns `EACCES`;
`io_uring_setup` returns `ENOSYS` (io_uring can create sockets without the
`socket` syscall); a syscall made through a foreign ABI kills the process.
Unix and netlink sockets are untouched, so `systemctl`, `ss` and `ip` work.
seccomp was chosen over Landlock's network rules because those cover TCP only
and need ABI 4; the filter covers UDP and raw sockets on any kernel with
seccomp. Supported on Linux x86_64 and aarch64; elsewhere the request is
reported as unenforced and `require_enforcement` decides.

`HardenedExecutor` applies it to every command not in `NETWORK_COMMANDS`
(the package managers, plus `ifconfig` and `netstat`, which open an inet
socket only for local ioctls). `SENTINEL_LANDLOCK=off` disables this together
with the filesystem confinement.

**Environment.** Children start from `env_clear()` with
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
`LC_ALL=C` and `LANG=C`. Package managers additionally get
`DEBIAN_FRONTEND=noninteractive` and the proxy variables. Overrides from
`ExecutionContext::env_overrides` pass through a filter that refuses `PATH`,
`LD_*`, `DYLD_*`, shell start-up variables and interpreter search paths.

Limits:

- A denied socket family is not a network namespace. A confined command can
  still talk to local daemons over Unix sockets, and a daemon may act on the
  network for it.
- The fixed `PATH` assumes a conventional layout. Distributions that keep
  binaries elsewhere (NixOS, Guix) will see "No such file or directory" for
  allowlisted commands; that needs a configurable search path, not yet built.
- The C locale changes the language of tool output. That is intended (the
  parsers expect it) but it is a behaviour change.

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
