# ADR-022: Fleet Path — Policy, Audit and Input Validation

**Status:** Accepted (amends ADR-008)  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Fleet, Security, Policy

---

## Context

`sentinel fleet` runs one capability on many hosts over SSH. The roadmap item
was narrow (constant-time fingerprint comparison, replace the stubs). Reading
the path end to end found more:

1. **It could not work.** The controller ran `sentinel agent-exec <cap> <args>`
   on each host, and no `agent-exec` subcommand existed. Every host answered
   with a usage error.
2. **It bypassed the product.** `run_fleet` did not consult the policy engine,
   asked for no approval, and wrote no audit event. Had it worked, it would
   have run any capability, including mutating ones, on every listed host with
   none of the controls every other path has.
3. **Local command execution through a host spec.** The destination was passed
   to `ssh` as a plain argument, so `--hosts '-oProxyCommand=…'` was parsed as
   an option and ran a command on the controller.
4. **Remote command injection.** The capability id was interpolated unquoted
   into the remote command line.
5. `AgentClient::register` / `heartbeat` returned `Ok(())` without doing
   anything.
6. The pinned-fingerprint check compared formatted hex strings.

## Decision

### Host side: `sentinel agent-exec`

Implemented (hidden from `--help`; it is called over SSH). It runs one
capability through the hardened executor under **this host's** policy, writes
its own audit chain, and prints the `CapabilityResult` as JSON.

- `Denied` is refused, whatever the controller says.
- `RequiresApproval` is refused unless the controller passed `--approved`.
- Unknown capabilities, non-object arguments and arguments that fail
  `validate_args` are refused before policy is consulted.

### Controller side: `sentinel fleet`

- The capability must exist locally; arguments are validated locally.
- Policy is evaluated per host (`target_host` = hostname). Denied hosts are
  skipped and reported. If any host needs approval and `--approve` was not
  given, **nothing is dispatched** and the run exits non-zero.
- An audit chain records the goal, each per-host decision, the dispatch, each
  outcome and completion, signed when `SENTINEL_AUDIT_KEY` is set.
- Exit status is non-zero when any host failed or was denied.

### Input validation

- Hostnames and users are restricted to `[A-Za-z0-9._-]` (plus `:` in
  hostnames) and may not begin with `-`; key paths may not begin with `-`.
- `ssh` is invoked with `--` before the destination.
- Capability ids are restricted to `[A-Za-z0-9._-]`.
- Every component of the remote command is single-quoted.
- The SSH executor repeats these checks itself, so a programmatic caller
  cannot skip them.

### Smaller fixes

- The fingerprint pin is parsed to 32 raw bytes once and compared with
  `subtle::ConstantTimeEq`. A pin that is not a SHA-256 digest now rejects
  every certificate instead of never matching by accident of formatting; case
  and colons are ignored.
- `AgentClient` methods return `FleetError::NotImplemented`.

## Trust model

The host trusts SSH authentication to identify the operator: `--approved` is a
claim made by whoever can log in and run `sentinel agent-exec`. That is the
same trust SSH access already implies, and the host's own `Denied` rules and
resource guards still apply. It is not a cryptographic proof of approval;
carrying a signed approval from the controller is future work.

## Not covered

- `StrictHostKeyChecking=accept-new` remains: first contact trusts the host
  key. Pre-populating `known_hosts` is the operator's job.
- The controller resolves `ssh` through its own `PATH`.
- Tested with a fake `ssh` that runs the remote command locally; not against a
  real SSH server.
- No staged rollout on this path: every approved host is contacted in
  parallel. `StagedRollout` exists but is not wired to `sentinel fleet`.
- The mTLS controller/agent protocol of ADR-008 is still unimplemented; the
  TLS code is exercised only by its tests.
