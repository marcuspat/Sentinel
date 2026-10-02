# ADR-018: Policy Files

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Policy, Configuration, Security

---

## Context

The policy was compiled in. An operator who wanted "never restart services on
`prod-*`" or "protect `/srv/app/data`" had to edit `engine.rs` and rebuild.
The MCP gate spec listed policy file loading as a follow-up (A.7 #4).

The risk in making policy configurable is that the configuration becomes the
way to switch safety off: one `allow` rule with priority 1 and the deny-by-default
engine allows everything.

## Decision

`--policy FILE` (global flag) or `$SENTINEL_POLICY`, TOML, read once at
start-up and used by every command that evaluates policy: `run`, the TUI,
`serve --mcp`, `execute` and `policy`.

```toml
version = 1

[[rule]]
id = "no-restarts-on-prod"
description = "Production services are restarted by the on-call human"
effect = "deny"            # deny | require_approval | audit_only | allow
priority = 10
[rule.when]                # every field present must match
capability_id_in = ["service_restart", "service_stop"]
target_host = "prod-*"

[[guard]]
id = "app-data"
protected_paths = ["/srv/app/data"]
protected_services = ["postgresql"]
```

`when` fields: `capability_id`, `capability_id_in`, `risk`, `risk_at_least`,
`kind`, `target_host` (glob), `phase`, `arg_contains = { path, value }`.

### Two modes

- **`tighten` (default).** The built-in rules still decide every request.
  File rules are then consulted (ascending priority, first match), and the
  final effect is the **stricter** of the two: `Deny` > `RequireApproval` >
  `AuditOnly` > `Allow`. A file rule can turn an allow into a denial; it can
  never turn a denial or an approval requirement into something weaker. An
  `allow` rule is rejected at load time, with an error that says why, because
  it could never take effect.
- **`replace`.** The file's rules replace the built-in rules. This is the only
  way to loosen policy. It is announced with a warning on every start, and a
  `replace` file with no rules is rejected (it would deny everything).

### What no file can change

- The kill switch.
- The built-in resource guards. File guards are added; redefining a built-in
  guard id is an error.
- Deny-by-default for requests no rule matches.

### Failing closed

- Unknown keys anywhere are an error (`deny_unknown_fields`): a misspelt
  `enabeld = false` must not silently leave a rule enabled.
- A file that is configured but missing, unparsable, over 1 MiB, or writable by
  group/other stops the process. There is no fallback to the default policy,
  and the gate does not start.
- `sentinel --policy FILE policy` prints the effective policy (rules,
  tightening rules, guards), so a file can be checked before it is deployed.

## Consequences

- New dependency in `sentinel-policy`: `toml` (already in the workspace).
- `PolicyEvaluator` gained `with_tightening_rules`, `tightening_rules()` and
  `resource_guards()`.
- Conditions are a flat AND. `Not`/`Or`/`TimeWindow` exist in the engine but are
  not exposed in the file format yet.
- The file is read at start-up only; changing it means restarting the process.
- **Not covered:** the policy file is not hashed into the audit log, so a chain
  does not yet prove which policy was in force. Worth adding.

## Found while doing this (not fixed here)

Resource guards read only `args.path` and `args.service`. `log_vacuum` takes
`log_dir` and `cache_prune` takes `cache_dirs`, so the path guard never sees
their targets (both capabilities carry their own blocked-prefix check, which is
what actually protects `/etc` today). Service names are matched exactly, so
`sshd.service` or `ssh` is not caught by the `sshd` guard, and paths are not
normalised (`/etc/../etc`). Tracked as a roadmap item.

## Alternatives considered

- **Serialise `PolicyRule` directly.** No new format, but nested tagged enums
  are unpleasant in TOML and expose every internal condition as stable API.
- **Priority interleaving** (file rules sorted in with built-ins). Simple, and
  exactly the footgun described above: one low-priority `allow` disables the
  policy.
- **Cedar / OPA.** The right answer for fleet-scale policy; a large dependency
  and a second language for a single-host tool.
