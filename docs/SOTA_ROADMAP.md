# SOTA roadmap — round 2

Working branch: `feat/sota-round-2` (one long-running draft PR; **not merged
without the maintainer's say-so**).

Round 1 (PR #10) shipped prompt-injection spotlighting and `cargo fmt` in CI.
Its own roadmap listed four more items that never landed; they open this round.
The rest comes from the follow-ups in `plans/SPEC-mcp-gate-and-arena.md` (A.7,
milestones M2–M3) and the "Known Limitations" section of `SECURITY.md`.

## Rules every loop follows

1. Take the first unchecked item below. One item per loop; if it turns out to
   be too big, land the part that is complete and tested and split the rest
   into a new item directly beneath it.
2. Ship code **with tests**. A security claim needs a test that fails without
   the change.
3. Before committing, all three must pass:
   `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`.
4. **No paid API calls.** LLM behaviour is tested with `wiremock` and fake
   backends only.
5. Update `CHANGELOG.md` under `[Unreleased]`; add or amend an ADR when a
   decision is made.
6. Commit, push to `feat/sota-round-2`, tick the item here with the commit hash
   and the workspace test count.
7. Say what is *not* covered. No claim in docs that a test does not back.

## Backlog

- [x] **0. Signed audit checkpoints** — Ed25519 signatures over the chain head, `audit-keygen`, `verify-audit --pubkey` (ADR-015). *454 → 473 tests.*
- [x] **1. Real sandbox: Landlock.** Landlock enforcement of `read_only_paths` / `writable_paths`, `no_new_privs`, and a `HardenedExecutor` that production now uses (it previously ran commands with no allowlist, timeout or rlimits). ADR-016. *473 → 486 tests.*
- [x] **1b. Per-capability Landlock profiles.** Every built-in command declares what it may write (`FsAccess`) and the hardened executor enforces it per call; `SENTINEL_LANDLOCK=off|require`. Found and fixed an arbitrary-file-deletion bug in `log_vacuum` (newline in a file name). *486 → 497 tests.*
- [x] **2. Real sandbox: network and environment.** seccomp filter denying inet/raw sockets for every command but the package managers; children start from an empty environment with a fixed `PATH`; dangerous overrides refused. *497 → 506 tests.*
- [x] **3. Provider-native tool use: Anthropic.** Argument schemas on every capability, `complete_with_tools` on the backend trait, Anthropic `tools`/`tool_use`, one call per turn, text never executed (ADR-017). *506 → 527 tests.*
- [x] **4. Provider-native tool use: OpenAI and Ollama.** OpenAI function calling (default on for api.openai.com, opt-in for compatible servers); Ollama tool calling (opt-in, cannot force a call); shared tool conversion; text fallback unchanged. *527 → 538 tests.*
- [x] **5. Policy file loading.** `--policy FILE` / `$SENTINEL_POLICY` (TOML) for every command; `tighten` mode can only make decisions stricter, `replace` is explicit and loud; guards and kill switch untouchable; strict parsing; fails closed (ADR-018). *538 → 552 tests.*
- [x] **6. Plan-store locking.** Per-plan `flock`, atomic `Approved -> Executing` claim, locked `approve`/`reject`, `fsync`ed writes. The double-execution race was real and is reproduced by a test. *552 → 556 tests.*
- [x] **7. One plan executor.** New `sentinel-runner` crate used by `run`, the TUI and `execute`; approval covers the plan; `Failure` is a failure; halt on first failure (ADR-019). *556 → 573 tests.*
- [x] **8. Rollback.** Done with item 7: reverse-order `invoke_inverse` in the shared executor, policy-checked, audited as `CapabilityRolledBack` only on success, `--no-rollback` opt-out on every path.
- [x] **9. LLM resilience.** `ResilientBackend`: per-attempt deadline, bounded retries with jittered backoff, `Retry-After` honoured, per-session call and token budget, capped response bodies (ADR-020). *573 → 587 tests.*
- [x] **10. Observability.** Metrics derived from the audit stream (they were defined but never incremented), LLM token/request/retry metrics, `SENTINEL_METRICS_FILE`, `gen_ai.chat` / `gen_ai.execute_tool` spans with GenAI semconv attributes (ADR-021). *587 → 597 tests.*
- [x] **11. Fleet hardening.** Constant-time pin comparison and honest stubs, plus what reading the path turned up: the missing `agent-exec` command, policy/approval/audit on the fleet path, ssh option injection via `--hosts`, shell injection via `--capability` (ADR-022). *597 → 612 tests.*
- [ ] **12. TUI pending-plans tab.** List `PendingApproval` gate plans with approve / reject, reusing `PlanStore`. (SPEC A.7 #1)
- [ ] **13. Supply chain.** Toolchain bump policy (CI is pinned to 1.97.0; 1.99's `double_must_use` fires in `async-trait` output — update or allow it, then bump). `cargo-deny` (advisories, licences, sources) and `cargo audit` in CI, pinned action SHAs, CycloneDX SBOM and build provenance attestation on release.
- [ ] **14. Property tests and fuzzing.** `proptest` for the policy evaluator (deny-by-default holds for arbitrary requests), the untrusted-data fence (no input can forge or close a fence), and audit-chain verification; `cargo-fuzz` targets for the MCP JSON-RPC parser.
- [ ] **14b. Resource guard coverage.** Guards read only `args.path` / `args.service`: `log_vacuum.log_dir` and `cache_prune.cache_dirs` are never checked, `sshd.service` / `ssh` bypass the `sshd` guard, and paths are not normalised (`/etc/../etc`, `//etc`). Make guards inspect every path- and service-typed argument, normalise, and match unit-name variants.
- [ ] **14c. Policy provenance in the audit log.** Record a hash of the effective policy (file path, mode, rule ids) at session start so a chain proves which policy was in force.
- [ ] **14d. Stuck `Executing` plans.** A process killed mid-run leaves its plan `Executing` forever; add `sentinel fail-plan ID` (operator, audited) and show the age of `Executing` plans in `sentinel plans`.
- [ ] **14e. OTLP export.** Optional `tracing-opentelemetry` layer behind a cargo feature and `OTEL_EXPORTER_OTLP_ENDPOINT`, so the GenAI spans reach a collector.
- [ ] **14f. Fleet follow-ups.** Wire `StagedRollout` into `sentinel fleet` (canary first), carry a signed approval instead of a flag, and decide whether the unimplemented mTLS controller code should stay in the tree.
- [ ] **15. Release wrap-up.** README, `SECURITY.md`, CHANGELOG and ADR index brought in line with what shipped; version bump to 0.2.0; PR description rewritten as a release summary.

If the backlog empties early, the remaining loops audit the code for new
defects (start with `unwrap`/`expect` on non-test paths and anything that
trusts LLM- or capability-supplied strings) and add findings here before
fixing them.

## Log

| Loop | Item | Commit | Tests | Notes |
|---|---|---|---|---|
| 0 | Signed audit checkpoints | *(first commit on the branch)* | 473 | Whole-file rewrite now detected; key custody and consistent truncation documented as open in ADR-015 |
| 1 | Landlock + hardened executor | *(second feature commit)* | 486 | Found production bypassing the documented allowlist/timeout/rlimits; fixed. Landlock not yet on for built-ins (item 1b). CI was red from Rust 1.99 clippy on untouched code; toolchain pinned |
| 2 | Per-capability Landlock profiles | *(third feature commit)* | 497 | `log_vacuum` newline path injection found and fixed. `systemctl` / package-manager profiles not verified against live systemd or package managers |
| 3 | Network denial + environment scrub | *(fourth feature commit)* | 506 | Fixed `PATH` assumes a conventional layout (not NixOS); socket-family denial is not a network namespace |
| 4 | Anthropic native tool use | *(fifth feature commit)* | 527 | Wire format tested with `wiremock` only; never sent to the live API. Schema test caught a wrong `cache_prune` schema before it shipped |
| 5 | OpenAI + Ollama tool use | *(sixth feature commit)* | 538 | `wiremock` only. OpenAI backend still sends `max_tokens` (newer models want `max_completion_tokens`); Ollama is not selectable from the CLI |
| 6 | Policy files | *(seventh feature commit)* | 552 | Found resource guards miss `log_dir` / `cache_dirs` and unit-name variants (item 14b). Policy file is not yet hashed into the audit log (14c) |
| 7 | Plan-store locking | *(eighth feature commit)* | 556 | Double execution confirmed (race tests fail 3/3 with the lock disabled). Killed executor leaves a plan stuck in `Executing` (14d); advisory lock does not cover NFS |
| 8 | One plan executor + rollback | *(ninth feature commit)* | 573 | Loop executor marked `Failure` results as completed and never ran approved Medium mutating steps; both fixed. `depends_on` is unused; step-by-step approval is still whole-plan |
| 9 | LLM resilience | *(tenth feature commit)* | 587 | Token budget can be overshot by one response; providers reporting no usage count as zero tokens. Fakes and `wiremock` only |
| 10 | Observability | *(eleventh feature commit)* | 597 | The ADR-011 metrics had never been wired to anything. No OTLP exporter bundled (14e); counters are per process |
| 11 | Fleet hardening | *(twelfth feature commit)* | 612 | `sentinel fleet` had no working remote command, no policy, no audit, and two injection routes. Tested with a fake `ssh`, not a real server. No staged rollout on this path (14f) |
