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
- [ ] **1. Real sandbox: Landlock.** Enforce `read_only_paths` / `writable_paths` in `sentinel-exec` with Landlock (they are advisory today), plus `PR_SET_NO_NEW_PRIVS`. Degrade loudly on kernels without it. Test: a sandboxed child cannot write outside its allowed paths.
- [ ] **2. Real sandbox: network and environment.** Enforce `deny_network` (Landlock ABI ≥ 4 TCP rules, or a seccomp socket filter as fallback) and scrub the child environment to an allowlist. Remove the "advisory" caveat from `SECURITY.md` only for what is actually enforced.
- [ ] **3. Provider-native tool use: Anthropic.** Generate JSON Schemas from capability manifests and use `tools` / `tool_use` instead of parsing free-text JSON. Structural boundary between data and instructions. `wiremock` tests.
- [ ] **4. Provider-native tool use: OpenAI and Ollama.** Function calling with the same schemas; shared schema generator; fallback to the text parser for models without tool support.
- [ ] **5. Policy file loading.** `--policy FILE` (TOML) for `run`, `tui`, `serve`, `execute`, `policy`; strict parsing (unknown keys rejected); a file can add rules and tighten, and the built-in resource guards and kill switch cannot be switched off from it. (SPEC A.7 #4)
- [ ] **6. Plan-store locking.** `flock` around read-modify-write in `PlanStore` to close the concurrent-`execute` race; test with two processes. (SPEC A.7 #5)
- [ ] **7. One plan executor.** Extract the executor shared by `ReasoningLoop::execute_plan` and `sentinel execute`; settle one `RequireApproval` meaning (today `sentinel run` skips Medium-risk mutating steps even after approval). Regression tests for both paths. (SPEC A.7 #2)
- [ ] **8. Rollback.** On step failure, call `invoke_inverse` for completed steps in reverse order, audited as `CapabilityRolledBack`; `--no-rollback` opt-out. (SPEC A.7 #3)
- [ ] **9. LLM resilience.** Per-request timeouts, bounded retry with jittered backoff on 429/5xx/`overloaded`, `Retry-After` honoured, response-size cap, and a hard per-session token/iteration budget.
- [ ] **10. Observability.** OpenTelemetry GenAI semantic-convention spans (`gen_ai.*`) for every model call and capability invocation, token accounting in Prometheus metrics. No collector required; spans are no-ops unless an exporter is configured.
- [ ] **11. Fleet hardening.** Constant-time fingerprint comparison (`subtle`), and replace or clearly gate the `controller` / `agent_client` stubs. (`SECURITY.md` known limitation)
- [ ] **12. TUI pending-plans tab.** List `PendingApproval` gate plans with approve / reject, reusing `PlanStore`. (SPEC A.7 #1)
- [ ] **13. Supply chain.** `cargo-deny` (advisories, licences, sources) and `cargo audit` in CI, pinned action SHAs, CycloneDX SBOM and build provenance attestation on release.
- [ ] **14. Property tests and fuzzing.** `proptest` for the policy evaluator (deny-by-default holds for arbitrary requests), the untrusted-data fence (no input can forge or close a fence), and audit-chain verification; `cargo-fuzz` targets for the MCP JSON-RPC parser.
- [ ] **15. Release wrap-up.** README, `SECURITY.md`, CHANGELOG and ADR index brought in line with what shipped; version bump to 0.2.0; PR description rewritten as a release summary.

If the backlog empties early, the remaining loops audit the code for new
defects (start with `unwrap`/`expect` on non-test paths and anything that
trusts LLM- or capability-supplied strings) and add findings here before
fixing them.

## Log

| Loop | Item | Commit | Tests | Notes |
|---|---|---|---|---|
| 0 | Signed audit checkpoints | *(first commit on the branch)* | 473 | Whole-file rewrite now detected; key custody and consistent truncation documented as open in ADR-015 |
