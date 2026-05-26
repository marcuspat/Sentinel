# ADR-002: Cargo Workspace with Specialized Crates

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Build System, Architecture, Modularity

---

## Context

Sentinel has multiple distinct subsystems — a capability abstraction layer, a policy engine, an execution sandbox, an LLM reasoning loop, a TUI, a fleet controller, and an audit log. These subsystems have different dependency profiles, different stability requirements, different testing strategies, and different replacement cadences. Decisions about how to organize this code have long-lived implications for compilation speed, test isolation, optional feature deployment, and API boundaries.

The primary structural options are:

1. A single Rust crate containing all subsystems in separate modules.
2. A Cargo workspace with multiple purpose-specific crates.
3. Separate repositories per subsystem, linked by version pinning.

The project must also support the following deployment scenarios:
- A single-host binary that includes all subsystems.
- A lightweight fleet agent that excludes the TUI and LLM components.
- Potential future CLI tooling that embeds only the capability and policy layers.

---

## Decision

Sentinel is organized as a single Cargo workspace at the repository root, with the following member crates:

| Crate | Responsibility |
|---|---|
| `sentinel-core` | Capability trait, plan schema, policy schema, shared type primitives |
| `sentinel-agent-llm` | LLM reasoning loop, model backends, session management |
| `sentinel-policy` | Policy rules engine, risk evaluation, dry-run, kill switches |
| `sentinel-exec` | Constrained subprocess execution, process sandboxing, resource limits |
| `sentinel-capabilities` | Baseline capability library (filesystem, process, network, etc.) |
| `sentinel-fleet` | Controller/agent protocol, mTLS transport, staged rollouts |
| `sentinel-audit` | Append-only hash-chained audit log, SIEM export |
| `sentinel-tui` | Ratatui-based terminal UI, plan rendering, approval workflows |

All shared dependency versions are declared once in the workspace `[workspace.dependencies]` table and referenced with `{ workspace = true }` in member crates, ensuring consistent versions across the workspace.

---

## Rationale

**Enforced API boundaries.** Rust's module system within a single crate provides encapsulation via `pub`/`pub(crate)`, but it does not enforce clean API boundaries with the same rigor as separate crate compilation. When `sentinel-policy` is a distinct crate, the only interface it exposes to `sentinel-agent-llm` is its public API — there is no way for the LLM module to accidentally reach into policy internals. This boundary is critical for security: the policy engine must not be bypassable via internal shortcuts.

**Selective compilation for deployment variants.** The fleet agent binary can depend on `sentinel-core`, `sentinel-exec`, `sentinel-policy`, `sentinel-capabilities`, and `sentinel-audit` without pulling in `sentinel-tui` or `sentinel-agent-llm`. This reduces binary size and attack surface for the agent component. Cargo workspace features make this opt-in dependency composition trivial.

**Parallel compilation.** Cargo compiles independent crates in parallel. With eight crates, the full workspace compiles significantly faster than a single monolithic crate — especially on multi-core CI machines — because leaf crates (e.g., `sentinel-core`, `sentinel-audit`) can compile while other crates that depend on them are being processed.

**Independent testability.** Each crate has its own `tests/` directory and can be tested in isolation with `cargo test -p sentinel-policy`. This makes unit test suites faster and more focused. Integration tests in `sentinel-exec` do not require `sentinel-tui` to compile. Mock implementations of `sentinel-core` traits can be used without the full dependency graph.

**Versioning and stability tiers.** In the future, stable, low-churn crates like `sentinel-core` and `sentinel-audit` can be published to crates.io with semantic versioning, allowing third-party capability authors to build against a stable API. Higher-churn crates like `sentinel-agent-llm` can iterate faster without breaking downstream users of the stable API.

**Dependency hygiene.** `sentinel-tui` requires `ratatui` and `crossterm`, which are large dependencies with terminal-specific behavior. `sentinel-agent-llm` requires `reqwest` and Anthropic/OpenAI client types. `sentinel-fleet` requires TLS libraries. By placing these in separate crates, integration tests for the policy engine do not need to compile the TUI or HTTP client. This significantly reduces test compilation time and avoids false positive dependency audit alerts.

---

## Consequences

**Positive:**

- Strict API boundary enforcement between subsystems prevents accidental coupling.
- Independent crate testing enables focused, fast unit tests.
- Deployment variants (single-host vs. fleet agent vs. CLI) can include only the crates they need.
- Parallel crate compilation on CI reduces wall-clock build time.
- Future public API publication is enabled without restructuring the repository.
- Dependency tree per-crate is minimal; security audits via `cargo audit` produce smaller, more meaningful results per component.

**Negative:**

- Refactoring types that are shared across crate boundaries requires updating public APIs and potentially bumping versions, which is more friction than moving items between modules.
- The workspace adds a small amount of configuration overhead (each crate has its own `Cargo.toml`).
- Developers must understand which crate a piece of functionality belongs to, which requires familiarity with the architecture. This is mitigated by clear naming and this documentation.
- `cargo test --workspace` must be run to ensure cross-crate integration, rather than a single `cargo test` at the crate level.

---

## Alternatives Considered

**Single monolithic crate:** A single crate with modules for each subsystem would simplify the build configuration and make refactoring easier. However, it would lose the enforced API boundaries between the policy engine and the LLM loop (a security-critical separation), make deployment variant compilation impossible without feature flags (which are less ergonomic), and increase test compilation times significantly by pulling all dependencies together.

**Separate repositories:** Multiple repositories with published crates and version-pinned dependencies is the approach taken by large ecosystems (e.g., the Rust async ecosystem itself). For a tightly co-developed project like Sentinel, this introduces too much overhead: coordinated changes across subsystems require simultaneous PRs, releases, and version bumps across repositories. The workspace model gives the benefits of separate crates without this overhead.

**Feature flags in a single crate:** Using Cargo feature flags to selectively compile subsystems in a single crate is possible but produces a complex, hard-to-reason-about `Cargo.toml` with many conditional compilation paths. Separate crates are cleaner and more idiomatic for this scale.
