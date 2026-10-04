# Architecture Decision Records

One record per decision. "Accepted" means the decision stands; the notes say
where the shipped code differs from the record.

| ADR | Decision | Status |
|---|---|---|
| [ADR-001](ADR-001-rust-language.md) | Use Rust as the Implementation Language | Accepted |
| [ADR-002](ADR-002-cargo-workspace.md) | Cargo Workspace with Specialized Crates | Accepted |
| [ADR-003](ADR-003-capability-system.md) | Typed Capability Abstraction as the Atomic Action Unit | Accepted |
| [ADR-004](ADR-004-policy-engine-deny-default.md) | Deny-by-Default Policy Engine with Risk Tiering | Accepted |
| [ADR-005](ADR-005-investigate-plan-approve-act.md) | Investigate → Plan → Approve → Act Workflow | Accepted |
| [ADR-006](ADR-006-llm-backend-trait.md) | Pluggable LLM Backends via Rust Trait | Accepted |
| [ADR-007](ADR-007-hash-chained-audit-log.md) | Append-Only SHA-256 Hash-Chained Audit Log | Accepted |
| [ADR-008](ADR-008-fleet-mtls.md) | Fleet Mode with Mutual TLS and Certificate Pinning | Accepted — not implemented in the shipped fleet path (see note); amended by [ADR-022](ADR-022-fleet-hardening.md) |
| [ADR-009](ADR-009-tui-ratatui.md) | Ratatui for the Terminal User Interface | Accepted |
| [ADR-010](ADR-010-static-musl-binary.md) | Single Statically-Linked musl Binary | Accepted |
| [ADR-011](ADR-011-prometheus-metrics.md) | Prometheus-Compatible Metrics Exposition | Accepted — amended by [ADR-021](ADR-021-observability.md) |
| [ADR-012](ADR-012-session-checkpointing.md) | Execution State Checkpointing | Accepted |
| [ADR-013](ADR-013-mcp-policy-gate.md) | MCP Policy Gate for Coding Agents | Accepted — implemented; plan-store locking added in 0.2.0 |
| [ADR-014](ADR-014-prompt-injection-spotlighting.md) | Spotlighting Untrusted Capability Output | Accepted |
| [ADR-015](ADR-015-signed-audit-checkpoints.md) | Ed25519-Signed Audit Checkpoints | Accepted |
| [ADR-016](ADR-016-landlock-and-hardened-executor.md) | Landlock Filesystem Sandbox and the Hardened Executor | Accepted |
| [ADR-017](ADR-017-native-tool-use.md) | Provider-Native Tool Use | Accepted |
| [ADR-018](ADR-018-policy-files.md) | Policy Files | Accepted |
| [ADR-019](ADR-019-one-plan-executor.md) | One Plan Executor | Accepted |
| [ADR-020](ADR-020-llm-resilience.md) | LLM Retries, Deadlines and Session Budgets | Accepted |
| [ADR-021](ADR-021-observability.md) | Observability — Metrics From the Audit Stream, GenAI Spans | Accepted (amends ADR-011) |
| [ADR-022](ADR-022-fleet-hardening.md) | Fleet Path — Policy, Audit and Input Validation | Accepted (amends ADR-008) |

ADR-001 to ADR-012 date from 0.1.0. ADR-013 and ADR-014 landed in PR #10.
ADR-015 to ADR-022 are the 0.2.0 round (`docs/SOTA_ROADMAP.md`).

Not implemented as written:

- **ADR-008** — the fleet path is SSH, not mTLS (ADR-022).
- **ADR-011** — no HTTP endpoint; metrics go to a text file (ADR-021).
