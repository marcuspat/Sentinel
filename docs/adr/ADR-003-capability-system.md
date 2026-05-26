# ADR-003: Typed Capability Abstraction as the Atomic Action Unit

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Architecture, Security, Policy, Extensibility

---

## Context

Sentinel is an autonomous agent that executes privileged operations on production infrastructure at the direction of an LLM reasoning engine. The central security challenge is ensuring that the LLM cannot instruct the agent to take actions outside of a sanctioned, auditable, and policy-gated set. This challenge has three dimensions:

**Prompt injection risk.** An adversarial system observation (e.g., a file containing malicious instructions, a crafted log line) could manipulate the LLM into proposing dangerous operations. Without a structural boundary between the LLM's textual output and the actual system operations, prompt injection translates directly into arbitrary command execution.

**Audit and reproducibility.** An autonomous agent that issues unstructured shell commands is fundamentally opaque: you cannot reliably reconstruct what it did, replay it, or subject it to pre-flight dry-runs. Structured, typed action units make the agent's behavior precisely describable and auditable.

**Policy enforcement.** For a deny-by-default policy engine to be meaningful, the actions it evaluates must be precisely defined. A policy rule like "deny all write operations to /etc" is only enforceable if the agent cannot bypass it by writing a shell script that writes to /etc.

**Rollback.** When an execution step fails midway through a multi-step plan, the agent needs to know how to undo completed steps. This requires each action to have a machine-readable inverse.

The alternative — allowing the LLM to generate arbitrary shell commands or scripts — was explicitly rejected as it makes all of the above properties impossible to guarantee.

---

## Decision

Every action that Sentinel takes on a target system is expressed as an invocation of a **Capability** — a statically typed, self-describing unit of work defined in `sentinel-core` and registered in the `CapabilityManifest`.

A Capability must implement the `Capability` trait, which requires:

- A unique `capability_id` string (e.g., `"fs.write_file"`, `"process.restart_service"`).
- A `name()` and `description()` for human-readable presentation.
- A `risk_tier()` returning one of `Low | Medium | High | Critical`.
- An `invoke(ctx: &ExecutionContext) -> Result<CapabilityResult, CoreError>` method that performs the actual work.
- A `dry_run(ctx: &ExecutionContext) -> Result<CapabilityResult, CoreError>` method that predicts the effect without side effects.
- An optional `inverse() -> Option<Box<dyn Capability>>` method that returns a capability to undo this one.
- A `schema() -> serde_json::Value` method returning the JSON Schema of accepted parameters, for LLM prompt construction and input validation.

The LLM reasoning loop in `sentinel-agent-llm` never calls system APIs or shells out directly. It constructs a `Plan` — a serialized list of `PlanStep` values — where each step names a capability by ID and provides JSON-serialized parameters. The policy engine validates the plan before any step is executed, and `sentinel-exec` invokes capabilities one at a time, passing an immutable `ExecutionContext`.

---

## Rationale

**Structural prompt injection prevention.** The attack surface for prompt injection is limited to the capability parameter schema. An adversary who controls the content of a file can inject text into the LLM's context window, but the LLM's output is constrained to selecting from a known set of capability IDs and filling in JSON parameters that are validated against a schema. It cannot instruct the system to run arbitrary shell code because there is no "run shell command" capability in the baseline manifest (or if one exists for advanced use cases, it is gated at `Critical` risk tier and requires explicit approval).

**Policy engine precision.** Each capability has a declared `RiskTier`, a known parameter schema, and a unique ID. The policy engine in `sentinel-policy` can evaluate rules like "deny any capability with `risk_tier >= High` targeting paths under `/etc/ssh`" with precision. Without typed capabilities, the policy engine would have to parse and interpret arbitrary shell commands — an unsolvable problem in the general case.

**Dry-run as first-class feature.** Every capability is required to implement `dry_run`, which returns a human-readable prediction of effects without taking any real action. This supports the plan approval workflow: the user sees exactly what each step will do before approving, and the policy engine can evaluate the plan in dry-run mode to catch violations before execution begins.

**Rollback chains.** The `inverse()` method allows the plan optimizer to construct a rollback sequence automatically. When step N in a ten-step plan fails, the system can invoke `step[N-1].inverse()`, `step[N-2].inverse()`, etc. to restore the prior state, without requiring the LLM to reason about how to undo its own actions.

**Capability library extensibility.** Third-party capability authors can implement the `Capability` trait and register capabilities with the `CapabilityRegistry`. This allows organizations to add proprietary capabilities (e.g., `"vendor.restart_appliance"`) without modifying Sentinel's core. The schema mechanism ensures that LLM prompt templates are auto-generated from the capability's declared parameter schema.

---

## Consequences

**Positive:**

- Prompt injection cannot result in arbitrary code execution — only parameterized, policy-validated capability invocations.
- Every action is fully auditable: the audit log records capability ID, parameters, result, and duration for every invocation.
- Dry-run support is guaranteed for all capabilities, enabling safe plan previewing and policy pre-flight.
- Rollback chains can be constructed automatically from `inverse()` implementations.
- The policy engine can express precise, enforceable rules against a fixed, known action vocabulary.
- New capabilities can be added without modifying core orchestration logic.
- The capability schema is machine-readable, enabling automated LLM prompt generation and input validation.

**Negative:**

- Implementing the full `Capability` trait is more work than writing an ad-hoc shell command. Contributors must implement `dry_run` and optionally `inverse`, which requires deeper understanding of the action's semantics.
- The capability library must be kept up to date with operational needs. If a novel system operation is needed and no capability exists for it, the agent cannot perform it until a capability is written and registered — this is intentional but can feel like a constraint in fast-moving operational contexts.
- The schema validation layer adds a small latency overhead on capability invocation (sub-millisecond for JSON schema validation, well within the 50 ms budget).
- Some capabilities (e.g., `fs.write_file`) have complex parameter schemas that require careful schema design to avoid being overly permissive.

---

## Alternatives Considered

**Shell command generation.** Allow the LLM to generate arbitrary shell commands (bash, sh, Python scripts) for execution. This is the approach taken by many early LLM agent frameworks. It was rejected because it makes prompt injection trivially exploitable, makes policy enforcement impossible in the general case, makes dry-run semantically undefined, and produces an audit log of opaque shell strings rather than typed, structured events.

**Capability as a simple string enum.** Define capabilities as a closed enum of known action strings (e.g., `Capability::RestartService(String)`). This is simpler than a trait-based system but prevents third-party extensibility, cannot carry rich typed parameters, and forces all capabilities into the core crate.

**Script templating with parameter escaping.** Allow shell command templates with sanitized parameter substitution. This approach (used by some configuration management tools) reduces but does not eliminate injection risk, provides no semantic dry-run support, and is difficult to reason about for policy evaluation. It also produces less informative audit events than typed capability invocations.

**OpenAI tool-use / function-calling API.** Use the LLM provider's native function-calling API as the capability layer. This approach ties the capability system to specific LLM vendors, does not work with local models (Ollama, llama.cpp), and moves schema validation out of the Sentinel type system into external service responses that can be spoofed or malformed.
