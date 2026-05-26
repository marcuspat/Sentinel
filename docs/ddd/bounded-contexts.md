# Bounded Contexts — Sentinel Domain Map

This document defines the bounded contexts within the Sentinel system, their responsibilities, internal models, and the relationships between them. Each bounded context corresponds to one or more Cargo crates and represents a coherent area of domain knowledge with its own **Ubiquitous Language** and internal model.

---

## Context Overview

Sentinel is organized into seven bounded contexts arranged in a layered dependency structure:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Presentation Context                         │
│                      (sentinel-tui)                             │
└───────────────────────────┬─────────────────────────────────────┘
                            │ subscribes to / commands
┌───────────────────────────▼─────────────────────────────────────┐
│                Agent / Reasoning Context                        │
│                   (sentinel-agent-llm)                          │
└──────────┬───────────────────────────┬──────────────────────────┘
           │                           │
           ▼                           ▼
┌──────────────────────┐   ┌───────────────────────────┐
│   Policy Context     │   │    Execution Context      │
│  (sentinel-policy)   │   │     (sentinel-exec)       │
└──────────┬───────────┘   └─────────────┬─────────────┘
           │                             │
           └──────────┬──────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Core Domain                               │
│                     (sentinel-core)                             │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌─────────────────┐ ┌──────────────┐ ┌────────────────────────────┐
│  Audit Context  │ │Fleet Context │ │  Capabilities Context      │
│ (sentinel-audit)│ │(sentinel-    │ │  (sentinel-capabilities)   │
│                 │ │  fleet)      │ │                            │
└─────────────────┘ └──────────────┘ └────────────────────────────┘
```

---

## 1. Core Domain

**Crate:** `sentinel-core`  
**Type:** Core Domain (highest domain richness, most stable)

### Responsibility

The Core Domain defines the foundational contracts, schemas, and primitive types that all other bounded contexts depend upon. It contains no business logic beyond type definitions and basic constructors — it is a shared kernel of domain language.

### Internal Model

- `Capability` trait: The fundamental interface for all actions
- `CapabilityResult`: The outcome type for all capability invocations
- `ExecutionContext`: Immutable runtime context threaded through invocations
- `ResourceLimits`: Hard resource constraints
- `SessionPhase`: Lifecycle phase enum
- `CoreError`: Base error type

### Language

The Core Domain establishes the **Ubiquitous Language** that all other contexts must use. Terms defined here — Capability, CapabilityResult, ExecutionContext, RiskTier — must be used consistently in all upstream contexts.

### Stability

The Core Domain is the most stable context. API changes require careful consideration and semantic versioning, as all other contexts depend on it. Changes here cascade to all dependents.

### Integration Patterns with Other Contexts

- **Published Language (PL):** The Core Domain publishes its trait and type definitions as the primary shared language for the entire system. All other contexts consume this language.
- All upstream contexts depend on `sentinel-core` as a library crate.

---

## 2. Execution Context

**Crate:** `sentinel-exec`  
**Type:** Supporting Domain

### Responsibility

The Execution Context owns all concerns related to the constrained, sandboxed execution of **Capability** invocations. It is responsible for process spawning, resource limit enforcement, timeout management, and environment isolation. The Execution Context is the only part of the system that performs actual system operations — all other contexts interact with the system exclusively through it.

### Internal Model

- `ExecutionHarness`: The primary orchestrator for capability invocations. Accepts a `Box<dyn Capability>` and an `ExecutionContext`, applies resource limits, enforces timeout, and returns a `CapabilityResult`.
- `ProcessGuard`: RAII guard for spawned subprocesses, ensuring cleanup on drop even if execution is interrupted.
- `SandboxPolicy`: Configuration for process isolation (filesystem namespaces, seccomp filters, cgroup limits where available).
- `CpuTimeEnforcer`: Monitors wall-clock time and terminates processes that exceed `ResourceLimits::max_cpu_time_ms`.
- `OutputCollector`: Streams and bounds stdout/stderr capture, enforcing `ResourceLimits::max_output_bytes`.

### Key Invariants

- The Execution Context never receives capability invocations directly from the Agent. All invocations flow through the Policy Context first.
- The Execution Context applies `ExecutionContext::dry_run` by dispatching to `Capability::dry_run` rather than `Capability::invoke`.
- Process isolation is best-effort on systems without namespace support; the `SandboxPolicy` degrades gracefully.

### Integration Patterns

- **Conformist (CF):** The Execution Context conforms to the Core Domain's `Capability` trait and `ExecutionContext` types without translation.
- **Downstream from Policy Context (Anti-Corruption Layer):** The Execution Context only receives capabilities after the Policy Context has issued an Allow decision. It does not re-evaluate policy — that is the Policy Context's exclusive responsibility.

---

## 3. Policy Context

**Crate:** `sentinel-policy`  
**Type:** Core Domain (co-equal with reasoning, high domain richness)

### Responsibility

The Policy Context owns all rule evaluation, risk assessment, and safety enforcement. It operates as a deterministic gatekeeper that is completely independent of the LLM reasoning loop. The Policy Context decides whether a proposed capability invocation is permitted, with full auditability of every decision.

### Internal Model

- `PolicyEngine`: The central evaluator. Loads `PolicyRuleset`, evaluates `PolicyDecision` for each proposed `CapabilityInvocation`.
- `PolicyRuleset`: An ordered list of `PolicyRule` records with precedence semantics.
- `PolicyRule`: A condition-action pair: if (capability matches pattern AND conditions are met) then (allow/deny).
- `RiskEvaluator`: Computes a composite risk score from capability tier, target path, session context, and historical invocation patterns. Used to provide advisory risk context alongside the binary PolicyDecision.
- `KillSwitchRegistry`: Tracks active kill switches and their scope (session / global / risk-tier threshold).
- `ResourceGuard`: Evaluates whether invocation would violate system resource thresholds.
- `DryRunValidator`: Runs a complete plan through policy evaluation without executing anything.

### Key Invariants

- The Policy Context never calls `Capability::invoke`. It may call `Capability::dry_run` for pre-flight validation.
- Deny-by-default: if no rule matches, the decision is Deny.
- The Policy Context has no dependency on `sentinel-agent-llm` — the LLM cannot influence policy decisions.
- Kill switch evaluation precedes all rule evaluation. An active kill switch for the invocation's risk tier immediately yields Deny without further rule processing.

### Integration Patterns

- **Open Host Service (OHS):** The Policy Context exposes a well-defined evaluation API used by the Agent/Reasoning Context and the Execution Context. It is a service that can be called synchronously as part of the execution pipeline.
- **Anti-Corruption Layer (ACL) toward Agent Context:** The Policy Context treats the Agent's plan as an external input that must be validated and sanitized, not trusted. The ACL prevents the Agent's internal model from bleeding into policy evaluation.

---

## 4. Agent / Reasoning Context

**Crate:** `sentinel-agent-llm`  
**Type:** Core Domain (the primary differentiator — LLM reasoning)

### Responsibility

The Agent / Reasoning Context owns the LLM interaction loop, session management, goal decomposition, observation accumulation, plan generation, and revision handling. It is the "intelligence" layer that translates natural language Goals into structured Plans.

### Internal Model

- `ReasoningLoop`: The main session driver. Manages phase transitions, accumulates `Observation` records, invokes the `LlmBackend`, and emits domain events.
- `LlmBackend` trait: The abstraction over model providers (see ADR-006). Implementations include `AnthropicBackend`, `OpenAiBackend`, `OllamaBackend`, `LlamaCppBackend`.
- `SessionContext`: The accumulated LLM conversation state — messages, observations, plan drafts — checkpointed for crash recovery.
- `ObservationAccumulator`: Manages the investigation phase, deduplicate observations, and formats them for LLM context injection.
- `PlanExtractor`: Parses structured `Plan` JSON from LLM responses, validates against the `CapabilityManifest`, and rejects or retries malformed outputs.
- `RevisionHandler`: When a plan fails policy pre-flight, formats the violation report into an LLM message and re-engages the model for plan revision.

### Key Invariants

- The Agent Context never calls `Capability::invoke` directly. It only constructs Plans and submits them for policy validation and approval.
- During the Executing phase, the Agent Context is passive — it does not receive new LLM inputs until the Verifying phase begins.
- The Agent Context depends on the `CapabilityManifest` to know what capabilities exist, but it cannot access capability implementations directly.

### Integration Patterns

- **Customer of Policy Context (OHS consumer):** The Agent Context submits plans to the Policy Context for pre-flight validation and receives structured violation reports.
- **Customer of Capabilities Context (catalog query):** The Agent Context reads the CapabilityManifest to construct LLM prompts and validate plan steps.
- **Upstream to Presentation Context:** The Agent Context emits domain events (phase transitions, plan proposals, execution progress) that the Presentation Context subscribes to for rendering.

---

## 5. Audit Context

**Crate:** `sentinel-audit`  
**Type:** Generic Subdomain (important for compliance, but not differentiating)

### Responsibility

The Audit Context owns the capture, storage, integrity protection, and export of all domain events as an immutable record. It is a write-optimized, append-only system that every other context writes to but that does not depend on any other context.

### Internal Model

- `AuditLog`: The primary write interface. Accepts `AuditEvent` records, computes `entry_hash`, chains with `prev_hash`, and writes atomically to storage.
- `AuditEvent`: The universal event record (see Ubiquitous Language).
- `HashChain`: Maintains the current chain state (last hash, entry count) for efficient new-entry hash computation.
- `ChainVerifier`: Reads the log and verifies hash chain continuity. Reports any gaps, mismatches, or tampering.
- `ExportConfig`: Configuration for SIEM export: format (JSON Lines, CEF, syslog), destination (file, TCP, UDP), filtering.
- `AuditExporter`: Streams audit events in the configured format to the configured destination.
- `RetentionManager`: Enforces configurable retention windows; archives and cleans up old entries.

### Key Invariants

- The Audit Context has no outbound dependencies on other Sentinel contexts. It is the ultimate downstream consumer.
- `AuditLog::append` is the only write path. No update or delete operations exist.
- Hash chain computation is synchronous with event write — the hash is computed before the write returns.

### Integration Patterns

- **Open Host Service (OHS):** The Audit Context exposes `AuditLog::append` as a service consumed by all other contexts.
- The Audit Context is the **downstream** of all other contexts in the context map. It receives events from everywhere but sends events to nowhere.

---

## 6. Fleet Context

**Crate:** `sentinel-fleet`  
**Type:** Supporting Domain

### Responsibility

The Fleet Context owns multi-host orchestration, controller-agent communication, host registration, and staged rollout management. It extends the single-host Sentinel model to manage infrastructure at scale.

### Internal Model

- `FleetController`: The controller-side orchestrator. Manages `Host` registry, dispatches plans to agents, monitors execution status, and coordinates staged rollouts.
- `FleetAgent`: The agent-side receiver. Receives Plans from the controller over mTLS, executes them using the local `ExecutionHarness`, and reports results.
- `FleetProtocol`: The wire protocol for controller-agent communication. Message types: `PlanDispatch`, `ExecutionStatus`, `ObservationReport`, `HealthReport`, `RegistrationRequest`.
- `HostRegistry`: Persistent store of `Host` records with their certificate fingerprints.
- `StagedRollout`: State machine for multi-stage fleet deployments. Tracks stage progress, health signals, and advancement criteria.
- `CertificatePinStore`: Maps host identifiers to expected certificate fingerprints for mTLS validation.
- `MtlsListener` / `MtlsConnector`: TLS endpoint factories using `tokio-rustls` with custom `ServerCertVerifier` enforcing certificate pinning.

### Key Invariants

- Every controller-agent connection uses mTLS with certificate pinning — no unauthenticated connections are accepted.
- Fleet agents do not forward plans back to a Policy Context on the controller — the policy pre-flight evaluation happens on the controller before dispatch.
- Fleet agents maintain local **SessionCheckpoint** records for partition tolerance.

### Integration Patterns

- **Published Language (PL):** The Fleet Context defines a stable wire protocol (the `FleetProtocol`) that both controller and agent implementations must conform to. The protocol is versioned.
- **Anti-Corruption Layer (ACL):** The Fleet Context translates between the controller's plan model and the agent's local execution model, adapting for differences in host-specific context (target hostname, local resource limits).

---

## 7. Presentation Context

**Crate:** `sentinel-tui`  
**Type:** Generic Subdomain

### Responsibility

The Presentation Context owns all operator-facing interaction: plan rendering, session monitoring, approval workflows, audit log browsing, fleet overview, and kill switch controls. It is a pure consumer of domain events and a producer of operator commands.

### Internal Model

- `AppState`: Central state container derived from domain events. The UI is a pure function of `AppState`.
- `EventBus`: The inbound async channel receiving domain events from the Agent, Policy, Execution, Audit, and Fleet contexts.
- `CommandSender`: The outbound channel for operator commands (Approve, Reject, EditPlan, ActivateKillSwitch).
- `PlanView`: Widget tree for rendering a `Plan` with risk tier indicators, dry-run results, and step status.
- `SessionDashboard`: Top-level layout with phase indicator, progress bars, and recent audit event stream.
- `FleetOverview`: Table widget showing connected hosts, current execution status, and per-host metrics.
- `AuditBrowser`: Scrollable, filterable view of recent `AuditEvent` records.
- `ApprovalModal`: Focused interaction pane for reviewing and approving/rejecting/editing a Plan.

### Key Invariants

- The Presentation Context has no business logic — it renders state and forwards operator input. It does not evaluate policy, invoke capabilities, or modify domain objects.
- All state mutations are driven by domain events received from other contexts, not by the UI rendering directly modifying domain objects.

### Integration Patterns

- **Conformist (CF) subscriber:** The Presentation Context conforms to the domain event model of the Agent, Policy, and Audit contexts without translation.
- **Command → Domain via Separate Channel:** Operator commands (approve, reject) are sent as typed command messages to the Agent Context via an async channel, not as direct method calls. This decouples the render loop from domain logic execution.

---

## Context Map

The following table summarizes the integration patterns between bounded contexts:

| Upstream Context | Downstream Context | Pattern | Notes |
|-----------------|-------------------|---------|-------|
| Core Domain | All contexts | Published Language (PL) | All contexts consume Core Domain types |
| Policy Context | Execution Context | Open Host Service (OHS) | Exec calls Policy for allow/deny before invoking |
| Agent/Reasoning | Policy Context | Customer / OHS | Agent submits plans for policy pre-flight |
| Agent/Reasoning | Capabilities Context | Customer (catalog read) | Agent reads manifest to build LLM prompts |
| Execution Context | Audit Context | OHS consumer | Exec writes CapabilityInvoked events to Audit |
| Policy Context | Audit Context | OHS consumer | Policy writes PolicyEvaluated events to Audit |
| Agent/Reasoning | Audit Context | OHS consumer | Agent writes GoalSubmitted, PlanProposed events |
| Fleet Context | Execution Context | ACL | Fleet adapts plans for per-host execution context |
| Fleet Context | Audit Context | OHS consumer | Fleet writes HostRegistered, FleetCommand events |
| Agent/Reasoning | Presentation Context | Event publication (upstream) | Agent emits phase/plan events the TUI subscribes to |
| Presentation Context | Agent/Reasoning | Commands (downstream) | TUI sends Approve/Reject/KillSwitch commands |

### Key Integration Boundaries

**The Policy Context as a mandatory gate.** No capability invocation reaches the Execution Context without first passing through the Policy Context. This is an architectural constraint enforced by the dependency graph — the Execution Context's `execute` function signature requires a `PolicyDecision::Allow` witness type, making it impossible to invoke a capability without a prior policy evaluation.

**The Audit Context as a write-only sink.** The Audit Context has no dependencies on any other Sentinel context. Every other context depends on the Audit Context to write events, but the Audit Context itself does not depend on any domain logic. This makes the Audit Context maximally stable — changes to the Agent or Policy contexts cannot break auditing.

**The Agent Context's read-only view of Capabilities.** The Agent Context reads the `CapabilityManifest` (capability IDs, schemas, risk tiers) but cannot access capability implementations. This separation ensures that the Agent cannot invoke capabilities by bypassing the execution pipeline.
