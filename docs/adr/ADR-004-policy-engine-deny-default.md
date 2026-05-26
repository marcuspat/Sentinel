# ADR-004: Deny-by-Default Policy Engine with Risk Tiering

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Security, Policy, Autonomy Bounds

---

## Context

Sentinel is an autonomous agent operating on production infrastructure. The core tension in any autonomous agent design is between capability (the agent must be able to take useful actions) and safety (the agent must not take catastrophic or unauthorized actions). The guiding principle of "bounded autonomy" requires a concrete mechanism: a component that deterministically decides whether a proposed action is allowed, independent of the LLM's reasoning.

Without a policy engine, the only check on the agent's actions is the LLM's judgment. LLM models are probabilistic, can be manipulated through prompt injection, can hallucinate incorrect assessment of risk, and do not provide auditable decision trails. Relying solely on LLM judgment for safety in a production system administration tool is insufficient.

The policy engine must address several concerns simultaneously:

- **Blast radius limitation.** An agent with broad permissions that makes a mistake can cause widespread damage. Limiting the set of allowed operations by default limits the worst-case impact of any error.
- **Compliance and audit.** Many regulated environments require demonstrable proof that automated systems cannot exceed a specified set of allowed operations. A policy engine with an explicit deny-by-default posture and a full audit trail provides this.
- **Human oversight integration.** Some classes of operations should always require human approval regardless of what the LLM proposes. The policy engine is the right place to enforce this requirement.
- **Operational risk differentiation.** Not all operations carry the same risk. Reading a file is qualitatively different from deleting a system user. The policy engine must model this distinction and apply proportionate controls.

The policy engine lives in `sentinel-policy` and evaluates proposed `Plan` objects before any execution begins, as well as individual `CapabilityInvocation` records at runtime.

---

## Decision

The `sentinel-policy` crate implements a deny-by-default policy engine with the following properties:

**Default posture: deny all.** A capability invocation is denied unless an explicit allow rule matches it. There is no implicit "allow if no deny rule matches" fallback. This is the opposite of a traditional allow-list posture and reflects the security principle that unknown operations are unsafe by default.

**Four-tier risk classification.** Every capability declares a `RiskTier`:

| Tier | Label | Description | Default Disposition |
|------|-------|-------------|---------------------|
| 1 | `Low` | Read-only, non-destructive, no persistent side effects (e.g., reading a file, listing processes) | Allow unless explicitly denied |
| 2 | `Medium` | Writes to non-critical paths, restarts services, modifies non-sensitive configuration | Allow with logging; human approval optional |
| 3 | `High` | Writes to system paths, deletes data, modifies security-sensitive configuration, creates users | Require human approval by default |
| 4 | `Critical` | Drops databases, removes system users, modifies kernel parameters, irreversible destructive operations | Require explicit operator confirmation; never auto-approved |

**Structured policy rules.** Policy rules are expressed in a declarative rule format (TOML/JSON) loaded from `sentinel-policy`'s configuration. Each rule specifies a `capability_id` pattern (exact or glob), a target path pattern, a risk tier threshold, an effect (`Allow` or `Deny`), and optional conditions (time-of-day, user role, session context).

**Kill switches.** The policy engine maintains a set of `KillSwitch` entries that, when activated, immediately deny all capabilities at or above a specified risk tier for the current session or globally. Kill switches can be triggered by the operator via the TUI, by an external API call, or by automated anomaly detection.

**Resource guards.** Policy rules can include resource guards that deny capabilities if the invocation would exceed defined system resource thresholds (e.g., disk usage > 90%, memory > 80%).

**Dry-run mode.** The policy engine can evaluate a full plan against current rules in dry-run mode before any capability is invoked, producing a pre-flight report listing which steps would be allowed, which denied, and why.

---

## Rationale

**Deny-by-default is the only correct security posture for a privileged autonomous agent.** Allow-by-default systems fail open: if a new capability is added and no one writes a deny rule for it, it is permitted. In a system that manages production infrastructure, failing open is catastrophic. Deny-by-default systems fail closed: a new capability must have an explicit allow rule before it can be used. The operational cost of writing allow rules is outweighed by the safety benefit.

**Risk tiering provides proportionate controls without over-constraining the agent.** A pure deny-all-then-allow-list approach would require explicit allow rules for every read operation, which is operationally burdensome. The risk tier system allows a practical default: Low-tier operations (reads) are permitted broadly, while High and Critical operations require explicit human approval. This balances autonomy with safety.

**Separation from the LLM reasoning loop is essential.** The policy engine is a deterministic, rule-based system in `sentinel-policy`, completely decoupled from the LLM in `sentinel-agent-llm`. The LLM cannot influence policy evaluation — it can only submit plans that are evaluated by the policy engine. This architectural separation means that even a compromised or manipulated LLM cannot bypass the policy layer.

**Kill switches provide an operational emergency stop.** In production incidents, operators need a reliable, fast mechanism to halt all agent activity. A kill switch that denies all High/Critical capabilities can be activated in one TUI keystroke, providing an immediate safety net without requiring the operator to understand the current plan's state.

**Pre-flight dry-run reduces execution risk.** Evaluating the entire plan against policy rules before executing any step ensures that mid-plan policy violations are caught before any irreversible steps are taken. The agent will not execute the first five steps of a ten-step plan only to find that step six is denied.

---

## Consequences

**Positive:**

- Unauthorized or novel capabilities are denied by default, providing a safety net for operator configuration errors or novel attack vectors.
- The audit log records every policy evaluation decision (allowed, denied, reason), providing a complete compliance trail.
- Risk tiering allows the agent to operate autonomously for Low/Medium tasks while requiring human oversight for High/Critical tasks.
- Kill switches provide a reliable emergency stop mechanism.
- Policy rules are externally configurable without code changes, enabling environment-specific policies (production vs. staging vs. development).
- Pre-flight dry-run evaluation catches plan-level policy violations before any execution begins.

**Negative:**

- The deny-by-default posture means that new capabilities must always have explicit allow rules written for them before they can be used. This creates initial configuration overhead when deploying Sentinel in a new environment.
- Policy rule evaluation adds latency to every capability invocation. This is bounded by the rule set size and is expected to remain well under 5 ms for typical configurations (within the 50 ms capability overhead budget).
- Complex policy rule interactions (e.g., overlapping glob patterns, rule ordering) require careful configuration management. Incorrect rules can cause legitimate operations to be unexpectedly denied.
- The four-tier risk model requires capability authors to correctly classify their capability's risk tier. An incorrectly classified Low-tier capability that is actually destructive undermines the tiering model.

---

## Alternatives Considered

**Allow-by-default with explicit deny rules.** This is the model used by traditional firewall rules (permit all, deny specific). It provides a better "getting started" experience because the agent can operate immediately without writing any policy rules. However, it fails open by definition: any capability not explicitly denied is allowed. For a system with root-level access to production infrastructure, this posture is unacceptable.

**Binary allow/deny without risk tiering.** A simpler system where every capability is either globally allowed or globally denied was considered. This would be easier to implement but provides insufficient granularity for real-world use cases. A sysadmin wants the agent to read log files freely but always approve before it modifies systemd units — binary allow/deny cannot express this.

**LLM-based policy reasoning.** Instead of a rule-based policy engine, use a second LLM call to evaluate whether a proposed action is safe. This approach was considered and rejected on the grounds that: LLM reasoning is non-deterministic and cannot provide audit-grade decision trails; it adds significant latency and API cost to every capability invocation; and it is vulnerable to the same prompt injection attacks as the primary reasoning loop.

**OPA (Open Policy Agent).** Using OPA (with Rego policies) as an external policy sidecar was considered. OPA provides a mature, expressive policy language and is widely used in Kubernetes environments. However, it introduces an external service dependency, requires learning Rego, and would prevent the single-binary deployment model (ADR-010). The `sentinel-policy` rule format is less expressive than Rego but covers all required use cases and compiles into the Sentinel binary.

**Per-capability hardcoded allow/deny flags.** Instead of a configurable rule engine, embed allow/deny decisions directly in capability implementations. This provides zero runtime overhead but makes policy configuration require code changes, which is operationally unacceptable. Environment-specific policies (e.g., a production environment that restricts operations permitted in staging) would be impossible to express.
