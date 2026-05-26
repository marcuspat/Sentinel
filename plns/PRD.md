# Sentinel: Rust-Based Agentic System Administration Tool
## Product Requirements Document — Draft v1.0

## Core Concept
Sentinel pairs a deterministic execution engine with LLM-driven reasoning, enabling administrators to describe operational goals in natural language. The system investigates issues, proposes concrete plans, and executes them only with explicit human approval. The guiding principle is "bounded autonomy"—the LLM proposes; a policy engine validates and disposes.

## Problem It Addresses
Targets the gap between manual system administration (slow, inconsistent, unscalable) and rigid automation (brittle, inflexible). Focuses on "adaptive operations"—recurring problems requiring investigation and judgment, like diagnosing disk-full scenarios with varied root causes.

## Target Users
- Solo operators and homelab administrators (1–20 hosts)
- SREs and platform engineers at small-to-mid companies
- Security/compliance-conscious administrators in regulated or air-gapped environments
- CI/CD pipelines for non-interactive remediation

## Key Design Principles

**Safety Architecture:** The agent cannot execute shell commands directly. All actions flow through typed "capabilities" validated against policy before execution. This prevents prompt-injection attacks and limits blast radius.

**Workflow Model:** Sessions follow an investigate-plan-approve-act cycle:
- Investigation phase: LLM requests read-only capabilities without step approval
- Planning phase: Agent produces structured, reviewable action plans with risk tiers
- Approval phase: Operator reviews and approves (full plan, step-by-step, or with edits)
- Execution phase: Policy engine validates each step; agent may pause for confirmation

## Technical Architecture

Rust cargo workspace with specialized crates:
- `sentinel-core`: Capability trait, plan/policy schemas
- `sentinel-agent-llm`: Reasoning loop and model backends
- `sentinel-policy`: Deterministic policy and risk evaluation
- `sentinel-exec`: Constrained subprocess execution
- `sentinel-capabilities`: Baseline capability library
- `sentinel-fleet`: Controller/agent protocol for multi-host management
- `sentinel-audit`: Hash-chained tamper-evident logging
- `sentinel-tui`: Terminal user interface

**Model Flexibility:** Pluggable LLM backends (Anthropic, OpenAI, Ollama, llama.cpp).

## Capability System

Each capability has:
- Typed input/output schemas
- Mutating vs. read-only classification
- Static risk tiers (Low, Medium, High, Critical)
- Optional inverse capabilities for rollback
- Resource impact declarations

MVP baseline: filesystem operations, process/service control, package management, logging, metrics, networking, user permissions.

## Policy Engine

- Deny-by-default rules constraining actions by name, risk tier, target host, argument values, and time windows
- Dry-run capability for predicting effects without applying them
- Resource guards protecting critical paths and services
- Global kill switches for halting execution across fleets
- Complete logging of all policy decisions

## Fleet Management

Two modes:
1. **Single-host mode**: Full stack runs locally
2. **Fleet mode**: Controller manages lightweight agents on multiple hosts using mTLS with certificate pinning

Fleet features: host grouping, ad-hoc selectors, staged rollouts with canary deployments, auto-halt on verification failures.

## Audit and Observability

- Append-only, hash-chained logs
- Goals, observations, plans, approval decisions, capability invocations, policy determinations
- JSON export + human-readable reports
- Prometheus-compatible metrics
- SIEM forwarding

## Non-Functional Requirements

- Agent loop overhead < 50 ms per capability
- Idle agent footprint < ~50 MB RAM
- Controller managing 500+ hosts on modest VM
- Crashes preserve execution state (checkpointing)
- Enforced timeouts prevent hung processes
- Reproducible builds with signatures and SBOMs
- Single statically-linked binary (musl target) for Linux x86-64 and arm64
- First session in under 15 minutes

## Implementation Timeline (MVP in 4 months)

- **M0 (weeks 1–3):** Workspace, capability trait, executor with sandboxing, ~10 read-only capabilities
- **M1 (weeks 3–6):** Policy engine, risk tiering, dry-run, audit logging with hash chaining
- **M2 (weeks 6–10):** LLM reasoning loop, model backends, structured plans, single-host end-to-end flow
- **M3 (weeks 10–13):** TUI, approval workflows, mutating capabilities with rollback, v0.1 MVP release
- **M4 (post-MVP):** Fleet mode, controller/agent split, staged rollouts, agent-side policy enforcement
