# ADR-006: Pluggable LLM Backends via Rust Trait

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Architecture, LLM Integration, Extensibility, Cost

---

## Context

Sentinel's reasoning loop depends on a large language model to interpret goals, analyze system observations, and generate structured execution plans. The LLM market is evolving rapidly: new models are released frequently, pricing changes, capabilities improve, and organizational requirements (data residency, air-gapped deployment, cost constraints) vary widely across deployments.

If Sentinel hard-coded a dependency on a single LLM provider's API, the following problems would arise:

**Vendor lock-in.** Switching from one provider to another would require significant code changes, increasing migration cost and friction.

**Air-gapped deployments.** Many sensitive infrastructure environments do not allow outbound network connections to commercial LLM APIs. These deployments require a locally-hosted model (Ollama, llama.cpp) rather than cloud-hosted APIs.

**Cost vs. capability trade-offs.** Different tasks warrant different model sizes. Routine log analysis may work well with a small local model (fast, free), while complex multi-service incident diagnosis benefits from a frontier model (more capable, higher cost). Operators should be able to configure which backend is used for which session types.

**Privacy and data residency.** Some organizations prohibit sending system state observations (which may contain hostnames, IP addresses, configuration data, or log content) to external APIs. Local model backends address this requirement.

**Model diversity.** Different LLM providers have different strengths, pricing models, context window sizes, and function-calling capabilities. A trait-based abstraction allows experimentation without rearchitecting the reasoning loop.

The `sentinel-agent-llm` crate is responsible for the LLM reasoning loop and must be able to use any of these backends interchangeably.

---

## Decision

The `sentinel-agent-llm` crate defines a `LlmBackend` trait that all model backends must implement. The reasoning loop depends only on this trait — it never imports provider-specific types or SDK methods.

The `LlmBackend` trait provides:

- `name() -> &str`: A human-readable identifier for the backend (e.g., `"anthropic/claude-opus-4"`, `"ollama/llama3.3"`).
- `complete(messages: &[Message], options: &CompletionOptions) -> Result<CompletionResponse, LlmError>`: Submit a conversation turn and receive a model response. Supports tool-use / function-calling through a standardized `ToolSpec` type.
- `count_tokens(messages: &[Message]) -> Result<u32, LlmError>`: Estimate the token count for a message set (used for context window management).
- `max_context_tokens() -> u32`: Report the backend's maximum context window size.
- `supports_tool_use() -> bool`: Indicate whether the backend supports structured tool-use / function-calling natively.

Concrete backends are implemented in `sentinel-agent-llm` as feature-gated modules:

| Backend | Feature Flag | Transport |
|---------|-------------|-----------|
| `AnthropicBackend` | `backend-anthropic` (default) | HTTPS to `api.anthropic.com` |
| `OpenAiBackend` | `backend-openai` | HTTPS to `api.openai.com` or compatible endpoint |
| `OllamaBackend` | `backend-ollama` | HTTP to local Ollama server |
| `LlamaCppBackend` | `backend-llamacpp` | HTTP to llama.cpp server or direct library binding |

The active backend is selected at runtime via configuration (`sentinel.toml` `[llm]` section), not at compile time (though feature flags control which backends are compiled in). The reasoning loop receives a `Box<dyn LlmBackend>` and is completely agnostic to the concrete type.

For backends that do not natively support structured tool-use (e.g., plain Ollama with models that lack function-calling support), the `LlmBackend` implementation wraps calls with a prompt-engineering layer that injects a JSON-mode system prompt and parses structured plan JSON from the response. This fallback is transparent to the reasoning loop.

---

## Rationale

**Trait-based abstraction is idiomatic Rust and provides compile-time safety.** A Rust trait is the standard mechanism for defining an interface that multiple types can implement. Using `Box<dyn LlmBackend>` (dynamic dispatch) allows runtime backend selection without any unsafe code, with the overhead of a single vtable lookup per call — negligible given the latency of an actual LLM API call.

**Feature flags keep the binary lean.** Air-gapped deployments that only need the Ollama backend do not need to compile in the Anthropic and OpenAI HTTP clients. Feature flags make each backend opt-in at compile time, reducing binary size and dependency surface for specialized deployments.

**Separation of reasoning from transport.** The reasoning loop logic — context accumulation, plan extraction, retry handling, observation summarization — is the same regardless of backend. Centralizing this logic in the reasoning loop and delegating only the model call to the backend prevents duplication and ensures consistent behavior across providers.

**Standardized tool-use abstraction.** Different LLM providers have different APIs for structured tool/function calling (Anthropic's `tool_use` content blocks, OpenAI's `function_call` / `tool_calls` format, Ollama's model-dependent support). The `LlmBackend` trait standardizes this into a common `ToolSpec` / `ToolCall` type that the reasoning loop understands. Backend implementations translate to/from provider-specific formats.

**Runtime backend selection enables operational flexibility.** Being able to switch backends via configuration without recompiling Sentinel means that operators can experiment with different models for different tasks, fall back to a cheaper model if the primary is unavailable, or switch to a local model for a sensitive session — all without code changes.

---

## Consequences

**Positive:**

- The reasoning loop code is completely decoupled from LLM provider specifics, enabling clean unit testing with a mock backend.
- New LLM providers can be added by implementing the `LlmBackend` trait and adding a feature flag — no changes to the reasoning loop are required.
- Air-gapped and privacy-sensitive deployments are supported without compromise via local model backends.
- Feature flags ensure that only the required HTTP clients and provider SDKs are compiled into a given binary.
- Operators can tune cost/latency/capability trade-offs by selecting the appropriate backend per deployment.
- Mock backends for testing can inject deterministic, pre-scripted responses, enabling fast and reliable unit tests for the reasoning loop.

**Negative:**

- The trait abstraction means that provider-specific features (e.g., Anthropic's extended thinking mode, OpenAI's Assistants API, provider-specific caching) cannot be used without extending the trait or adding provider-specific escape hatches.
- Maintaining multiple backend implementations requires ongoing effort as provider APIs evolve. API-breaking changes in one provider must be addressed in that backend's implementation.
- The tool-use fallback for models without native function-calling support is less reliable than native structured output. Plans generated through JSON-mode prompt engineering may have higher parse failure rates and require more robust error handling in the reasoning loop.
- Different backends have different context window sizes, pricing models, and latency profiles. The reasoning loop must handle context window overflow gracefully when the model backend has a small context limit.

---

## Alternatives Considered

**Hard-code a single provider (Anthropic).** Sentinel's initial implementation could target Anthropic's Claude models exclusively, given their strong reasoning capabilities and function-calling support. This would simplify the initial implementation but would immediately exclude air-gapped and cost-sensitive deployments. Given that local model quality is improving rapidly, deferring the abstraction would accumulate technical debt.

**Use an existing LLM abstraction crate (e.g., `langchain-rust`, `rig`).** Third-party LLM abstraction crates exist in the Rust ecosystem. Using one would reduce the implementation burden for backend adapters. However, these libraries are early-stage, have unstable APIs, bring in large dependency graphs, and do not provide the specific interface shape (tool-use abstraction, token counting, feature flag gating) that Sentinel requires. Building a focused internal trait is more appropriate than adopting a large framework dependency.

**gRPC service abstraction.** Define a gRPC service interface for the LLM backend, allowing backends to be separate processes or services. This would enable backends written in Python (closer to the ML ecosystem) and would allow hot-swapping backends without restarting Sentinel. However, it introduces an inter-process communication overhead on every LLM call, requires a running gRPC server alongside Sentinel, and significantly complicates the single-binary deployment model (ADR-010).

**OpenAI-compatible API as the sole interface.** Many providers and local model servers (Ollama, llama.cpp, LM Studio) expose OpenAI-compatible REST APIs. Using the OpenAI API format as the common interface would mean only one HTTP client is needed. However, this would lose the ability to use Anthropic-specific features (extended thinking, document blocks, citation mode) and would require all backends to conform to a lowest-common-denominator interface. The provider-specific backends provide richer, more idiomatic access to each platform.
