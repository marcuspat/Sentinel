//! `sentinel-agent-llm` — LLM reasoning loop with pluggable backends.
//!
//! This crate drives the **investigate → plan → approve → act** cycle:
//!
//! 1. **Investigate** — the LLM iteratively requests read-only capability
//!    invocations to gather system observations.
//! 2. **Plan** — the LLM produces a structured, reviewable [`Plan`].
//! 3. **Approve** — handled externally by the TUI/CLI layer.
//! 4. **Act** — policy-gated capability execution, with rollback support.
//!
//! # Backends
//!
//! All LLM communication goes through the [`LlmBackend`] trait, with three
//! provided implementations:
//!
//! * [`AnthropicBackend`] — Anthropic Claude API
//! * [`OpenAiBackend`] — OpenAI Chat Completions API (also works with local servers)
//! * [`OllamaBackend`] — Ollama local inference

pub mod anthropic;
pub mod backend;
pub mod error;
pub mod ollama;
pub mod openai;
pub mod planner;
pub mod prompt_builder;
pub mod reasoning_loop;

pub use anthropic::AnthropicBackend;
pub use backend::{LlmBackend, LlmResponse, Message, MessageRole};
pub use error::AgentError;
pub use ollama::OllamaBackend;
pub use openai::OpenAiBackend;
pub use planner::{
    CapabilityRegistry, CapabilityRequest, CapabilityRequestParser, InvestigationAction,
    Observation, PlanParser,
};
pub use prompt_builder::PromptBuilder;
pub use reasoning_loop::{ExecutionSummary, ReasoningConfig, ReasoningLoop};
