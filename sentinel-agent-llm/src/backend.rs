use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::AgentError;

/// LLM message role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageRole {
    System,
    User,
    Assistant,
}

impl MessageRole {
    /// Return the lowercase string representation used by most API providers.
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageRole::System => "system",
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
        }
    }
}

/// A single message in an LLM conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub content: String,
}

impl Message {
    /// Construct a system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: content.into(),
        }
    }

    /// Construct a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: content.into(),
        }
    }

    /// Construct an assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: content.into(),
        }
    }
}

/// Response from an LLM backend.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// The text content of the response.
    pub content: String,
    /// Model identifier returned by the API.
    pub model: String,
    /// Number of tokens in the prompt/input.
    pub input_tokens: u32,
    /// Number of tokens generated in the response.
    pub output_tokens: u32,
    /// Why the model stopped generating (e.g. "end_turn", "stop", "length").
    pub finish_reason: String,
}

/// The pluggable LLM backend trait.
///
/// Implementors provide the concrete HTTP calls to a specific LLM service.
/// The reasoning loop depends only on this trait, making backends fully
/// interchangeable.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Human-readable name of this backend (e.g. "anthropic", "openai", "ollama").
    fn name(&self) -> &str;

    /// Model identifier in use (e.g. "claude-3-5-sonnet-20241022").
    fn model(&self) -> &str;

    /// Send a conversation to the LLM and obtain a completion.
    ///
    /// `messages` is the full conversation history. The implementation is
    /// responsible for separating out any `System` role message and passing it
    /// to the API in the appropriate field if required by the provider.
    async fn complete(
        &self,
        messages: Vec<Message>,
        max_tokens: u32,
    ) -> Result<LlmResponse, AgentError>;

    /// Ping the backend to verify connectivity and credentials.
    async fn health_check(&self) -> Result<(), AgentError>;
}
