//! Ollama local inference backend.
//!
//! Implements [`LlmBackend`] against the Ollama Chat API
//! (`POST /api/chat`).  Defaults to `http://localhost:11434`.
//!
//! Ollama uses the same role names as OpenAI ("system", "user", "assistant")
//! but a different request/response envelope.  It also supports streaming;
//! this implementation requests non-streaming responses (`"stream": false`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::backend::{LlmBackend, LlmResponse, Message};
use crate::error::AgentError;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    messages: Vec<OllamaMessage<'a>>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Serialize)]
struct OllamaMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct OllamaOptions {
    num_predict: u32,
}

#[derive(Deserialize)]
struct OllamaResponse {
    model: String,
    message: OllamaResponseMessage,
    done: bool,
    done_reason: Option<String>,
    prompt_eval_count: Option<u32>,
    eval_count: Option<u32>,
}

#[derive(Deserialize)]
struct OllamaResponseMessage {
    content: String,
}

// ── OllamaBackend ─────────────────────────────────────────────────────────────

/// LLM backend targeting a local Ollama inference server.
pub struct OllamaBackend {
    client: reqwest::Client,
    model: String,
    base_url: String,
}

impl OllamaBackend {
    /// Create a backend pointing at `http://localhost:11434`.
    pub fn new(model: String) -> Self {
        Self::with_base_url(model, "http://localhost:11434".to_string())
    }

    /// Create a backend with a custom base URL — useful for injecting a
    /// `wiremock` server in tests or pointing at a remote Ollama instance.
    pub fn with_base_url(model: String, base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300)) // Local models can be slow
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            model,
            base_url,
        }
    }

    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.base_url.trim_end_matches('/'))
    }

    fn tags_url(&self) -> String {
        format!("{}/api/tags", self.base_url.trim_end_matches('/'))
    }
}

#[async_trait]
impl LlmBackend for OllamaBackend {
    fn name(&self) -> &str {
        "ollama"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn complete(
        &self,
        messages: Vec<Message>,
        max_tokens: u32,
    ) -> Result<LlmResponse, AgentError> {
        let api_messages: Vec<OllamaMessage> = messages
            .iter()
            .map(|m| OllamaMessage {
                role: m.role.as_str(),
                content: &m.content,
            })
            .collect();

        let request_body = OllamaRequest {
            model: &self.model,
            messages: api_messages,
            stream: false,
            options: Some(OllamaOptions {
                num_predict: max_tokens,
            }),
        };

        debug!(model = %self.model, max_tokens, "sending Ollama completion request");

        let response = self
            .client
            .post(self.chat_url())
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let status = response.status();
        let status_u16 = status.as_u16();

        if !status.is_success() {
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            warn!(status = status_u16, body = %body_text, "Ollama API error");
            return Err(AgentError::ApiError {
                status: status_u16,
                message: body_text,
            });
        }

        let api_response: OllamaResponse = response
            .json()
            .await
            .map_err(|e| AgentError::InvalidResponse(format!("failed to parse Ollama response: {e}")))?;

        if !api_response.done {
            warn!("Ollama response marked as not done");
        }

        let content = api_response.message.content;
        if content.is_empty() {
            return Err(AgentError::InvalidResponse(
                "Ollama response contained empty content".to_string(),
            ));
        }

        debug!(
            model = %api_response.model,
            input_tokens = ?api_response.prompt_eval_count,
            output_tokens = ?api_response.eval_count,
            "Ollama completion received"
        );

        Ok(LlmResponse {
            content,
            model: api_response.model,
            input_tokens: api_response.prompt_eval_count.unwrap_or(0),
            output_tokens: api_response.eval_count.unwrap_or(0),
            finish_reason: api_response
                .done_reason
                .unwrap_or_else(|| "stop".to_string()),
        })
    }

    async fn health_check(&self) -> Result<(), AgentError> {
        // Use the /api/tags endpoint (model list) as a lightweight liveness check.
        let response = self
            .client
            .get(self.tags_url())
            .send()
            .await?;

        let status = response.status().as_u16();
        if status == 200 {
            Ok(())
        } else {
            Err(AgentError::ApiError {
                status,
                message: format!("Ollama health check failed with HTTP {status}"),
            })
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_success_response(content: &str, model: &str) -> serde_json::Value {
        serde_json::json!({
            "model": model,
            "created_at": "2024-01-01T00:00:00Z",
            "message": {"role": "assistant", "content": content},
            "done": true,
            "done_reason": "stop",
            "prompt_eval_count": 8,
            "eval_count": 12
        })
    }

    #[tokio::test]
    async fn complete_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(make_success_response("Ollama response", "llama3.2")),
            )
            .mount(&server)
            .await;

        let backend = OllamaBackend::with_base_url("llama3.2".into(), server.uri());

        let messages = vec![Message::user("What is 2+2?")];
        let response = backend.complete(messages, 256).await.unwrap();

        assert_eq!(response.content, "Ollama response");
        assert_eq!(response.model, "llama3.2");
        assert_eq!(response.input_tokens, 8);
        assert_eq!(response.output_tokens, 12);
        assert_eq!(response.finish_reason, "stop");
    }

    #[tokio::test]
    async fn complete_api_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_string("model not found"),
            )
            .mount(&server)
            .await;

        let backend = OllamaBackend::with_base_url("nonexistent-model".into(), server.uri());

        let err = backend
            .complete(vec![Message::user("hi")], 64)
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::ApiError { status: 404, .. }));
    }

    #[tokio::test]
    async fn health_check_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [{"name": "llama3.2", "modified_at": "2024-01-01T00:00:00Z"}]
            })))
            .mount(&server)
            .await;

        let backend = OllamaBackend::with_base_url("llama3.2".into(), server.uri());
        assert!(backend.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn health_check_failure() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let backend = OllamaBackend::with_base_url("llama3.2".into(), server.uri());
        let err = backend.health_check().await.unwrap_err();
        assert!(matches!(err, AgentError::ApiError { status: 503, .. }));
    }

    #[test]
    fn name_and_model() {
        let backend = OllamaBackend::new("mistral".into());
        assert_eq!(backend.name(), "ollama");
        assert_eq!(backend.model(), "mistral");
    }

    #[test]
    fn with_base_url_sets_url() {
        let backend =
            OllamaBackend::with_base_url("llama3.2".into(), "http://remote:11434".into());
        assert_eq!(backend.chat_url(), "http://remote:11434/api/chat");
    }
}
