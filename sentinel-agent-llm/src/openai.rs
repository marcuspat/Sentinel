//! OpenAI-compatible API backend.
//!
//! Implements [`LlmBackend`] against the OpenAI Chat Completions API
//! (`POST /v1/chat/completions`).  Because the interface is OpenAI-compatible
//! this backend also works with local inference servers such as LM Studio,
//! vLLM, or `text-generation-webui`.
//!
//! The `with_base_url` constructor allows tests to inject a mock server URL.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::backend::{LlmBackend, LlmResponse, Message};
use crate::error::AgentError;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<OpenAiMessage<'a>>,
}

#[derive(Serialize)]
struct OpenAiMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    model: String,
    choices: Vec<OpenAiChoice>,
    usage: OpenAiUsage,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiChoiceMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiChoiceMessage {
    content: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[derive(Deserialize)]
struct OpenAiErrorBody {
    error: OpenAiErrorDetail,
}

#[derive(Deserialize)]
struct OpenAiErrorDetail {
    message: String,
}

// ── OpenAiBackend ─────────────────────────────────────────────────────────────

/// LLM backend targeting the OpenAI Chat Completions API (or any compatible
/// server).
pub struct OpenAiBackend {
    client: reqwest::Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl OpenAiBackend {
    /// Create a backend pointing at `https://api.openai.com`.
    pub fn new(api_key: String, model: String) -> Self {
        Self::with_base_url(api_key, model, "https://api.openai.com".to_string())
    }

    /// Create a backend with a custom base URL — useful for local inference
    /// servers or injecting a `wiremock` server in tests.
    pub fn with_base_url(api_key: String, model: String, base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            api_key,
            model,
            base_url,
        }
    }

    fn completions_url(&self) -> String {
        format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        )
    }
}

#[async_trait]
impl LlmBackend for OpenAiBackend {
    fn name(&self) -> &str {
        "openai"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn complete(
        &self,
        messages: Vec<Message>,
        max_tokens: u32,
    ) -> Result<LlmResponse, AgentError> {
        let api_messages: Vec<OpenAiMessage> = messages
            .iter()
            .map(|m| OpenAiMessage {
                role: m.role.as_str(),
                content: &m.content,
            })
            .collect();

        let request_body = OpenAiRequest {
            model: &self.model,
            max_tokens,
            messages: api_messages,
        };

        debug!(model = %self.model, max_tokens, "sending OpenAI completion request");

        let response = self
            .client
            .post(self.completions_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let status = response.status();
        let status_u16 = status.as_u16();

        if status_u16 == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            warn!("OpenAI API rate limited, retry after {}s", retry_after);
            return Err(AgentError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        if !status.is_success() {
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            let message = serde_json::from_str::<OpenAiErrorBody>(&body_text)
                .map(|e| e.error.message)
                .unwrap_or(body_text);
            warn!(status = status_u16, %message, "OpenAI API error");
            return Err(AgentError::ApiError {
                status: status_u16,
                message,
            });
        }

        let api_response: OpenAiResponse = response
            .json()
            .await
            .map_err(|e| AgentError::InvalidResponse(format!("failed to parse response: {e}")))?;

        let choice = api_response.choices.into_iter().next().ok_or_else(|| {
            AgentError::InvalidResponse("OpenAI response had no choices".to_string())
        })?;

        let content = choice.message.content.ok_or_else(|| {
            AgentError::InvalidResponse("OpenAI choice had no message content".to_string())
        })?;

        if content.is_empty() {
            return Err(AgentError::InvalidResponse(
                "OpenAI response contained empty content".to_string(),
            ));
        }

        debug!(
            model = %api_response.model,
            prompt_tokens = api_response.usage.prompt_tokens,
            completion_tokens = api_response.usage.completion_tokens,
            "OpenAI completion received"
        );

        Ok(LlmResponse {
            content,
            model: api_response.model,
            input_tokens: api_response.usage.prompt_tokens,
            output_tokens: api_response.usage.completion_tokens,
            finish_reason: choice
                .finish_reason
                .unwrap_or_else(|| "stop".to_string()),
        })
    }

    async fn health_check(&self) -> Result<(), AgentError> {
        let response = self
            .client
            .post(self.completions_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "model": self.model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}]
            }))
            .send()
            .await?;

        let status = response.status().as_u16();
        if status == 200 || status == 400 {
            Ok(())
        } else if status == 401 || status == 403 {
            Err(AgentError::ApiError {
                status,
                message: "Invalid API key or unauthorized".to_string(),
            })
        } else if status == 429 {
            Err(AgentError::RateLimited { retry_after_secs: 60 })
        } else {
            Err(AgentError::ApiError {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_success_response(content: &str, model: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 7,
                "total_tokens": 19
            }
        })
    }

    #[tokio::test]
    async fn complete_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_success_response(
                "Hello from GPT",
                "gpt-4o",
            )))
            .mount(&server)
            .await;

        let backend =
            OpenAiBackend::with_base_url("test-key".into(), "gpt-4o".into(), server.uri());

        let messages = vec![
            Message::system("Be helpful."),
            Message::user("Hello!"),
        ];

        let response = backend.complete(messages, 128).await.unwrap();
        assert_eq!(response.content, "Hello from GPT");
        assert_eq!(response.model, "gpt-4o");
        assert_eq!(response.input_tokens, 12);
        assert_eq!(response.output_tokens, 7);
        assert_eq!(response.finish_reason, "stop");
    }

    #[tokio::test]
    async fn complete_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "45")
                    .set_body_json(serde_json::json!({
                        "error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}
                    })),
            )
            .mount(&server)
            .await;

        let backend =
            OpenAiBackend::with_base_url("test-key".into(), "gpt-4o-mini".into(), server.uri());

        let err = backend
            .complete(vec![Message::user("hi")], 64)
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::RateLimited { retry_after_secs: 45 }));
    }

    #[tokio::test]
    async fn complete_api_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {"message": "Invalid model", "type": "invalid_request_error"}
            })))
            .mount(&server)
            .await;

        let backend =
            OpenAiBackend::with_base_url("test-key".into(), "gpt-4o".into(), server.uri());

        let err = backend
            .complete(vec![Message::user("hi")], 64)
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::ApiError { status: 400, .. }));
    }

    #[test]
    fn name_and_model() {
        let backend = OpenAiBackend::new("key".into(), "gpt-4o".into());
        assert_eq!(backend.name(), "openai");
        assert_eq!(backend.model(), "gpt-4o");
    }

    #[test]
    fn system_message_role_serializes_correctly() {
        // System messages for OpenAI are passed inline in the messages array.
        let msg = Message::system("system prompt");
        assert_eq!(msg.role.as_str(), "system");
    }
}
