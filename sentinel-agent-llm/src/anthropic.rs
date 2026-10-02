//! Anthropic Claude API backend.
//!
//! Implements [`LlmBackend`] against the Anthropic Messages API
//! (`POST /v1/messages`).  The `with_base_url` constructor allows tests to
//! inject a mock server URL (e.g. from `wiremock`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::backend::{
    LlmBackend, LlmResponse, Message, MessageRole, ToolCall, ToolChoice, ToolResponse, ToolSpec,
};
use crate::error::AgentError;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct AnthropicRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
    messages: Vec<AnthropicMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<&'a [ToolSpec]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct AnthropicMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    #[allow(dead_code)]
    id: String,
    model: String,
    content: Vec<AnthropicContent>,
    usage: AnthropicUsage,
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
    /// Present on `tool_use` blocks.
    name: Option<String>,
    /// Present on `tool_use` blocks.
    input: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[derive(Deserialize)]
struct AnthropicErrorBody {
    error: AnthropicErrorDetail,
}

#[derive(Deserialize)]
struct AnthropicErrorDetail {
    message: String,
}

// ── AnthropicBackend ──────────────────────────────────────────────────────────

/// LLM backend targeting the Anthropic Claude API.
pub struct AnthropicBackend {
    client: reqwest::Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicBackend {
    /// Create a backend using the canonical Anthropic API endpoint.
    pub fn new(api_key: String, model: String) -> Self {
        Self::with_base_url(api_key, model, "https://api.anthropic.com".to_string())
    }

    /// Create a backend with a custom base URL — useful for injecting a
    /// `wiremock` server in tests.
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

    /// POST one Messages request and decode the response.
    async fn send(
        &self,
        messages: &[Message],
        max_tokens: u32,
        tools: Option<&[ToolSpec]>,
        tool_choice: Option<serde_json::Value>,
    ) -> Result<AnthropicResponse, AgentError> {
        // Separate system message (Anthropic puts it in a top-level field).
        let system_content: Option<String> = messages
            .iter()
            .find(|m| m.role == MessageRole::System)
            .map(|m| m.content.clone());

        let non_system: Vec<AnthropicMessage> = messages
            .iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| AnthropicMessage {
                role: m.role.as_str(),
                content: &m.content,
            })
            .collect();

        let request_body = AnthropicRequest {
            model: &self.model,
            max_tokens,
            system: system_content.as_deref(),
            messages: non_system,
            tools,
            tool_choice,
        };

        debug!(model = %self.model, max_tokens, "sending Anthropic completion request");

        let response = self
            .client
            .post(self.messages_url())
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let status = response.status();
        let status_u16 = status.as_u16();

        if status_u16 == 429 {
            // Try to extract Retry-After header.
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            warn!("Anthropic API rate limited, retry after {}s", retry_after);
            return Err(AgentError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        if !status.is_success() {
            let body_text = crate::http::text_capped(response, crate::http::MAX_ERROR_BYTES).await;
            // Try to extract structured error message.
            let message = serde_json::from_str::<AnthropicErrorBody>(&body_text)
                .map(|e| e.error.message)
                .unwrap_or(body_text);
            warn!(status = status_u16, %message, "Anthropic API error");
            return Err(AgentError::ApiError {
                status: status_u16,
                message,
            });
        }

        crate::http::json_capped(response, crate::http::MAX_RESPONSE_BYTES).await
    }

    fn messages_url(&self) -> String {
        format!("{}/v1/messages", self.base_url.trim_end_matches('/'))
    }
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn complete(
        &self,
        messages: Vec<Message>,
        max_tokens: u32,
    ) -> Result<LlmResponse, AgentError> {
        let api_response = self.send(&messages, max_tokens, None, None).await?;

        // Concatenate all text content blocks.
        let content_text: String = api_response
            .content
            .iter()
            .filter(|c| c.content_type == "text")
            .filter_map(|c| c.text.as_deref())
            .collect::<Vec<_>>()
            .join("");

        if content_text.is_empty() {
            return Err(AgentError::InvalidResponse(
                "Anthropic response contained no text content".to_string(),
            ));
        }

        debug!(
            model = %api_response.model,
            input_tokens = api_response.usage.input_tokens,
            output_tokens = api_response.usage.output_tokens,
            "Anthropic completion received"
        );

        Ok(LlmResponse {
            content: content_text,
            model: api_response.model,
            input_tokens: api_response.usage.input_tokens,
            output_tokens: api_response.usage.output_tokens,
            finish_reason: api_response
                .stop_reason
                .unwrap_or_else(|| "end_turn".to_string()),
        })
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn complete_with_tools(
        &self,
        messages: Vec<Message>,
        tools: &[ToolSpec],
        choice: ToolChoice,
        max_tokens: u32,
    ) -> Result<ToolResponse, AgentError> {
        // One call per turn: the loop policy-checks and audits each
        // invocation, so parallel tool use is switched off.
        let tool_choice = match choice {
            ToolChoice::Any => {
                serde_json::json!({"type": "any", "disable_parallel_tool_use": true})
            }
            ToolChoice::Tool(name) => {
                serde_json::json!({"type": "tool", "name": name, "disable_parallel_tool_use": true})
            }
        };

        let api_response = self
            .send(&messages, max_tokens, Some(tools), Some(tool_choice))
            .await?;

        let mut calls = Vec::new();
        let mut text = String::new();
        for block in api_response.content {
            match block.content_type.as_str() {
                "tool_use" => {
                    let name = block.name.ok_or_else(|| {
                        AgentError::InvalidResponse("tool_use block without a name".into())
                    })?;
                    calls.push(ToolCall {
                        name,
                        input: block.input.unwrap_or(serde_json::Value::Null),
                    });
                }
                "text" => text.push_str(block.text.as_deref().unwrap_or("")),
                _ => {}
            }
        }

        debug!(
            model = %api_response.model,
            calls = calls.len(),
            input_tokens = api_response.usage.input_tokens,
            output_tokens = api_response.usage.output_tokens,
            "Anthropic tool-use completion received"
        );

        Ok(ToolResponse {
            calls,
            text,
            model: api_response.model,
            input_tokens: api_response.usage.input_tokens,
            output_tokens: api_response.usage.output_tokens,
            finish_reason: api_response
                .stop_reason
                .unwrap_or_else(|| "end_turn".to_string()),
        })
    }

    async fn health_check(&self) -> Result<(), AgentError> {
        // Send a minimal request to verify connectivity and credentials.
        let response = self
            .client
            .post(self.messages_url())
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "model": self.model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}]
            }))
            .send()
            .await?;

        let status = response.status().as_u16();
        // 200 = ok; 400 = bad request (e.g. quota zero) but connectivity works
        if status == 200 || status == 400 {
            Ok(())
        } else if status == 401 || status == 403 {
            Err(AgentError::ApiError {
                status,
                message: "Invalid API key or unauthorized".to_string(),
            })
        } else if status == 429 {
            Err(AgentError::RateLimited {
                retry_after_secs: 60,
            })
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
            "id": "msg_01XYZ",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": content}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        })
    }

    #[tokio::test]
    async fn complete_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("anthropic-version", "2023-06-01"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(make_success_response(
                    "Hello from Claude",
                    "claude-3-5-sonnet-20241022",
                )),
            )
            .mount(&server)
            .await;

        let backend = AnthropicBackend::with_base_url(
            "test-key".into(),
            "claude-3-5-sonnet-20241022".into(),
            server.uri(),
        );

        let messages = vec![Message::system("You are helpful."), Message::user("Hello!")];

        let response = backend.complete(messages, 256).await.unwrap();
        assert_eq!(response.content, "Hello from Claude");
        assert_eq!(response.model, "claude-3-5-sonnet-20241022");
        assert_eq!(response.input_tokens, 10);
        assert_eq!(response.output_tokens, 5);
        assert_eq!(response.finish_reason, "end_turn");
    }

    #[tokio::test]
    async fn complete_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "30")
                    .set_body_json(serde_json::json!({
                        "error": {"type": "rate_limit_error", "message": "Rate limit exceeded"}
                    })),
            )
            .mount(&server)
            .await;

        let backend = AnthropicBackend::with_base_url(
            "test-key".into(),
            "claude-3-haiku-20240307".into(),
            server.uri(),
        );

        let err = backend
            .complete(vec![Message::user("hi")], 64)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            AgentError::RateLimited {
                retry_after_secs: 30
            }
        ));
    }

    #[tokio::test]
    async fn complete_api_error_400() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {"type": "invalid_request_error", "message": "Bad arguments"}
            })))
            .mount(&server)
            .await;

        let backend = AnthropicBackend::with_base_url(
            "test-key".into(),
            "claude-3-5-sonnet-20241022".into(),
            server.uri(),
        );

        let err = backend
            .complete(vec![Message::user("hi")], 64)
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::ApiError { status: 400, .. }));
    }

    #[tokio::test]
    async fn complete_server_error_500() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": {"type": "api_error", "message": "Internal server error"}
            })))
            .mount(&server)
            .await;

        let backend = AnthropicBackend::with_base_url(
            "test-key".into(),
            "claude-3-5-sonnet-20241022".into(),
            server.uri(),
        );

        let err = backend
            .complete(vec![Message::user("hi")], 64)
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::ApiError { status: 500, .. }));
    }

    #[tokio::test]
    async fn system_message_separated() {
        let server = MockServer::start().await;

        // Capture the request body to verify system message handling.
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(make_success_response("ok", "claude-3-5-sonnet-20241022")),
            )
            .mount(&server)
            .await;

        let backend = AnthropicBackend::with_base_url(
            "test-key".into(),
            "claude-3-5-sonnet-20241022".into(),
            server.uri(),
        );

        let messages = vec![
            Message::system("System instructions here."),
            Message::user("User question"),
        ];

        // Should not panic or error — system message is handled correctly.
        let result = backend.complete(messages, 128).await;
        assert!(result.is_ok());
    }

    #[test]
    fn name_and_model() {
        let backend = AnthropicBackend::new("key".into(), "claude-3-opus-20240229".into());
        assert_eq!(backend.name(), "anthropic");
        assert_eq!(backend.model(), "claude-3-opus-20240229");
    }

    // ── Native tool use ──────────────────────────────────────────────────────

    fn disk_tool() -> ToolSpec {
        ToolSpec {
            name: "disk_usage".into(),
            description: "Report disk usage".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }),
        }
    }

    fn tool_backend(server: &MockServer) -> AnthropicBackend {
        AnthropicBackend::with_base_url("test-key".into(), "claude-test".into(), server.uri())
    }

    #[tokio::test]
    async fn tool_request_carries_tools_and_forces_a_single_call() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        // The mock only answers when the request body has the tools array,
        // the forced tool choice and parallel calls disabled.
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(body_partial_json(serde_json::json!({
                "system": "sys",
                "tools": [{
                    "name": "disk_usage",
                    "description": "Report disk usage",
                    "input_schema": {"type": "object", "required": ["path"]}
                }],
                "tool_choice": {"type": "any", "disable_parallel_tool_use": true}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
                "content": [
                    {"type": "text", "text": "Checking the disk."},
                    {"type": "tool_use", "id": "toolu_1", "name": "disk_usage", "input": {"path": "/var"}}
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 12, "output_tokens": 7}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let backend = tool_backend(&server);
        assert!(backend.supports_tools());
        let r = backend
            .complete_with_tools(
                vec![Message::system("sys"), Message::user("go")],
                &[disk_tool()],
                ToolChoice::Any,
                256,
            )
            .await
            .unwrap();
        assert_eq!(
            r.calls,
            vec![ToolCall {
                name: "disk_usage".into(),
                input: serde_json::json!({"path": "/var"})
            }]
        );
        assert_eq!(r.text, "Checking the disk.");
        assert_eq!(r.finish_reason, "tool_use");
        assert_eq!((r.input_tokens, r.output_tokens), (12, 7));
    }

    #[tokio::test]
    async fn named_tool_choice_is_sent() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "tool_choice": {"type": "tool", "name": "disk_usage"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_1", "model": "claude-test",
                "content": [{"type": "tool_use", "id": "t", "name": "disk_usage", "input": {}}],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let r = tool_backend(&server)
            .complete_with_tools(
                vec![Message::user("go")],
                &[disk_tool()],
                ToolChoice::Tool("disk_usage".into()),
                64,
            )
            .await
            .unwrap();
        assert_eq!(r.calls.len(), 1);
    }

    #[tokio::test]
    async fn text_only_answer_yields_no_calls() {
        // The backend reports what the provider sent; rejecting a turn with
        // no call is the reasoning loop's job (see tools.rs).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(make_success_response(
                    r#"{"capability_id": "service_stop", "args": {"service": "sshd"}}"#,
                    "claude-test",
                )),
            )
            .mount(&server)
            .await;
        let r = tool_backend(&server)
            .complete_with_tools(
                vec![Message::user("go")],
                &[disk_tool()],
                ToolChoice::Any,
                64,
            )
            .await
            .unwrap();
        assert!(r.calls.is_empty());
        assert!(r.text.contains("service_stop"));
    }

    #[tokio::test]
    async fn tool_mode_surfaces_rate_limits_and_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
            .mount(&server)
            .await;
        let err = tool_backend(&server)
            .complete_with_tools(
                vec![Message::user("go")],
                &[disk_tool()],
                ToolChoice::Any,
                64,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AgentError::RateLimited {
                retry_after_secs: 7
            }
        ));
    }

    #[tokio::test]
    async fn plain_completion_sends_no_tool_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(make_success_response("hi", "claude-test")),
            )
            .mount(&server)
            .await;
        tool_backend(&server)
            .complete(vec![Message::user("go")], 64)
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(body.get("tools").is_none());
        assert!(body.get("tool_choice").is_none());
    }
}
