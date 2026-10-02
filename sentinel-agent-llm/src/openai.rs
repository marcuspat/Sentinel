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

use crate::backend::{
    LlmBackend, LlmResponse, Message, ToolCall, ToolChoice, ToolResponse, ToolSpec,
};
use crate::error::AgentError;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<OpenAiMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
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
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    function: OpenAiFunctionCall,
}

#[derive(Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    /// A JSON document encoded as a string.
    arguments: String,
}

/// The OpenAI function-calling shape for a [`ToolSpec`].  Ollama accepts the
/// same shape.
pub(crate) fn function_tool(spec: &ToolSpec) -> serde_json::Value {
    serde_json::json!({
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.input_schema,
        }
    })
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
    native_tools: bool,
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

        // Function calling is a given on api.openai.com.  "OpenAI-compatible"
        // local servers vary, so they stay on the text protocol unless the
        // caller opts in with `with_native_tools(true)`.
        let native_tools = base_url.trim_end_matches('/') == "https://api.openai.com";

        Self {
            client,
            api_key,
            model,
            base_url,
            native_tools,
        }
    }

    /// Force native tool use on or off (see [`LlmBackend::supports_tools`]).
    pub fn with_native_tools(mut self, enabled: bool) -> Self {
        self.native_tools = enabled;
        self
    }

    /// POST one Chat Completions request and decode the response.
    async fn send(
        &self,
        messages: &[Message],
        max_tokens: u32,
        tools: Option<Vec<serde_json::Value>>,
        tool_choice: Option<serde_json::Value>,
    ) -> Result<OpenAiResponse, AgentError> {
        // One call per turn: the loop policy-checks and audits each one.
        let parallel_tool_calls = tools.as_ref().map(|_| false);
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
            tools,
            tool_choice,
            parallel_tool_calls,
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

        response
            .json()
            .await
            .map_err(|e| AgentError::InvalidResponse(format!("failed to parse response: {e}")))
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
        let api_response = self.send(&messages, max_tokens, None, None).await?;

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
            finish_reason: choice.finish_reason.unwrap_or_else(|| "stop".to_string()),
        })
    }

    fn supports_tools(&self) -> bool {
        self.native_tools
    }

    async fn complete_with_tools(
        &self,
        messages: Vec<Message>,
        tools: &[ToolSpec],
        choice: ToolChoice,
        max_tokens: u32,
    ) -> Result<ToolResponse, AgentError> {
        let tool_choice = match choice {
            ToolChoice::Any => serde_json::json!("required"),
            ToolChoice::Tool(name) => {
                serde_json::json!({"type": "function", "function": {"name": name}})
            }
        };
        let api_response = self
            .send(
                &messages,
                max_tokens,
                Some(tools.iter().map(function_tool).collect()),
                Some(tool_choice),
            )
            .await?;

        let choice = api_response.choices.into_iter().next().ok_or_else(|| {
            AgentError::InvalidResponse("OpenAI response had no choices".to_string())
        })?;

        let mut calls = Vec::new();
        for call in choice.message.tool_calls.unwrap_or_default() {
            // `arguments` is model-written JSON in a string; a malformed
            // document is a failed turn, not an empty argument object.
            let input = serde_json::from_str(&call.function.arguments).map_err(|e| {
                AgentError::InvalidResponse(format!(
                    "tool '{}' arguments are not valid JSON: {e}",
                    call.function.name
                ))
            })?;
            calls.push(ToolCall {
                name: call.function.name,
                input,
            });
        }

        debug!(
            model = %api_response.model,
            calls = calls.len(),
            "OpenAI tool-call completion received"
        );

        Ok(ToolResponse {
            calls,
            text: choice.message.content.unwrap_or_default(),
            model: api_response.model,
            input_tokens: api_response.usage.prompt_tokens,
            output_tokens: api_response.usage.completion_tokens,
            finish_reason: choice.finish_reason.unwrap_or_else(|| "stop".to_string()),
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
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(make_success_response("Hello from GPT", "gpt-4o")),
            )
            .mount(&server)
            .await;

        let backend =
            OpenAiBackend::with_base_url("test-key".into(), "gpt-4o".into(), server.uri());

        let messages = vec![Message::system("Be helpful."), Message::user("Hello!")];

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

        assert!(matches!(
            err,
            AgentError::RateLimited {
                retry_after_secs: 45
            }
        ));
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

    fn tool_reply(tool_calls: serde_json::Value, content: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-test",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content, "tool_calls": tool_calls},
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13}
        })
    }

    fn tool_backend(server: &MockServer) -> OpenAiBackend {
        OpenAiBackend::with_base_url("k".into(), "gpt-test".into(), server.uri())
            .with_native_tools(true)
    }

    #[test]
    fn tools_default_on_for_openai_and_off_for_compatible_servers() {
        assert!(OpenAiBackend::new("k".into(), "m".into()).supports_tools());
        let local =
            OpenAiBackend::with_base_url("k".into(), "m".into(), "http://localhost:1234".into());
        assert!(!local.supports_tools(), "compatible servers must opt in");
        assert!(local.with_native_tools(true).supports_tools());
    }

    #[tokio::test]
    async fn tool_request_uses_function_calling_and_forbids_parallel_calls() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_partial_json(serde_json::json!({
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": "disk_usage",
                        "description": "Report disk usage",
                        "parameters": {"type": "object", "required": ["path"]}
                    }
                }],
                "tool_choice": "required",
                "parallel_tool_calls": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_reply(
                serde_json::json!([{
                    "id": "call_1", "type": "function",
                    "function": {"name": "disk_usage", "arguments": "{\"path\": \"/var\"}"}
                }]),
                serde_json::Value::Null,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let r = tool_backend(&server)
            .complete_with_tools(
                vec![Message::system("sys"), Message::user("go")],
                &[disk_tool()],
                ToolChoice::Any,
                128,
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
        assert_eq!(r.text, "", "null content is not an error in tool mode");
        assert_eq!((r.input_tokens, r.output_tokens), (9, 4));
    }

    #[tokio::test]
    async fn named_tool_choice_is_sent_as_a_function_reference() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "tool_choice": {"type": "function", "function": {"name": "disk_usage"}}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_reply(
                serde_json::json!([{
                    "id": "c", "type": "function",
                    "function": {"name": "disk_usage", "arguments": "{}"}
                }]),
                serde_json::Value::Null,
            )))
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
    async fn malformed_arguments_fail_the_turn() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_reply(
                serde_json::json!([{
                    "id": "c", "type": "function",
                    "function": {"name": "disk_usage", "arguments": "{\"path\": "}
                }]),
                serde_json::Value::Null,
            )))
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
        assert!(err.to_string().contains("not valid JSON"), "{err}");
    }

    #[tokio::test]
    async fn text_only_answer_yields_no_calls() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_reply(
                serde_json::Value::Null,
                serde_json::json!("{\"capability_id\": \"service_stop\"}"),
            )))
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
    async fn plain_completion_sends_no_tool_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_reply(
                serde_json::Value::Null,
                serde_json::json!("hello"),
            )))
            .mount(&server)
            .await;
        tool_backend(&server)
            .complete(vec![Message::user("go")], 64)
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        for field in ["tools", "tool_choice", "parallel_tool_calls"] {
            assert!(
                body.get(field).is_none(),
                "{field} leaked into a text request"
            );
        }
    }
}
