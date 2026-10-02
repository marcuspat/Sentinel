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

use crate::backend::{
    LlmBackend, LlmResponse, Message, ToolCall, ToolChoice, ToolResponse, ToolSpec,
};
use crate::error::AgentError;

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    messages: Vec<OllamaMessage<'a>>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
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
    #[serde(default)]
    content: String,
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[derive(Deserialize)]
struct OllamaToolCall {
    function: OllamaFunctionCall,
}

#[derive(Deserialize)]
struct OllamaFunctionCall {
    name: String,
    /// Ollama returns arguments as a JSON object, not a string.
    #[serde(default)]
    arguments: serde_json::Value,
}

// ── OllamaBackend ─────────────────────────────────────────────────────────────

/// LLM backend targeting a local Ollama inference server.
pub struct OllamaBackend {
    client: reqwest::Client,
    model: String,
    base_url: String,
    native_tools: bool,
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
            // Tool support depends on the model; many local models reject a
            // request that carries `tools`.  Opt in per backend.
            native_tools: false,
        }
    }

    /// Enable native tool use for models that support it.
    ///
    /// Ollama has no `tool_choice`, so a call cannot be forced: a model that
    /// answers in text instead fails the turn (text is never executed).
    pub fn with_native_tools(mut self, enabled: bool) -> Self {
        self.native_tools = enabled;
        self
    }

    /// POST one chat request and decode the response.
    async fn send(
        &self,
        messages: &[Message],
        max_tokens: u32,
        tools: Option<Vec<serde_json::Value>>,
    ) -> Result<OllamaResponse, AgentError> {
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
            tools,
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

        let api_response: OllamaResponse = response.json().await.map_err(|e| {
            AgentError::InvalidResponse(format!("failed to parse Ollama response: {e}"))
        })?;

        if !api_response.done {
            warn!("Ollama response marked as not done");
        }

        Ok(api_response)
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
        let api_response = self.send(&messages, max_tokens, None).await?;

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
        // No `tool_choice` in the Ollama API.  For a named choice, offer
        // only that tool; the caller rejects a turn without exactly one call.
        let offered: Vec<serde_json::Value> = tools
            .iter()
            .filter(|t| match &choice {
                ToolChoice::Any => true,
                ToolChoice::Tool(name) => &t.name == name,
            })
            .map(crate::openai::function_tool)
            .collect();

        let api_response = self.send(&messages, max_tokens, Some(offered)).await?;

        let calls = api_response
            .message
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .map(|c| ToolCall {
                name: c.function.name,
                input: c.function.arguments,
            })
            .collect::<Vec<_>>();

        debug!(
            model = %api_response.model,
            calls = calls.len(),
            "Ollama tool-call completion received"
        );

        Ok(ToolResponse {
            calls,
            text: api_response.message.content,
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
        let response = self.client.get(self.tags_url()).send().await?;

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
            .respond_with(ResponseTemplate::new(404).set_body_string("model not found"))
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
        let backend = OllamaBackend::with_base_url("llama3.2".into(), "http://remote:11434".into());
        assert_eq!(backend.chat_url(), "http://remote:11434/api/chat");
    }

    // ── Native tool use ──────────────────────────────────────────────────────

    fn tool(name: &str) -> ToolSpec {
        ToolSpec {
            name: name.into(),
            description: format!("{name} tool"),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
        }
    }

    fn tool_reply(message: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "model": "llama-test", "created_at": "2024-01-01T00:00:00Z",
            "message": message,
            "done": true, "done_reason": "stop",
            "prompt_eval_count": 3, "eval_count": 5
        })
    }

    #[test]
    fn tools_are_opt_in() {
        assert!(!OllamaBackend::new("m".into()).supports_tools());
        assert!(OllamaBackend::new("m".into())
            .with_native_tools(true)
            .supports_tools());
    }

    #[tokio::test]
    async fn tool_call_with_object_arguments_is_parsed() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(serde_json::json!({
                "stream": false,
                "tools": [{"type": "function", "function": {"name": "disk_usage"}}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_reply(serde_json::json!({
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "disk_usage", "arguments": {"path": "/var"}}}]
            }))))
            .expect(1)
            .mount(&server)
            .await;

        let backend =
            OllamaBackend::with_base_url("llama-test".into(), server.uri()).with_native_tools(true);
        let r = backend
            .complete_with_tools(
                vec![Message::user("go")],
                &[tool("disk_usage")],
                ToolChoice::Any,
                64,
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
        assert_eq!((r.input_tokens, r.output_tokens), (3, 5));
    }

    #[tokio::test]
    async fn named_choice_offers_only_that_tool() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(tool_reply(serde_json::json!({
                    "role": "assistant", "content": "",
                    "tool_calls": [{"function": {"name": "propose_plan", "arguments": {}}}]
                }))),
            )
            .mount(&server)
            .await;
        let backend =
            OllamaBackend::with_base_url("llama-test".into(), server.uri()).with_native_tools(true);
        backend
            .complete_with_tools(
                vec![Message::user("go")],
                &[tool("disk_usage"), tool("propose_plan")],
                ToolChoice::Tool("propose_plan".into()),
                64,
            )
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let offered: Vec<&str> = body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["function"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(offered, ["propose_plan"]);
    }

    #[tokio::test]
    async fn text_answer_in_tool_mode_yields_no_calls() {
        // Ollama cannot force a call; a text answer comes back as zero calls
        // and the reasoning loop rejects the turn.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(make_success_response(
                    "{\"capability_id\": \"service_stop\"}",
                    "llama-test",
                )),
            )
            .mount(&server)
            .await;
        let backend =
            OllamaBackend::with_base_url("llama-test".into(), server.uri()).with_native_tools(true);
        let r = backend
            .complete_with_tools(
                vec![Message::user("go")],
                &[tool("disk_usage")],
                ToolChoice::Any,
                64,
            )
            .await
            .unwrap();
        assert!(r.calls.is_empty());
        assert!(r.text.contains("service_stop"));
    }

    #[tokio::test]
    async fn plain_completion_sends_no_tools() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(make_success_response("hi", "llama-test")),
            )
            .mount(&server)
            .await;
        OllamaBackend::with_base_url("llama-test".into(), server.uri())
            .complete(vec![Message::user("go")], 64)
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(body.get("tools").is_none());
    }
}
