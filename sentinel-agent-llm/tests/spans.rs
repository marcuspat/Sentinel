//! Span attributes emitted by `ResilientBackend` (ADR-021).
//!
//! One process-wide subscriber records every span.  A thread-local
//! subscriber is not reliable here: `tracing` caches per-callsite interest
//! globally, so a callsite first reached by a thread without a subscriber
//! can stay disabled for a thread that has one.  Each test uses its own
//! model name and looks up only its own span.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use sentinel_agent_llm::{
    AgentError, Budget, LlmBackend, LlmResponse, Message, ResilientBackend, RetryPolicy,
    ToolChoice, ToolResponse, ToolSpec,
};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

type SpanRecord = (String, HashMap<String, String>);

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<SpanRecord>>>);

struct FieldMap<'a>(&'a mut HashMap<String, String>);

impl Visit for FieldMap<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            format!("{value:?}").trim_matches('"').to_string(),
        );
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

impl<S> Layer<S> for Capture
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        _ctx: Context<'_, S>,
    ) {
        let mut fields = HashMap::new();
        attrs.record(&mut FieldMap(&mut fields));
        fields.insert("__id".into(), id.into_u64().to_string());
        self.0
            .lock()
            .unwrap()
            .push((attrs.metadata().name().to_string(), fields));
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: Context<'_, S>,
    ) {
        let key = id.into_u64().to_string();
        let mut spans = self.0.lock().unwrap();
        // Ids are reused after a span closes: update the newest match.
        if let Some((_, fields)) = spans.iter_mut().rev().find(|(_, f)| f["__id"] == key) {
            values.record(&mut FieldMap(fields));
        }
    }
}

/// Install the recording subscriber once for the whole test binary.
fn capture() -> &'static Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(capture.clone()),
        )
        .expect("no other global subscriber in this test binary");
        capture
    })
}

/// The `gen_ai.chat` span for `model`.
fn chat_span(model: &str) -> HashMap<String, String> {
    capture()
        .0
        .lock()
        .unwrap()
        .iter()
        .find(|(name, f)| {
            name == "gen_ai.chat"
                && f.get("gen_ai.request.model").map(String::as_str) == Some(model)
        })
        .map(|(_, f)| f.clone())
        .unwrap_or_else(|| panic!("no gen_ai.chat span for model {model}"))
}

struct Scripted {
    model: String,
    script: Mutex<VecDeque<Result<(u32, u32), AgentError>>>,
}

impl Scripted {
    fn boxed(model: &str, script: Vec<Result<(u32, u32), AgentError>>) -> Box<dyn LlmBackend> {
        Box::new(Self {
            model: model.to_string(),
            script: Mutex::new(script.into()),
        })
    }
    fn next(&self) -> Result<(u32, u32), AgentError> {
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok((1, 1)))
    }
}

#[async_trait]
impl LlmBackend for Scripted {
    fn name(&self) -> &str {
        "scripted"
    }
    fn model(&self) -> &str {
        &self.model
    }
    async fn complete(&self, _m: Vec<Message>, _t: u32) -> Result<LlmResponse, AgentError> {
        let (input_tokens, output_tokens) = self.next()?;
        Ok(LlmResponse {
            content: "ok".into(),
            model: self.model.clone(),
            input_tokens,
            output_tokens,
            finish_reason: "end_turn".into(),
        })
    }
    fn supports_tools(&self) -> bool {
        true
    }
    async fn complete_with_tools(
        &self,
        _m: Vec<Message>,
        _tools: &[ToolSpec],
        _c: ToolChoice,
        _t: u32,
    ) -> Result<ToolResponse, AgentError> {
        let (input_tokens, output_tokens) = self.next()?;
        Ok(ToolResponse {
            calls: vec![],
            text: String::new(),
            model: self.model.clone(),
            input_tokens,
            output_tokens,
            finish_reason: "tool_use".into(),
        })
    }
    async fn health_check(&self) -> Result<(), AgentError> {
        Ok(())
    }
}

fn backend(model: &str, script: Vec<Result<(u32, u32), AgentError>>) -> ResilientBackend {
    capture(); // subscriber in place before the first span is created
    let policy = RetryPolicy {
        max_attempts: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(4),
        max_retry_after: Duration::from_secs(1),
        request_timeout: Duration::from_millis(500),
    };
    ResilientBackend::with(Scripted::boxed(model, script), policy, Budget::default())
}

fn api(status: u16) -> AgentError {
    AgentError::ApiError {
        status,
        message: "x".into(),
    }
}

#[tokio::test]
async fn successful_call_emits_a_gen_ai_chat_span_with_usage() {
    let b = backend("model-success", vec![Err(api(503)), Ok((120, 30))]);
    b.complete(vec![Message::user("hi")], 256).await.unwrap();

    let f = chat_span("model-success");
    assert_eq!(f["gen_ai.operation.name"], "chat");
    assert_eq!(f["gen_ai.system"], "scripted");
    assert_eq!(f["gen_ai.request.max_tokens"], "256");
    assert_eq!(f["gen_ai.usage.input_tokens"], "120");
    assert_eq!(f["gen_ai.usage.output_tokens"], "30");
    assert_eq!(f["gen_ai.response.model"], "model-success");
    assert_eq!(f["gen_ai.response.finish_reasons"], "end_turn");
    assert_eq!(f["sentinel.gen_ai.retries"], "1");
    assert_eq!(f["otel.name"], "chat model-success");
    assert!(!f.contains_key("error.type"));
}

#[tokio::test]
async fn failed_call_records_error_type_and_no_usage() {
    let b = backend("model-failure", vec![Err(api(401))]);
    assert!(b
        .complete_with_tools(vec![Message::user("hi")], &[], ToolChoice::Any, 64)
        .await
        .is_err());

    let f = chat_span("model-failure");
    assert_eq!(f["error.type"], "client_error");
    assert_eq!(f["sentinel.gen_ai.tools.offered"], "0");
    assert_eq!(f["sentinel.gen_ai.retries"], "0");
    assert!(!f.contains_key("gen_ai.usage.input_tokens"));
}

/// Prompts and completions must not be attached to spans: they contain host
/// details and attacker-influenced capability output.
#[tokio::test]
async fn spans_carry_no_prompt_or_completion_text() {
    let b = backend("model-private", vec![]);
    b.complete(vec![Message::user("the secret hostname is db-prod-7")], 16)
        .await
        .unwrap();

    let f = chat_span("model-private");
    for (k, v) in &f {
        assert!(!v.contains("db-prod-7"), "{k} leaked prompt text");
        assert!(!k.contains("prompt") && !k.contains("completion"), "{k}");
    }
    // And nowhere else in the process either.
    for (name, fields) in capture().0.lock().unwrap().iter() {
        for v in fields.values() {
            assert!(!v.contains("db-prod-7"), "span {name} leaked prompt text");
        }
    }
}
