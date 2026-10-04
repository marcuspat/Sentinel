use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use prometheus::{
    Counter, CounterVec, Gauge, Histogram, HistogramOpts, HistogramVec, Opts, Registry,
};

use crate::events::AuditEventType;

/// Prometheus metrics for the Sentinel audit system.
///
/// All metrics are registered with the provided `Registry` at construction
/// time.  Use `gather_text` to produce a Prometheus text-format exposition.
pub struct SentinelMetrics {
    /// Total number of capability invocations attempted.
    pub capabilities_invoked_total: Counter,
    /// Total number of capability invocations that succeeded.
    pub capabilities_succeeded_total: Counter,
    /// Total number of capability invocations that failed.
    pub capabilities_failed_total: Counter,
    /// Total number of policy-denial decisions.
    pub policy_denials_total: Counter,
    /// Total number of kill-switch activations.
    pub kill_switch_activations_total: Counter,
    /// Total number of capability roll-backs.
    pub rollbacks_total: Counter,
    /// Total number of sessions started.
    pub sessions_started_total: Counter,
    /// Total number of sessions that completed successfully.
    pub sessions_completed_total: Counter,
    /// Histogram of capability execution durations in milliseconds.
    pub capability_duration_ms: Histogram,
    /// Gauge tracking the number of currently active sessions.
    pub active_sessions: Gauge,
    /// Total number of audit events written across all sessions.
    pub audit_events_total: Counter,
    /// Suspected prompt-injection hits (ADR-014 tripwire).
    pub prompt_injection_suspected_total: Counter,
    /// Calls made to the MCP gate, by tool.
    pub mcp_tool_calls_total: CounterVec,
    /// Model requests, by backend, model and outcome (`ok` / `error`).
    pub llm_requests_total: CounterVec,
    /// Tokens reported by the provider, by backend, model and direction
    /// (`input` / `output`).
    pub llm_tokens_total: CounterVec,
    /// Model-call attempts that failed and were retried.
    pub llm_retries_total: CounterVec,
    /// Wall-clock duration of a model request including retries, in seconds.
    pub llm_request_duration_seconds: HistogramVec,
}

impl SentinelMetrics {
    /// Create and register all metrics in `registry`.
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let capabilities_invoked_total = Counter::with_opts(Opts::new(
            "sentinel_capabilities_invoked_total",
            "Total capability invocations attempted",
        ))?;

        let capabilities_succeeded_total = Counter::with_opts(Opts::new(
            "sentinel_capabilities_succeeded_total",
            "Total capability invocations that succeeded",
        ))?;

        let capabilities_failed_total = Counter::with_opts(Opts::new(
            "sentinel_capabilities_failed_total",
            "Total capability invocations that failed",
        ))?;

        let policy_denials_total = Counter::with_opts(Opts::new(
            "sentinel_policy_denials_total",
            "Total policy-denial decisions",
        ))?;

        let kill_switch_activations_total = Counter::with_opts(Opts::new(
            "sentinel_kill_switch_activations_total",
            "Total kill-switch activations",
        ))?;

        let rollbacks_total = Counter::with_opts(Opts::new(
            "sentinel_rollbacks_total",
            "Total capability roll-backs performed",
        ))?;

        let sessions_started_total = Counter::with_opts(Opts::new(
            "sentinel_sessions_started_total",
            "Total sessions started",
        ))?;

        let sessions_completed_total = Counter::with_opts(Opts::new(
            "sentinel_sessions_completed_total",
            "Total sessions completed successfully",
        ))?;

        // Buckets: 1 ms, 5 ms, 10 ms, 50 ms, 100 ms, 500 ms, 1 s, 5 s, 30 s
        let capability_duration_ms = Histogram::with_opts(
            HistogramOpts::new(
                "sentinel_capability_duration_ms",
                "Capability execution duration in milliseconds",
            )
            .buckets(vec![
                1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1_000.0, 5_000.0, 30_000.0,
            ]),
        )?;

        let active_sessions = Gauge::with_opts(Opts::new(
            "sentinel_active_sessions",
            "Number of currently active sessions",
        ))?;

        let audit_events_total = Counter::with_opts(Opts::new(
            "sentinel_audit_events_total",
            "Total audit events written across all sessions",
        ))?;

        let prompt_injection_suspected_total = Counter::with_opts(Opts::new(
            "sentinel_prompt_injection_suspected_total",
            "Capability outputs that matched a prompt-injection heuristic",
        ))?;

        let mcp_tool_calls_total = CounterVec::new(
            Opts::new("sentinel_mcp_tool_calls_total", "MCP gate tool calls"),
            &["tool"],
        )?;

        let llm_requests_total = CounterVec::new(
            Opts::new("sentinel_llm_requests_total", "Model requests by outcome"),
            &["backend", "model", "outcome"],
        )?;

        let llm_tokens_total = CounterVec::new(
            Opts::new(
                "sentinel_llm_tokens_total",
                "Tokens reported by the model provider",
            ),
            &["backend", "model", "direction"],
        )?;

        let llm_retries_total = CounterVec::new(
            Opts::new(
                "sentinel_llm_retries_total",
                "Model-call attempts that failed and were retried",
            ),
            &["backend", "model"],
        )?;

        let llm_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "sentinel_llm_request_duration_seconds",
                "Model request duration including retries, in seconds",
            )
            .buckets(vec![
                0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
            ]),
            &["backend", "model"],
        )?;

        // Register everything.
        registry.register(Box::new(prompt_injection_suspected_total.clone()))?;
        registry.register(Box::new(mcp_tool_calls_total.clone()))?;
        registry.register(Box::new(llm_requests_total.clone()))?;
        registry.register(Box::new(llm_tokens_total.clone()))?;
        registry.register(Box::new(llm_retries_total.clone()))?;
        registry.register(Box::new(llm_request_duration_seconds.clone()))?;
        registry.register(Box::new(capabilities_invoked_total.clone()))?;
        registry.register(Box::new(capabilities_succeeded_total.clone()))?;
        registry.register(Box::new(capabilities_failed_total.clone()))?;
        registry.register(Box::new(policy_denials_total.clone()))?;
        registry.register(Box::new(kill_switch_activations_total.clone()))?;
        registry.register(Box::new(rollbacks_total.clone()))?;
        registry.register(Box::new(sessions_started_total.clone()))?;
        registry.register(Box::new(sessions_completed_total.clone()))?;
        registry.register(Box::new(capability_duration_ms.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;
        registry.register(Box::new(audit_events_total.clone()))?;

        Ok(Self {
            capabilities_invoked_total,
            capabilities_succeeded_total,
            capabilities_failed_total,
            policy_denials_total,
            kill_switch_activations_total,
            rollbacks_total,
            sessions_started_total,
            sessions_completed_total,
            capability_duration_ms,
            active_sessions,
            audit_events_total,
            prompt_injection_suspected_total,
            mcp_tool_calls_total,
            llm_requests_total,
            llm_tokens_total,
            llm_retries_total,
            llm_request_duration_seconds,
        })
    }

    /// Update counters from one audit event.
    ///
    /// The audit log calls this on every append, so the metrics are derived
    /// from the same stream the hash chain records and cannot drift from it.
    pub fn observe(&self, event: &AuditEventType) {
        self.audit_events_total.inc();
        match event {
            AuditEventType::GoalSubmitted { .. } => {
                self.sessions_started_total.inc();
                self.active_sessions.inc();
            }
            AuditEventType::SessionCompleted { .. } => {
                self.sessions_completed_total.inc();
                self.active_sessions.dec();
            }
            AuditEventType::SessionAborted { .. } => self.active_sessions.dec(),
            AuditEventType::CapabilityInvoked { .. } => self.capabilities_invoked_total.inc(),
            AuditEventType::CapabilitySucceeded { duration_ms, .. } => {
                self.capabilities_succeeded_total.inc();
                self.capability_duration_ms.observe(*duration_ms as f64);
            }
            AuditEventType::CapabilityFailed { .. } => self.capabilities_failed_total.inc(),
            AuditEventType::CapabilityRolledBack { .. } => self.rollbacks_total.inc(),
            AuditEventType::PolicyDenied { .. } => self.policy_denials_total.inc(),
            AuditEventType::KillSwitchActivated { .. } => self.kill_switch_activations_total.inc(),
            AuditEventType::SuspectedPromptInjection { .. } => {
                self.prompt_injection_suspected_total.inc()
            }
            AuditEventType::McpToolCalled { tool, .. } => {
                // `tool` is client-supplied; only known tool names become
                // label values, so a client cannot mint unbounded series.
                let label = if KNOWN_MCP_TOOLS.contains(&tool.as_str()) {
                    tool.as_str()
                } else {
                    "other"
                };
                self.mcp_tool_calls_total.with_label_values(&[label]).inc();
            }
            _ => {}
        }
    }

    /// Record one finished model request.
    pub fn observe_llm(&self, call: &LlmCall<'_>) {
        let LlmCall {
            backend,
            model,
            ok,
            input_tokens,
            output_tokens,
            retries,
            duration,
        } = *call;
        let outcome = if ok { "ok" } else { "error" };
        self.llm_requests_total
            .with_label_values(&[backend, model, outcome])
            .inc();
        self.llm_tokens_total
            .with_label_values(&[backend, model, "input"])
            .inc_by(input_tokens as f64);
        self.llm_tokens_total
            .with_label_values(&[backend, model, "output"])
            .inc_by(output_tokens as f64);
        if retries > 0 {
            self.llm_retries_total
                .with_label_values(&[backend, model])
                .inc_by(retries as f64);
        }
        self.llm_request_duration_seconds
            .with_label_values(&[backend, model])
            .observe(duration.as_secs_f64());
    }

    /// Gather all metrics from `registry` and return them in the Prometheus
    /// text exposition format (UTF-8, ends with a newline).
    pub fn gather_text(&self, registry: &Registry) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = Vec::new();
        encoder
            .encode(&registry.gather(), &mut buffer)
            .unwrap_or_default();
        String::from_utf8(buffer).unwrap_or_default()
    }
}

/// One finished model request, as recorded by [`SentinelMetrics::observe_llm`].
#[derive(Debug, Clone, Copy)]
pub struct LlmCall<'a> {
    pub backend: &'a str,
    pub model: &'a str,
    pub ok: bool,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Failed attempts that were retried before this outcome.
    pub retries: u64,
    /// Wall-clock time including retries and backoff.
    pub duration: std::time::Duration,
}

/// Tool names the MCP gate exposes; used to bound a metric label.
const KNOWN_MCP_TOOLS: &[&str] = &[
    "sentinel_capabilities",
    "sentinel_policy_check",
    "sentinel_investigate",
    "sentinel_propose_plan",
    "sentinel_plan_status",
];

/// Environment variable naming a Prometheus text file to keep up to date.
pub const METRICS_FILE_ENV: &str = "SENTINEL_METRICS_FILE";

/// Process-wide metrics: one registry, fed by every audit log and every
/// resilient LLM backend in the process.
pub struct GlobalMetrics {
    registry: Registry,
    metrics: SentinelMetrics,
    file: Option<PathBuf>,
}

impl GlobalMetrics {
    fn build(file: Option<PathBuf>) -> Self {
        let registry = Registry::new();
        // Metric names are constants; registration cannot collide.
        let metrics = SentinelMetrics::new(&registry).expect("static metric definitions");
        Self {
            registry,
            metrics,
            file,
        }
    }

    pub fn metrics(&self) -> &SentinelMetrics {
        &self.metrics
    }

    /// Prometheus text exposition of everything recorded so far.
    pub fn render(&self) -> String {
        self.metrics.gather_text(&self.registry)
    }

    /// Rewrite the metrics file, if one is configured.  Atomic (temp file +
    /// rename) so a scraper never reads a half-written file.  Errors are
    /// logged, not returned: losing a metrics write must never fail an
    /// operation.
    pub fn flush(&self) {
        if let Some(path) = &self.file {
            if let Err(e) = write_atomically(path, &self.render()) {
                tracing::warn!(file = %path.display(), error = %e, "could not write metrics file");
            }
        }
    }
}

fn write_atomically(path: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// The process-wide metrics.  `$SENTINEL_METRICS_FILE` is read once, on
/// first use.
pub fn global() -> &'static Arc<GlobalMetrics> {
    static GLOBAL: OnceLock<Arc<GlobalMetrics>> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        let file = std::env::var_os(METRICS_FILE_ENV)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        Arc::new(GlobalMetrics::build(file))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gauge_text(text: &str, name: &str) -> Option<f64> {
        text.lines()
            .find(|l| l.starts_with(name) && !l.starts_with('#'))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    }

    #[test]
    fn observe_maps_audit_events_to_counters() {
        let registry = Registry::new();
        let m = SentinelMetrics::new(&registry).unwrap();
        let events = [
            AuditEventType::GoalSubmitted {
                goal: "g".into(),
                host: "h".into(),
            },
            AuditEventType::CapabilityInvoked {
                capability_id: "disk_usage".into(),
                args: serde_json::json!({}),
                risk_tier: "Low".into(),
            },
            AuditEventType::CapabilitySucceeded {
                capability_id: "disk_usage".into(),
                duration_ms: 42,
            },
            AuditEventType::CapabilityFailed {
                capability_id: "x".into(),
                error: "e".into(),
            },
            AuditEventType::CapabilityRolledBack {
                capability_id: "x".into(),
            },
            AuditEventType::PolicyDenied {
                capability_id: "x".into(),
                reason: "r".into(),
            },
            AuditEventType::SuspectedPromptInjection {
                capability_id: "x".into(),
                patterns: vec!["p".into()],
            },
            AuditEventType::SessionCompleted {
                duration_ms: 1,
                capabilities_executed: 1,
            },
        ];
        for e in &events {
            m.observe(e);
        }
        assert_eq!(m.audit_events_total.get(), events.len() as f64);
        assert_eq!(m.sessions_started_total.get(), 1.0);
        assert_eq!(m.sessions_completed_total.get(), 1.0);
        assert_eq!(m.active_sessions.get(), 0.0);
        assert_eq!(m.capabilities_invoked_total.get(), 1.0);
        assert_eq!(m.capabilities_succeeded_total.get(), 1.0);
        assert_eq!(m.capabilities_failed_total.get(), 1.0);
        assert_eq!(m.rollbacks_total.get(), 1.0);
        assert_eq!(m.policy_denials_total.get(), 1.0);
        assert_eq!(m.prompt_injection_suspected_total.get(), 1.0);
        assert_eq!(m.capability_duration_ms.get_sample_count(), 1);
    }

    #[test]
    fn mcp_tool_label_is_bounded() {
        let registry = Registry::new();
        let m = SentinelMetrics::new(&registry).unwrap();
        let call = |tool: &str| AuditEventType::McpToolCalled {
            tool: tool.into(),
            arguments: serde_json::json!({}),
        };
        m.observe(&call("sentinel_policy_check"));
        for i in 0..50 {
            m.observe(&call(&format!("made_up_{i}")));
        }
        assert_eq!(
            m.mcp_tool_calls_total
                .with_label_values(&["sentinel_policy_check"])
                .get(),
            1.0
        );
        assert_eq!(
            m.mcp_tool_calls_total.with_label_values(&["other"]).get(),
            50.0
        );
        let series = m
            .gather_text(&registry)
            .lines()
            .filter(|l| l.starts_with("sentinel_mcp_tool_calls_total{"))
            .count();
        assert_eq!(series, 2, "client-chosen names must not create series");
    }

    #[test]
    fn llm_metrics_record_tokens_outcomes_and_retries() {
        let registry = Registry::new();
        let m = SentinelMetrics::new(&registry).unwrap();
        let d = std::time::Duration::from_millis(1500);
        let call = |ok, input_tokens, output_tokens, retries| LlmCall {
            backend: "anthropic",
            model: "claude-x",
            ok,
            input_tokens,
            output_tokens,
            retries,
            duration: d,
        };
        m.observe_llm(&call(true, 100, 20, 0));
        m.observe_llm(&call(true, 50, 5, 2));
        m.observe_llm(&call(false, 0, 0, 3));

        let tokens = |dir: &str| {
            m.llm_tokens_total
                .with_label_values(&["anthropic", "claude-x", dir])
                .get()
        };
        assert_eq!(tokens("input"), 150.0);
        assert_eq!(tokens("output"), 25.0);
        let requests = |o: &str| {
            m.llm_requests_total
                .with_label_values(&["anthropic", "claude-x", o])
                .get()
        };
        assert_eq!(requests("ok"), 2.0);
        assert_eq!(requests("error"), 1.0);
        assert_eq!(
            m.llm_retries_total
                .with_label_values(&["anthropic", "claude-x"])
                .get(),
            5.0
        );
        let text = m.gather_text(&registry);
        assert!(text.contains("sentinel_llm_request_duration_seconds_count{backend=\"anthropic\",model=\"claude-x\"} 3"), "{text}");
    }

    #[test]
    fn metrics_file_is_written_atomically() {
        let dir = std::env::temp_dir().join(format!("sentinel-metrics-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sentinel.prom");
        let g = GlobalMetrics::build(Some(path.clone()));
        g.metrics().observe(&AuditEventType::InvestigationStarted);
        g.flush();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(gauge_text(&text, "sentinel_audit_events_total"), Some(1.0));
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);

        // No file configured: flush is a no-op, not an error.
        GlobalMetrics::build(None).flush();
        // Unwritable path: logged, never panics.
        GlobalMetrics::build(Some(dir.join("no/such/dir/x.prom"))).flush();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn make_registry_and_metrics() -> (Registry, SentinelMetrics) {
        let registry = Registry::new();
        let metrics = SentinelMetrics::new(&registry).expect("metrics should register");
        (registry, metrics)
    }

    #[test]
    fn metrics_register_without_error() {
        make_registry_and_metrics();
    }

    #[test]
    fn counter_increments_are_reflected() {
        let (_reg, m) = make_registry_and_metrics();

        m.capabilities_invoked_total.inc();
        m.capabilities_invoked_total.inc();
        assert_eq!(m.capabilities_invoked_total.get(), 2.0);

        m.capabilities_succeeded_total.inc();
        assert_eq!(m.capabilities_succeeded_total.get(), 1.0);

        m.capabilities_failed_total.inc();
        assert_eq!(m.capabilities_failed_total.get(), 1.0);

        m.policy_denials_total.inc();
        assert_eq!(m.policy_denials_total.get(), 1.0);

        m.kill_switch_activations_total.inc();
        assert_eq!(m.kill_switch_activations_total.get(), 1.0);

        m.rollbacks_total.inc();
        assert_eq!(m.rollbacks_total.get(), 1.0);

        m.sessions_started_total.inc();
        assert_eq!(m.sessions_started_total.get(), 1.0);

        m.sessions_completed_total.inc();
        assert_eq!(m.sessions_completed_total.get(), 1.0);

        m.audit_events_total.inc_by(5.0);
        assert_eq!(m.audit_events_total.get(), 5.0);
    }

    #[test]
    fn gauge_set_and_inc_dec() {
        let (_reg, m) = make_registry_and_metrics();

        m.active_sessions.set(3.0);
        assert_eq!(m.active_sessions.get(), 3.0);

        m.active_sessions.inc();
        assert_eq!(m.active_sessions.get(), 4.0);

        m.active_sessions.dec();
        assert_eq!(m.active_sessions.get(), 3.0);
    }

    #[test]
    fn histogram_observes_values() {
        let (_reg, m) = make_registry_and_metrics();
        m.capability_duration_ms.observe(10.0);
        m.capability_duration_ms.observe(250.0);
        m.capability_duration_ms.observe(1500.0);
        // Just verify it doesn't panic; the histogram tracks internally.
    }

    #[test]
    fn gather_text_contains_metric_names() {
        let (reg, m) = make_registry_and_metrics();
        m.capabilities_invoked_total.inc();
        m.policy_denials_total.inc();
        m.audit_events_total.inc_by(3.0);

        let text = m.gather_text(&reg);
        assert!(text.contains("sentinel_capabilities_invoked_total"));
        assert!(text.contains("sentinel_policy_denials_total"));
        assert!(text.contains("sentinel_audit_events_total"));
        assert!(text.contains("sentinel_active_sessions"));
        assert!(text.contains("sentinel_capability_duration_ms"));
    }

    #[test]
    fn double_registration_fails() {
        let registry = Registry::new();
        SentinelMetrics::new(&registry).unwrap();
        // Attempting to register the same metric names again must fail.
        let result = SentinelMetrics::new(&registry);
        assert!(
            result.is_err(),
            "double registration should return an error"
        );
    }
}
