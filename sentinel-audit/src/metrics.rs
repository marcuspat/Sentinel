use prometheus::{Counter, Gauge, Histogram, HistogramOpts, Opts, Registry};

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
            .buckets(vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1_000.0, 5_000.0, 30_000.0]),
        )?;

        let active_sessions = Gauge::with_opts(Opts::new(
            "sentinel_active_sessions",
            "Number of currently active sessions",
        ))?;

        let audit_events_total = Counter::with_opts(Opts::new(
            "sentinel_audit_events_total",
            "Total audit events written across all sessions",
        ))?;

        // Register everything.
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
        })
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(result.is_err(), "double registration should return an error");
    }
}
