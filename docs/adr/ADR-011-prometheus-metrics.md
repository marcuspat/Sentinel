# ADR-011: Prometheus-Compatible Metrics Exposition

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Observability, Operations, Monitoring

---

## Context

Sentinel is an autonomous agent that operates on production infrastructure, potentially running long-duration sessions, managing multiple fleet hosts concurrently, and executing hundreds of capability invocations per session. Operators and platform teams need visibility into Sentinel's operational behavior to:

**Detect anomalies.** Unusual patterns — a sudden spike in `PolicyDenied` events, a capability with unexpectedly high failure rate, an LLM backend with elevated latency — should be detectable by alerting systems without requiring manual log inspection.

**Measure SLOs.** The performance requirements (< 50 ms per capability overhead, < 50 MB idle RAM) must be measurable in production. Operators need to verify that deployed instances are meeting these targets.

**Capacity planning.** Fleet deployments require understanding per-host resource consumption and LLM API call volumes to manage costs and scale appropriately.

**Audit summary statistics.** Aggregate metrics (capabilities executed per hour, plans approved vs. rejected ratio, most-used capability types) provide a high-level operational picture complementary to the detailed audit log.

**Integration with existing monitoring stacks.** Most infrastructure teams already operate a monitoring platform. Sentinel's metrics must integrate with existing alerting and dashboarding infrastructure without requiring a new, Sentinel-specific monitoring system.

The `sentinel-core` crate (or a dedicated metrics module) is responsible for registering and updating metrics. The HTTP metrics endpoint is exposed by the main binary or the fleet agent.

---

## Decision

Sentinel exposes metrics in the **Prometheus text format** on an HTTP endpoint (`/metrics`, default port 9090, configurable).

Metrics are implemented using the `prometheus` crate (version 0.13, with the `process` feature for automatic CPU, memory, and file descriptor metrics).

**Metric families exposed:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sentinel_capability_invocations_total` | Counter | `capability_id`, `risk_tier`, `result` | Total capability invocations by ID and outcome |
| `sentinel_capability_duration_ms` | Histogram | `capability_id`, `risk_tier` | Wall-clock duration distribution per capability |
| `sentinel_policy_evaluations_total` | Counter | `decision`, `risk_tier` | Policy evaluation outcomes (allowed/denied) |
| `sentinel_policy_denied_total` | Counter | `capability_id`, `reason` | Denied capability invocations with reason |
| `sentinel_sessions_total` | Counter | `outcome` | Completed sessions by outcome (completed/aborted/failed) |
| `sentinel_session_duration_seconds` | Histogram | | End-to-end session duration distribution |
| `sentinel_llm_requests_total` | Counter | `backend`, `model`, `result` | LLM API requests by backend and outcome |
| `sentinel_llm_request_duration_ms` | Histogram | `backend`, `model` | LLM API request latency distribution |
| `sentinel_llm_tokens_total` | Counter | `backend`, `model`, `direction` | Token consumption (input/output) per backend |
| `sentinel_fleet_hosts_connected` | Gauge | | Current number of connected fleet agents |
| `sentinel_fleet_commands_dispatched_total` | Counter | `host_group`, `result` | Fleet command dispatch outcomes |
| `sentinel_audit_events_written_total` | Counter | `event_type` | Audit events written by type |
| `sentinel_kill_switch_activations_total` | Counter | `scope`, `risk_tier_threshold` | Kill switch activation events |
| `process_resident_memory_bytes` | Gauge | | (from prometheus process feature) |
| `process_cpu_seconds_total` | Counter | | (from prometheus process feature) |

**Scrape configuration.** The metrics endpoint is unauthenticated by default (consistent with standard Prometheus deployment patterns) but can be restricted to a configured IP allowlist. TLS on the metrics endpoint is optional and configured separately from the fleet mTLS.

**Push gateway support.** For fleet agents that are not directly scrape-able (e.g., behind NAT, short-lived), a push gateway mode is supported via the Prometheus Pushgateway protocol.

---

## Rationale

**Prometheus is the de facto standard for infrastructure metrics.** The Prometheus ecosystem (including Grafana dashboards, Alertmanager alerting, and remote write to long-term storage) is the dominant monitoring standard for Linux infrastructure and Kubernetes environments. Any organization that already operates infrastructure monitoring is very likely to have a Prometheus-compatible scraper. Using the Prometheus format means Sentinel integrates into existing monitoring infrastructure without requiring new tooling.

**Text-based exposition format is simple, debuggable, and widely supported.** The Prometheus text format is human-readable (viewable with `curl /metrics`), well-documented, and supported by all Prometheus-compatible systems including Datadog, InfluxDB, VictoriaMetrics, and others. Using a binary format (e.g., Protocol Buffers OpenMetrics) would reduce human-readability without meaningfully improving performance at Sentinel's metrics volume.

**Pull-based scraping matches the operational model.** Prometheus's pull model (the scraper fetches metrics from the `/metrics` endpoint) means that Sentinel does not need to know about the monitoring infrastructure configuration. The metrics endpoint is always available; whether it is scraped and at what interval is the monitoring platform's concern. This decoupling is preferable to a push model where Sentinel must be configured with the monitoring system's address.

**The `prometheus` crate integrates cleanly with the Rust ecosystem.** The `prometheus` crate is mature, actively maintained, and provides the correct primitives (Counters, Gauges, Histograms, process metrics) with minimal boilerplate. It is thread-safe via atomic operations, which is compatible with Sentinel's async Tokio runtime.

**Capability duration histograms directly support the 50 ms SLO.** Prometheus histograms allow precise SLO alerting rules (e.g., "alert if the 99th percentile of `sentinel_capability_duration_ms` exceeds 50 ms over a 5-minute window"). This provides automated enforcement monitoring for the performance requirement in ADR-001.

**LLM token counting enables cost monitoring.** LLM API costs are primarily driven by token consumption. The `sentinel_llm_tokens_total` counter allows operators to track API costs in their monitoring dashboard and set alerts if token consumption exceeds expected thresholds.

---

## Consequences

**Positive:**

- Integrates into existing Prometheus/Grafana monitoring stacks without new tooling.
- Human-readable metrics format for direct inspection with `curl`.
- Capability duration histograms provide automated SLO monitoring for the 50 ms performance requirement.
- LLM API usage metrics enable cost tracking and anomaly detection.
- Process metrics (memory, CPU) provide automated monitoring for the 50 MB RAM requirement.
- Policy denial metrics enable security alerting (unusual denial spikes may indicate an attack).

**Negative:**

- The HTTP `/metrics` endpoint adds a small attack surface. IP allowlisting and optional TLS must be configured in security-sensitive deployments.
- Prometheus's pull model requires that the monitoring system can reach Sentinel's metrics port. In strict network environments, this may require firewall rule changes. The Pushgateway option mitigates this for agents behind NAT.
- Histogram buckets must be pre-configured at startup. Poorly chosen bucket boundaries (too wide or too narrow) reduce the precision of latency percentile estimates. Default buckets must be calibrated for Sentinel's expected latency distribution.
- High-cardinality label values (e.g., using a unique session ID as a metric label) would cause memory growth proportional to the number of distinct label values. Metric label design must avoid unbounded cardinality. Session IDs are recorded in the audit log, not in metric labels.
- The `prometheus` crate uses global static registries. In test code, care must be taken to isolate metric registration between tests to prevent `AlreadyReg` errors.

---

## Alternatives Considered

**OpenTelemetry.** OpenTelemetry (OTEL) provides a vendor-neutral observability framework covering metrics, traces, and logs. Using OTEL would provide a richer observability signal (distributed traces across fleet operations) and support more backends. However, the Rust OTEL SDK is more complex to integrate, has a larger dependency footprint, and the added complexity of distributed tracing is not justified for Sentinel's current architecture. Prometheus is the right tool for the specific use case of operational metrics. OTEL traces are a noted future enhancement for fleet multi-hop operations.

**Custom metrics format / binary protocol.** A custom metrics binary protocol would be more efficient for high-throughput metric writes. At Sentinel's metric write frequency (capabilities are at most hundreds per second, not millions), the overhead of the Prometheus text format is negligible. Custom formats create integration complexity for every monitoring backend.

**StatsD / Graphite.** StatsD is a push-based metrics protocol with wide support. Using StatsD would require Sentinel to be configured with a StatsD server address, creating an external service dependency. Prometheus's pull model is preferable for operator experience and deployment simplicity.

**Structured logging as the only observability channel.** Using only the structured audit log (and relying on log aggregation tools to generate metrics) was considered. This approach works but requires additional tooling (log-to-metrics conversion in the SIEM or log aggregation system) and introduces latency in metric availability. Native Prometheus metrics provide immediate, low-latency operational visibility that structured logging alone cannot.

**Embedded Grafana dashboard.** Bundling a pre-configured Grafana dashboard definition (JSON) with Sentinel's release artifacts to provide an "out of the box" monitoring experience was considered as a complementary measure. This is noted as a documentation enhancement (ship a `grafana-dashboard.json` file alongside the binary) rather than an architectural decision.
