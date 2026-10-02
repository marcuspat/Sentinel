# ADR-021: Observability — Metrics From the Audit Stream, GenAI Spans

**Status:** Accepted (amends ADR-011)  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Observability, Metrics, Tracing

---

## Context

ADR-011 chose Prometheus, and `SentinelMetrics` defined eleven metrics with
tests. Nothing ever incremented them: no code path constructed the struct, and
there was no way to read the values out. The README listed "Prometheus metrics
integration" for a feature that produced no data.

There was also no record of what a session cost: token counts were logged at
`debug` and discarded.

## Decision

### Metrics are derived from the audit log

`SentinelMetrics::observe(&AuditEventType)` maps each audit event to its
counters, and `AuditLog::append` calls it for every file-backed log. Every path
that audits (`run`, the TUI, `serve --mcp`, `approve`, `reject`, `execute`) is
therefore measured, with no instrumentation scattered through the code, and
the metrics cannot disagree with the audit chain: they are the chain, counted.

New: `sentinel_prompt_injection_suspected_total`, and
`sentinel_mcp_tool_calls_total{tool}`. The `tool` label only takes the five
real tool names; anything else a client sends is counted under `other`, so a
client cannot create unbounded series.

### LLM metrics

`ResilientBackend` records every model request:

- `sentinel_llm_requests_total{backend,model,outcome}`
- `sentinel_llm_tokens_total{backend,model,direction}`
- `sentinel_llm_retries_total{backend,model}`
- `sentinel_llm_request_duration_seconds{backend,model}` (includes retries)

### Exposition: a text file

Sentinel is a CLI and a stdio server; it has no HTTP listener and this ADR does
not add one. When `SENTINEL_METRICS_FILE` is set, the Prometheus text
exposition is rewritten atomically after each audit event and each model call.
Point it at node_exporter's textfile-collector directory.

### Spans follow the OpenTelemetry GenAI semantic conventions

Emitted through `tracing`, so they cost nothing unless a subscriber wants them:

- `gen_ai.chat` per model request: `gen_ai.operation.name = "chat"`,
  `gen_ai.system`, `gen_ai.request.model`, `gen_ai.request.max_tokens`,
  `gen_ai.response.model`, `gen_ai.response.finish_reasons`,
  `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `error.type`.
- `gen_ai.execute_tool` per capability invocation: `gen_ai.tool.name`, plus
  `sentinel.risk_tier`, `sentinel.policy.effect`, `sentinel.step.sequence`.

**Prompts, completions, tool arguments and tool output are never put on a
span.** They contain host details and attacker-influenced text; the audit log
is the place for what was run. A test asserts prompt text does not appear in
any span field.

## Limits

- **No OTLP exporter is bundled.** The spans carry the right names and
  attributes; shipping them to a collector means adding a
  `tracing-opentelemetry` layer in `main`, which is not done here. Today they
  appear in the normal log output at `info`.
- Counters are per process. A short-lived `sentinel run` writes its totals and
  exits; the next run starts from zero and overwrites the file. Prometheus
  handles counter resets, but two processes sharing one file path overwrite
  each other. Give long-lived and one-shot processes different files.
- `sentinel_active_sessions` is only meaningful inside one process.
- The GenAI conventions are still marked experimental upstream; attribute
  names may change.

## Alternatives considered

- **HTTP `/metrics` endpoint.** Natural for a daemon, but it adds a listener
  and an authentication question to a tool whose security story is "no network
  surface".
- **Push gateway / OTLP metrics.** Needs a network client and an endpoint in
  every environment.
- **Instrument call sites directly.** What ADR-011 implied; it is how the
  metrics ended up defined and unused.
