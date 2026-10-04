# ADR-020: LLM Retries, Deadlines and Session Budgets

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Reliability, Cost Control, Backends

---

## Context

Each backend made one HTTP request and returned the result.

- A `429`, a `529 overloaded` or a dropped connection ended the session. The
  backends parsed `Retry-After` into the error and nothing acted on it.
- Nothing bounded what a session could spend. Investigation has a round limit,
  but a caller driving `plan()` in a loop, or a future multi-turn flow, had no
  ceiling on calls or tokens.
- `response.json()` buffered whatever the server sent. The base URL is
  configurable (local servers, proxies), so a misbehaving endpoint could return
  an arbitrarily large body.

## Decision

### `ResilientBackend`

A wrapper that implements `LlmBackend` around any other backend, for text and
tool calls alike. `sentinel run` and the TUI wrap their backend with it.

- **Deadline per attempt** (120 s default), independent of the HTTP client's
  own timeout.
- **Retries**: up to 4 attempts. Retried: `RateLimited`, HTTP `408`, `409`,
  `425`, every `5xx` (including `529`), network errors and attempt timeouts.
  Not retried: other `4xx`, malformed responses, anything that is not a
  transport or server condition.
- **Backoff**: `base × 2^(attempt−1)`, capped at 20 s, scaled into
  `[50%, 100%]` with clock-derived jitter so concurrent sessions do not retry
  in step.
- **`Retry-After`** is honoured as a minimum wait. If the server asks for more
  than 60 s the error is returned instead of sleeping; an agent that goes
  silent for ten minutes is worse than one that reports a rate limit.
- **Budget**, checked before every request: at most 100 model calls and
  2,000,000 tokens (input + output, as reported by the provider) per session.
  `SENTINEL_MAX_LLM_CALLS` / `SENTINEL_MAX_LLM_TOKENS` override; `0` means
  unlimited. Exceeding it returns `AgentError::BudgetExceeded` without making
  the request.
- `usage()` exposes calls, tokens and retries for the observability work that
  follows.

### Bounded response bodies

Success bodies are read with an 8 MiB cap and refused beyond it; error bodies
are truncated at 64 KiB. Both count the stream, not just `Content-Length`.

## Consequences

- New `AgentError::Timeout` and `AgentError::BudgetExceeded`.
- A session can now take longer before failing: worst case four attempts plus
  backoff. Callers that need a strict wall-clock bound should set
  `RetryPolicy::max_attempts` to 1.
- Retried requests are billed by the provider when the failed attempt reached
  the model. Only transport and server-side failures are retried, where that
  is usually not the case, but it is not guaranteed.

## Not covered

- The token budget is checked before a request, so it can be overshot by one
  response. Providers that report no usage (some Ollama responses) count as
  zero tokens; the call budget still applies.
- No circuit breaker across sessions, and no fallback to a second provider.
- Jitter uses clock noise, not a CSPRNG. It only needs to decorrelate clients.
- Tested with scripted fakes and `wiremock`; no live provider traffic.

## Alternatives considered

- **Retry inside each backend.** Three copies of the same loop, and the budget
  would still need a shared owner.
- **`tower` retry/timeout layers.** Fits `reqwest` poorly here (the unit that
  must be retried is the whole provider call, not the HTTP request), and adds
  a dependency for one loop.
- **Cost budget in dollars.** Needs per-model price tables that go stale;
  tokens are what the provider actually reports.
