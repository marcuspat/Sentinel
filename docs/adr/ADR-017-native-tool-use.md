# ADR-017: Provider-Native Tool Use

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** LLM Safety, Prompt Injection, Backends

---

## Context

The reasoning loop asked the model to "respond with ONLY a JSON object" and
then searched the response text for one. That has two costs.

1. **No boundary between data and action.** Whatever the model writes is a
   candidate action. Capability output is attacker-influenced (ADR-014), and a
   model that is talked into echoing `{"capability_id": "service_stop", …}`
   has, in text mode, issued a request. Spotlighting lowers the odds; it does
   not change the fact that the action channel and the prose channel are the
   same string.
2. **The model guesses argument names.** Capabilities validated arguments but
   never described them, so the only documentation the model had was the
   one-line capability description.

## Decision

- **`Capability::args_schema()`**, a JSON Schema for the capability's
  arguments, with a permissive default. All 14 built-in capabilities implement
  it. A test asserts that "an empty object is rejected" agrees with "the schema
  has required fields" for every built-in, so schema and validator cannot drift
  on what is mandatory. `validate_args` remains the authority.
- **`LlmBackend::complete_with_tools`** and `supports_tools()`, both with
  defaults, so existing backends are untouched. Types: `ToolSpec`,
  `ToolChoice::{Any, Tool}`, `ToolCall`, `ToolResponse`.
- **Anthropic backend** sends `tools` and a forced `tool_choice` with
  `disable_parallel_tool_use: true`, and reads `tool_use` content blocks.
- **Investigation:** one tool per capability (input schema = its argument
  schema) plus `done_investigating`; `tool_choice: any`.
- **Planning:** a single `propose_plan` tool whose schema is the plan document;
  `tool_choice` names it.
- **Exactly one call per turn.** A turn with no call (text only) or more than
  one call is an error. Text next to a call is kept as the step's reasoning and
  is never parsed.
- **One parser.** A tool call is converted to the same JSON document the text
  protocol uses and passed through the existing `CapabilityRequestParser` /
  `PlanParser`. Identifier validation and registry checks are therefore
  identical on both paths.
- Capability ids may contain `.`, which provider tool names do not allow; ids
  are mapped (`.` → `__`) and mapped back. A capability cannot shadow a control
  tool or collide with another capability after mapping.
- **Fallback.** Backends without tool support, or `SENTINEL_NATIVE_TOOLS=off`,
  use the text protocol unchanged.

## What this does and does not buy

- Text the model writes can no longer become an action when tools are in use.
  `json_in_text_is_never_executed` and
  `injected_json_in_model_text_is_not_executed_in_tool_mode` pin this.
- It does **not** stop a model that has been persuaded from *choosing* to call
  a harmful tool. The policy engine, the approval gate and the sandbox remain
  the controls for that. This removes one injection route; it is not a fix for
  prompt injection.
- Schemas are advisory to the provider. Nothing here relies on the provider
  enforcing them.

## Not verified

Every test runs against `wiremock` or an in-process fake. The request and
response shapes follow the published Messages API, but **no request has been
sent to the live Anthropic API** (the project does not make paid calls in
testing). The first real run is the validation; `SENTINEL_NATIVE_TOOLS=off`
restores the previous behaviour if it misbehaves.

OpenAI and Ollama still use the text protocol; that is the next roadmap item.

## Alternatives considered

- **One generic `invoke_capability(capability_id, args)` tool.** Fewer tools,
  but the model gets no per-capability schema and the id is free text again.
- **Structured-output / JSON mode.** Guarantees syntax, not that the content
  came through a channel separate from prose.
- **Multi-turn `tool_result` conversation.** The idiomatic shape, and worth
  doing, but it changes how observations are fed back (today they are rebuilt
  into one spotlighted user turn each round). Kept out to limit this change.
