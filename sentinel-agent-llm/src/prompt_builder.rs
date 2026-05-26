//! Prompt construction for the investigate-plan-approve-act cycle.
//!
//! [`PromptBuilder`] provides static methods that produce the system and user
//! prompts fed to the LLM at each phase.  Prompts embed the available
//! capabilities (with their IDs, descriptions, and risk tiers) and instruct
//! the LLM to respond in structured JSON so the rest of the pipeline can parse
//! the output deterministically.

use sentinel_core::{CapabilityManifest, RiskTier};

use crate::planner::Observation;

// ── PromptBuilder ─────────────────────────────────────────────────────────────

/// Constructs prompts for the LLM at each phase of the agent cycle.
pub struct PromptBuilder;

impl PromptBuilder {
    // ── Investigation phase ───────────────────────────────────────────────────

    /// Build the system prompt for the **investigation** phase.
    ///
    /// Explains the agent model and lists read-only capabilities the LLM may
    /// request to gather observations about the target system.
    pub fn investigation_system(capabilities: &[CapabilityManifest]) -> String {
        let cap_list = Self::format_capabilities(capabilities);

        format!(
            r#"You are Sentinel, a safe and precise AI system administration agent.

## Your Role
You are in the INVESTIGATION phase. Your job is to gather observations about the
target system by requesting read-only capability invocations. You MUST NOT
suggest any changes to the system at this stage.

## How This Works
1. **Investigate**: You request capability invocations to collect observations.
2. **Plan**: After sufficient investigation, you produce a structured action plan.
3. **Approve**: A human operator reviews and approves the plan before any action.
4. **Act**: Approved steps are executed under policy control.

You will never execute mutating actions without explicit operator approval.
Safety and correctness always take priority over speed.

## Requesting a Capability
To request a capability invocation, respond with ONLY a JSON object:

```json
{{
  "capability_id": "<id>",
  "args": {{ ... }},
  "reasoning": "Why you need this information"
}}
```

When you have gathered enough information to form a plan, respond with:

```json
{{
  "done_investigating": true,
  "reasoning": "Summary of what you learned and why you are ready to plan"
}}
```

## Available Investigation Capabilities

{cap_list}

## Important Rules
- Only request capabilities listed above.
- Do not request High or Critical risk capabilities during investigation.
- Each capability invocation costs time; be efficient.
- Always explain your reasoning.
- Respond ONLY with valid JSON — no prose, no markdown outside code blocks."#
        )
    }

    // ── Planning phase ────────────────────────────────────────────────────────

    /// Build the system prompt for the **planning** phase.
    ///
    /// Explains the expected output format for a structured action plan.
    pub fn planning_system(capabilities: &[CapabilityManifest]) -> String {
        let cap_list = Self::format_capabilities(capabilities);
        let schema = Self::plan_schema_prompt();

        format!(
            r#"You are Sentinel, a safe and precise AI system administration agent.

## Your Role
You are in the PLANNING phase. Based on the observations you collected during
investigation, you must produce a structured, reviewable action plan.

## Critical Safety Requirements
- Every step MUST use a capability from the list below.
- Be conservative: prefer reversible steps and low-risk capabilities.
- If a high-risk step is unavoidable, explain clearly why.
- A human operator WILL review and approve this plan before anything runs.
- Prefer idempotent operations where possible.
- If you are unsure, choose the safer option.

## Output Format
You MUST respond with ONLY a JSON object matching this schema:

{schema}

## Available Capabilities

{cap_list}

## Important Rules
- Respond ONLY with valid JSON — no prose, no markdown outside the code block.
- Every `capability_id` must exactly match one of the IDs listed above.
- `depends_on` should list step indices (0-based) that must complete first.
- Set `can_rollback: true` only if the capability's `has_inverse` is true."#
        )
    }

    // ── Observation-enriched planning user message ─────────────────────────

    /// Build the user message for the planning phase, embedding the goal and
    /// all observations collected during investigation.
    pub fn planning_user_with_observations(goal: &str, observations: &[Observation]) -> String {
        let obs_text = if observations.is_empty() {
            "No observations were collected during investigation.".to_string()
        } else {
            observations
                .iter()
                .enumerate()
                .map(|(i, obs)| {
                    let (success, output_summary) = match &obs.result {
                        sentinel_core::CapabilityResult::Success { output } => {
                            let s = serde_json::to_string_pretty(output).unwrap_or_default();
                            (true, s)
                        }
                        sentinel_core::CapabilityResult::Failure { error, .. } => {
                            (false, error.clone())
                        }
                        sentinel_core::CapabilityResult::DryRun { predicted_effect } => {
                            let s = serde_json::to_string_pretty(predicted_effect).unwrap_or_default();
                            (true, format!("[dry-run] {s}"))
                        }
                    };

                    format!(
                        "### Observation {} — `{}`\n- Args: {}\n- Success: {}\n- Result:\n```\n{}\n```",
                        i + 1,
                        obs.capability_id,
                        serde_json::to_string(&obs.args).unwrap_or_default(),
                        success,
                        output_summary
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        };

        format!(
            r#"## Goal
{goal}

## Observations Collected During Investigation

{obs_text}

## Your Task
Based on the goal and the observations above, produce a complete, safe, and
minimal action plan as a JSON object matching the schema in your instructions.

Think carefully about:
1. What is the minimal set of steps to achieve the goal?
2. What is the risk of each step?
3. Can any steps be rolled back if something goes wrong?
4. Are there dependencies between steps?"#
        )
    }

    // ── Plan schema ───────────────────────────────────────────────────────────

    /// Returns a description of the expected plan JSON schema.
    pub fn plan_schema_prompt() -> String {
        r#"```json
{
  "rationale": "string — why these steps achieve the goal safely",
  "steps": [
    {
      "capability_id": "string — exact ID of the capability to invoke",
      "args": {},
      "description": "string — what this step does and why",
      "can_rollback": false,
      "depends_on": []
    }
  ]
}
```

Fields:
- `rationale`: Overall explanation of the plan strategy.
- `steps[].capability_id`: Must exactly match an available capability ID.
- `steps[].args`: JSON object of arguments for the capability.
- `steps[].description`: Human-readable description shown to the operator.
- `steps[].can_rollback`: `true` only if the capability supports inverse/rollback.
- `steps[].depends_on`: List of 0-based step indices that must succeed first."#
            .to_string()
    }

    // ── Investigation turn ────────────────────────────────────────────────────

    /// Build a user-turn message prompting the LLM to request its next
    /// capability invocation (or declare investigation complete).
    pub fn investigation_turn(goal: &str, observations_so_far: &[Observation]) -> String {
        if observations_so_far.is_empty() {
            return format!(
                r#"## Goal
{goal}

No observations collected yet. Begin investigating the system.
Request the first capability invocation as a JSON object."#
            );
        }

        let obs_text = observations_so_far
            .iter()
            .enumerate()
            .map(|(i, obs)| {
                let (ok_label, result_summary) = match &obs.result {
                    sentinel_core::CapabilityResult::Success { output } => {
                        let s = serde_json::to_string_pretty(output).unwrap_or_default();
                        let truncated = if s.len() > 2000 {
                            format!("{}... [truncated, {} bytes total]", &s[..2000], s.len())
                        } else {
                            s
                        };
                        ("OK", truncated)
                    }
                    sentinel_core::CapabilityResult::Failure { error, .. } => {
                        ("FAILED", error.clone())
                    }
                    sentinel_core::CapabilityResult::DryRun { predicted_effect } => {
                        let s = serde_json::to_string_pretty(predicted_effect).unwrap_or_default();
                        ("DRY-RUN", s)
                    }
                };

                format!(
                    "[{}] `{}` ({}) → {}: {}",
                    i + 1,
                    obs.capability_id,
                    serde_json::to_string(&obs.args).unwrap_or_default(),
                    ok_label,
                    result_summary
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"## Goal
{goal}

## Observations So Far ({count})

{obs_text}

## Next Step
Do you have enough information to plan? If yes, respond with:
```json
{{"done_investigating": true, "reasoning": "..."}}
```

If not, request the next capability invocation:
```json
{{"capability_id": "...", "args": {{}}, "reasoning": "..."}}
```"#,
            count = observations_so_far.len()
        )
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn format_capabilities(capabilities: &[CapabilityManifest]) -> String {
        if capabilities.is_empty() {
            return "No capabilities available.".to_string();
        }

        capabilities
            .iter()
            .map(|cap| {
                let risk_label = match cap.risk_tier {
                    RiskTier::Low => "LOW",
                    RiskTier::Medium => "MEDIUM",
                    RiskTier::High => "HIGH",
                    RiskTier::Critical => "CRITICAL",
                };
                let inverse = if cap.has_inverse {
                    " (supports rollback)"
                } else {
                    ""
                };
                format!(
                    "- `{}` [{}{}]: {}",
                    cap.id, risk_label, inverse, cap.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{CapabilityKind, CapabilityManifest, RiskTier};

    fn make_manifest(id: &str, risk: RiskTier, description: &str, has_inverse: bool) -> CapabilityManifest {
        CapabilityManifest {
            id: id.to_string(),
            name: id.to_string(),
            description: description.to_string(),
            kind: CapabilityKind::ReadOnly,
            risk_tier: risk,
            resource_impact: Default::default(),
            has_inverse,
            version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn investigation_system_contains_capability_id() {
        let caps = vec![
            make_manifest("disk_usage", RiskTier::Low, "Check disk usage", false),
            make_manifest("process_list", RiskTier::Low, "List processes", false),
        ];

        let prompt = PromptBuilder::investigation_system(&caps);
        assert!(prompt.contains("disk_usage"));
        assert!(prompt.contains("process_list"));
        assert!(prompt.contains("INVESTIGATION"));
        assert!(prompt.contains("done_investigating"));
    }

    #[test]
    fn investigation_system_empty_caps() {
        let prompt = PromptBuilder::investigation_system(&[]);
        assert!(prompt.contains("No capabilities available."));
    }

    #[test]
    fn planning_system_contains_schema() {
        let caps = vec![
            make_manifest("restart_service", RiskTier::Medium, "Restart a service", true),
        ];
        let prompt = PromptBuilder::planning_system(&caps);
        assert!(prompt.contains("rationale"));
        assert!(prompt.contains("capability_id"));
        assert!(prompt.contains("can_rollback"));
        assert!(prompt.contains("restart_service"));
        assert!(prompt.contains("PLANNING"));
    }

    #[test]
    fn planning_user_no_observations() {
        let prompt = PromptBuilder::planning_user_with_observations("Fix disk", &[]);
        assert!(prompt.contains("Fix disk"));
        assert!(prompt.contains("No observations"));
    }

    #[test]
    fn planning_user_with_observation() {
        use sentinel_core::CapabilityResult;
        use crate::planner::Observation;

        let obs = Observation {
            id: uuid::Uuid::new_v4(),
            capability_id: "disk_usage".to_string(),
            args: serde_json::json!({"path": "/"}),
            result: CapabilityResult::success(serde_json::json!({"used": "85%"})),
            timestamp: chrono::Utc::now(),
        };

        let prompt = PromptBuilder::planning_user_with_observations("Fix disk", &[obs]);
        assert!(prompt.contains("disk_usage"));
        assert!(prompt.contains("85%"));
    }

    #[test]
    fn investigation_turn_no_observations() {
        let prompt = PromptBuilder::investigation_turn("Fix CPU", &[]);
        assert!(prompt.contains("Fix CPU"));
        assert!(prompt.contains("No observations"));
    }

    #[test]
    fn investigation_turn_with_observations() {
        use sentinel_core::CapabilityResult;
        use crate::planner::Observation;

        let obs = Observation {
            id: uuid::Uuid::new_v4(),
            capability_id: "cpu_info".to_string(),
            args: serde_json::json!({}),
            result: CapabilityResult::success(serde_json::json!({"cpu": "95%"})),
            timestamp: chrono::Utc::now(),
        };

        let prompt = PromptBuilder::investigation_turn("Fix CPU", &[obs]);
        assert!(prompt.contains("cpu_info"));
        assert!(prompt.contains("done_investigating"));
    }

    #[test]
    fn plan_schema_prompt_contains_fields() {
        let schema = PromptBuilder::plan_schema_prompt();
        assert!(schema.contains("rationale"));
        assert!(schema.contains("capability_id"));
        assert!(schema.contains("can_rollback"));
        assert!(schema.contains("depends_on"));
    }

    #[test]
    fn capability_with_rollback_shows_flag() {
        let caps = vec![
            make_manifest("write_file", RiskTier::Medium, "Write a file", true),
        ];
        let prompt = PromptBuilder::investigation_system(&caps);
        assert!(prompt.contains("supports rollback"));
    }

    #[test]
    fn critical_capability_shows_risk() {
        let caps = vec![
            make_manifest("wipe_disk", RiskTier::Critical, "Wipe all data", false),
        ];
        let prompt = PromptBuilder::investigation_system(&caps);
        assert!(prompt.contains("CRITICAL"));
    }
}
