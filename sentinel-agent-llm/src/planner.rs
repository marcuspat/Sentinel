//! Plan parsing and capability request parsing.
//!
//! [`PlanParser`] turns raw LLM JSON output into a [`Plan`] value, resolving
//! capability IDs against the registry and filling in risk tiers.
//!
//! [`CapabilityRequestParser`] parses the investigation-phase JSON requests
//! that ask the loop to invoke a specific capability.

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use uuid::Uuid;

use sentinel_core::{CapabilityManifest, CapabilityResult, Plan, PlanStep, RiskTier};

use crate::error::AgentError;

// ── Re-export Observation so prompt_builder can use it ───────────────────────

/// A single system observation recorded during the Investigating phase.
///
/// This is a local mirror of `sentinel_core::session::Observation` so that
/// the agent-llm crate can operate without importing the full session module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// Unique identifier for this observation.
    pub id: Uuid,
    /// The capability that produced this observation.
    pub capability_id: String,
    /// Arguments that were passed to the capability.
    pub args: serde_json::Value,
    /// Result returned by the capability.
    pub result: CapabilityResult,
    /// Wall-clock time when the observation was recorded.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Observation {
    /// Construct a new observation, stamping the current UTC time.
    pub fn new(
        capability_id: impl Into<String>,
        args: serde_json::Value,
        result: CapabilityResult,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            capability_id: capability_id.into(),
            args,
            result,
            timestamp: chrono::Utc::now(),
        }
    }
}

// ── CapabilityRegistry ────────────────────────────────────────────────────────

/// A simple registry mapping capability IDs to their manifests.
///
/// The reasoning loop uses this to validate capability requests from the LLM
/// and to look up risk tiers when constructing plan steps.
pub struct CapabilityRegistry {
    capabilities: std::collections::HashMap<String, CapabilityManifest>,
}

impl CapabilityRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            capabilities: std::collections::HashMap::new(),
        }
    }

    /// Register a capability manifest.
    pub fn register(&mut self, manifest: CapabilityManifest) {
        self.capabilities.insert(manifest.id.clone(), manifest);
    }

    /// Look up a capability by ID.
    pub fn get(&self, id: &str) -> Option<&CapabilityManifest> {
        self.capabilities.get(id)
    }

    /// Return all registered manifests.
    pub fn all(&self) -> Vec<&CapabilityManifest> {
        self.capabilities.values().collect()
    }

    /// Return all manifests as a cloned `Vec` (useful for prompt building).
    pub fn all_cloned(&self) -> Vec<CapabilityManifest> {
        self.capabilities.values().cloned().collect()
    }

    /// Number of registered capabilities.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// `true` if no capabilities are registered.
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── CapabilityRequest ─────────────────────────────────────────────────────────

/// A parsed investigation-phase request from the LLM to invoke a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// The capability the LLM wants to invoke.
    pub capability_id: String,
    /// Arguments for the capability.
    pub args: serde_json::Value,
    /// The LLM's explanation for why it needs this invocation.
    pub reasoning: String,
}

/// Signals that the LLM is done with investigation and ready to plan.
#[derive(Debug, Clone)]
pub struct InvestigationComplete {
    pub reasoning: String,
}

/// The LLM's response during the investigation phase.
#[derive(Debug, Clone)]
pub enum InvestigationAction {
    /// Request a capability invocation.
    InvokeCapability(CapabilityRequest),
    /// Declare investigation complete and move to planning.
    Done(InvestigationComplete),
}

// ── CapabilityRequestParser ───────────────────────────────────────────────────

/// Parses LLM responses during the investigation phase.
pub struct CapabilityRequestParser;

impl CapabilityRequestParser {
    /// Parse an LLM response string into an [`InvestigationAction`].
    ///
    /// Accepts two JSON shapes:
    ///
    /// **Capability request:**
    /// ```json
    /// {"capability_id": "...", "args": {}, "reasoning": "..."}
    /// ```
    ///
    /// **Done investigating:**
    /// ```json
    /// {"done_investigating": true, "reasoning": "..."}
    /// ```
    pub fn parse(llm_response: &str) -> Result<InvestigationAction, AgentError> {
        let value = PlanParser::extract_json(llm_response)?;

        debug!("parsing investigation action from LLM response");

        // Check for done_investigating flag first.
        if let Some(done) = value.get("done_investigating") {
            if done.as_bool().unwrap_or(false) {
                let reasoning = value
                    .get("reasoning")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Investigation complete")
                    .to_string();
                return Ok(InvestigationAction::Done(InvestigationComplete { reasoning }));
            }
        }

        // Otherwise expect a capability request.
        let capability_id = value
            .get("capability_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AgentError::InvalidResponse(
                    "investigation response missing 'capability_id' field".to_string(),
                )
            })?
            .to_string();

        if capability_id.is_empty() {
            return Err(AgentError::InvalidResponse(
                "investigation response 'capability_id' is empty".to_string(),
            ));
        }

        let args = value
            .get("args")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let reasoning = value
            .get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(InvestigationAction::InvokeCapability(CapabilityRequest {
            capability_id,
            args,
            reasoning,
        }))
    }
}

// ── PlanParser ────────────────────────────────────────────────────────────────

/// Parses LLM planning responses into a [`Plan`].
pub struct PlanParser;

impl PlanParser {
    /// Parse LLM JSON output into a [`Plan`].
    ///
    /// Expected LLM JSON format:
    /// ```json
    /// {
    ///   "rationale": "string",
    ///   "steps": [
    ///     {
    ///       "capability_id": "string",
    ///       "args": {},
    ///       "description": "string",
    ///       "can_rollback": false,
    ///       "depends_on": []
    ///     }
    ///   ]
    /// }
    /// ```
    pub fn parse(
        session_id: Uuid,
        goal: &str,
        llm_response: &str,
        capability_registry: &CapabilityRegistry,
    ) -> Result<Plan, AgentError> {
        let value = Self::extract_json(llm_response)?;

        let rationale = value
            .get("rationale")
            .and_then(|v| v.as_str())
            .unwrap_or("No rationale provided")
            .to_string();

        let steps_value = value.get("steps").and_then(|v| v.as_array()).ok_or_else(|| {
            AgentError::InvalidResponse("plan JSON missing 'steps' array".to_string())
        })?;

        if steps_value.is_empty() {
            return Err(AgentError::InvalidResponse(
                "plan has no steps".to_string(),
            ));
        }

        let mut plan = Plan::new(session_id, goal.to_string(), rationale);

        for (i, step_value) in steps_value.iter().enumerate() {
            let capability_id = step_value
                .get("capability_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AgentError::InvalidResponse(format!(
                        "step {} missing 'capability_id' field",
                        i
                    ))
                })?
                .to_string();

            // Validate capability exists in registry.
            let manifest = capability_registry
                .get(&capability_id)
                .ok_or_else(|| AgentError::CapabilityNotFound(capability_id.clone()))?;

            let args = step_value
                .get("args")
                .cloned()
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

            let description = step_value
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or(&capability_id)
                .to_string();

            let can_rollback = step_value
                .get("can_rollback")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Clamp: can_rollback can only be true if the manifest supports it.
            let effective_can_rollback = can_rollback && manifest.has_inverse;
            if can_rollback && !manifest.has_inverse {
                warn!(
                    capability = %capability_id,
                    "LLM marked step as rollback-capable but manifest says no inverse exists; ignoring"
                );
            }

            let depends_on: Vec<u32> = step_value
                .get("depends_on")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u32))
                        .collect()
                })
                .unwrap_or_default();

            // Validate dependency indices are in range.
            for dep in &depends_on {
                if *dep >= i as u32 {
                    return Err(AgentError::InvalidResponse(format!(
                        "step {} has invalid dependency index {} (must be < {})",
                        i, dep, i
                    )));
                }
            }

            let step = PlanStep {
                id: Uuid::new_v4(),
                sequence: i as u32,
                capability_id,
                args,
                description,
                risk_tier: manifest.risk_tier,
                requires_approval: manifest.risk_tier >= RiskTier::High,
                can_rollback: effective_can_rollback,
                depends_on: Vec::new(), // index-based deps resolved by reasoning loop
                status: sentinel_core::StepStatus::Pending,
            };

            plan.add_step(step);
        }

        debug!(
            session_id = %session_id,
            step_count = plan.steps.len(),
            overall_risk = ?plan.overall_risk,
            "plan parsed successfully"
        );

        Ok(plan)
    }

    /// Extract a JSON value from an LLM response string.
    ///
    /// Handles:
    /// - Plain JSON objects/arrays
    /// - JSON wrapped in markdown code blocks (` ```json ... ``` ` or ` ``` ... ``` `)
    /// - JSON preceded or followed by prose (extracts the first `{...}` block)
    pub fn extract_json(response: &str) -> Result<serde_json::Value, AgentError> {
        let trimmed = response.trim();

        // Try parsing directly first (most common case when the LLM follows instructions).
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            return Ok(v);
        }

        // Try stripping markdown code fences.
        // Patterns: ```json\n...\n``` or ```\n...\n```
        if let Some(extracted) = Self::strip_code_fence(trimmed) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(extracted.trim()) {
                return Ok(v);
            }
        }

        // Last resort: find the first `{` and last `}` and try to parse that substring.
        if let Some(extracted) = Self::extract_braces(trimmed) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(extracted) {
                return Ok(v);
            }
        }

        Err(AgentError::InvalidResponse(format!(
            "could not extract JSON from LLM response (first 200 chars): {}",
            &response[..response.len().min(200)]
        )))
    }

    fn strip_code_fence(s: &str) -> Option<&str> {
        // Match ``` optionally followed by a language tag, then a newline.
        let fence_start = s.find("```")?;
        let after_fence = &s[fence_start + 3..];

        // Skip optional language tag on the same line.
        let content_start = after_fence.find('\n').map(|i| i + 1).unwrap_or(0);
        let content = &after_fence[content_start..];

        // Find closing fence.
        let fence_end = content.find("```")?;
        Some(&content[..fence_end])
    }

    fn extract_braces(s: &str) -> Option<&str> {
        let start = s.find('{')?;
        let end = s.rfind('}')?;
        if end >= start {
            Some(&s[start..=end])
        } else {
            None
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{CapabilityKind, RiskTier};

    fn make_registry() -> CapabilityRegistry {
        let mut registry = CapabilityRegistry::new();

        registry.register(CapabilityManifest {
            id: "disk_usage".to_string(),
            name: "Disk Usage".to_string(),
            description: "Check disk space usage".to_string(),
            kind: CapabilityKind::ReadOnly,
            risk_tier: RiskTier::Low,
            resource_impact: Default::default(),
            has_inverse: false,
            version: "1.0.0".to_string(),
        });

        registry.register(CapabilityManifest {
            id: "delete_files".to_string(),
            name: "Delete Files".to_string(),
            description: "Delete files matching a pattern".to_string(),
            kind: CapabilityKind::Mutating,
            risk_tier: RiskTier::High,
            resource_impact: Default::default(),
            has_inverse: true,
            version: "1.0.0".to_string(),
        });

        registry.register(CapabilityManifest {
            id: "restart_service".to_string(),
            name: "Restart Service".to_string(),
            description: "Restart a systemd service".to_string(),
            kind: sentinel_core::CapabilityKind::Mutating,
            risk_tier: RiskTier::Medium,
            resource_impact: Default::default(),
            has_inverse: false,
            version: "1.0.0".to_string(),
        });

        registry
    }

    // ── PlanParser::extract_json ──────────────────────────────────────────────

    #[test]
    fn extract_json_plain() {
        let response = r#"{"rationale": "test", "steps": []}"#;
        let v = PlanParser::extract_json(response).unwrap();
        assert_eq!(v["rationale"], "test");
    }

    #[test]
    fn extract_json_markdown_code_block_json() {
        let response = "Some preamble text.\n\n```json\n{\"key\": \"value\"}\n```\n\nTrailing text.";
        let v = PlanParser::extract_json(response).unwrap();
        assert_eq!(v["key"], "value");
    }

    #[test]
    fn extract_json_markdown_code_block_no_lang() {
        let response = "Here is the JSON:\n```\n{\"foo\": 42}\n```";
        let v = PlanParser::extract_json(response).unwrap();
        assert_eq!(v["foo"], 42);
    }

    #[test]
    fn extract_json_buried_in_prose() {
        let response = r#"I will now produce the plan. {"rationale": "fix it", "steps": []} Done."#;
        let v = PlanParser::extract_json(response).unwrap();
        assert_eq!(v["rationale"], "fix it");
    }

    #[test]
    fn extract_json_invalid() {
        let response = "This is not JSON at all.";
        assert!(PlanParser::extract_json(response).is_err());
    }

    // ── PlanParser::parse ─────────────────────────────────────────────────────

    #[test]
    fn parse_valid_plan() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        let llm_response = r#"{
            "rationale": "Check disk then clean up",
            "steps": [
                {
                    "capability_id": "disk_usage",
                    "args": {"path": "/"},
                    "description": "Check root disk usage",
                    "can_rollback": false,
                    "depends_on": []
                },
                {
                    "capability_id": "delete_files",
                    "args": {"pattern": "/var/log/*.gz"},
                    "description": "Delete old compressed logs",
                    "can_rollback": true,
                    "depends_on": [0]
                }
            ]
        }"#;

        let plan = PlanParser::parse(session_id, "Fix disk space", llm_response, &registry)
            .unwrap();

        assert_eq!(plan.session_id, session_id);
        assert_eq!(plan.goal, "Fix disk space");
        assert_eq!(plan.rationale, "Check disk then clean up");
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.overall_risk, RiskTier::High);
    }

    #[test]
    fn parse_plan_in_markdown_block() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        let llm_response = r#"Here is my plan:

```json
{
    "rationale": "Restart the service",
    "steps": [
        {
            "capability_id": "restart_service",
            "args": {"service": "nginx"},
            "description": "Restart nginx",
            "can_rollback": false,
            "depends_on": []
        }
    ]
}
```"#;

        let plan = PlanParser::parse(session_id, "Restart nginx", llm_response, &registry)
            .unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.overall_risk, RiskTier::Medium);
    }

    #[test]
    fn parse_plan_unknown_capability() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        let llm_response = r#"{
            "rationale": "test",
            "steps": [
                {
                    "capability_id": "nonexistent_cap",
                    "args": {},
                    "description": "This does not exist",
                    "can_rollback": false,
                    "depends_on": []
                }
            ]
        }"#;

        let err = PlanParser::parse(session_id, "test", llm_response, &registry).unwrap_err();
        assert!(matches!(err, AgentError::CapabilityNotFound(_)));
    }

    #[test]
    fn parse_plan_missing_steps() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        let llm_response = r#"{"rationale": "test"}"#;
        let err = PlanParser::parse(session_id, "test", llm_response, &registry).unwrap_err();
        assert!(matches!(err, AgentError::InvalidResponse(_)));
    }

    #[test]
    fn parse_plan_empty_steps() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        let llm_response = r#"{"rationale": "nothing to do", "steps": []}"#;
        let err = PlanParser::parse(session_id, "test", llm_response, &registry).unwrap_err();
        assert!(matches!(err, AgentError::InvalidResponse(_)));
    }

    #[test]
    fn parse_plan_rollback_clamped_when_no_inverse() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        // disk_usage has has_inverse: false, but LLM says can_rollback: true
        let llm_response = r#"{
            "rationale": "test",
            "steps": [
                {
                    "capability_id": "disk_usage",
                    "args": {},
                    "description": "Check disk",
                    "can_rollback": true,
                    "depends_on": []
                }
            ]
        }"#;

        let plan = PlanParser::parse(session_id, "test", llm_response, &registry).unwrap();
        // should be clamped to false since disk_usage has no inverse
        assert!(!plan.steps[0].can_rollback);
    }

    #[test]
    fn parse_plan_invalid_dependency_index() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();

        let llm_response = r#"{
            "rationale": "test",
            "steps": [
                {
                    "capability_id": "disk_usage",
                    "args": {},
                    "description": "Check disk",
                    "can_rollback": false,
                    "depends_on": [5]
                }
            ]
        }"#;

        let err = PlanParser::parse(session_id, "test", llm_response, &registry).unwrap_err();
        assert!(matches!(err, AgentError::InvalidResponse(_)));
    }

    // ── CapabilityRequestParser ───────────────────────────────────────────────

    #[test]
    fn parse_capability_request() {
        let response = r#"{"capability_id": "disk_usage", "args": {"path": "/"}, "reasoning": "Need disk info"}"#;
        let action = CapabilityRequestParser::parse(response).unwrap();
        assert!(matches!(action, InvestigationAction::InvokeCapability(_)));
        if let InvestigationAction::InvokeCapability(req) = action {
            assert_eq!(req.capability_id, "disk_usage");
            assert_eq!(req.args["path"], "/");
            assert_eq!(req.reasoning, "Need disk info");
        }
    }

    #[test]
    fn parse_capability_request_in_markdown() {
        let response = "```json\n{\"capability_id\": \"process_list\", \"args\": {}, \"reasoning\": \"Check processes\"}\n```";
        let action = CapabilityRequestParser::parse(response).unwrap();
        assert!(matches!(action, InvestigationAction::InvokeCapability(_)));
    }

    #[test]
    fn parse_done_investigating() {
        let response = r#"{"done_investigating": true, "reasoning": "I have enough info"}"#;
        let action = CapabilityRequestParser::parse(response).unwrap();
        assert!(matches!(action, InvestigationAction::Done(_)));
        if let InvestigationAction::Done(done) = action {
            assert_eq!(done.reasoning, "I have enough info");
        }
    }

    #[test]
    fn parse_done_investigating_false_is_capability_request() {
        let response = r#"{"done_investigating": false, "capability_id": "disk_usage", "args": {}, "reasoning": "need more"}"#;
        let action = CapabilityRequestParser::parse(response).unwrap();
        // done_investigating is false, so it should be treated as a capability request
        assert!(matches!(action, InvestigationAction::InvokeCapability(_)));
    }

    #[test]
    fn parse_capability_request_missing_id() {
        let response = r#"{"args": {}, "reasoning": "test"}"#;
        let err = CapabilityRequestParser::parse(response).unwrap_err();
        assert!(matches!(err, AgentError::InvalidResponse(_)));
    }

    #[test]
    fn parse_capability_request_default_args() {
        let response = r#"{"capability_id": "disk_usage", "reasoning": "no args"}"#;
        let action = CapabilityRequestParser::parse(response).unwrap();
        if let InvestigationAction::InvokeCapability(req) = action {
            assert!(req.args.is_object());
        }
    }

    // ── CapabilityRegistry ────────────────────────────────────────────────────

    #[test]
    fn registry_register_and_get() {
        let mut reg = CapabilityRegistry::new();
        assert!(reg.is_empty());

        reg.register(CapabilityManifest {
            id: "test_cap".into(),
            name: "Test".into(),
            description: "desc".into(),
            kind: CapabilityKind::ReadOnly,
            risk_tier: RiskTier::Low,
            resource_impact: Default::default(),
            has_inverse: false,
            version: "1.0.0".into(),
        });

        assert_eq!(reg.len(), 1);
        assert!(reg.get("test_cap").is_some());
        assert!(reg.get("nonexistent").is_none());
    }
}
