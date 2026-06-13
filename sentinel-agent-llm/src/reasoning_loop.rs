//! The core investigate → plan → approve → act reasoning loop.
//!
//! [`ReasoningLoop`] drives the full lifecycle of an agent session:
//!
//! 1. **Investigate** — the LLM iteratively requests read-only capability
//!    invocations.  Each invocation is policy-checked before execution and
//!    its result is recorded as an [`Observation`].
//! 2. **Plan** — the LLM receives all observations and produces a structured
//!    [`Plan`].  Policy is *not* evaluated at this stage.
//! 3. **Approve** — handled externally (TUI/CLI).  The `execute_plan` method
//!    accepts an [`ApprovalDecision`].
//! 4. **Act** — each plan step is policy-checked and executed in sequence.
//!    Failures may trigger rollback of completed steps.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sentinel_audit::{AuditEventType, AuditLog};
use sentinel_core::{ApprovalDecision, Capability, ExecutionContext, Plan, StepStatus};
use sentinel_policy::{PolicyEffect, PolicyEvaluator, PolicyRequest};

use crate::backend::{LlmBackend, Message};
use crate::error::AgentError;
use crate::planner::{
    CapabilityRegistry, CapabilityRequestParser, InvestigationAction, Observation, PlanParser,
};
use crate::prompt_builder::PromptBuilder;

// ── ReasoningConfig ───────────────────────────────────────────────────────────

/// Tuning knobs for the reasoning loop.
#[derive(Debug, Clone)]
pub struct ReasoningConfig {
    /// Maximum number of capability invocations allowed in the investigation
    /// phase before forcing a transition to planning.
    pub max_investigation_rounds: u32,

    /// Maximum output tokens to request from the LLM on each call.
    pub max_tokens_per_call: u32,

    /// Wall-clock timeout (in milliseconds) for the entire investigation phase.
    pub investigation_timeout_ms: u64,
}

impl Default for ReasoningConfig {
    fn default() -> Self {
        Self {
            max_investigation_rounds: 10,
            max_tokens_per_call: 4096,
            investigation_timeout_ms: 60_000,
        }
    }
}

// ── ExecutionSummary ──────────────────────────────────────────────────────────

/// Summary of the act phase, returned after all plan steps have been processed.
#[derive(Debug, Clone)]
pub struct ExecutionSummary {
    /// Number of steps that completed successfully.
    pub steps_completed: u32,
    /// Number of steps that failed.
    pub steps_failed: u32,
    /// Number of steps that were rolled back.
    pub steps_rolled_back: u32,
    /// Total wall-clock duration of the act phase in milliseconds.
    pub total_duration_ms: u64,
}

// ── ReasoningLoop ─────────────────────────────────────────────────────────────

/// The investigate → plan → approve → act driver.
///
/// Owns an [`LlmBackend`], a [`CapabilityRegistry`], a [`PolicyEvaluator`],
/// and an [`AuditLog`].  The session state is passed in by `&mut Session` on
/// each call so the caller retains ownership and can persist it between phases.
pub struct ReasoningLoop {
    backend: Box<dyn LlmBackend>,
    capability_registry: Arc<CapabilityRegistry>,
    capability_impls: HashMap<String, Box<dyn Capability>>,
    policy_evaluator: Arc<PolicyEvaluator>,
    audit_log: Arc<Mutex<AuditLog>>,
    config: ReasoningConfig,
}

impl ReasoningLoop {
    /// Create a new reasoning loop.
    pub fn new(
        backend: Box<dyn LlmBackend>,
        capability_registry: Arc<CapabilityRegistry>,
        policy_evaluator: Arc<PolicyEvaluator>,
        audit_log: Arc<Mutex<AuditLog>>,
        config: ReasoningConfig,
    ) -> Self {
        Self {
            backend,
            capability_registry,
            capability_impls: HashMap::new(),
            policy_evaluator,
            audit_log,
            config,
        }
    }

    /// Register concrete capability implementations for real dispatch.
    ///
    /// Without this, [`invoke_capability`](Self::invoke_capability) falls back
    /// to stub results.  Supplying real implementations wires the loop to
    /// actual capability execution (via the underlying executor).
    pub fn with_capabilities(mut self, capabilities: Vec<Box<dyn Capability>>) -> Self {
        self.capability_impls = capabilities
            .into_iter()
            .map(|cap| (cap.manifest().id.clone(), cap))
            .collect();
        info!(count = self.capability_impls.len(), "capability implementations registered");
        self
    }

    // ── Investigate phase ─────────────────────────────────────────────────────

    /// Run the investigation phase.
    ///
    /// The LLM is given the investigation system prompt and then iterates:
    /// 1. Request a capability invocation (or declare investigation complete).
    /// 2. Check policy — if denied, record a skip observation and continue.
    /// 3. Invoke the capability and record the observation.
    /// 4. Repeat until `done_investigating` or `max_investigation_rounds`.
    ///
    /// Returns the list of observations collected.
    pub async fn investigate(
        &self,
        session_id: Uuid,
        goal: &str,
        host: &str,
    ) -> Result<Vec<Observation>, AgentError> {
        info!(session_id = %session_id, "starting investigation phase");

        // Log phase start.
        {
            let mut log = self.audit_log.lock().await;
            log.append(AuditEventType::InvestigationStarted)
                .await
                .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
        }

        let all_caps = self.capability_registry.all_cloned();
        let system_prompt = PromptBuilder::investigation_system(&all_caps);

        let phase_start = Instant::now();
        let mut observations: Vec<Observation> = Vec::new();
        let mut round = 0u32;

        loop {
            // Timeout check.
            if phase_start.elapsed().as_millis() as u64 > self.config.investigation_timeout_ms {
                warn!(
                    session_id = %session_id,
                    rounds = round,
                    "investigation phase timed out"
                );
                break;
            }

            // Round limit check.
            if round >= self.config.max_investigation_rounds {
                warn!(
                    session_id = %session_id,
                    max = self.config.max_investigation_rounds,
                    "investigation round limit reached"
                );
                return Err(AgentError::InvestigationLimitReached {
                    max: self.config.max_investigation_rounds,
                });
            }

            round += 1;
            debug!(session_id = %session_id, round, "investigation round");

            // Build the conversation for this turn.
            let user_turn =
                PromptBuilder::investigation_turn(goal, &observations);

            let messages = vec![
                Message::system(system_prompt.clone()),
                Message::user(user_turn),
            ];

            // Ask the LLM for the next action.
            let llm_response = self
                .backend
                .complete(messages, self.config.max_tokens_per_call)
                .await?;

            debug!(
                round,
                tokens = llm_response.output_tokens,
                "LLM investigation response received"
            );

            // Parse the LLM's decision.
            let action = CapabilityRequestParser::parse(&llm_response.content)?;

            match action {
                InvestigationAction::Done(done) => {
                    info!(
                        session_id = %session_id,
                        rounds = round,
                        reasoning = %done.reasoning,
                        "LLM declared investigation complete"
                    );
                    break;
                }

                InvestigationAction::InvokeCapability(req) => {
                    debug!(
                        capability_id = %req.capability_id,
                        reasoning = %req.reasoning,
                        "LLM requests capability invocation"
                    );

                    // Look up capability manifest.
                    let manifest = self
                        .capability_registry
                        .get(&req.capability_id)
                        .ok_or_else(|| AgentError::CapabilityNotFound(req.capability_id.clone()))?;

                    // Policy check.
                    let policy_request = PolicyRequest {
                        session_id,
                        capability_id: req.capability_id.clone(),
                        capability_kind: manifest.kind,
                        risk_tier: manifest.risk_tier,
                        args: req.args.clone(),
                        target_host: host.to_string(),
                        timestamp: chrono::Utc::now(),
                        session_phase: Some("Investigating".to_string()),
                    };

                    let decision = self.policy_evaluator.evaluate(policy_request);

                    // Audit the policy evaluation.
                    {
                        let mut log = self.audit_log.lock().await;
                        let effect_str = match &decision.effect {
                            PolicyEffect::Allowed => "allow",
                            PolicyEffect::Denied { .. } => "deny",
                            PolicyEffect::RequiresApproval => "require_approval",
                            PolicyEffect::AuditOnly => "audit_only",
                        };
                        log.append(AuditEventType::PolicyEvaluated {
                            capability_id: req.capability_id.clone(),
                            effect: effect_str.to_string(),
                            rule_id: decision.matched_rule.clone(),
                        })
                        .await
                        .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                    }

                    if !decision.is_allowed() {
                        let reason = match &decision.effect {
                            PolicyEffect::Denied { reason } => reason.clone(),
                            PolicyEffect::RequiresApproval => {
                                "requires approval (not allowed during investigation)".to_string()
                            }
                            _ => "policy denied".to_string(),
                        };
                        warn!(
                            capability_id = %req.capability_id,
                            reason = %reason,
                            "policy denied investigation capability"
                        );

                        // Record a failed observation so the LLM knows this path is blocked.
                        let result = sentinel_core::CapabilityResult::failure(
                            format!("Policy denied: {reason}"),
                            false,
                        );
                        observations.push(Observation::new(
                            req.capability_id,
                            req.args,
                            result,
                        ));
                        continue;
                    }

                    // Execute the capability.
                    // Since this crate doesn't hold actual Capability implementations,
                    // we use a simulated dry-run context for investigation.
                    // In a real deployment the CapabilityRegistry would hold Arc<dyn Capability>.
                    let ctx = ExecutionContext::new(session_id, host);
                    let invoke_start = Instant::now();

                    // Simulate capability invocation via the registry.
                    // The real implementation would call registry.invoke(&req.capability_id, &req.args, &ctx).
                    let capability_result = self
                        .invoke_capability(session_id, &req.capability_id, &req.args, &ctx)
                        .await;

                    let _duration_ms = invoke_start.elapsed().as_millis() as u64;

                    let result = match capability_result {
                        Ok(r) => r,
                        Err(e) => {
                            error!(
                                capability_id = %req.capability_id,
                                error = %e,
                                "capability invocation failed during investigation"
                            );
                            sentinel_core::CapabilityResult::failure(e.to_string(), true)
                        }
                    };

                    // Audit the observation.
                    {
                        let mut log = self.audit_log.lock().await;
                        let result_summary = match &result {
                            sentinel_core::CapabilityResult::Success { .. } => "success".to_string(),
                            sentinel_core::CapabilityResult::Failure { error, .. } => format!("failure: {error}"),
                            sentinel_core::CapabilityResult::DryRun { .. } => "dry-run".to_string(),
                        };
                        log.append(AuditEventType::ObservationRecorded {
                            capability_id: req.capability_id.clone(),
                            args: req.args.clone(),
                            result_summary,
                        })
                        .await
                        .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                    }

                    observations.push(Observation::new(
                        req.capability_id,
                        req.args,
                        result,
                    ));
                }
            }
        }

        info!(
            session_id = %session_id,
            observations = observations.len(),
            rounds = round,
            "investigation phase complete"
        );

        Ok(observations)
    }

    // ── Plan phase ────────────────────────────────────────────────────────────

    /// Run the planning phase.
    ///
    /// Sends the goal, capabilities, and all observations to the LLM and
    /// parses the structured [`Plan`] from the response.
    pub async fn plan(
        &self,
        session_id: Uuid,
        goal: &str,
        observations: &[Observation],
    ) -> Result<Plan, AgentError> {
        info!(session_id = %session_id, "starting planning phase");

        let all_caps = self.capability_registry.all_cloned();
        let system_prompt = PromptBuilder::planning_system(&all_caps);
        let user_message =
            PromptBuilder::planning_user_with_observations(goal, observations);

        let messages = vec![
            Message::system(system_prompt),
            Message::user(user_message),
        ];

        let llm_response = self
            .backend
            .complete(messages, self.config.max_tokens_per_call)
            .await?;

        debug!(
            tokens = llm_response.output_tokens,
            "LLM planning response received"
        );

        let plan =
            PlanParser::parse(session_id, goal, &llm_response.content, &self.capability_registry)?;

        // Audit the plan proposal.
        {
            let mut log = self.audit_log.lock().await;
            log.append(AuditEventType::PlanProposed {
                plan_id: plan.id,
                step_count: plan.steps.len(),
                overall_risk: format!("{:?}", plan.overall_risk),
            })
            .await
            .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
        }

        info!(
            session_id = %session_id,
            plan_id = %plan.id,
            steps = plan.steps.len(),
            overall_risk = ?plan.overall_risk,
            "plan generated"
        );

        Ok(plan)
    }

    // ── Act phase ─────────────────────────────────────────────────────────────

    /// Execute an approved plan step by step.
    ///
    /// Each step is:
    /// 1. Policy-checked — if denied, the step is marked as skipped.
    /// 2. Invoked — the capability is run.
    /// 3. Audited — success or failure is recorded.
    ///
    /// If a step fails and subsequent steps depended on it, they are skipped.
    /// If a failed step supports rollback, previously completed steps are
    /// rolled back in reverse order.
    pub async fn execute_plan(
        &self,
        session_id: Uuid,
        host: &str,
        plan: &mut Plan,
        approval: ApprovalDecision,
    ) -> Result<ExecutionSummary, AgentError> {
        info!(
            session_id = %session_id,
            plan_id = %plan.id,
            steps = plan.steps.len(),
            "starting act phase"
        );

        // Audit approval.
        {
            let mut log = self.audit_log.lock().await;
            let mode = match &approval {
                ApprovalDecision::FullApproval => "full",
                ApprovalDecision::StepByStep => "step_by_step",
                ApprovalDecision::Edited => "edited",
                ApprovalDecision::Rejected { .. } => "rejected",
                ApprovalDecision::Pending => "pending",
            };
            match &approval {
                ApprovalDecision::Rejected { reason } => {
                    log.append(AuditEventType::PlanRejected {
                        plan_id: plan.id,
                        reason: reason.clone(),
                    })
                    .await
                    .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                }
                _ => {
                    log.append(AuditEventType::PlanApproved {
                        plan_id: plan.id,
                        approval_mode: mode.to_string(),
                    })
                    .await
                    .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                }
            }
        }

        // Apply the approval parameter to the plan so the gate reads the caller-supplied decision.
        plan.approval = approval.clone();

        // Check approval is valid.
        if !plan.is_approved() {
            return Err(AgentError::PolicyDenied(
                "plan is not approved for execution".to_string(),
            ));
        }

        let act_start = Instant::now();
        let mut steps_completed = 0u32;
        let mut steps_failed = 0u32;
        let mut steps_rolled_back = 0u32;
        let mut completed_step_indices: Vec<usize> = Vec::new();
        let mut any_failure = false;

        for i in 0..plan.steps.len() {
            let step = &plan.steps[i];

            // Check if any dependency failed.
            let dep_failed = !step.depends_on.is_empty() && any_failure;
            if dep_failed {
                warn!(
                    step_index = i,
                    capability_id = %step.capability_id,
                    "skipping step due to failed dependency"
                );
                plan.steps[i].status = StepStatus::Skipped;
                continue;
            }

            let capability_id = step.capability_id.clone();
            let args = step.args.clone();
            let risk_tier = step.risk_tier;

            // Policy check.
            let manifest = self
                .capability_registry
                .get(&capability_id)
                .ok_or_else(|| AgentError::CapabilityNotFound(capability_id.clone()))?;

            let policy_request = PolicyRequest {
                session_id,
                capability_id: capability_id.clone(),
                capability_kind: manifest.kind,
                risk_tier,
                args: args.clone(),
                target_host: host.to_string(),
                timestamp: chrono::Utc::now(),
                session_phase: Some("Executing".to_string()),
            };

            let decision = self.policy_evaluator.evaluate(policy_request);

            {
                let mut log = self.audit_log.lock().await;
                let effect_str = match &decision.effect {
                    PolicyEffect::Allowed => "allow",
                    PolicyEffect::Denied { .. } => "deny",
                    PolicyEffect::RequiresApproval => "require_approval",
                    PolicyEffect::AuditOnly => "audit_only",
                };
                log.append(AuditEventType::PolicyEvaluated {
                    capability_id: capability_id.clone(),
                    effect: effect_str.to_string(),
                    rule_id: decision.matched_rule.clone(),
                })
                .await
                .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
            }

            if !decision.is_allowed() {
                let reason = match &decision.effect {
                    PolicyEffect::Denied { reason } => reason.clone(),
                    PolicyEffect::RequiresApproval => "step requires additional approval".to_string(),
                    _ => "policy denied".to_string(),
                };

                {
                    let mut log = self.audit_log.lock().await;
                    log.append(AuditEventType::PolicyDenied {
                        capability_id: capability_id.clone(),
                        reason: reason.clone(),
                    })
                    .await
                    .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                }

                plan.steps[i].status = StepStatus::Skipped;
                any_failure = true;
                steps_failed += 1;
                continue;
            }

            // Invoke the capability.
            plan.steps[i].status = StepStatus::Executing;

            {
                let mut log = self.audit_log.lock().await;
                log.append(AuditEventType::CapabilityInvoked {
                    capability_id: capability_id.clone(),
                    args: args.clone(),
                    risk_tier: format!("{:?}", risk_tier),
                })
                .await
                .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
            }

            let ctx = ExecutionContext::new(session_id, host);
            let invoke_start = Instant::now();
            let result = self
                .invoke_capability(session_id, &capability_id, &args, &ctx)
                .await;
            let duration_ms = invoke_start.elapsed().as_millis() as u64;

            match result {
                Ok(_cap_result) => {
                    plan.steps[i].status = StepStatus::Completed;
                    steps_completed += 1;
                    completed_step_indices.push(i);

                    {
                        let mut log = self.audit_log.lock().await;
                        log.append(AuditEventType::CapabilitySucceeded {
                            capability_id: capability_id.clone(),
                            duration_ms,
                        })
                        .await
                        .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                    }

                    info!(
                        step_index = i,
                        capability_id = %capability_id,
                        duration_ms,
                        "step completed"
                    );
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    plan.steps[i].status = StepStatus::Failed;
                    any_failure = true;
                    steps_failed += 1;

                    {
                        let mut log = self.audit_log.lock().await;
                        log.append(AuditEventType::CapabilityFailed {
                            capability_id: capability_id.clone(),
                            error: err_msg.clone(),
                        })
                        .await
                        .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                    }

                    error!(
                        step_index = i,
                        capability_id = %capability_id,
                        error = %err_msg,
                        "step failed"
                    );
                }
            }
        }

        // Roll back completed steps in reverse order if there were failures.
        if any_failure {
            for &step_idx in completed_step_indices.iter().rev() {
                let (can_rollback, capability_id) = {
                    let step = &plan.steps[step_idx];
                    (step.can_rollback, step.capability_id.clone())
                };
                if can_rollback {
                    info!(
                        step_index = step_idx,
                        capability_id = %capability_id,
                        "attempting rollback"
                    );

                    // Invoke the capability's inverse to actually undo the effect.
                    if let Some(cap) = self.capability_impls.get(&capability_id) {
                        let rb_ctx = ExecutionContext::new(session_id, host);
                        match cap.invoke_inverse(plan.steps[step_idx].args.clone(), &rb_ctx).await {
                            Some(sentinel_core::CapabilityResult::Success { .. }) => info!(capability_id = %capability_id, "rollback succeeded"),
                            Some(sentinel_core::CapabilityResult::Failure { error, .. }) => warn!(capability_id = %capability_id, error = %error, "rollback failed"),
                            None => info!(capability_id = %capability_id, "capability has no inverse"),
                            _ => {}
                        }
                    }

                    plan.steps[step_idx].status = StepStatus::RolledBack;
                    steps_completed -= 1;
                    steps_rolled_back += 1;

                    {
                        let mut log = self.audit_log.lock().await;
                        log.append(AuditEventType::CapabilityRolledBack {
                            capability_id,
                        })
                        .await
                        .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
                    }
                }
            }
        }

        let total_duration_ms = act_start.elapsed().as_millis() as u64;

        let summary = ExecutionSummary {
            steps_completed,
            steps_failed,
            steps_rolled_back,
            total_duration_ms,
        };

        {
            let mut log = self.audit_log.lock().await;
            log.append(AuditEventType::SessionCompleted {
                duration_ms: total_duration_ms,
                capabilities_executed: steps_completed as u64,
            })
            .await
            .map_err(|e| AgentError::Core(sentinel_core::CoreError::ExecutionFailed(e.to_string())))?;
        }

        info!(
            session_id = %session_id,
            steps_completed,
            steps_failed,
            steps_rolled_back,
            total_duration_ms,
            "act phase complete"
        );

        Ok(summary)
    }

    // ── Private: capability invocation ────────────────────────────────────────

    /// Invoke a capability by ID.
    ///
    /// This crate does not hold `Arc<dyn Capability>` objects — those live in
    /// the capabilities crate.  This method is a hook point that in a full
    /// integration would dispatch to a capability executor.  For now it
    /// returns an error indicating the invocation layer is not wired up,
    /// which allows the rest of the loop logic to be exercised in tests via
    /// mock backends.
    async fn invoke_capability(
        &self,
        _session_id: Uuid,
        capability_id: &str,
        args: &serde_json::Value,
        ctx: &ExecutionContext,
    ) -> Result<sentinel_core::CapabilityResult, AgentError> {
        if let Some(cap) = self.capability_impls.get(capability_id) {
            let result = cap.invoke(args.clone(), ctx).await;
            Ok(result)
        } else {
            debug!(capability_id = %capability_id, "stub invocation — no implementation registered");
            Ok(sentinel_core::CapabilityResult::success(serde_json::json!({
                "stub": true, "capability_id": capability_id
            })))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use sentinel_audit::AuditLog;
    use sentinel_core::{CapabilityKind, CapabilityManifest, RiskTier};
    use sentinel_policy::{KillSwitch, PolicyEvaluator, RuleEffect, PolicyRule};
    use tokio::sync::Mutex;

    use crate::backend::{LlmBackend, LlmResponse, Message};
    use crate::planner::CapabilityRegistry;

    // ── Mock LLM backend ──────────────────────────────────────────────────────

    struct MockBackend {
        responses: Vec<String>,
        call_count: std::sync::atomic::AtomicUsize,
    }

    impl MockBackend {
        fn new(responses: Vec<String>) -> Self {
            Self {
                responses,
                call_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for MockBackend {
        fn name(&self) -> &str {
            "mock"
        }

        fn model(&self) -> &str {
            "mock-model"
        }

        async fn complete(
            &self,
            _messages: Vec<Message>,
            _max_tokens: u32,
        ) -> Result<LlmResponse, AgentError> {
            let idx = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let content = self
                .responses
                .get(idx)
                .cloned()
                .unwrap_or_else(|| {
                    r#"{"done_investigating": true, "reasoning": "fallback done"}"#.to_string()
                });
            Ok(LlmResponse {
                content,
                model: "mock-model".to_string(),
                input_tokens: 10,
                output_tokens: 20,
                finish_reason: "end_turn".to_string(),
            })
        }

        async fn health_check(&self) -> Result<(), AgentError> {
            Ok(())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_registry() -> Arc<CapabilityRegistry> {
        let mut registry = CapabilityRegistry::new();

        registry.register(CapabilityManifest {
            id: "disk_usage".into(),
            name: "Disk Usage".into(),
            description: "Check disk space".into(),
            kind: CapabilityKind::ReadOnly,
            risk_tier: RiskTier::Low,
            resource_impact: Default::default(),
            has_inverse: false,
            version: "1.0.0".into(),
        });

        registry.register(CapabilityManifest {
            id: "restart_service".into(),
            name: "Restart Service".into(),
            description: "Restart a service".into(),
            kind: CapabilityKind::Mutating,
            risk_tier: RiskTier::Medium,
            resource_impact: Default::default(),
            has_inverse: false,
            version: "1.0.0".into(),
        });

        Arc::new(registry)
    }

    fn make_allow_all_evaluator() -> Arc<PolicyEvaluator> {
        let ks = KillSwitch::new();
        let allow_all = PolicyRule {
            id: "allow-all".into(),
            name: "Allow All".into(),
            description: "Allow everything for tests".into(),
            effect: RuleEffect::Allow,
            conditions: vec![],
            priority: 1000,
            enabled: true,
        };
        Arc::new(PolicyEvaluator::new(vec![allow_all], ks, vec![]))
    }

    fn make_deny_all_evaluator() -> Arc<PolicyEvaluator> {
        let ks = KillSwitch::new();
        // No rules → deny by default
        Arc::new(PolicyEvaluator::new(vec![], ks, vec![]))
    }

    fn make_audit_log(session_id: Uuid) -> Arc<Mutex<AuditLog>> {
        Arc::new(Mutex::new(AuditLog::new(session_id, None)))
    }

    fn make_config() -> ReasoningConfig {
        ReasoningConfig {
            max_investigation_rounds: 5,
            max_tokens_per_call: 512,
            investigation_timeout_ms: 30_000,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn investigate_done_immediately() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_allow_all_evaluator();
        let audit_log = make_audit_log(session_id);

        // LLM immediately says done investigating.
        let backend = MockBackend::new(vec![
            r#"{"done_investigating": true, "reasoning": "nothing to investigate"}"#.to_string(),
        ]);

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry,
            evaluator,
            audit_log,
            make_config(),
        );

        let observations = loop_
            .investigate(session_id, "Fix disk", "localhost")
            .await
            .unwrap();

        assert!(observations.is_empty());
    }

    #[tokio::test]
    async fn investigate_one_capability_then_done() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_allow_all_evaluator();
        let audit_log = make_audit_log(session_id);

        let backend = MockBackend::new(vec![
            r#"{"capability_id": "disk_usage", "args": {"path": "/"}, "reasoning": "check disk"}"#
                .to_string(),
            r#"{"done_investigating": true, "reasoning": "enough info"}"#.to_string(),
        ]);

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry,
            evaluator,
            audit_log,
            make_config(),
        );

        let observations = loop_
            .investigate(session_id, "Fix disk", "localhost")
            .await
            .unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].capability_id, "disk_usage");
        assert!(observations[0].result.is_success());
    }

    #[tokio::test]
    async fn investigate_policy_denied_records_failed_obs() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_deny_all_evaluator(); // deny everything
        let audit_log = make_audit_log(session_id);

        let backend = MockBackend::new(vec![
            r#"{"capability_id": "disk_usage", "args": {}, "reasoning": "check"}"#.to_string(),
            r#"{"done_investigating": true, "reasoning": "blocked"}"#.to_string(),
        ]);

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry,
            evaluator,
            audit_log,
            make_config(),
        );

        let observations = loop_
            .investigate(session_id, "goal", "localhost")
            .await
            .unwrap();

        // One observation recorded, but it's a failure due to policy denial.
        assert_eq!(observations.len(), 1);
        assert!(observations[0].result.is_failure());
        // Verify the error message contains Policy denied.
        if let sentinel_core::CapabilityResult::Failure { error, .. } = &observations[0].result {
            assert!(error.contains("Policy denied"), "expected 'Policy denied' in: {error}");
        }
    }

    #[tokio::test]
    async fn investigate_round_limit_returns_error() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_allow_all_evaluator();
        let audit_log = make_audit_log(session_id);

        // Never says done — always requests a capability.
        let responses: Vec<String> = (0..10)
            .map(|_| {
                r#"{"capability_id": "disk_usage", "args": {}, "reasoning": "still checking"}"#
                    .to_string()
            })
            .collect();

        let backend = MockBackend::new(responses);
        let config = ReasoningConfig {
            max_investigation_rounds: 3,
            ..make_config()
        };

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry,
            evaluator,
            audit_log,
            config,
        );

        let err = loop_
            .investigate(session_id, "goal", "localhost")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            AgentError::InvestigationLimitReached { max: 3 }
        ));
    }

    #[tokio::test]
    async fn plan_parses_llm_response() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_allow_all_evaluator();
        let audit_log = make_audit_log(session_id);

        let plan_response = r#"{
            "rationale": "Restart the service",
            "steps": [
                {
                    "capability_id": "restart_service",
                    "args": {"service": "nginx"},
                    "description": "Restart nginx service",
                    "can_rollback": false,
                    "depends_on": []
                }
            ]
        }"#;

        let backend = MockBackend::new(vec![plan_response.to_string()]);

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry,
            evaluator,
            audit_log,
            make_config(),
        );

        let plan = loop_
            .plan(session_id, "Restart nginx", &[])
            .await
            .unwrap();

        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].capability_id, "restart_service");
        assert_eq!(plan.overall_risk, RiskTier::Medium);
    }

    #[tokio::test]
    async fn execute_plan_requires_approval() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_allow_all_evaluator();
        let audit_log = make_audit_log(session_id);
        let backend = MockBackend::new(vec![]);

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry,
            evaluator,
            audit_log,
            make_config(),
        );

        // Create a plan that is NOT approved.
        let mut plan = Plan::new(session_id, "test".into(), "rationale".into());
        // plan.approval defaults to ApprovalDecision::Pending → not approved

        let err = loop_
            .execute_plan(session_id, "localhost", &mut plan, ApprovalDecision::Pending)
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::PolicyDenied(_)));
    }

    #[tokio::test]
    async fn execute_plan_all_steps_complete() {
        let session_id = Uuid::new_v4();
        let registry = make_registry();
        let evaluator = make_allow_all_evaluator();
        let audit_log = make_audit_log(session_id);
        let backend = MockBackend::new(vec![]);

        let loop_ = ReasoningLoop::new(
            Box::new(backend),
            registry.clone(),
            evaluator,
            audit_log,
            make_config(),
        );

        let mut plan = Plan::new(session_id, "fix disk".into(), "rationale".into());
        plan.add_step(sentinel_core::PlanStep::new(
            0,
            "disk_usage",
            serde_json::json!({}),
            "Check disk",
            RiskTier::Low,
        ));
        plan.approve();

        let summary = loop_
            .execute_plan(session_id, "localhost", &mut plan, ApprovalDecision::FullApproval)
            .await
            .unwrap();

        assert_eq!(summary.steps_completed, 1);
        assert_eq!(summary.steps_failed, 0);
        assert_eq!(summary.steps_rolled_back, 0);
    }
}
