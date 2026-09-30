//! The policy gate: tool implementations exposed to MCP clients.
//!
//! The gate exposes exactly five tools.  None of them can approve or execute
//! a plan:
//!
//! | Tool                     | Effect on the host                         |
//! |--------------------------|--------------------------------------------|
//! | `sentinel_capabilities`  | none (manifest listing)                    |
//! | `sentinel_policy_check`  | none (dry policy evaluation)               |
//! | `sentinel_investigate`   | runs one **read-only** capability          |
//! | `sentinel_propose_plan`  | writes a `PendingApproval` plan to the store |
//! | `sentinel_plan_status`   | none (reads the store)                     |
//!
//! Every `tools/call` is recorded as [`AuditEventType::McpToolCalled`] before
//! dispatch, followed by the policy / capability events it produced.  If the
//! audit write fails the call fails closed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use uuid::Uuid;

use sentinel_audit::AuditEventType;
use sentinel_core::{
    Capability, CapabilityKind, CapabilityResult, ExecutionContext, Plan, PlanStep,
};
use sentinel_policy::{PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyRequest};

use crate::audit::AuditSink;
use crate::store::{PlanStore, StoreError, StoredPlan};

/// Capability implementations indexed by id.
pub type CapabilitySet = BTreeMap<String, Box<dyn Capability>>;

/// Index a list of capabilities by manifest id.
pub fn index_capabilities(caps: Vec<Box<dyn Capability>>) -> CapabilitySet {
    caps.into_iter()
        .map(|c| (c.manifest().id.clone(), c))
        .collect()
}

/// Names of every tool the gate exposes.  There is intentionally no approve
/// or execute tool; see ADR-013.
pub const TOOL_NAMES: [&str; 5] = [
    "sentinel_capabilities",
    "sentinel_policy_check",
    "sentinel_investigate",
    "sentinel_propose_plan",
    "sentinel_plan_status",
];

/// Gate configuration.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Root of the plan store and audit logs.
    pub state_dir: PathBuf,
    /// Host label used in policy requests and execution contexts.
    pub host: String,
    /// Upper bound on steps in a proposed plan.
    pub max_plan_steps: usize,
    /// Wall-clock budget for one `sentinel_investigate` call.
    pub investigate_timeout_ms: u64,
}

impl GateConfig {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            host: "localhost".into(),
            max_plan_steps: 16,
            investigate_timeout_ms: 30_000,
        }
    }
}

/// Result of a tool call: MCP `isError` plus a JSON body.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    pub is_error: bool,
    pub body: Value,
}

impl ToolOutcome {
    fn ok(body: Value) -> Self {
        Self {
            is_error: false,
            body,
        }
    }

    fn err(message: impl Into<String>, extra: Value) -> Self {
        let mut body = json!({ "error": message.into() });
        if let (Some(obj), Value::Object(extra)) = (body.as_object_mut(), extra) {
            obj.extend(extra);
        }
        Self {
            is_error: true,
            body,
        }
    }
}

/// Returned when a client calls a tool name the gate does not expose.
#[derive(Debug, thiserror::Error)]
#[error("unknown tool: {0}")]
pub struct UnknownTool(pub String);

/// Errors constructing a gate.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("audit log setup failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Agent-facing policy gate.
pub struct Gate {
    caps: CapabilitySet,
    policy: PolicyEvaluator,
    audit: AuditSink,
    store: PlanStore,
    config: GateConfig,
}

pub(crate) fn effect_label(effect: &PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allowed => "allow",
        PolicyEffect::Denied { .. } => "deny",
        PolicyEffect::RequiresApproval => "require_approval",
        PolicyEffect::AuditOnly => "audit_only",
    }
}

fn decision_json(d: &PolicyDecision) -> Value {
    json!({
        "decision": effect_label(&d.effect),
        "allowed_without_approval": d.is_allowed(),
        "matched_rule": d.matched_rule,
        "rationale": d.rationale,
        "reason": match &d.effect {
            PolicyEffect::Denied { reason } => Some(reason.clone()),
            _ => None,
        },
    })
}

fn kind_label(kind: CapabilityKind) -> &'static str {
    match kind {
        CapabilityKind::ReadOnly => "ReadOnly",
        CapabilityKind::Mutating => "Mutating",
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn obj_arg(args: &Value, key: &str) -> Result<Value, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(json!({})),
        Some(v @ Value::Object(_)) => Ok(v.clone()),
        Some(_) => Err(format!("'{key}' must be a JSON object")),
    }
}

fn summarize(result: &CapabilityResult) -> String {
    let s = match result {
        CapabilityResult::Success { output } => format!("success: {output}"),
        CapabilityResult::Failure { error, .. } => format!("failure: {error}"),
        CapabilityResult::DryRun { predicted_effect } => format!("dry_run: {predicted_effect}"),
    };
    // Keep audit entries bounded; full output goes back to the caller only.
    if s.len() > 256 {
        let mut cut = 256;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    } else {
        s
    }
}

impl Gate {
    /// Build a gate over the given capabilities and policy.  Creates the
    /// plan store and a fresh `mcp-<session>.jsonl` audit log.
    pub fn new(
        config: GateConfig,
        caps: Vec<Box<dyn Capability>>,
        policy: PolicyEvaluator,
    ) -> Result<Self, GateError> {
        let store = PlanStore::open(&config.state_dir)?;
        let audit = AuditSink::create(&config.state_dir, "mcp")?;
        Ok(Self {
            caps: index_capabilities(caps),
            policy,
            audit,
            store,
            config,
        })
    }

    pub fn session_id(&self) -> Uuid {
        self.audit.session_id()
    }

    pub fn audit(&self) -> &AuditSink {
        &self.audit
    }

    pub fn store(&self) -> &PlanStore {
        &self.store
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// MCP `tools/list` payload.
    pub fn tool_definitions(&self) -> Vec<Value> {
        let cap_ids: Vec<&String> = self.caps.keys().collect();
        let max_steps = self.config.max_plan_steps;
        vec![
            json!({
                "name": "sentinel_capabilities",
                "title": "List Sentinel capabilities",
                "description": "List every capability Sentinel can run, with kind (ReadOnly/Mutating) and risk tier. Only ReadOnly capabilities can be run via sentinel_investigate; everything else must go through sentinel_propose_plan and out-of-band operator approval.",
                "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
                "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
            }),
            json!({
                "name": "sentinel_policy_check",
                "title": "Dry-run a policy decision",
                "description": "Evaluate a proposed capability request against Sentinel's deny-by-default policy WITHOUT executing it. Returns allow / deny / require_approval / audit_only plus the matching rule. Unknown capabilities are denied.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "capability_id": { "type": "string", "description": "Capability id, e.g. one of the ids returned by sentinel_capabilities", "examples": cap_ids },
                        "args": { "type": "object", "description": "Arguments the capability would be called with" },
                        "phase": { "type": "string", "enum": ["Investigating", "Executing"], "default": "Executing" }
                    },
                    "required": ["capability_id"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
            }),
            json!({
                "name": "sentinel_investigate",
                "title": "Run a read-only capability",
                "description": "Execute ONE read-only capability (e.g. disk_usage, process_list, system_metrics) after a policy check, and return its output. Mutating capabilities are refused. The call and its result are recorded in Sentinel's hash-chained audit log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "capability_id": { "type": "string" },
                        "args": { "type": "object" }
                    },
                    "required": ["capability_id"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false }
            }),
            json!({
                "name": "sentinel_propose_plan",
                "title": "Propose a plan for operator approval",
                "description": "Validate and store a multi-step plan. NEVER executes anything. Returns a plan_id in status PendingApproval. A human operator must approve it out-of-band (`sentinel approve <plan_id>`) and then run it (`sentinel execute <plan_id>`); this server has no way to approve or execute plans. Plans containing any policy-denied step are refused.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "goal": { "type": "string", "minLength": 1 },
                        "rationale": { "type": "string" },
                        "steps": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": max_steps,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "capability_id": { "type": "string" },
                                    "args": { "type": "object" },
                                    "description": { "type": "string" }
                                },
                                "required": ["capability_id"],
                                "additionalProperties": false
                            }
                        }
                    },
                    "required": ["goal", "steps"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false }
            }),
            json!({
                "name": "sentinel_plan_status",
                "title": "Get plan status",
                "description": "Return the stored status of a plan (PendingApproval, Approved, Rejected, Executing, Executed, ExecutionFailed) with its steps, content hash and operator decision.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "plan_id": { "type": "string", "format": "uuid" } },
                    "required": ["plan_id"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }
            }),
        ]
    }

    /// Dispatch a `tools/call`.  Unknown tool names are a protocol-level
    /// error (`Err`); tool failures are `Ok` with `is_error = true`.
    pub async fn call_tool(&self, name: &str, args: Value) -> Result<ToolOutcome, UnknownTool> {
        // Audit first — every call, including unknown tools, lands in the chain.
        if let Err(e) = self
            .audit
            .record(AuditEventType::McpToolCalled {
                tool: name.to_string(),
                arguments: args.clone(),
            })
            .await
        {
            if !TOOL_NAMES.contains(&name) {
                return Err(UnknownTool(name.to_string()));
            }
            return Ok(ToolOutcome::err(
                format!("audit log write failed; refusing to proceed: {e}"),
                json!({}),
            ));
        }

        let outcome = match name {
            "sentinel_capabilities" => self.tool_capabilities(),
            "sentinel_policy_check" => self.tool_policy_check(&args).await,
            "sentinel_investigate" => self.tool_investigate(&args).await,
            "sentinel_propose_plan" => self.tool_propose_plan(&args).await,
            "sentinel_plan_status" => self.tool_plan_status(&args),
            other => return Err(UnknownTool(other.to_string())),
        };
        Ok(outcome)
    }

    fn policy_request(&self, cap: &dyn Capability, args: &Value, phase: &str) -> PolicyRequest {
        let m = cap.manifest();
        PolicyRequest {
            session_id: self.session_id(),
            capability_id: m.id.clone(),
            capability_kind: m.kind,
            risk_tier: m.risk_tier,
            args: args.clone(),
            target_host: self.config.host.clone(),
            timestamp: chrono::Utc::now(),
            session_phase: Some(phase.to_string()),
        }
    }

    /// Record `PolicyEvaluated` (and `PolicyDenied` for denials).
    async fn audit_decision(&self, d: &PolicyDecision) -> Result<(), String> {
        self.audit
            .record(AuditEventType::PolicyEvaluated {
                capability_id: d.request.capability_id.clone(),
                effect: effect_label(&d.effect).to_string(),
                rule_id: d.matched_rule.clone(),
            })
            .await
            .map_err(|e| e.to_string())?;
        if let PolicyEffect::Denied { reason } = &d.effect {
            self.audit
                .record(AuditEventType::PolicyDenied {
                    capability_id: d.request.capability_id.clone(),
                    reason: reason.clone(),
                })
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    async fn audit_denied(&self, capability_id: &str, reason: &str) -> Result<(), String> {
        self.audit
            .record(AuditEventType::PolicyDenied {
                capability_id: capability_id.to_string(),
                reason: reason.to_string(),
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    // ── sentinel_capabilities ────────────────────────────────────────────────

    fn tool_capabilities(&self) -> ToolOutcome {
        let list: Vec<Value> = self
            .caps
            .values()
            .map(|c| {
                let m = c.manifest();
                json!({
                    "id": m.id,
                    "name": m.name,
                    "description": m.description,
                    "kind": kind_label(m.kind),
                    "risk_tier": m.risk_tier.to_string(),
                    "has_inverse": m.has_inverse,
                    "investigable": m.kind == CapabilityKind::ReadOnly,
                })
            })
            .collect();
        ToolOutcome::ok(json!({ "count": list.len(), "capabilities": list }))
    }

    // ── sentinel_policy_check ────────────────────────────────────────────────

    async fn tool_policy_check(&self, args: &Value) -> ToolOutcome {
        let Some(cap_id) = str_arg(args, "capability_id") else {
            return ToolOutcome::err("'capability_id' (string) is required", json!({}));
        };
        let cap_args = match obj_arg(args, "args") {
            Ok(v) => v,
            Err(e) => return ToolOutcome::err(e, json!({})),
        };
        let phase = str_arg(args, "phase").unwrap_or("Executing");
        if phase != "Executing" && phase != "Investigating" {
            return ToolOutcome::err("'phase' must be 'Investigating' or 'Executing'", json!({}));
        }

        let Some(cap) = self.caps.get(cap_id) else {
            let reason = format!("unknown capability '{cap_id}' (deny by default)");
            if let Err(e) = self.audit_denied(cap_id, &reason).await {
                return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
            }
            return ToolOutcome::ok(json!({
                "capability_id": cap_id,
                "decision": "deny",
                "allowed_without_approval": false,
                "matched_rule": null,
                "reason": reason,
                "rationale": "Deny-by-default: capability is not registered",
            }));
        };

        let decision = self
            .policy
            .evaluate(self.policy_request(cap.as_ref(), &cap_args, phase));
        if let Err(e) = self.audit_decision(&decision).await {
            return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
        }
        let m = cap.manifest();
        let (valid, err) = match cap.validate_args(&cap_args) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let mut body = decision_json(&decision);
        if let Some(obj) = body.as_object_mut() {
            obj.insert("capability_id".into(), json!(m.id));
            obj.insert("kind".into(), json!(kind_label(m.kind)));
            obj.insert("risk_tier".into(), json!(m.risk_tier.to_string()));
            obj.insert("phase".into(), json!(phase));
            obj.insert("args_valid".into(), json!(valid));
            obj.insert("args_error".into(), json!(err));
            obj.insert("executed".into(), json!(false));
        }
        ToolOutcome::ok(body)
    }

    // ── sentinel_investigate ─────────────────────────────────────────────────

    async fn tool_investigate(&self, args: &Value) -> ToolOutcome {
        let Some(cap_id) = str_arg(args, "capability_id") else {
            return ToolOutcome::err("'capability_id' (string) is required", json!({}));
        };
        let cap_args = match obj_arg(args, "args") {
            Ok(v) => v,
            Err(e) => return ToolOutcome::err(e, json!({})),
        };
        let Some(cap) = self.caps.get(cap_id) else {
            let reason = format!("unknown capability '{cap_id}'");
            let _ = self.audit_denied(cap_id, &reason).await;
            return ToolOutcome::err(reason, json!({ "executed": false }));
        };
        let m = cap.manifest();

        // Hard structural check, independent of the policy rules in force.
        if m.kind != CapabilityKind::ReadOnly {
            let reason = format!(
                "'{cap_id}' is a Mutating capability; sentinel_investigate only runs ReadOnly capabilities. Use sentinel_propose_plan and ask an operator to approve it."
            );
            if let Err(e) = self.audit_denied(cap_id, &reason).await {
                return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
            }
            return ToolOutcome::err(reason, json!({ "executed": false }));
        }

        if let Err(e) = cap.validate_args(&cap_args) {
            return ToolOutcome::err(
                format!("invalid args for '{cap_id}': {e}"),
                json!({ "executed": false }),
            );
        }

        let decision =
            self.policy
                .evaluate(self.policy_request(cap.as_ref(), &cap_args, "Investigating"));
        if let Err(e) = self.audit_decision(&decision).await {
            return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
        }
        if !decision.is_allowed() {
            return ToolOutcome::err(
                format!(
                    "policy did not allow '{cap_id}' during investigation ({})",
                    effect_label(&decision.effect)
                ),
                json!({ "executed": false, "policy": decision_json(&decision) }),
            );
        }

        if let Err(e) = self
            .audit
            .record(AuditEventType::CapabilityInvoked {
                capability_id: cap_id.to_string(),
                args: cap_args.clone(),
                risk_tier: format!("{:?}", m.risk_tier),
            })
            .await
        {
            return ToolOutcome::err(
                format!("audit log write failed; not executing: {e}"),
                json!({ "executed": false }),
            );
        }

        let ctx = ExecutionContext::new(self.session_id(), self.config.host.clone())
            .with_timeout_ms(self.config.investigate_timeout_ms);
        let started = Instant::now();
        let result = match tokio::time::timeout(
            Duration::from_millis(self.config.investigate_timeout_ms),
            cap.invoke(cap_args.clone(), &ctx),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => CapabilityResult::failure(
                format!("timed out after {}ms", self.config.investigate_timeout_ms),
                true,
            ),
        };
        let duration_ms = started.elapsed().as_millis() as u64;

        let post = match &result {
            CapabilityResult::Success { .. } => AuditEventType::CapabilitySucceeded {
                capability_id: cap_id.to_string(),
                duration_ms,
            },
            CapabilityResult::Failure { error, .. } => AuditEventType::CapabilityFailed {
                capability_id: cap_id.to_string(),
                error: error.clone(),
            },
            CapabilityResult::DryRun { .. } => AuditEventType::CapabilityFailed {
                capability_id: cap_id.to_string(),
                error: "capability returned a dry-run result from invoke".into(),
            },
        };
        let _ = self.audit.record(post).await;
        let _ = self
            .audit
            .record(AuditEventType::ObservationRecorded {
                capability_id: cap_id.to_string(),
                args: cap_args,
                result_summary: summarize(&result),
            })
            .await;

        let is_error = !result.is_success();
        ToolOutcome {
            is_error,
            body: json!({
                "capability_id": cap_id,
                "executed": true,
                "duration_ms": duration_ms,
                "policy": decision_json(&decision),
                "result": result,
            }),
        }
    }

    // ── sentinel_propose_plan ────────────────────────────────────────────────

    async fn tool_propose_plan(&self, args: &Value) -> ToolOutcome {
        let goal = match str_arg(args, "goal").map(str::trim) {
            Some(g) if !g.is_empty() => g.to_string(),
            _ => return ToolOutcome::err("'goal' must be a non-empty string", json!({})),
        };
        let rationale = str_arg(args, "rationale").unwrap_or("").to_string();
        let Some(steps) = args.get("steps").and_then(Value::as_array) else {
            return ToolOutcome::err("'steps' must be an array", json!({}));
        };
        if steps.is_empty() || steps.len() > self.config.max_plan_steps {
            return ToolOutcome::err(
                format!(
                    "'steps' must contain between 1 and {} items",
                    self.config.max_plan_steps
                ),
                json!({}),
            );
        }

        let mut plan = Plan::new(self.session_id(), goal, rationale);
        let mut step_reports = Vec::with_capacity(steps.len());
        let mut problems = Vec::new();

        for (i, raw) in steps.iter().enumerate() {
            let seq = (i + 1) as u32;
            let Some(cap_id) = str_arg(raw, "capability_id") else {
                problems.push(json!({ "sequence": seq, "error": "'capability_id' is required" }));
                continue;
            };
            let step_args = match obj_arg(raw, "args") {
                Ok(v) => v,
                Err(e) => {
                    problems.push(json!({ "sequence": seq, "capability_id": cap_id, "error": e }));
                    continue;
                }
            };
            let Some(cap) = self.caps.get(cap_id) else {
                let reason = format!("unknown capability '{cap_id}'");
                if let Err(e) = self.audit_denied(cap_id, &reason).await {
                    return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
                }
                problems.push(json!({ "sequence": seq, "capability_id": cap_id, "error": reason }));
                continue;
            };
            if let Err(e) = cap.validate_args(&step_args) {
                problems.push(json!({
                    "sequence": seq, "capability_id": cap_id,
                    "error": format!("invalid args: {e}")
                }));
                continue;
            }
            let decision =
                self.policy
                    .evaluate(self.policy_request(cap.as_ref(), &step_args, "Executing"));
            if let Err(e) = self.audit_decision(&decision).await {
                return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
            }
            let m = cap.manifest();
            if matches!(decision.effect, PolicyEffect::Denied { .. }) {
                problems.push(json!({
                    "sequence": seq, "capability_id": cap_id,
                    "error": "denied by policy",
                    "policy": decision_json(&decision),
                }));
                continue;
            }
            let description = str_arg(raw, "description")
                .map(str::to_string)
                .unwrap_or_else(|| m.description.clone());
            // Risk tier always comes from the manifest, never from the agent.
            let mut step = PlanStep::new(seq, cap_id, step_args, description, m.risk_tier);
            step.requires_approval = true;
            step.can_rollback = m.has_inverse;
            step_reports.push(json!({
                "sequence": seq,
                "capability_id": cap_id,
                "kind": kind_label(m.kind),
                "risk_tier": m.risk_tier.to_string(),
                "policy": decision_json(&decision),
            }));
            plan.add_step(step);
        }

        if !problems.is_empty() {
            return ToolOutcome::err(
                "plan refused; nothing was stored",
                json!({ "stored": false, "problems": problems }),
            );
        }

        let rec = StoredPlan::new_pending(
            plan,
            self.config.host.clone(),
            self.session_id(),
            Some(self.audit.path_string()),
        );
        if let Err(e) = self.store.save(&rec) {
            return ToolOutcome::err(format!("failed to store plan: {e}"), json!({}));
        }
        if let Err(e) = self
            .audit
            .record(AuditEventType::PlanProposed {
                plan_id: rec.plan.id,
                step_count: rec.plan.steps.len(),
                overall_risk: rec.plan.overall_risk.to_string(),
            })
            .await
        {
            return ToolOutcome::err(format!("audit log write failed: {e}"), json!({}));
        }

        ToolOutcome::ok(json!({
            "plan_id": rec.plan.id,
            "status": rec.status.to_string(),
            "executed": false,
            "content_hash": rec.content_hash,
            "overall_risk": rec.plan.overall_risk.to_string(),
            "steps": step_reports,
            "next": format!(
                "An operator must review and approve this plan out-of-band: `sentinel approve {id}` then `sentinel execute {id}`. This MCP server cannot approve or execute plans. Poll sentinel_plan_status for the outcome.",
                id = rec.plan.id
            ),
        }))
    }

    // ── sentinel_plan_status ─────────────────────────────────────────────────

    fn tool_plan_status(&self, args: &Value) -> ToolOutcome {
        let Some(raw) = str_arg(args, "plan_id") else {
            return ToolOutcome::err("'plan_id' (string) is required", json!({}));
        };
        let Ok(id) = Uuid::parse_str(raw) else {
            return ToolOutcome::err("'plan_id' must be a UUID", json!({}));
        };
        match self.store.load(id) {
            Ok(rec) => ToolOutcome::ok(plan_status_json(&rec)),
            Err(StoreError::NotFound(_)) => {
                ToolOutcome::err(format!("plan {id} not found"), json!({}))
            }
            Err(e) => ToolOutcome::err(e.to_string(), json!({})),
        }
    }
}

/// Public JSON view of a stored plan (used by MCP and the CLI).
pub fn plan_status_json(rec: &StoredPlan) -> Value {
    json!({
        "plan_id": rec.plan.id,
        "status": rec.status.to_string(),
        "goal": rec.plan.goal,
        "rationale": rec.plan.rationale,
        "host": rec.host,
        "overall_risk": rec.plan.overall_risk.to_string(),
        "content_hash": rec.content_hash,
        "integrity_ok": rec.integrity_ok(),
        "proposed_at": rec.proposed_at,
        "steps": rec.plan.steps.iter().map(|s| json!({
            "sequence": s.sequence,
            "capability_id": s.capability_id,
            "args": s.args,
            "description": s.description,
            "risk_tier": s.risk_tier.to_string(),
            "status": format!("{:?}", s.status),
        })).collect::<Vec<_>>(),
        "decision": rec.decision,
        "execution": rec.execution,
    })
}
