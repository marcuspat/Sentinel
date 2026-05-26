use serde::{Deserialize, Serialize};

use crate::capability::RiskTier;

/// Status of a single step within an execution plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    /// Step is waiting to be approved or executed.
    Pending,
    /// Step has been explicitly approved by the operator.
    Approved,
    /// Step is currently being executed.
    Executing,
    /// Step completed successfully.
    Completed,
    /// Step failed during execution.
    Failed,
    /// Step was rolled back after a failure.
    RolledBack,
    /// Step was intentionally skipped (e.g. dependency failed).
    Skipped,
}

/// A single step in an execution plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    /// Unique identifier for this step.
    pub id: uuid::Uuid,
    /// Execution order within the plan (0-based).
    pub sequence: u32,
    /// The capability to invoke for this step.
    pub capability_id: String,
    /// Arguments to pass to the capability.
    pub args: serde_json::Value,
    /// Human-readable description of what this step does.
    pub description: String,
    /// Risk tier of this step, used for approval decisions.
    pub risk_tier: RiskTier,
    /// Whether this step requires explicit operator approval before execution.
    pub requires_approval: bool,
    /// Whether this step can be rolled back if a subsequent step fails.
    pub can_rollback: bool,
    /// Step IDs that must complete successfully before this step may execute.
    pub depends_on: Vec<uuid::Uuid>,
    /// Current execution status.
    pub status: StepStatus,
}

impl PlanStep {
    /// Construct a new pending step with the given fields.
    pub fn new(
        sequence: u32,
        capability_id: impl Into<String>,
        args: serde_json::Value,
        description: impl Into<String>,
        risk_tier: RiskTier,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            sequence,
            capability_id: capability_id.into(),
            args,
            description: description.into(),
            risk_tier,
            requires_approval: risk_tier >= RiskTier::High,
            can_rollback: false,
            depends_on: Vec::new(),
            status: StepStatus::Pending,
        }
    }
}

/// The operator's decision regarding plan execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// No decision has been made yet.
    Pending,
    /// All steps are approved for immediate execution.
    FullApproval,
    /// Each step must be individually approved before execution.
    StepByStep,
    /// The plan was rejected; no steps will be executed.
    Rejected {
        /// Reason provided by the operator.
        reason: String,
    },
    /// The plan was approved after the operator made inline edits.
    Edited,
}

/// A complete execution plan proposed by the agent.
///
/// A plan is created during the `Planning` phase and transitions to
/// `AwaitingApproval` once submitted.  The `approval` field records the
/// operator's decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// Unique identifier for this plan.
    pub id: uuid::Uuid,
    /// The session that owns this plan.
    pub session_id: uuid::Uuid,
    /// Natural-language description of what the plan achieves.
    pub goal: String,
    /// Ordered list of execution steps.
    pub steps: Vec<PlanStep>,
    /// The highest risk tier across all steps (computed by `compute_overall_risk`).
    pub overall_risk: RiskTier,
    /// Explanation of why this plan was chosen over alternatives.
    pub rationale: String,
    /// Wall-clock time when the plan was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Wall-clock time when the plan received its first approval decision.
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The operator's approval decision.
    pub approval: ApprovalDecision,
}

impl Plan {
    /// Create a new plan with no steps and a `Pending` approval decision.
    pub fn new(session_id: uuid::Uuid, goal: String, rationale: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            session_id,
            goal,
            steps: Vec::new(),
            overall_risk: RiskTier::Low,
            rationale,
            created_at: chrono::Utc::now(),
            approved_at: None,
            approval: ApprovalDecision::Pending,
        }
    }

    /// Append a step to the plan and recompute `overall_risk`.
    pub fn add_step(&mut self, step: PlanStep) {
        self.steps.push(step);
        self.compute_overall_risk();
    }

    /// Set `overall_risk` to the maximum `risk_tier` across all steps.
    ///
    /// If there are no steps the risk defaults to `Low`.
    pub fn compute_overall_risk(&mut self) {
        self.overall_risk = self
            .steps
            .iter()
            .map(|s| s.risk_tier)
            .max()
            .unwrap_or(RiskTier::Low);
    }

    /// Return all steps whose status is `Pending`.
    pub fn pending_steps(&self) -> Vec<&PlanStep> {
        self.steps
            .iter()
            .filter(|s| s.status == StepStatus::Pending)
            .collect()
    }

    /// Return `true` when every step has reached a terminal status
    /// (`Completed`, `Failed`, `RolledBack`, or `Skipped`).
    pub fn is_complete(&self) -> bool {
        if self.steps.is_empty() {
            return false;
        }
        self.steps.iter().all(|s| {
            matches!(
                s.status,
                StepStatus::Completed
                    | StepStatus::Failed
                    | StepStatus::RolledBack
                    | StepStatus::Skipped
            )
        })
    }

    /// Approve the entire plan for immediate execution.
    pub fn approve(&mut self) {
        self.approved_at = Some(chrono::Utc::now());
        self.approval = ApprovalDecision::FullApproval;
    }

    /// Reject the plan with a reason.
    pub fn reject(&mut self, reason: impl Into<String>) {
        self.approval = ApprovalDecision::Rejected { reason: reason.into() };
    }

    /// Returns `true` if the plan has been approved (full or step-by-step).
    pub fn is_approved(&self) -> bool {
        matches!(
            self.approval,
            ApprovalDecision::FullApproval | ApprovalDecision::StepByStep | ApprovalDecision::Edited
        )
    }

    /// Returns `true` if the plan has been rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self.approval, ApprovalDecision::Rejected { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_plan() -> Plan {
        Plan::new(
            uuid::Uuid::new_v4(),
            "Reduce disk usage below 80%".into(),
            "Clean old logs and rotate journal".into(),
        )
    }

    fn make_step(seq: u32, risk: RiskTier) -> PlanStep {
        PlanStep::new(
            seq,
            format!("sentinel.test.step_{seq}"),
            serde_json::json!({}),
            format!("Step {seq}"),
            risk,
        )
    }

    // ── StepStatus ────────────────────────────────────────────────────────────

    #[test]
    fn step_status_equality() {
        assert_eq!(StepStatus::Pending, StepStatus::Pending);
        assert_ne!(StepStatus::Pending, StepStatus::Completed);
    }

    #[test]
    fn step_status_serde_roundtrip() {
        let statuses = [
            StepStatus::Pending,
            StepStatus::Approved,
            StepStatus::Executing,
            StepStatus::Completed,
            StepStatus::Failed,
            StepStatus::RolledBack,
            StepStatus::Skipped,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let back: StepStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
    }

    // ── PlanStep ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_step_new_defaults() {
        let step = make_step(0, RiskTier::Low);
        assert!(!step.id.is_nil());
        assert_eq!(step.sequence, 0);
        assert_eq!(step.risk_tier, RiskTier::Low);
        assert_eq!(step.status, StepStatus::Pending);
        assert!(step.depends_on.is_empty());
        assert!(!step.can_rollback);
        // Low risk → approval not required
        assert!(!step.requires_approval);
    }

    #[test]
    fn plan_step_high_risk_requires_approval() {
        let step = make_step(0, RiskTier::High);
        assert!(step.requires_approval);
    }

    #[test]
    fn plan_step_critical_risk_requires_approval() {
        let step = make_step(0, RiskTier::Critical);
        assert!(step.requires_approval);
    }

    #[test]
    fn plan_step_serde_roundtrip() {
        let step = make_step(1, RiskTier::Medium);
        let json = serde_json::to_string(&step).unwrap();
        let back: PlanStep = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, step.id);
        assert_eq!(back.sequence, step.sequence);
        assert_eq!(back.risk_tier, step.risk_tier);
        assert_eq!(back.status, step.status);
    }

    // ── ApprovalDecision ──────────────────────────────────────────────────────

    #[test]
    fn approval_decision_equality() {
        assert_eq!(ApprovalDecision::Pending, ApprovalDecision::Pending);
        assert_ne!(ApprovalDecision::FullApproval, ApprovalDecision::Pending);
    }

    #[test]
    fn approval_decision_rejected_carries_reason() {
        let d = ApprovalDecision::Rejected {
            reason: "too risky".into(),
        };
        if let ApprovalDecision::Rejected { reason } = &d {
            assert_eq!(reason, "too risky");
        } else {
            panic!("expected Rejected");
        }
    }

    #[test]
    fn approval_decision_serde_roundtrip() {
        let decisions = vec![
            ApprovalDecision::Pending,
            ApprovalDecision::FullApproval,
            ApprovalDecision::StepByStep,
            ApprovalDecision::Rejected { reason: "nope".into() },
            ApprovalDecision::Edited,
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).unwrap();
            let back: ApprovalDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // ── Plan::new ─────────────────────────────────────────────────────────────

    #[test]
    fn plan_new_starts_empty() {
        let p = make_plan();
        assert!(!p.id.is_nil());
        assert!(p.steps.is_empty());
        assert_eq!(p.overall_risk, RiskTier::Low);
        assert_eq!(p.approval, ApprovalDecision::Pending);
        assert!(p.approved_at.is_none());
    }

    // ── Plan::add_step ────────────────────────────────────────────────────────

    #[test]
    fn add_step_appends_and_updates_risk() {
        let mut p = make_plan();
        p.add_step(make_step(0, RiskTier::Low));
        assert_eq!(p.steps.len(), 1);
        assert_eq!(p.overall_risk, RiskTier::Low);

        p.add_step(make_step(1, RiskTier::High));
        assert_eq!(p.steps.len(), 2);
        assert_eq!(p.overall_risk, RiskTier::High);
    }

    // ── Plan::compute_overall_risk ────────────────────────────────────────────

    #[test]
    fn compute_overall_risk_no_steps() {
        let mut p = make_plan();
        p.compute_overall_risk();
        assert_eq!(p.overall_risk, RiskTier::Low);
    }

    #[test]
    fn compute_overall_risk_picks_max() {
        let mut p = make_plan();
        p.steps.push(make_step(0, RiskTier::Medium));
        p.steps.push(make_step(1, RiskTier::Low));
        p.steps.push(make_step(2, RiskTier::Critical));
        p.steps.push(make_step(3, RiskTier::High));
        p.compute_overall_risk();
        assert_eq!(p.overall_risk, RiskTier::Critical);
    }

    // ── Plan::pending_steps ───────────────────────────────────────────────────

    #[test]
    fn pending_steps_filters_correctly() {
        let mut p = make_plan();
        let mut step0 = make_step(0, RiskTier::Low);
        step0.status = StepStatus::Completed;
        let step1 = make_step(1, RiskTier::Low);  // Pending
        let mut step2 = make_step(2, RiskTier::Low);
        step2.status = StepStatus::Skipped;

        p.steps.push(step0);
        p.steps.push(step1);
        p.steps.push(step2);

        let pending = p.pending_steps();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sequence, 1);
    }

    #[test]
    fn pending_steps_empty_when_all_done() {
        let mut p = make_plan();
        let mut s = make_step(0, RiskTier::Low);
        s.status = StepStatus::Completed;
        p.steps.push(s);
        assert!(p.pending_steps().is_empty());
    }

    // ── Plan::is_complete ─────────────────────────────────────────────────────

    #[test]
    fn is_complete_false_with_no_steps() {
        let p = make_plan();
        assert!(!p.is_complete());
    }

    #[test]
    fn is_complete_false_with_pending_step() {
        let mut p = make_plan();
        p.steps.push(make_step(0, RiskTier::Low)); // Pending
        assert!(!p.is_complete());
    }

    #[test]
    fn is_complete_true_when_all_terminal() {
        let mut p = make_plan();
        let terminal_statuses = [
            StepStatus::Completed,
            StepStatus::Failed,
            StepStatus::RolledBack,
            StepStatus::Skipped,
        ];
        for (i, status) in terminal_statuses.iter().enumerate() {
            let mut step = make_step(i as u32, RiskTier::Low);
            step.status = status.clone();
            p.steps.push(step);
        }
        assert!(p.is_complete());
    }

    #[test]
    fn is_complete_false_when_one_pending() {
        let mut p = make_plan();
        let mut s0 = make_step(0, RiskTier::Low);
        s0.status = StepStatus::Completed;
        let s1 = make_step(1, RiskTier::Low); // Pending
        p.steps.push(s0);
        p.steps.push(s1);
        assert!(!p.is_complete());
    }

    // ── Plan::approve / reject ────────────────────────────────────────────────

    #[test]
    fn approve_sets_full_approval_and_timestamp() {
        let mut p = make_plan();
        assert!(p.approved_at.is_none());
        p.approve();
        assert_eq!(p.approval, ApprovalDecision::FullApproval);
        assert!(p.approved_at.is_some());
        assert!(p.is_approved());
        assert!(!p.is_rejected());
    }

    #[test]
    fn reject_sets_rejected_decision() {
        let mut p = make_plan();
        p.reject("not safe for production");
        assert!(p.is_rejected());
        assert!(!p.is_approved());
        if let ApprovalDecision::Rejected { reason } = &p.approval {
            assert_eq!(reason, "not safe for production");
        } else {
            panic!("expected Rejected");
        }
    }

    #[test]
    fn step_by_step_is_approved() {
        let mut p = make_plan();
        p.approval = ApprovalDecision::StepByStep;
        assert!(p.is_approved());
    }

    #[test]
    fn edited_approval_is_approved() {
        let mut p = make_plan();
        p.approval = ApprovalDecision::Edited;
        assert!(p.is_approved());
    }

    #[test]
    fn pending_approval_is_not_approved() {
        let p = make_plan();
        assert!(!p.is_approved());
        assert!(!p.is_rejected());
    }

    // ── Plan serde ────────────────────────────────────────────────────────────

    #[test]
    fn plan_serde_roundtrip() {
        let mut p = make_plan();
        p.add_step(make_step(0, RiskTier::Low));
        p.add_step(make_step(1, RiskTier::High));
        p.approve();

        let json = serde_json::to_string(&p).unwrap();
        let back: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, p.id);
        assert_eq!(back.session_id, p.session_id);
        assert_eq!(back.goal, p.goal);
        assert_eq!(back.steps.len(), 2);
        assert_eq!(back.overall_risk, RiskTier::High);
        assert_eq!(back.approval, ApprovalDecision::FullApproval);
    }
}
