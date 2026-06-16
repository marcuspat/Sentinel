use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use sentinel_core::{RiskTier, SessionPhase};

// ── Local plan / session types ────────────────────────────────────────────────
// These mirror what the agent-llm crate will eventually expose.  They are
// defined here so the TUI can compile independently while that crate is a
// placeholder.

/// Execution status of a single plan step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed { reason: String },
    Skipped,
    RolledBack,
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepStatus::Pending => write!(f, "Pending"),
            StepStatus::Running => write!(f, "Running"),
            StepStatus::Succeeded => write!(f, "Succeeded"),
            StepStatus::Failed { reason } => write!(f, "Failed: {}", reason),
            StepStatus::Skipped => write!(f, "Skipped"),
            StepStatus::RolledBack => write!(f, "Rolled Back"),
        }
    }
}

/// A single step in an agent plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: Uuid,
    pub description: String,
    pub capability_id: String,
    pub args: serde_json::Value,
    pub risk_tier: RiskTier,
    pub estimated_duration_ms: Option<u64>,
    pub status: StepStatus,
}

impl PlanStep {
    pub fn new(
        description: impl Into<String>,
        capability_id: impl Into<String>,
        args: serde_json::Value,
        risk_tier: RiskTier,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.into(),
            capability_id: capability_id.into(),
            args,
            risk_tier,
            estimated_duration_ms: None,
            status: StepStatus::Pending,
        }
    }
}

/// A complete remediation plan produced by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: Uuid,
    pub goal: String,
    pub steps: Vec<PlanStep>,
    pub overall_risk: RiskTier,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Plan {
    pub fn new(goal: impl Into<String>, steps: Vec<PlanStep>) -> Self {
        let overall_risk = steps
            .iter()
            .map(|s| s.risk_tier)
            .max()
            .unwrap_or(RiskTier::Low);
        Self {
            id: Uuid::new_v4(),
            goal: goal.into(),
            steps,
            overall_risk,
            created_at: chrono::Utc::now(),
        }
    }
}

/// How a plan was approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    ApproveAll,
    StepByStep,
    Reject { reason: String },
}

// ── Interactive per-step approval ─────────────────────────────────────────────

/// The operator's answer to a blocking per-step approval prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Approve this step — the agent may proceed.
    Approve,
    /// Abort — the agent must not run this step (and should stop the plan).
    Abort,
}

/// A request from the agent for interactive approval of a single step.
///
/// When the policy engine returns `RequiresApproval`, the agent sends one of
/// these on the approval channel instead of blocking on stdin.  The TUI
/// surfaces it as a modal and replies with an [`ApprovalOutcome`] on
/// `responder`.
#[derive(Debug)]
pub struct ApprovalRequest {
    /// The step awaiting approval (capability, risk, args, description).
    pub step: PlanStep,
    /// One-shot channel the TUI uses to send the operator's decision back.
    pub responder: oneshot::Sender<ApprovalOutcome>,
}

/// High-level interaction state of the TUI.
#[derive(Debug)]
pub enum AppState {
    /// Normal browsing/editing — tabs and inputs are active.
    Normal,
    /// A modal is blocking input, awaiting approval of the contained step.
    ApprovingPlan(PlanStep),
}

/// Severity level for TUI log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Debug => write!(f, "DEBUG"),
        }
    }
}

/// A single line in the session activity log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
}

/// An active agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub goal: String,
    pub host: String,
    pub phase: SessionPhase,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub log_entries: Vec<LogEntry>,
    pub current_plan: Option<Plan>,
    pub dry_run: bool,
}

impl Session {
    pub fn new(goal: impl Into<String>, host: impl Into<String>, dry_run: bool) -> Self {
        Self {
            id: Uuid::new_v4(),
            goal: goal.into(),
            host: host.into(),
            phase: SessionPhase::Investigating,
            started_at: chrono::Utc::now(),
            log_entries: Vec::new(),
            current_plan: None,
            dry_run,
        }
    }

    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.log_entries.push(LogEntry {
            timestamp: chrono::Utc::now(),
            level,
            message: message.into(),
        });
    }
}

// ── SessionUpdate ─────────────────────────────────────────────────────────────

/// An update pushed from the background agent task into the TUI event loop.
#[derive(Debug, Clone)]
pub enum SessionUpdate {
    PhaseChanged(SessionPhase),
    LogAppended(LogEntry),
    PlanProposed(Plan),
    PlanApproved,
    PlanRejected { reason: String },
    StepStarted(Uuid),
    StepCompleted { step_id: Uuid, status: StepStatus },
    SessionCompleted,
    Error(String),
}

// ── Plan view ─────────────────────────────────────────────────────────────────

/// Per-step display state in the Plan tab.
#[derive(Debug, Clone)]
pub struct PlanStepView {
    pub step: PlanStep,
    pub approved: bool,
    pub expanded: bool,
}

impl PlanStepView {
    pub fn new(step: PlanStep) -> Self {
        Self {
            step,
            approved: false,
            expanded: false,
        }
    }
}

/// Full plan display/approval state.
#[derive(Debug, Clone)]
pub struct PlanView {
    pub steps: Vec<PlanStepView>,
    pub selected_index: usize,
    pub approval_mode: Option<ApprovalDecision>,
}

impl Default for PlanView {
    fn default() -> Self {
        Self::new()
    }
}

impl PlanView {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            selected_index: 0,
            approval_mode: None,
        }
    }

    pub fn load_plan(&mut self, plan: &Plan) {
        self.steps = plan
            .steps
            .iter()
            .map(|s| PlanStepView::new(s.clone()))
            .collect();
        self.selected_index = 0;
        self.approval_mode = None;
    }

    pub fn move_down(&mut self) {
        if !self.steps.is_empty() {
            self.selected_index = (self.selected_index + 1).min(self.steps.len() - 1);
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn toggle_expanded(&mut self) {
        if let Some(step) = self.steps.get_mut(self.selected_index) {
            step.expanded = !step.expanded;
        }
    }
}

// ── Tab enum ──────────────────────────────────────────────────────────────────

/// Top-level navigation tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Goal,
    Investigation,
    Plan,
    Execution,
    Audit,
}

impl Tab {
    pub const ALL: &'static [Tab] = &[
        Tab::Goal,
        Tab::Investigation,
        Tab::Plan,
        Tab::Execution,
        Tab::Audit,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Goal => "Goal",
            Tab::Investigation => "Investigation",
            Tab::Plan => "Plan",
            Tab::Execution => "Execution",
            Tab::Audit => "Audit",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }

    pub fn next(self) -> Tab {
        let idx = (self.index() + 1) % Self::ALL.len();
        Self::ALL[idx]
    }

    pub fn prev(self) -> Tab {
        let len = Self::ALL.len();
        let idx = (self.index() + len - 1) % len;
        Self::ALL[idx]
    }
}

// ── App ───────────────────────────────────────────────────────────────────────

/// Top-level TUI application state.
pub struct App {
    /// Active session, if one has been started.
    pub session: Option<Session>,
    /// Currently visible tab.
    pub current_tab: Tab,
    /// Goal string being typed by the operator.
    pub goal_input: String,
    /// Vertical scroll offset for the log/investigation views.
    pub log_scroll: u16,
    /// Plan display and approval state.
    pub plan_view: PlanView,
    /// Set to `true` to request application exit on the next tick.
    pub should_quit: bool,
    /// Transient status bar message.
    pub status_message: Option<String>,
    /// Cursor position within the goal input field.
    pub input_cursor: usize,
    /// Current interaction state — drives modal/blocking input handling.
    pub state: AppState,
    /// Channel responder for the in-flight approval modal, if any.
    approval_responder: Option<oneshot::Sender<ApprovalOutcome>>,
    /// Channel on which the agent emits approval requests for the TUI to poll.
    approval_rx: Option<mpsc::Receiver<ApprovalRequest>>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            session: None,
            current_tab: Tab::Goal,
            goal_input: String::new(),
            log_scroll: 0,
            plan_view: PlanView::new(),
            should_quit: false,
            status_message: None,
            input_cursor: 0,
            state: AppState::Normal,
            approval_responder: None,
            approval_rx: None,
        }
    }

    // ── Interactive approval ──────────────────────────────────────────────────

    /// Attach the channel on which the agent will send approval requests.
    pub fn set_approval_channel(&mut self, rx: mpsc::Receiver<ApprovalRequest>) {
        self.approval_rx = Some(rx);
    }

    /// Returns `true` when a blocking approval modal is active.
    pub fn is_approving(&self) -> bool {
        matches!(self.state, AppState::ApprovingPlan(_))
    }

    /// The step currently awaiting approval, if any.
    pub fn pending_approval_step(&self) -> Option<&PlanStep> {
        match &self.state {
            AppState::ApprovingPlan(step) => Some(step),
            AppState::Normal => None,
        }
    }

    /// Enter the approval modal for `step`, replying on `responder`.
    ///
    /// Used by [`poll_approval`](Self::poll_approval); also exposed for direct
    /// wiring and tests.
    pub fn begin_approval(
        &mut self,
        step: PlanStep,
        responder: oneshot::Sender<ApprovalOutcome>,
    ) {
        self.status_message = Some(format!(
            "Approval required for '{}' (risk {:?}). Press y to approve, n/Esc to abort.",
            step.capability_id, step.risk_tier
        ));
        self.state = AppState::ApprovingPlan(step);
        self.approval_responder = Some(responder);
    }

    /// Non-blocking check for an incoming approval request.  When one arrives
    /// and no modal is already active, enter the approval modal state.
    ///
    /// Call this on every tick so requests surface promptly.
    pub fn poll_approval(&mut self) {
        if self.is_approving() {
            return;
        }
        let Some(rx) = self.approval_rx.as_mut() else {
            return;
        };
        if let Ok(req) = rx.try_recv() {
            self.begin_approval(req.step, req.responder);
        }
    }

    /// Resolve the active approval modal, replying to the agent and returning
    /// to [`AppState::Normal`].  A no-op if no modal is active.
    pub fn submit_approval(&mut self, outcome: ApprovalOutcome) {
        if !self.is_approving() {
            return;
        }
        if let Some(responder) = self.approval_responder.take() {
            // The agent may have given up waiting; ignore a closed channel.
            let _ = responder.send(outcome);
        }
        if let Some(s) = &mut self.session {
            match outcome {
                ApprovalOutcome::Approve => {
                    s.log(LogLevel::Info, "Step approved by operator.")
                }
                ApprovalOutcome::Abort => {
                    s.log(LogLevel::Warn, "Step aborted by operator.")
                }
            }
        }
        self.status_message = Some(match outcome {
            ApprovalOutcome::Approve => "Step approved.".to_string(),
            ApprovalOutcome::Abort => "Plan aborted by operator.".to_string(),
        });
        self.state = AppState::Normal;
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    pub fn next_tab(&mut self) {
        self.current_tab = self.current_tab.next();
    }

    pub fn prev_tab(&mut self) {
        self.current_tab = self.current_tab.prev();
    }

    // ── Log scrolling ─────────────────────────────────────────────────────────

    pub fn scroll_log_down(&mut self) {
        self.log_scroll = self.log_scroll.saturating_add(1);
    }

    pub fn scroll_log_up(&mut self) {
        self.log_scroll = self.log_scroll.saturating_sub(1);
    }

    // ── Plan approval ─────────────────────────────────────────────────────────

    /// Approve every step in the current plan at once.
    pub fn approve_all(&mut self) {
        for step in &mut self.plan_view.steps {
            step.approved = true;
        }
        self.plan_view.approval_mode = Some(ApprovalDecision::ApproveAll);
        self.status_message = Some("All steps approved.".into());
    }

    /// Approve the single step at `index`.
    pub fn approve_step(&mut self, index: usize) {
        if let Some(step) = self.plan_view.steps.get_mut(index) {
            step.approved = true;
        }
        self.plan_view.approval_mode = Some(ApprovalDecision::StepByStep);
        self.status_message = Some(format!("Step {} approved.", index + 1));
    }

    /// Reject the current plan with a human-readable reason.
    pub fn reject_plan(&mut self, reason: String) {
        self.plan_view.approval_mode = Some(ApprovalDecision::Reject {
            reason: reason.clone(),
        });
        if let Some(session) = &mut self.session {
            session.log(LogLevel::Warn, format!("Plan rejected: {}", reason));
        }
        self.status_message = Some(format!("Plan rejected: {}", reason));
    }

    // ── Goal / session helpers ────────────────────────────────────────────────

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }

    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    /// Start a new session with `goal_input`.
    pub fn start_session(&mut self, host: String, dry_run: bool) {
        let goal = self.goal_input.clone();
        if goal.is_empty() {
            self.status_message = Some("Please enter a goal first.".into());
            return;
        }
        let mut session = Session::new(goal.clone(), host, dry_run);
        session.log(LogLevel::Info, format!("Session started — goal: {}", goal));
        self.session = Some(session);
        self.current_tab = Tab::Investigation;
        self.status_message = Some("Session started.".into());
    }

    /// Apply a `SessionUpdate` received from the background agent.
    pub fn apply_session_update(&mut self, update: SessionUpdate) {
        match update {
            SessionUpdate::PhaseChanged(phase) => {
                if let Some(s) = &mut self.session {
                    s.phase = phase;
                }
            }
            SessionUpdate::LogAppended(entry) => {
                if let Some(s) = &mut self.session {
                    s.log_entries.push(entry);
                }
            }
            SessionUpdate::PlanProposed(plan) => {
                self.plan_view.load_plan(&plan);
                if let Some(s) = &mut self.session {
                    s.log(LogLevel::Info, "Plan proposed — review required.");
                    s.current_plan = Some(plan);
                }
                self.current_tab = Tab::Plan;
                self.status_message =
                    Some("New plan proposed. Press 'a' to approve all.".into());
            }
            SessionUpdate::PlanApproved => {
                if let Some(s) = &mut self.session {
                    s.log(LogLevel::Info, "Plan approved — beginning execution.");
                }
                self.current_tab = Tab::Execution;
            }
            SessionUpdate::PlanRejected { reason } => {
                self.reject_plan(reason);
            }
            SessionUpdate::StepStarted(step_id) => {
                if let Some(sv) = self
                    .plan_view
                    .steps
                    .iter_mut()
                    .find(|sv| sv.step.id == step_id)
                {
                    sv.step.status = StepStatus::Running;
                }
                if let Some(s) = &mut self.session {
                    s.log(LogLevel::Info, format!("Step {} started.", step_id));
                }
            }
            SessionUpdate::StepCompleted { step_id, status } => {
                if let Some(sv) = self
                    .plan_view
                    .steps
                    .iter_mut()
                    .find(|sv| sv.step.id == step_id)
                {
                    sv.step.status = status.clone();
                }
                let msg = match &status {
                    StepStatus::Succeeded => format!("Step {} succeeded.", step_id),
                    StepStatus::Failed { reason } => {
                        format!("Step {} failed: {}", step_id, reason)
                    }
                    _ => format!("Step {} status: {}", step_id, status),
                };
                if let Some(s) = &mut self.session {
                    s.log(LogLevel::Info, msg);
                }
            }
            SessionUpdate::SessionCompleted => {
                if let Some(s) = &mut self.session {
                    s.phase = SessionPhase::Completed;
                    s.log(LogLevel::Info, "Session completed successfully.");
                }
                self.current_tab = Tab::Audit;
                self.status_message = Some("Session completed.".into());
            }
            SessionUpdate::Error(msg) => {
                if let Some(s) = &mut self.session {
                    s.log(LogLevel::Error, msg.clone());
                }
                self.status_message = Some(format!("Error: {}", msg));
            }
        }
    }

    // ── Plan view delegation ──────────────────────────────────────────────────

    pub fn plan_scroll_down(&mut self) {
        self.plan_view.move_down();
    }

    pub fn plan_scroll_up(&mut self) {
        self.plan_view.move_up();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── Tab navigation ────────────────────────────────────────────────────────

    #[test]
    fn new_app_starts_on_goal_tab() {
        let app = App::new();
        assert_eq!(app.current_tab, Tab::Goal);
        assert!(!app.should_quit);
        assert!(app.goal_input.is_empty());
    }

    #[test]
    fn tab_next_wraps_around() {
        let mut app = App::new();
        app.current_tab = Tab::Audit;
        app.next_tab();
        assert_eq!(app.current_tab, Tab::Goal);
    }

    #[test]
    fn tab_prev_wraps_around() {
        let mut app = App::new();
        app.current_tab = Tab::Goal;
        app.prev_tab();
        assert_eq!(app.current_tab, Tab::Audit);
    }

    #[test]
    fn tab_cycle_forward_returns_to_start() {
        let mut app = App::new();
        let start = app.current_tab;
        for _ in 0..Tab::ALL.len() {
            app.next_tab();
        }
        assert_eq!(app.current_tab, start);
    }

    #[test]
    fn tab_titles_are_non_empty_and_unique() {
        let titles: Vec<_> = Tab::ALL.iter().map(|t| t.title()).collect();
        for t in &titles {
            assert!(!t.is_empty());
        }
        let unique: std::collections::HashSet<_> = titles.iter().collect();
        assert_eq!(titles.len(), unique.len());
    }

    // ── Log scroll ────────────────────────────────────────────────────────────

    #[test]
    fn scroll_down_and_up() {
        let mut app = App::new();
        app.scroll_log_down();
        assert_eq!(app.log_scroll, 1);
        app.scroll_log_up();
        assert_eq!(app.log_scroll, 0);
    }

    #[test]
    fn scroll_up_does_not_underflow() {
        let mut app = App::new();
        app.scroll_log_up();
        assert_eq!(app.log_scroll, 0);
    }

    // ── Plan approval ─────────────────────────────────────────────────────────

    fn make_plan() -> Plan {
        Plan::new(
            "fix nginx",
            vec![
                PlanStep::new(
                    "Restart nginx",
                    "sentinel.svc.restart",
                    serde_json::json!({"service": "nginx"}),
                    RiskTier::Medium,
                ),
                PlanStep::new(
                    "Read config",
                    "sentinel.fs.read_file",
                    serde_json::json!({"path": "/etc/nginx.conf"}),
                    RiskTier::Low,
                ),
            ],
        )
    }

    #[test]
    fn approve_all_marks_every_step() {
        let mut app = App::new();
        app.plan_view.load_plan(&make_plan());
        app.approve_all();
        assert!(app.plan_view.steps.iter().all(|s| s.approved));
        assert_eq!(app.plan_view.approval_mode, Some(ApprovalDecision::ApproveAll));
    }

    #[test]
    fn approve_step_marks_single_step() {
        let mut app = App::new();
        app.plan_view.load_plan(&make_plan());
        app.approve_step(0);
        assert!(app.plan_view.steps[0].approved);
        assert!(!app.plan_view.steps[1].approved);
        assert_eq!(app.plan_view.approval_mode, Some(ApprovalDecision::StepByStep));
    }

    #[test]
    fn reject_plan_sets_rejection_mode() {
        let mut app = App::new();
        app.session = Some(Session::new("goal", "localhost", false));
        app.reject_plan("too risky".into());
        assert!(matches!(
            app.plan_view.approval_mode,
            Some(ApprovalDecision::Reject { .. })
        ));
    }

    // ── Session ───────────────────────────────────────────────────────────────

    #[test]
    fn start_session_without_goal_shows_message() {
        let mut app = App::new();
        app.start_session("localhost".into(), false);
        assert!(app.session.is_none());
        assert!(app.status_message.is_some());
    }

    #[test]
    fn start_session_with_goal_creates_session() {
        let mut app = App::new();
        app.goal_input = "fix disk full".into();
        app.start_session("web01".into(), false);
        assert!(app.session.is_some());
        let s = app.session.as_ref().unwrap();
        assert_eq!(s.goal, "fix disk full");
        assert_eq!(s.host, "web01");
        assert!(!s.dry_run);
        assert_eq!(app.current_tab, Tab::Investigation);
    }

    #[test]
    fn apply_plan_proposed_switches_to_plan_tab() {
        let mut app = App::new();
        app.session = Some(Session::new("goal", "h", false));
        app.apply_session_update(SessionUpdate::PlanProposed(make_plan()));
        assert_eq!(app.current_tab, Tab::Plan);
        assert!(!app.plan_view.steps.is_empty());
    }

    #[test]
    fn apply_session_completed_switches_to_audit_tab() {
        let mut app = App::new();
        app.session = Some(Session::new("goal", "h", false));
        app.apply_session_update(SessionUpdate::SessionCompleted);
        assert_eq!(app.current_tab, Tab::Audit);
        assert_eq!(
            app.session.as_ref().unwrap().phase,
            SessionPhase::Completed
        );
    }

    // ── Status message ────────────────────────────────────────────────────────

    #[test]
    fn set_and_clear_status() {
        let mut app = App::new();
        app.set_status("Connected");
        assert_eq!(app.status_message.as_deref(), Some("Connected"));
        app.clear_status();
        assert!(app.status_message.is_none());
    }

    // ── PlanView ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_view_move_down_clamps_at_end() {
        let mut pv = PlanView::new();
        pv.load_plan(&make_plan());
        pv.move_down();
        pv.move_down();
        pv.move_down(); // beyond end
        assert_eq!(pv.selected_index, 1); // 0-indexed, 2 steps
    }

    #[test]
    fn plan_view_toggle_expanded() {
        let mut pv = PlanView::new();
        pv.load_plan(&make_plan());
        assert!(!pv.steps[0].expanded);
        pv.toggle_expanded();
        assert!(pv.steps[0].expanded);
        pv.toggle_expanded();
        assert!(!pv.steps[0].expanded);
    }

    // ── Interactive approval ──────────────────────────────────────────────────

    fn approval_step() -> PlanStep {
        PlanStep::new(
            "Restart nginx",
            "service_restart",
            serde_json::json!({ "service": "nginx" }),
            RiskTier::High,
        )
    }

    #[tokio::test]
    async fn poll_approval_enters_modal_state() {
        let mut app = App::new();
        assert!(!app.is_approving());

        let (tx, rx) = mpsc::channel::<ApprovalRequest>(4);
        app.set_approval_channel(rx);

        // Agent emits an approval request.
        let (responder, _resp_rx) = oneshot::channel();
        tx.send(ApprovalRequest {
            step: approval_step(),
            responder,
        })
        .await
        .unwrap();

        app.poll_approval();

        assert!(app.is_approving());
        let step = app.pending_approval_step().expect("step present");
        assert_eq!(step.capability_id, "service_restart");
        assert_eq!(step.risk_tier, RiskTier::High);
    }

    #[tokio::test]
    async fn submit_approval_approve_sends_outcome_and_resets() {
        let mut app = App::new();
        let (responder, resp_rx) = oneshot::channel();
        app.begin_approval(approval_step(), responder);
        assert!(app.is_approving());

        app.submit_approval(ApprovalOutcome::Approve);

        assert!(!app.is_approving());
        assert!(matches!(app.state, AppState::Normal));
        assert_eq!(resp_rx.await.unwrap(), ApprovalOutcome::Approve);
    }

    #[tokio::test]
    async fn submit_approval_abort_sends_outcome() {
        let mut app = App::new();
        let (responder, resp_rx) = oneshot::channel();
        app.begin_approval(approval_step(), responder);

        app.submit_approval(ApprovalOutcome::Abort);

        assert!(!app.is_approving());
        assert_eq!(resp_rx.await.unwrap(), ApprovalOutcome::Abort);
    }

    #[test]
    fn submit_approval_is_noop_when_not_approving() {
        let mut app = App::new();
        // Should not panic or change state.
        app.submit_approval(ApprovalOutcome::Approve);
        assert!(matches!(app.state, AppState::Normal));
    }
}
