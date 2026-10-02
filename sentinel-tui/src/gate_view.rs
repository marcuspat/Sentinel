//! The TUI's Gate tab: plans proposed through the MCP gate, with approve and
//! reject (SPEC A.7 #1).
//!
//! Decisions go through `sentinel_mcp::approve_plan` / `reject_plan`, the
//! same functions the CLI uses, so the audit events and checks are identical.
//! Approving asks the operator to type the first eight characters of the
//! plan id, the same confirmation `sentinel approve` requires.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use sentinel_mcp::{default_state_dir, PlanStatus, PlanStore, StoredPlan};
use uuid::Uuid;

/// A decision awaiting confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    /// Approve `plan_id` once `typed` equals the first 8 chars of the id.
    Approve { plan_id: Uuid, typed: String },
    /// Reject `plan_id` on `y`.
    Reject { plan_id: Uuid },
}

/// State of the Gate tab.
#[derive(Debug)]
pub struct GateView {
    state_dir: PathBuf,
    pub plans: Vec<StoredPlan>,
    pub selected: usize,
    pub confirm: Option<Confirm>,
    /// Outcome of the last action or load, shown under the list.
    pub message: Option<String>,
}

impl Default for GateView {
    /// `$SENTINEL_STATE_DIR` when set, otherwise the default state dir: the
    /// same resolution the `plans` / `approve` commands use.
    fn default() -> Self {
        let dir = std::env::var_os("SENTINEL_STATE_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_state_dir);
        Self::new(dir)
    }
}

impl GateView {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            plans: Vec::new(),
            selected: 0,
            confirm: None,
            message: None,
        }
    }

    pub fn state_dir(&self) -> &std::path::Path {
        &self.state_dir
    }

    /// Reload the plan list from disk.  Pending plans sort first, newest
    /// first within each group.
    pub fn refresh(&mut self) {
        // Looking must not create anything: `PlanStore::open` makes the
        // directory, so only open a store that already exists.
        if !self.state_dir.join("plans").is_dir() {
            self.plans.clear();
            self.selected = 0;
            return;
        }
        match PlanStore::open(&self.state_dir).and_then(|s| s.list()) {
            Ok(mut plans) => {
                plans.sort_by_key(|p| {
                    (
                        p.status != PlanStatus::PendingApproval,
                        std::cmp::Reverse(p.proposed_at),
                    )
                });
                self.plans = plans;
                self.selected = self.selected.min(self.plans.len().saturating_sub(1));
            }
            Err(e) => {
                self.plans.clear();
                self.selected = 0;
                self.message = Some(format!("could not read plans: {e}"));
            }
        }
    }

    pub fn selected_plan(&self) -> Option<&StoredPlan> {
        self.plans.get(self.selected)
    }

    pub fn pending_count(&self) -> usize {
        self.plans
            .iter()
            .filter(|p| p.status == PlanStatus::PendingApproval)
            .count()
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.plans.len() {
            self.selected += 1;
        }
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Start an approve or reject confirmation for the selected plan.
    fn begin(&mut self, approve: bool) {
        let Some(plan) = self.selected_plan() else {
            return;
        };
        let plan_id = plan.plan.id;
        if let Err(e) = sentinel_mcp::check_approvable(plan) {
            // Same refusal the CLI gives: not pending, or tampered with.
            self.message = Some(e.to_string());
            return;
        }
        self.message = None;
        self.confirm = Some(if approve {
            Confirm::Approve {
                plan_id,
                typed: String::new(),
            }
        } else {
            Confirm::Reject { plan_id }
        });
    }

    /// Handle a key while the Gate tab is active.  Returns `true` when the
    /// key was consumed (the caller must not treat it as a global shortcut).
    pub async fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.confirm.clone() {
            Some(Confirm::Approve { plan_id, mut typed }) => {
                match key.code {
                    KeyCode::Esc => {
                        self.confirm = None;
                        self.message = Some("approval cancelled".into());
                    }
                    KeyCode::Backspace => {
                        typed.pop();
                        self.confirm = Some(Confirm::Approve { plan_id, typed });
                    }
                    KeyCode::Enter => {
                        self.confirm = None;
                        if typed == plan_id.to_string()[..8] {
                            self.approve(plan_id).await;
                        } else {
                            self.message =
                                Some("confirmation did not match; plan left pending".into());
                        }
                    }
                    KeyCode::Char(c) if typed.len() < 8 => {
                        typed.push(c);
                        self.confirm = Some(Confirm::Approve { plan_id, typed });
                    }
                    _ => {}
                }
                true
            }
            Some(Confirm::Reject { plan_id }) => {
                self.confirm = None;
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => self.reject(plan_id).await,
                    _ => self.message = Some("rejection cancelled".into()),
                }
                true
            }
            None => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_down();
                    true
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_up();
                    true
                }
                KeyCode::Char('a') => {
                    self.begin(true);
                    true
                }
                KeyCode::Char('x') => {
                    self.begin(false);
                    true
                }
                KeyCode::Char('r') => {
                    self.refresh();
                    self.message = Some(format!("{} plan(s) loaded", self.plans.len()));
                    true
                }
                _ => false,
            },
        }
    }

    async fn approve(&mut self, plan_id: Uuid) {
        let who = sentinel_mcp::operator_identity();
        let result = match PlanStore::open(&self.state_dir) {
            Ok(store) => {
                sentinel_mcp::approve_plan(&store, &self.state_dir, plan_id, &who, "operator_tui")
                    .await
                    .map(|_| ())
            }
            Err(e) => Err(e.into()),
        };
        self.message = Some(match result {
            Ok(()) => format!("approved {plan_id}; run `sentinel execute {plan_id}`"),
            Err(e) => format!("not approved: {e}"),
        });
        self.refresh();
    }

    async fn reject(&mut self, plan_id: Uuid) {
        let who = sentinel_mcp::operator_identity();
        let result = match PlanStore::open(&self.state_dir) {
            Ok(store) => sentinel_mcp::reject_plan(
                &store,
                &self.state_dir,
                plan_id,
                &who,
                "rejected by operator in the TUI",
            )
            .await
            .map(|_| ()),
            Err(e) => Err(e.into()),
        };
        self.message = Some(match result {
            Ok(()) => format!("rejected {plan_id}"),
            Err(e) => format!("not rejected: {e}"),
        });
        self.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use sentinel_core::{Plan, PlanStep, RiskTier};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    async fn type_str(view: &mut GateView, s: &str) {
        for c in s.chars() {
            view.handle_key(key(KeyCode::Char(c))).await;
        }
    }

    fn store_plan(state: &std::path::Path, goal: &str) -> Uuid {
        let mut p = Plan::new(Uuid::new_v4(), goal.into(), "why".into());
        p.add_step(PlanStep::new(
            1,
            "log_vacuum",
            serde_json::json!({"log_dir": "/var/log/app", "older_than_days": 7}),
            "vacuum",
            RiskTier::Medium,
        ));
        let id = p.id;
        let store = PlanStore::open(state).unwrap();
        store
            .save(&StoredPlan::new_pending(
                p,
                "localhost",
                Uuid::new_v4(),
                None,
            ))
            .unwrap();
        id
    }

    fn status(state: &std::path::Path, id: Uuid) -> PlanStatus {
        PlanStore::open(state).unwrap().load(id).unwrap().status
    }

    fn audit_text(state: &std::path::Path) -> String {
        let mut all = String::new();
        if let Ok(dir) = std::fs::read_dir(state.join("audit")) {
            for e in dir {
                all.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap());
            }
        }
        all
    }

    #[tokio::test]
    async fn approving_requires_typing_the_plan_id_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let id = store_plan(dir.path(), "free disk");
        let mut view = GateView::new(dir.path().to_path_buf());
        view.refresh();
        assert_eq!(view.pending_count(), 1);

        assert!(view.handle_key(key(KeyCode::Char('a'))).await);
        assert!(matches!(view.confirm, Some(Confirm::Approve { .. })));

        // Wrong text: nothing happens to the plan.
        type_str(&mut view, "deadbeef").await;
        view.handle_key(key(KeyCode::Enter)).await;
        assert_eq!(status(dir.path(), id), PlanStatus::PendingApproval);
        assert!(view.message.as_deref().unwrap().contains("did not match"));
        assert!(!audit_text(dir.path()).contains("PlanApproved"));

        // Right text approves, through the same path as the CLI.
        view.handle_key(key(KeyCode::Char('a'))).await;
        type_str(&mut view, &id.to_string()[..8]).await;
        view.handle_key(key(KeyCode::Enter)).await;
        assert_eq!(status(dir.path(), id), PlanStatus::Approved);
        let audit = audit_text(dir.path());
        assert!(audit.contains("PlanApproved") && audit.contains("operator_tui"));
        assert_eq!(view.pending_count(), 0);
    }

    #[tokio::test]
    async fn escape_cancels_and_enter_alone_does_not_approve() {
        let dir = tempfile::tempdir().unwrap();
        let id = store_plan(dir.path(), "g");
        let mut view = GateView::new(dir.path().to_path_buf());
        view.refresh();

        view.handle_key(key(KeyCode::Char('a'))).await;
        view.handle_key(key(KeyCode::Enter)).await; // nothing typed
        assert_eq!(status(dir.path(), id), PlanStatus::PendingApproval);

        view.handle_key(key(KeyCode::Char('a'))).await;
        type_str(&mut view, &id.to_string()[..8]).await;
        view.handle_key(key(KeyCode::Esc)).await;
        assert!(view.confirm.is_none());
        assert_eq!(status(dir.path(), id), PlanStatus::PendingApproval);
    }

    #[tokio::test]
    async fn reject_needs_y_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let id = store_plan(dir.path(), "g");
        let mut view = GateView::new(dir.path().to_path_buf());
        view.refresh();

        view.handle_key(key(KeyCode::Char('x'))).await;
        view.handle_key(key(KeyCode::Char('n'))).await;
        assert_eq!(status(dir.path(), id), PlanStatus::PendingApproval);

        view.handle_key(key(KeyCode::Char('x'))).await;
        view.handle_key(key(KeyCode::Char('y'))).await;
        assert_eq!(status(dir.path(), id), PlanStatus::Rejected);
        assert!(audit_text(dir.path()).contains("PlanRejected"));
    }

    #[tokio::test]
    async fn decided_and_tampered_plans_cannot_be_approved() {
        let dir = tempfile::tempdir().unwrap();
        let id = store_plan(dir.path(), "g");
        let store = PlanStore::open(dir.path()).unwrap();

        // Tamper with the stored plan after it was proposed.
        let mut rec = store.load(id).unwrap();
        rec.plan.steps[0].args = serde_json::json!({"log_dir": "/", "older_than_days": 0});
        store.save(&rec).unwrap();

        let mut view = GateView::new(dir.path().to_path_buf());
        view.refresh();
        view.handle_key(key(KeyCode::Char('a'))).await;
        assert!(view.confirm.is_none(), "no confirmation is even offered");
        assert!(view.message.as_deref().unwrap().contains("integrity"));

        // A plan that is already decided is refused the same way.
        let id2 = store_plan(dir.path(), "second");
        store.reject(id2, "bob", "no", None).unwrap();
        view.refresh();
        view.selected = view.plans.iter().position(|p| p.plan.id == id2).unwrap();
        view.handle_key(key(KeyCode::Char('a'))).await;
        assert!(view.confirm.is_none());
        assert!(view
            .message
            .as_deref()
            .unwrap()
            .contains("not PendingApproval"));
    }

    #[tokio::test]
    async fn pending_plans_sort_first_and_navigation_is_clamped() {
        let dir = tempfile::tempdir().unwrap();
        let a = store_plan(dir.path(), "a");
        let _b = store_plan(dir.path(), "b");
        PlanStore::open(dir.path())
            .unwrap()
            .reject(a, "bob", "no", None)
            .unwrap();
        let mut view = GateView::new(dir.path().to_path_buf());
        view.refresh();
        assert_eq!(view.plans[0].status, PlanStatus::PendingApproval);
        assert_eq!(view.plans[1].plan.id, a);

        view.handle_key(key(KeyCode::Up)).await;
        assert_eq!(view.selected, 0);
        for _ in 0..5 {
            view.handle_key(key(KeyCode::Down)).await;
        }
        assert_eq!(view.selected, 1);
        // Keys the tab does not own are left for the global handler.
        assert!(!view.handle_key(key(KeyCode::Tab)).await);
        assert!(!view.handle_key(key(KeyCode::Char('q'))).await);
    }

    #[tokio::test]
    async fn empty_or_missing_state_dir_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut view = GateView::new(dir.path().join("fresh"));
        view.refresh();
        assert!(view.plans.is_empty());
        assert!(
            !dir.path().join("fresh").exists(),
            "refresh must not create the state dir"
        );
        assert!(!view.handle_key(key(KeyCode::Enter)).await);
        view.handle_key(key(KeyCode::Char('a'))).await;
        assert!(view.confirm.is_none());
    }
}
