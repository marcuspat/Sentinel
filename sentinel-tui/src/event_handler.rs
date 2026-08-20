use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use uuid::Uuid;

use crate::app::{App, ApprovalOutcome, SessionUpdate, StepStatus, Tab};

/// Events that the TUI event loop dispatches.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// A keyboard input event from crossterm.
    Key(KeyEvent),
    /// Periodic clock tick used to refresh the UI.
    Tick,
    /// An update from the running background agent session.
    SessionUpdate(SessionUpdate),
    /// The agent has proposed a new plan.
    PlanProposed(crate::app::Plan),
    /// A plan step's status changed.
    ExecutionProgress { step_id: Uuid, status: StepStatus },
}

/// Process a single `AppEvent`, mutating `app` state accordingly.
///
/// Returns `Ok(())` in all normal cases.  Returns `Err` only on I/O errors
/// that prevent the TUI from continuing.
pub async fn handle_events(
    app: &mut App,
    event: AppEvent,
) -> Result<(), anyhow::Error> {
    // Surface any pending approval request from the agent before handling the
    // event, so a freshly-arrived request blocks input on this same pass.
    app.poll_approval();

    match event {
        AppEvent::Key(key) => handle_key(app, key),
        AppEvent::Tick => {
            // Periodic tick â nothing to do beyond the approval poll above.
        }
        AppEvent::SessionUpdate(update) => {
            app.apply_session_update(update);
        }
        AppEvent::PlanProposed(plan) => {
            app.apply_session_update(SessionUpdate::PlanProposed(plan));
        }
        AppEvent::ExecutionProgress { step_id, status } => {
            app.apply_session_update(SessionUpdate::StepCompleted { step_id, status });
        }
    }
    Ok(())
}

/// Handle a raw keyboard event.
fn handle_key(app: &mut App, key: KeyEvent) {
    // A blocking approval modal owns all input while active: only y/n/Esc act.
    if app.is_approving() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.submit_approval(ApprovalOutcome::Approve);
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.submit_approval(ApprovalOutcome::Abort);
            }
            _ => {}
        }
        return;
    }

    // Ctrl-C or Ctrl-Q always quits, regardless of tab.
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => {
                app.should_quit = true;
                return;
            }
            _ => {}
        }
    }

    match key.code {
        // ââ Global quit âââââââââââââââââââââââââââââââââââââââââââââââââââ
        KeyCode::Char('q') | KeyCode::Esc => {
            // On the Goal tab, Esc clears the input; on other tabs it quits.
            if app.current_tab == Tab::Goal && key.code == KeyCode::Esc {
                app.goal_input.clear();
                app.input_cursor = 0;
            } else {
                app.should_quit = true;
            }
        }

        // ââ Tab navigation ââââââââââââââââââââââââââââââââââââââââââââââââ
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.prev_tab(),

        // ââ Scrolling âââââââââââââââââââââââââââââââââââââââââââââââââââââ
        KeyCode::Down | KeyCode::Char('j') => {
            match app.current_tab {
                Tab::Plan => app.plan_scroll_down(),
                _ => app.scroll_log_down(),
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            match app.current_tab {
                Tab::Plan => app.plan_scroll_up(),
                _ => app.scroll_log_up(),
            }
        }

        // ââ Plan approval actions âââââââââââââââââââââââââââââââââââââââââ
        KeyCode::Char('a') if app.current_tab == Tab::Plan => {
            app.approve_all();
        }
        KeyCode::Char('s') if app.current_tab == Tab::Plan => {
            // Step-by-step approval: approve the currently selected step.
            let idx = app.plan_view.selected_index;
            app.approve_step(idx);
        }
        KeyCode::Char('r') if app.current_tab == Tab::Plan => {
            app.reject_plan("Rejected by operator.".into());
        }
        // Off the Plan tab these three keys are swallowed rather than falling
        // through to the Goal-tab text input below. Removing these arms would
        // change behaviour: 'a', 's' and 'r' would start inserting characters.
        KeyCode::Char('a') | KeyCode::Char('s') | KeyCode::Char('r') => {}

        // ââ Goal input (only on Goal tab) âââââââââââââââââââââââââââââââââ
        KeyCode::Enter if app.current_tab == Tab::Goal => {
            // Use the host and dry_run stored in app state (set from CLI args
            // in run_tui) rather than hardcoded defaults.
            let host = app.host.clone();
            let dry_run = app.dry_run;
            app.start_session(host, dry_run);
        }
        KeyCode::Char(c) if app.current_tab == Tab::Goal => {
            // Insert character at cursor position.
            app.goal_input.insert(app.input_cursor, c);
            app.input_cursor += 1;
        }
        KeyCode::Backspace if app.current_tab == Tab::Goal && app.input_cursor > 0 => {
            app.input_cursor -= 1;
            app.goal_input.remove(app.input_cursor);
        }
        KeyCode::Left if app.input_cursor > 0 => {
            app.input_cursor -= 1;
        }
        KeyCode::Right if app.input_cursor < app.goal_input.len() => {
            app.input_cursor += 1;
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    // ââ Quit ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    #[test]
    fn q_sets_should_quit_on_non_goal_tab() {
        let mut app = App::new();
        app.current_tab = Tab::Execution;
        handle_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn ctrl_c_sets_should_quit() {
        let mut app = App::new();
        handle_key(
            &mut app,
            key_with_mod(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );
        assert!(app.should_quit);
    }

    // ââ Tab navigation ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    #[test]
    fn tab_key_advances_tab() {
        let mut app = App::new();
        let initial = app.current_tab;
        handle_key(&mut app, key(KeyCode::Tab));
        assert_ne!(app.current_tab, initial);
    }

    #[test]
    fn back_tab_retreats_tab() {
        let mut app = App::new();
        app.current_tab = Tab::Plan;
        handle_key(&mut app, key(KeyCode::BackTab));
        assert_eq!(app.current_tab, Tab::Investigation);
    }

    // ââ Goal input ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    #[test]
    fn char_keys_append_to_goal_on_goal_tab() {
        let mut app = App::new();
        handle_key(&mut app, key(KeyCode::Char('f')));
        handle_key(&mut app, key(KeyCode::Char('i')));
        handle_key(&mut app, key(KeyCode::Char('x')));
        assert_eq!(app.goal_input, "fix");
    }

    #[test]
    fn backspace_removes_last_char() {
        let mut app = App::new();
        app.goal_input = "ab".into();
        app.input_cursor = 2;
        handle_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.goal_input, "a");
    }

    #[test]
    fn enter_starts_session_when_goal_is_set() {
        let mut app = App::new();
        app.goal_input = "restart sshd".into();
        handle_key(&mut app, key(KeyCode::Enter));
        assert!(app.session.is_some());
        assert_eq!(app.current_tab, Tab::Investigation);
        // pending_goal should be set for the agent task spawn
        assert_eq!(app.pending_goal.as_deref(), Some("restart sshd"));
    }

    #[test]
    fn enter_uses_app_host_not_hardcoded_localhost() {
        let mut app = App::new();
        app.host = "prod-web-01".to_string();
        app.goal_input = "check logs".into();
        handle_key(&mut app, key(KeyCode::Enter));
        let session = app.session.as_ref().unwrap();
        assert_eq!(session.host, "prod-web-01");
    }

    // ââ Plan approval âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    #[test]
    fn a_key_approves_all_on_plan_tab() {
        use crate::app::{Plan, PlanStep};
        use sentinel_core::RiskTier;
        let mut app = App::new();
        app.current_tab = Tab::Plan;
        let plan = Plan::new(
            "test",
            vec![PlanStep::new(
                "step1",
                "cap1",
                serde_json::json!({}),
                RiskTier::Low,
            )],
        );
        app.plan_view.load_plan(&plan);
        handle_key(&mut app, key(KeyCode::Char('a')));
        assert!(app.plan_view.steps[0].approved);
    }

    #[test]
    fn r_key_rejects_plan_on_plan_tab() {
        let mut app = App::new();
        app.current_tab = Tab::Plan;
        app.session = Some(crate::app::Session::new("g", "h", false));
        handle_key(&mut app, key(KeyCode::Char('r')));
        assert!(matches!(
            app.plan_view.approval_mode,
            Some(crate::app::ApprovalDecision::Reject { .. })
        ));
    }

    // ââ Scroll ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    #[test]
    fn j_key_scrolls_down_on_investigation_tab() {
        let mut app = App::new();
        app.current_tab = Tab::Investigation;
        handle_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(app.log_scroll, 1);
    }

    #[test]
    fn k_key_scrolls_up_on_investigation_tab() {
        let mut app = App::new();
        app.current_tab = Tab::Investigation;
        app.log_scroll = 3;
        handle_key(&mut app, key(KeyCode::Char('k')));
        assert_eq!(app.log_scroll, 2);
    }

    // ââ Interactive approval modal ââââââââââââââââââââââââââââââââââââââââââââ

    fn approving_app() -> (App, tokio::sync::oneshot::Receiver<ApprovalOutcome>) {
        use crate::app::PlanStep;
        use sentinel_core::RiskTier;
        let mut app = App::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let step = PlanStep::new(
            "Restart nginx",
            "service_restart",
            serde_json::json!({ "service": "nginx" }),
            RiskTier::High,
        );
        app.begin_approval(step, tx);
        (app, rx)
    }

    #[test]
    fn y_key_approves_during_modal() {
        let (mut app, mut rx) = approving_app();
        handle_key(&mut app, key(KeyCode::Char('y')));
        assert!(!app.is_approving());
        assert_eq!(rx.try_recv().unwrap(), ApprovalOutcome::Approve);
    }

    #[test]
    fn n_key_aborts_during_modal() {
        let (mut app, mut rx) = approving_app();
        handle_key(&mut app, key(KeyCode::Char('n')));
        assert!(!app.is_approving());
        assert_eq!(rx.try_recv().unwrap(), ApprovalOutcome::Abort);
    }

    #[test]
    fn esc_aborts_during_modal() {
        let (mut app, mut rx) = approving_app();
        handle_key(&mut app, key(KeyCode::Esc));
        assert!(!app.is_approving());
        assert_eq!(rx.try_recv().unwrap(), ApprovalOutcome::Abort);
    }

    #[test]
    fn other_key_does_nothing_during_modal() {
        let (mut app, _rx) = approving_app();
        handle_key(&mut app, key(KeyCode::Char('x')));
        // Still blocking on approval; modal not dismissed.
        assert!(app.is_approving());
        handle_key(&mut app, key(KeyCode::Tab));
        assert!(app.is_approving());
    }

    // ââ Async handle_events âââââââââââââââââââââââââââââââââââââââââââââââââââ

    #[tokio::test]
    async fn handle_tick_is_noop() {
        let mut app = App::new();
        handle_events(&mut app, AppEvent::Tick).await.unwrap();
        assert!(!app.should_quit);
    }

    #[tokio::test]
    async fn handle_session_update_event() {
        let mut app = App::new();
        app.session = Some(crate::app::Session::new("g", "h", false));
        handle_events(
            &mut app,
            AppEvent::SessionUpdate(SessionUpdate::SessionCompleted),
        )
        .await
        .unwrap();
        assert_eq!(app.current_tab, Tab::Audit);
    }
}
