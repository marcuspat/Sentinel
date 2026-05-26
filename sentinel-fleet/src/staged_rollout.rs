use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::topology::HostSelector;

/// Configuration for a canary phase that precedes the main rollout stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryConfig {
    /// Selector identifying the canary host(s).
    pub selector: HostSelector,
    /// How long (in milliseconds) to observe canary results before proceeding.
    pub observation_window_ms: u64,
    /// Minimum percentage of successful canary invocations required to continue.
    pub success_threshold_percent: f64,
}

/// A single stage in a staged rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutStage {
    /// Human-readable name for this stage (e.g. "staging", "prod-us-east").
    pub name: String,
    /// Which hosts to include in this stage.
    pub selector: HostSelector,
    /// Maximum number of hosts to update simultaneously.
    pub max_parallel: usize,
    /// Milliseconds to wait after this stage completes before advancing.
    pub wait_after_ms: u64,
}

/// Lifecycle state of a staged rollout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RolloutStatus {
    /// The rollout has been created but not yet started.
    Pending,
    /// The rollout is actively executing the given stage index.
    InProgress { stage: usize },
    /// Execution was paused by an operator or error condition.
    Halted { reason: String },
    /// All stages completed successfully.
    Completed,
    /// A stage failed and the rollout cannot continue.
    Failed { stage: usize, reason: String },
}

/// A multi-stage deployment rollout with optional canary support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedRollout {
    /// Unique identifier for this rollout.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Ordered list of deployment stages.
    pub stages: Vec<RolloutStage>,
    /// Optional canary configuration run before the main stages.
    pub canary_config: Option<CanaryConfig>,
    /// If `true`, any stage failure immediately halts the rollout.
    pub halt_on_failure: bool,
    /// Index into `stages` of the stage currently being executed.
    pub current_stage: usize,
    /// Current lifecycle state.
    pub status: RolloutStatus,
}

impl StagedRollout {
    /// Create a new rollout with no stages and `Pending` status.
    pub fn new(name: String, halt_on_failure: bool) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            stages: Vec::new(),
            canary_config: None,
            halt_on_failure,
            current_stage: 0,
            status: RolloutStatus::Pending,
        }
    }

    /// Append a stage to the rollout.  Stages are executed in append order.
    pub fn add_stage(&mut self, stage: RolloutStage) {
        self.stages.push(stage);
    }

    /// Set (or replace) the canary configuration.
    pub fn set_canary(&mut self, canary: CanaryConfig) {
        self.canary_config = Some(canary);
    }

    /// Return a reference to the stage currently being executed, if any.
    ///
    /// Returns `None` when the rollout is `Pending`, `Completed`, `Failed`, or
    /// has no stages.
    pub fn current_stage(&self) -> Option<&RolloutStage> {
        match &self.status {
            RolloutStatus::InProgress { stage } => self.stages.get(*stage),
            RolloutStatus::Pending => {
                // Not started yet — return the first stage as a preview, if present.
                self.stages.first()
            }
            _ => None,
        }
    }

    /// Advance to the next stage.
    ///
    /// * When called on a `Pending` rollout, transitions to `InProgress { stage: 0 }`.
    /// * When already in progress, increments the stage index.
    /// * When the final stage is complete, transitions to `Completed`.
    ///
    /// Returns `true` if there are more stages to execute after this call,
    /// `false` if the rollout has just been marked `Completed`.
    ///
    /// Does nothing and returns `false` if the rollout is `Halted`, `Failed`,
    /// or `Completed`.
    pub fn advance(&mut self) -> bool {
        match &self.status {
            RolloutStatus::Pending => {
                if self.stages.is_empty() {
                    self.status = RolloutStatus::Completed;
                    return false;
                }
                self.current_stage = 0;
                self.status = RolloutStatus::InProgress { stage: 0 };
                // More stages remain if there is more than one.
                self.stages.len() > 1
            }
            RolloutStatus::InProgress { stage } => {
                let next = stage + 1;
                if next >= self.stages.len() {
                    self.status = RolloutStatus::Completed;
                    false
                } else {
                    self.current_stage = next;
                    self.status = RolloutStatus::InProgress { stage: next };
                    next + 1 < self.stages.len()
                }
            }
            // Terminal or halted states — no-op.
            RolloutStatus::Completed
            | RolloutStatus::Halted { .. }
            | RolloutStatus::Failed { .. } => false,
        }
    }

    /// Transition the rollout to `Halted` with the given reason.
    ///
    /// A halted rollout can be resumed by calling `advance()` — callers are
    /// responsible for implementing that logic.  This method only records the
    /// halt.
    pub fn halt(&mut self, reason: String) {
        self.status = RolloutStatus::Halted { reason };
    }

    /// Transition to `Failed` at the current stage with the given reason.
    pub fn fail(&mut self, reason: String) {
        self.status = RolloutStatus::Failed {
            stage: self.current_stage,
            reason,
        };
    }

    /// Returns `true` if the rollout is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            &self.status,
            RolloutStatus::Completed | RolloutStatus::Failed { .. }
        )
    }

    /// Returns `true` if the rollout is currently running.
    pub fn is_in_progress(&self) -> bool {
        matches!(&self.status, RolloutStatus::InProgress { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::HostSelector;

    fn make_stage(name: &str) -> RolloutStage {
        RolloutStage {
            name: name.into(),
            selector: HostSelector::All,
            max_parallel: 2,
            wait_after_ms: 0,
        }
    }

    // ── Construction ──────────────────────────────────────────────────────────

    #[test]
    fn new_rollout_is_pending() {
        let r = StagedRollout::new("deploy-v2".into(), true);
        assert_eq!(r.status, RolloutStatus::Pending);
        assert!(r.stages.is_empty());
        assert!(r.canary_config.is_none());
    }

    #[test]
    fn add_stages_appends_in_order() {
        let mut r = StagedRollout::new("test".into(), false);
        r.add_stage(make_stage("stage-1"));
        r.add_stage(make_stage("stage-2"));
        assert_eq!(r.stages.len(), 2);
        assert_eq!(r.stages[0].name, "stage-1");
        assert_eq!(r.stages[1].name, "stage-2");
    }

    #[test]
    fn set_canary_stores_config() {
        let mut r = StagedRollout::new("canary-test".into(), true);
        r.set_canary(CanaryConfig {
            selector: HostSelector::ByGroup("canary".into()),
            observation_window_ms: 5000,
            success_threshold_percent: 90.0,
        });
        assert!(r.canary_config.is_some());
        assert_eq!(
            r.canary_config.as_ref().unwrap().observation_window_ms,
            5000
        );
    }

    // ── State machine: advance ────────────────────────────────────────────────

    #[test]
    fn advance_empty_rollout_completes_immediately() {
        let mut r = StagedRollout::new("empty".into(), false);
        let more = r.advance();
        assert!(!more);
        assert_eq!(r.status, RolloutStatus::Completed);
    }

    #[test]
    fn advance_single_stage_rollout() {
        let mut r = StagedRollout::new("single".into(), false);
        r.add_stage(make_stage("only"));

        let more = r.advance(); // Pending → InProgress { stage: 0 }
        assert!(!more, "only one stage — no more after first advance");
        assert_eq!(r.status, RolloutStatus::InProgress { stage: 0 });

        let more2 = r.advance(); // InProgress { 0 } → Completed
        assert!(!more2);
        assert_eq!(r.status, RolloutStatus::Completed);
    }

    #[test]
    fn advance_through_all_stages() {
        let mut r = StagedRollout::new("multi".into(), false);
        r.add_stage(make_stage("s1"));
        r.add_stage(make_stage("s2"));
        r.add_stage(make_stage("s3"));

        assert!(r.advance()); // Pending → InProgress { 0 }, more: true
        assert_eq!(r.current_stage, 0);
        assert!(r.advance()); // InProgress { 0 } → InProgress { 1 }, more: true
        assert_eq!(r.current_stage, 1);
        let more = r.advance(); // InProgress { 1 } → InProgress { 2 }, more: false
        assert!(!more);
        assert_eq!(r.current_stage, 2);
        let done = r.advance(); // InProgress { 2 } → Completed
        assert!(!done);
        assert_eq!(r.status, RolloutStatus::Completed);
    }

    // ── State machine: halt / fail ────────────────────────────────────────────

    #[test]
    fn halt_transitions_to_halted() {
        let mut r = StagedRollout::new("halt-test".into(), true);
        r.add_stage(make_stage("s1"));
        r.advance(); // start
        r.halt("operator requested".into());
        assert!(matches!(r.status, RolloutStatus::Halted { .. }));
        assert!(!r.is_in_progress());
        assert!(!r.is_terminal());
    }

    #[test]
    fn fail_records_stage_and_reason() {
        let mut r = StagedRollout::new("fail-test".into(), true);
        r.add_stage(make_stage("s1"));
        r.add_stage(make_stage("s2"));
        r.advance(); // Pending → InProgress { 0 }
        r.fail("connection timeout".into());
        assert!(matches!(
            &r.status,
            RolloutStatus::Failed { stage: 0, reason } if reason == "connection timeout"
        ));
        assert!(r.is_terminal());
    }

    #[test]
    fn advance_is_noop_on_completed() {
        let mut r = StagedRollout::new("noop".into(), false);
        r.add_stage(make_stage("s1"));
        r.advance();
        r.advance(); // Complete
        let more = r.advance(); // Should be no-op
        assert!(!more);
        assert_eq!(r.status, RolloutStatus::Completed);
    }

    #[test]
    fn advance_is_noop_on_halted() {
        let mut r = StagedRollout::new("halt-noop".into(), false);
        r.add_stage(make_stage("s1"));
        r.advance();
        r.halt("paused".into());
        let more = r.advance(); // Should be no-op
        assert!(!more);
        assert!(matches!(r.status, RolloutStatus::Halted { .. }));
    }

    // ── current_stage accessor ────────────────────────────────────────────────

    #[test]
    fn current_stage_returns_none_when_completed() {
        let mut r = StagedRollout::new("done".into(), false);
        r.add_stage(make_stage("s1"));
        r.advance();
        r.advance(); // Completed
        assert!(r.current_stage().is_none());
    }

    #[test]
    fn current_stage_returns_correct_stage_while_running() {
        let mut r = StagedRollout::new("run".into(), false);
        r.add_stage(make_stage("first"));
        r.add_stage(make_stage("second"));
        r.advance(); // InProgress { 0 }
        assert_eq!(r.current_stage().map(|s| s.name.as_str()), Some("first"));
        r.advance(); // InProgress { 1 }
        assert_eq!(r.current_stage().map(|s| s.name.as_str()), Some("second"));
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn rollout_serde_roundtrip() {
        let mut r = StagedRollout::new("serde-test".into(), true);
        r.add_stage(make_stage("prod"));
        r.advance();

        let json = serde_json::to_string(&r).expect("serialize");
        let back: StagedRollout = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name, r.name);
        assert_eq!(back.stages.len(), 1);
        assert!(matches!(back.status, RolloutStatus::InProgress { stage: 0 }));
    }
}
