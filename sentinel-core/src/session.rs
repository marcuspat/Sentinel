use serde::{Deserialize, Serialize};

use crate::capability::CapabilityResult;
use crate::error::CoreError;
use crate::plan::Plan;

/// The lifecycle phase of an agent session.
///
/// Phase transitions are validated by `Session::transition`.  Not every
/// transition is legal — see `Session::transition` for the allowed edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPhase {
    /// Gathering information about the target system.
    Investigating,
    /// Analysing observations and constructing an execution plan.
    Planning,
    /// Plan has been submitted; waiting for operator approval.
    AwaitingApproval,
    /// Approved plan steps are being executed.
    Executing,
    /// All plan steps completed successfully.
    Completed,
    /// Session was stopped due to an error or operator abort.
    Aborted { reason: String },
}

/// A single system observation recorded during the Investigating phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// Unique identifier for this observation.
    pub id: uuid::Uuid,
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
            id: uuid::Uuid::new_v4(),
            capability_id: capability_id.into(),
            args,
            result,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// A point-in-time snapshot of a session that can be used to resume it later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCheckpoint {
    /// Unique identifier for this checkpoint.
    pub checkpoint_id: uuid::Uuid,
    /// The phase the session was in when the checkpoint was taken.
    pub phase: SessionPhase,
    /// Full serialised session state as JSON.
    pub snapshot: serde_json::Value,
    /// Wall-clock time when the checkpoint was taken.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// An agent session: the top-level unit of work for Sentinel.
///
/// A session captures everything from the initial goal statement through
/// investigation, planning, approval, and execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique identifier for this session.
    pub id: uuid::Uuid,
    /// Natural-language description of what the operator wants to achieve.
    pub goal: String,
    /// Target hostname or IP address.
    pub host: String,
    /// Current lifecycle phase.
    pub phase: SessionPhase,
    /// Ordered list of observations recorded during the Investigating phase.
    pub observations: Vec<Observation>,
    /// The execution plan, once it has been created.
    pub plan: Option<Plan>,
    /// Wall-clock time when the session was started.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Wall-clock time when the session reached Completed or Aborted.
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The most recent checkpoint, if one has been taken.
    pub checkpoint: Option<SessionCheckpoint>,
}

impl Session {
    /// Create a new session in the `Investigating` phase.
    pub fn new(goal: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            goal: goal.into(),
            host: host.into(),
            phase: SessionPhase::Investigating,
            observations: Vec::new(),
            plan: None,
            started_at: chrono::Utc::now(),
            completed_at: None,
            checkpoint: None,
        }
    }

    /// Record a new observation in this session.
    pub fn record_observation(&mut self, obs: Observation) {
        self.observations.push(obs);
    }

    /// Attach an execution plan to this session.
    pub fn set_plan(&mut self, plan: Plan) {
        self.plan = Some(plan);
    }

    /// Attempt to transition the session to `phase`.
    ///
    /// # Allowed transitions
    ///
    /// ```text
    /// Investigating  → Planning
    /// Planning       → AwaitingApproval
    /// AwaitingApproval → Executing
    /// Executing      → Completed
    /// * (any)        → Aborted { .. }
    /// ```
    ///
    /// All other transitions return `Err(CoreError::InvalidPhaseTransition)`.
    pub fn transition(&mut self, phase: SessionPhase) -> Result<(), CoreError> {
        let allowed = match &self.phase {
            SessionPhase::Investigating => {
                matches!(phase, SessionPhase::Planning | SessionPhase::Aborted { .. })
            }
            SessionPhase::Planning => {
                matches!(
                    phase,
                    SessionPhase::AwaitingApproval | SessionPhase::Aborted { .. }
                )
            }
            SessionPhase::AwaitingApproval => {
                matches!(
                    phase,
                    SessionPhase::Executing | SessionPhase::Aborted { .. }
                )
            }
            SessionPhase::Executing => {
                matches!(
                    phase,
                    SessionPhase::Completed | SessionPhase::Aborted { .. }
                )
            }
            // Terminal phases — no further transitions allowed.
            SessionPhase::Completed | SessionPhase::Aborted { .. } => false,
        };

        if allowed {
            // Stamp completion time when entering a terminal phase.
            if matches!(phase, SessionPhase::Completed | SessionPhase::Aborted { .. }) {
                self.completed_at = Some(chrono::Utc::now());
            }
            self.phase = phase;
            Ok(())
        } else {
            Err(CoreError::InvalidPhaseTransition {
                from: self.phase.clone(),
                to: phase,
            })
        }
    }

    /// Take a checkpoint of the current session state.
    pub fn checkpoint(&self) -> SessionCheckpoint {
        let snapshot = serde_json::to_value(self)
            .unwrap_or_else(|_| serde_json::Value::Null);
        let cp = SessionCheckpoint {
            checkpoint_id: uuid::Uuid::new_v4(),
            phase: self.phase.clone(),
            snapshot,
            timestamp: chrono::Utc::now(),
        };
        cp
    }

    /// Restore a session from a previously taken checkpoint.
    ///
    /// Returns `Err(CoreError::Serialization(_))` if the snapshot cannot be
    /// deserialised back into a `Session`.
    pub fn restore_from_checkpoint(checkpoint: SessionCheckpoint) -> Result<Self, CoreError> {
        let session: Session = serde_json::from_value(checkpoint.snapshot)?;
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityResult;
    use crate::plan::Plan;

    fn make_session() -> Session {
        Session::new("Fix high CPU usage", "prod-web-01.example.com")
    }

    // ── SessionPhase ──────────────────────────────────────────────────────────

    #[test]
    fn phase_equality() {
        assert_eq!(SessionPhase::Investigating, SessionPhase::Investigating);
        assert_ne!(SessionPhase::Investigating, SessionPhase::Planning);
    }

    #[test]
    fn aborted_phase_carries_reason() {
        let phase = SessionPhase::Aborted {
            reason: "operator requested stop".into(),
        };
        if let SessionPhase::Aborted { reason } = &phase {
            assert_eq!(reason, "operator requested stop");
        } else {
            panic!("expected Aborted");
        }
    }

    #[test]
    fn phase_serde_roundtrip() {
        let phases: Vec<SessionPhase> = vec![
            SessionPhase::Investigating,
            SessionPhase::Planning,
            SessionPhase::AwaitingApproval,
            SessionPhase::Executing,
            SessionPhase::Completed,
            SessionPhase::Aborted { reason: "test".into() },
        ];
        for phase in &phases {
            let json = serde_json::to_string(phase).unwrap();
            let back: SessionPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, back);
        }
    }

    // ── Observation ───────────────────────────────────────────────────────────

    #[test]
    fn observation_new_stamps_timestamp() {
        let obs = Observation::new(
            "sentinel.fs.read",
            serde_json::json!({"path": "/etc/passwd"}),
            CapabilityResult::success(serde_json::json!({"lines": 42})),
        );
        assert!(!obs.id.is_nil());
        assert_eq!(obs.capability_id, "sentinel.fs.read");
        assert_eq!(obs.args["path"], "/etc/passwd");
    }

    #[test]
    fn observation_serde_roundtrip() {
        let obs = Observation::new(
            "sentinel.net.ping",
            serde_json::json!({"host": "8.8.8.8"}),
            CapabilityResult::success(serde_json::json!({"rtt_ms": 5})),
        );
        let json = serde_json::to_string(&obs).unwrap();
        let back: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, obs.id);
        assert_eq!(back.capability_id, obs.capability_id);
    }

    // ── Session::new ──────────────────────────────────────────────────────────

    #[test]
    fn session_new_starts_in_investigating() {
        let s = make_session();
        assert_eq!(s.phase, SessionPhase::Investigating);
        assert!(s.observations.is_empty());
        assert!(s.plan.is_none());
        assert!(s.completed_at.is_none());
        assert!(s.checkpoint.is_none());
        assert!(!s.id.is_nil());
    }

    #[test]
    fn session_new_stores_goal_and_host() {
        let s = make_session();
        assert_eq!(s.goal, "Fix high CPU usage");
        assert_eq!(s.host, "prod-web-01.example.com");
    }

    // ── record_observation ────────────────────────────────────────────────────

    #[test]
    fn record_observation_appends() {
        let mut s = make_session();
        let obs = Observation::new(
            "sentinel.proc.list",
            serde_json::json!({}),
            CapabilityResult::success(serde_json::json!([])),
        );
        let obs_id = obs.id;
        s.record_observation(obs);
        assert_eq!(s.observations.len(), 1);
        assert_eq!(s.observations[0].id, obs_id);
    }

    #[test]
    fn record_multiple_observations() {
        let mut s = make_session();
        for i in 0..5 {
            s.record_observation(Observation::new(
                format!("cap_{i}"),
                serde_json::json!({}),
                CapabilityResult::success(serde_json::json!(i)),
            ));
        }
        assert_eq!(s.observations.len(), 5);
    }

    // ── set_plan ──────────────────────────────────────────────────────────────

    #[test]
    fn set_plan_stores_plan() {
        let mut s = make_session();
        let plan = Plan::new(s.id, "Fix CPU".into(), "Restart runaway daemon".into());
        let plan_id = plan.id;
        s.set_plan(plan);
        assert!(s.plan.is_some());
        assert_eq!(s.plan.as_ref().unwrap().id, plan_id);
    }

    // ── transition ────────────────────────────────────────────────────────────

    #[test]
    fn valid_transition_investigating_to_planning() {
        let mut s = make_session();
        assert!(s.transition(SessionPhase::Planning).is_ok());
        assert_eq!(s.phase, SessionPhase::Planning);
    }

    #[test]
    fn valid_transition_full_happy_path() {
        let mut s = make_session();
        s.transition(SessionPhase::Planning).unwrap();
        s.transition(SessionPhase::AwaitingApproval).unwrap();
        s.transition(SessionPhase::Executing).unwrap();
        s.transition(SessionPhase::Completed).unwrap();
        assert_eq!(s.phase, SessionPhase::Completed);
        assert!(s.completed_at.is_some());
    }

    #[test]
    fn invalid_transition_investigating_to_completed() {
        let mut s = make_session();
        let err = s.transition(SessionPhase::Completed).unwrap_err();
        assert!(matches!(err, CoreError::InvalidPhaseTransition { .. }));
        // Phase must not have changed
        assert_eq!(s.phase, SessionPhase::Investigating);
    }

    #[test]
    fn invalid_transition_from_completed() {
        let mut s = make_session();
        s.transition(SessionPhase::Planning).unwrap();
        s.transition(SessionPhase::AwaitingApproval).unwrap();
        s.transition(SessionPhase::Executing).unwrap();
        s.transition(SessionPhase::Completed).unwrap();
        let err = s.transition(SessionPhase::Planning).unwrap_err();
        assert!(matches!(err, CoreError::InvalidPhaseTransition { .. }));
    }

    #[test]
    fn abort_is_allowed_from_any_non_terminal_phase() {
        let phases = [
            SessionPhase::Investigating,
            SessionPhase::Planning,
            SessionPhase::AwaitingApproval,
            SessionPhase::Executing,
        ];
        for phase in phases {
            let mut s = make_session();
            s.phase = phase;
            let result = s.transition(SessionPhase::Aborted {
                reason: "test abort".into(),
            });
            assert!(result.is_ok(), "should be able to abort from {:?}", s.phase);
            assert!(s.completed_at.is_some());
        }
    }

    #[test]
    fn abort_from_completed_is_disallowed() {
        let mut s = make_session();
        s.phase = SessionPhase::Completed;
        s.completed_at = Some(chrono::Utc::now());
        let result = s.transition(SessionPhase::Aborted {
            reason: "late abort".into(),
        });
        assert!(result.is_err());
    }

    // ── checkpoint / restore ──────────────────────────────────────────────────

    #[test]
    fn checkpoint_captures_current_state() {
        let s = make_session();
        let cp = s.checkpoint();
        assert!(!cp.checkpoint_id.is_nil());
        assert_eq!(cp.phase, s.phase);
        assert!(!cp.snapshot.is_null());
    }

    #[test]
    fn restore_from_checkpoint_round_trips() {
        let mut s = make_session();
        s.transition(SessionPhase::Planning).unwrap();
        s.record_observation(Observation::new(
            "sentinel.fs.stat",
            serde_json::json!({}),
            CapabilityResult::success(serde_json::json!({"exists": true})),
        ));
        let cp = s.checkpoint();
        let restored = Session::restore_from_checkpoint(cp).unwrap();
        assert_eq!(restored.id, s.id);
        assert_eq!(restored.goal, s.goal);
        assert_eq!(restored.host, s.host);
        assert_eq!(restored.phase, s.phase);
        assert_eq!(restored.observations.len(), 1);
    }

    #[test]
    fn restore_from_bad_snapshot_returns_error() {
        let cp = SessionCheckpoint {
            checkpoint_id: uuid::Uuid::new_v4(),
            phase: SessionPhase::Investigating,
            snapshot: serde_json::json!("this is not a session"),
            timestamp: chrono::Utc::now(),
        };
        let result = Session::restore_from_checkpoint(cp);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoreError::Serialization(_)));
    }

    // ── serde ─────────────────────────────────────────────────────────────────

    #[test]
    fn session_serde_roundtrip() {
        let s = make_session();
        let json = serde_json::to_string(&s).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, s.id);
        assert_eq!(back.goal, s.goal);
        assert_eq!(back.host, s.host);
        assert_eq!(back.phase, s.phase);
    }
}
