use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use sentinel_core::{CapabilityKind, CoreError, PlanStep, RiskTier};
use sentinel_policy::default_policy;
use serde_json::{json, Value};

use super::*;

/// Capability whose behaviour is set per test.
struct Fake {
    manifest: CapabilityManifest,
    fail: bool,
    slow_ms: u64,
    inverse: Option<bool>, // None = no inverse, Some(ok)
    invoked: Arc<AtomicU32>,
    inverted: Arc<AtomicU32>,
}

impl Fake {
    fn new(id: &str, kind: CapabilityKind, tier: RiskTier) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: id.into(),
                name: id.into(),
                description: id.into(),
                kind,
                risk_tier: tier,
                resource_impact: Default::default(),
                has_inverse: false,
                version: "1".into(),
            },
            fail: false,
            slow_ms: 0,
            inverse: None,
            invoked: Arc::new(AtomicU32::new(0)),
            inverted: Arc::new(AtomicU32::new(0)),
        }
    }
    fn read(id: &str) -> Self {
        Self::new(id, CapabilityKind::ReadOnly, RiskTier::Low)
    }
    fn mutating(id: &str) -> Self {
        Self::new(id, CapabilityKind::Mutating, RiskTier::Medium)
    }
}

#[async_trait]
impl Capability for Fake {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    async fn invoke(&self, _args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        if self.slow_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.slow_ms)).await;
        }
        if self.fail {
            CapabilityResult::failure("boom".to_string(), false)
        } else {
            CapabilityResult::success(json!({"ok": true}))
        }
    }
    async fn dry_run(&self, _args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        CapabilityResult::dry_run(json!({}))
    }
    async fn invoke_inverse(
        &self,
        _args: Value,
        _ctx: &ExecutionContext,
    ) -> Option<CapabilityResult> {
        self.inverted.fetch_add(1, Ordering::SeqCst);
        self.inverse.map(|ok| {
            if ok {
                CapabilityResult::success(json!({}))
            } else {
                CapabilityResult::failure("cannot undo".to_string(), false)
            }
        })
    }
    fn validate_args(&self, _args: &Value) -> Result<(), CoreError> {
        Ok(())
    }
}

fn caps(list: Vec<Fake>) -> HashMap<String, Box<dyn Capability>> {
    list.into_iter()
        .map(|c| (c.manifest.id.clone(), Box::new(c) as Box<dyn Capability>))
        .collect()
}

fn plan(steps: &[(&str, bool)]) -> Plan {
    let mut p = Plan::new(Uuid::new_v4(), "goal".into(), "why".into());
    for (i, (id, can_rollback)) in steps.iter().enumerate() {
        let mut s = PlanStep::new(i as u32 + 1, *id, json!({}), "d", RiskTier::Low);
        s.can_rollback = *can_rollback;
        p.add_step(s);
    }
    p.approve();
    p
}

fn audit() -> tokio::sync::Mutex<AuditLog> {
    tokio::sync::Mutex::new(AuditLog::new(Uuid::new_v4(), None))
}

async fn kinds(log: &tokio::sync::Mutex<AuditLog>) -> Vec<String> {
    log.lock()
        .await
        .events()
        .iter()
        .map(|e| {
            serde_json::to_value(&e.event_type).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

async fn run(
    plan: &mut Plan,
    caps: &HashMap<String, Box<dyn Capability>>,
    log: &tokio::sync::Mutex<AuditLog>,
    opts: &RunOptions,
) -> RunReport {
    run_plan(
        plan,
        "localhost",
        Uuid::new_v4(),
        caps,
        &default_policy(),
        log,
        opts,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn unapproved_plan_is_refused_before_anything_runs() {
    let fake = Fake::read("a");
    let invoked = fake.invoked.clone();
    let caps = caps(vec![fake]);
    let mut p = Plan::new(Uuid::new_v4(), "g".into(), "r".into());
    p.add_step(PlanStep::new(1, "a", json!({}), "d", RiskTier::Low));
    let log = audit();
    let err = run_plan(
        &mut p,
        "h",
        Uuid::new_v4(),
        &caps,
        &default_policy(),
        &log,
        &RunOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RunError::NotApproved));
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert!(log.lock().await.events().is_empty());
}

/// Rule 1.  The default policy answers `RequiresApproval` for a Medium-risk
/// mutating capability.  The plan was approved, so the step runs.  This is
/// the behaviour `sentinel run` got wrong: it skipped these steps.
#[tokio::test]
async fn approved_plan_runs_steps_that_policy_marks_require_approval() {
    let fake = Fake::mutating("log_vacuum");
    let invoked = fake.invoked.clone();
    let caps = caps(vec![fake]);
    let mut p = plan(&[("log_vacuum", false)]);
    let log = audit();
    let r = run(&mut p, &caps, &log, &RunOptions::default()).await;

    assert_eq!(r.steps[0].state, StepState::Completed);
    assert_eq!(r.steps[0].policy.as_deref(), Some("require_approval"));
    assert_eq!(invoked.load(Ordering::SeqCst), 1);
    assert!(!r.halted);
    assert_eq!(p.steps[0].status, StepStatus::Completed);
}

#[tokio::test]
async fn denied_steps_never_run_even_in_an_approved_plan() {
    // High-risk mutating: denied by the default policy.
    let fake = Fake::new("nuke", CapabilityKind::Mutating, RiskTier::High);
    let invoked = fake.invoked.clone();
    let after = Fake::read("after");
    let after_invoked = after.invoked.clone();
    let caps = caps(vec![fake, after]);
    let mut p = plan(&[("nuke", false), ("after", false)]);
    let log = audit();
    let r = run(&mut p, &caps, &log, &RunOptions::default()).await;

    assert_eq!(r.steps[0].state, StepState::Denied);
    assert_eq!(r.steps[1].state, StepState::Skipped);
    assert!(r.halted);
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert_eq!(after_invoked.load(Ordering::SeqCst), 0);
    let k = kinds(&log).await;
    assert!(k.contains(&"PolicyDenied".to_string()));
    assert!(!k.contains(&"CapabilityInvoked".to_string()));
}

/// Rule 2.  The plan records a step as Low risk; the capability's manifest
/// says High mutating.  Policy must see the manifest.
#[tokio::test]
async fn policy_uses_the_current_manifest_not_the_tier_stored_in_the_plan() {
    let fake = Fake::new("escalated", CapabilityKind::Mutating, RiskTier::High);
    let invoked = fake.invoked.clone();
    let caps = caps(vec![fake]);
    let mut p = plan(&[("escalated", false)]);
    assert_eq!(
        p.steps[0].risk_tier,
        RiskTier::Low,
        "the plan understates the risk"
    );
    let r = run(&mut p, &caps, &audit(), &RunOptions::default()).await;
    assert_eq!(r.steps[0].state, StepState::Denied);
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
}

/// Rule 3 and 4.  The old loop executor counted a `Failure` result as a
/// completed step and carried on.
#[tokio::test]
async fn a_failure_result_fails_the_step_and_halts_the_plan() {
    let mut bad = Fake::read("bad");
    bad.fail = true;
    let next = Fake::read("next");
    let next_invoked = next.invoked.clone();
    let caps = caps(vec![bad, next]);
    let mut p = plan(&[("bad", false), ("next", false)]);
    let log = audit();
    let r = run(&mut p, &caps, &log, &RunOptions::default()).await;

    assert_eq!(r.steps[0].state, StepState::Failed);
    assert_eq!(r.steps[0].detail, "boom");
    assert_eq!(r.steps[1].state, StepState::Skipped);
    assert_eq!(next_invoked.load(Ordering::SeqCst), 0);
    assert_eq!(p.steps[0].status, StepStatus::Failed);
    assert_eq!(p.steps[1].status, StepStatus::Skipped);
    let k = kinds(&log).await;
    assert!(k.contains(&"CapabilityFailed".to_string()));
    assert!(!k.contains(&"CapabilitySucceeded".to_string()));
}

#[tokio::test]
async fn step_timeout_fails_the_step() {
    let mut slow = Fake::read("slow");
    slow.slow_ms = 2_000;
    let caps = caps(vec![slow]);
    let mut p = plan(&[("slow", false)]);
    let opts = RunOptions {
        step_timeout_ms: Some(50),
        ..Default::default()
    };
    let r = run(&mut p, &caps, &audit(), &opts).await;
    assert_eq!(r.steps[0].state, StepState::Failed);
    assert!(
        r.steps[0].detail.contains("timed out"),
        "{}",
        r.steps[0].detail
    );
    assert!(r.duration_ms < 1_500);
}

/// Rule 5.  Three completed steps, then a failure: the two that can roll
/// back are undone newest-first; the one that cannot stays Completed.
#[tokio::test]
async fn rollback_undoes_completed_steps_in_reverse_order() {
    let order = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    struct Ordered(Fake, Arc<std::sync::Mutex<Vec<String>>>);
    #[async_trait]
    impl Capability for Ordered {
        fn manifest(&self) -> &CapabilityManifest {
            self.0.manifest()
        }
        async fn invoke(&self, a: Value, c: &ExecutionContext) -> CapabilityResult {
            self.0.invoke(a, c).await
        }
        async fn dry_run(&self, a: Value, c: &ExecutionContext) -> CapabilityResult {
            self.0.dry_run(a, c).await
        }
        async fn invoke_inverse(&self, a: Value, c: &ExecutionContext) -> Option<CapabilityResult> {
            self.1.lock().unwrap().push(self.0.manifest.id.clone());
            self.0.invoke_inverse(a, c).await
        }
        fn validate_args(&self, a: &Value) -> Result<(), CoreError> {
            self.0.validate_args(a)
        }
    }

    let mut caps: HashMap<String, Box<dyn Capability>> = HashMap::new();
    for id in ["first", "second", "third"] {
        let mut f = Fake::read(id);
        f.inverse = Some(true);
        caps.insert(id.into(), Box::new(Ordered(f, order.clone())));
    }
    let mut bad = Fake::read("bad");
    bad.fail = true;
    caps.insert("bad".into(), Box::new(bad));

    let mut p = plan(&[
        ("first", true),
        ("second", false),
        ("third", true),
        ("bad", false),
    ]);
    let log = audit();
    let r = run(&mut p, &caps, &log, &RunOptions::default()).await;

    assert_eq!(*order.lock().unwrap(), ["third", "first"]);
    assert_eq!(r.steps[0].state, StepState::RolledBack);
    assert_eq!(
        r.steps[1].state,
        StepState::Completed,
        "can_rollback = false"
    );
    assert_eq!(r.steps[2].state, StepState::RolledBack);
    assert_eq!(r.steps[3].state, StepState::Failed);
    assert_eq!(p.steps[0].status, StepStatus::RolledBack);
    assert_eq!(p.steps[1].status, StepStatus::Completed);
    assert_eq!(
        kinds(&log)
            .await
            .iter()
            .filter(|k| *k == "CapabilityRolledBack")
            .count(),
        2
    );
}

/// A step is `RolledBack` only when its inverse succeeded.  The old executor
/// marked it rolled back when the inverse failed or did not exist.
#[tokio::test]
async fn failed_or_missing_inverse_leaves_the_step_completed() {
    let mut cannot = Fake::read("cannot");
    cannot.inverse = Some(false);
    let none = Fake::read("none"); // inverse: None
    let mut bad = Fake::read("bad");
    bad.fail = true;
    let caps = caps(vec![cannot, none, bad]);
    let mut p = plan(&[("cannot", true), ("none", true), ("bad", false)]);
    let log = audit();
    let r = run(&mut p, &caps, &log, &RunOptions::default()).await;

    assert_eq!(r.steps[0].state, StepState::Completed);
    assert!(r.steps[0]
        .rollback
        .as_deref()
        .unwrap()
        .contains("cannot undo"));
    assert_eq!(r.steps[1].state, StepState::Completed);
    assert!(r.steps[1]
        .rollback
        .as_deref()
        .unwrap()
        .contains("no inverse"));
    assert_eq!(r.count(StepState::RolledBack), 0);
    assert!(!kinds(&log)
        .await
        .contains(&"CapabilityRolledBack".to_string()));
}

#[tokio::test]
async fn rollback_can_be_switched_off_and_does_not_run_on_success() {
    let mut a = Fake::read("a");
    a.inverse = Some(true);
    let inverted = a.inverted.clone();
    let mut bad = Fake::read("bad");
    bad.fail = true;
    let caps = caps(vec![a, bad]);

    let mut p = plan(&[("a", true), ("bad", false)]);
    let opts = RunOptions {
        rollback: false,
        ..Default::default()
    };
    let r = run(&mut p, &caps, &audit(), &opts).await;
    assert_eq!(r.steps[0].state, StepState::Completed);
    assert_eq!(inverted.load(Ordering::SeqCst), 0);

    let mut ok = plan(&[("a", true)]);
    let r = run(&mut ok, &caps, &audit(), &RunOptions::default()).await;
    assert!(!r.halted);
    assert_eq!(
        inverted.load(Ordering::SeqCst),
        0,
        "nothing to undo after success"
    );
}

#[tokio::test]
async fn kill_switch_blocks_rollback_too() {
    let mut a = Fake::read("a");
    a.inverse = Some(true);
    let inverted = a.inverted.clone();

    // Second step trips the kill switch, then fails.
    struct Tripper(Fake, Arc<sentinel_policy::KillSwitch>);
    #[async_trait]
    impl Capability for Tripper {
        fn manifest(&self) -> &CapabilityManifest {
            self.0.manifest()
        }
        async fn invoke(&self, _a: Value, _c: &ExecutionContext) -> CapabilityResult {
            self.1.activate("operator hit stop");
            CapabilityResult::failure("stopped".to_string(), false)
        }
        async fn dry_run(&self, a: Value, c: &ExecutionContext) -> CapabilityResult {
            self.0.dry_run(a, c).await
        }
        fn validate_args(&self, _a: &Value) -> Result<(), CoreError> {
            Ok(())
        }
    }

    let policy = default_policy();
    let mut caps: HashMap<String, Box<dyn Capability>> = HashMap::new();
    caps.insert("a".into(), Box::new(a));
    caps.insert(
        "trip".into(),
        Box::new(Tripper(Fake::read("trip"), policy.kill_switch().clone())),
    );
    let mut p = plan(&[("a", true), ("trip", false)]);
    let log = audit();
    let r = run_plan(
        &mut p,
        "h",
        Uuid::new_v4(),
        &caps,
        &policy,
        &log,
        &RunOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(r.steps[0].state, StepState::Completed, "not rolled back");
    assert!(r.steps[0]
        .rollback
        .as_deref()
        .unwrap()
        .contains("refused by policy"));
    assert_eq!(inverted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_and_unimplemented_capabilities_fail_unless_stubbing_is_on() {
    let caps = caps(vec![]);
    let mut p = plan(&[("ghost", false)]);
    let r = run(&mut p, &caps, &audit(), &RunOptions::default()).await;
    assert_eq!(r.steps[0].state, StepState::Failed);
    assert!(r.steps[0].detail.contains("not registered"));

    // Manifest known, no implementation.
    struct ManifestOnly(CapabilityManifest);
    impl CapabilityLookup for ManifestOnly {
        fn implementation(&self, _id: &str) -> Option<&dyn Capability> {
            None
        }
        fn manifest(&self, id: &str) -> Option<CapabilityManifest> {
            (id == self.0.id).then(|| self.0.clone())
        }
    }
    let lookup = ManifestOnly(Fake::read("known").manifest);
    let policy = default_policy();

    let mut p = plan(&[("known", false)]);
    let r = run_plan(
        &mut p,
        "h",
        Uuid::new_v4(),
        &lookup,
        &policy,
        &audit(),
        &RunOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        r.steps[0].state,
        StepState::Failed,
        "no silent stub success"
    );

    let mut p = plan(&[("known", false)]);
    let opts = RunOptions {
        stub_unimplemented: true,
        ..Default::default()
    };
    let r = run_plan(
        &mut p,
        "h",
        Uuid::new_v4(),
        &lookup,
        &policy,
        &audit(),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(r.steps[0].state, StepState::Completed);
    assert!(r.steps[0].detail.contains("stub"));
}

/// Rule 6.  If the audit log cannot be written, nothing is invoked.
#[tokio::test]
async fn audit_failure_stops_execution_before_the_capability_runs() {
    struct Broken(AtomicBool);
    #[async_trait]
    impl AuditWriter for Broken {
        async fn record(&self, _e: AuditEventType) -> Result<(), String> {
            self.0.store(true, Ordering::SeqCst);
            Err("disk full".into())
        }
    }
    let fake = Fake::read("a");
    let invoked = fake.invoked.clone();
    let caps = caps(vec![fake]);
    let mut p = plan(&[("a", false)]);
    let broken = Broken(AtomicBool::new(false));
    let err = run_plan(
        &mut p,
        "h",
        Uuid::new_v4(),
        &caps,
        &default_policy(),
        &broken,
        &RunOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RunError::Audit(_)), "{err}");
    assert!(broken.0.load(Ordering::SeqCst));
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn audit_order_is_evaluate_invoke_outcome() {
    let caps = caps(vec![Fake::read("a")]);
    let mut p = plan(&[("a", false)]);
    let log = audit();
    run(&mut p, &caps, &log, &RunOptions::default()).await;
    assert_eq!(
        kinds(&log).await,
        [
            "PolicyEvaluated",
            "CapabilityInvoked",
            "CapabilitySucceeded"
        ]
    );
    assert!(log.lock().await.verify_chain().valid);
}
