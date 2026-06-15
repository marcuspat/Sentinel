//! End-to-end integration tests for the Sentinel agent loop.
//!
//! These tests wire real capability implementations (via a mock executor)
//! to the reasoning loop, verifying the full
//! Investigate → Plan → Approve → Act → Audit path without hitting the OS.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sentinel_agent_llm::{
    backend::{LlmBackend, LlmResponse, Message},
    error::AgentError,
    planner::CapabilityRegistry,
    reasoning_loop::{ReasoningConfig, ReasoningLoop},
};
use sentinel_audit::AuditLog;
use sentinel_capabilities::all_capabilities;
use sentinel_core::{ApprovalDecision, CapabilityManifest, RiskTier};
use sentinel_exec::{CommandExecutorTrait, CommandOutput, ExecError};
use sentinel_policy::{KillSwitch, PolicyEvaluator, PolicyRule, RuleEffect};
use tokio::sync::Mutex;
use uuid::Uuid;

// ── Mock LLM backend ──────────────────────────────────────────────────────────

struct SequentialMockBackend {
    responses: Vec<String>,
    idx: std::sync::atomic::AtomicUsize,
}

impl SequentialMockBackend {
    fn new(responses: Vec<impl Into<String>>) -> Self {
        Self {
            responses: responses.into_iter().map(Into::into).collect(),
            idx: Default::default(),
        }
    }
}

#[async_trait]
impl LlmBackend for SequentialMockBackend {
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
        let i = self.idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let content = self.responses.get(i).cloned().unwrap_or_else(|| {
            r#"{"done_investigating": true, "reasoning": "no more responses"}"#.to_string()
        });
        Ok(LlmResponse {
            content,
            model: "mock-model".to_string(),
            input_tokens: 5,
            output_tokens: 30,
            finish_reason: "end_turn".to_string(),
        })
    }

    async fn health_check(&self) -> Result<(), AgentError> {
        Ok(())
    }
}

// ── Instrumented mock executor ────────────────────────────────────────────────
//
// Records each (program, args) invocation so tests can assert which real
// OS commands the capabilities tried to run. Returns canned stdout per
// program to keep capabilities happy.

struct RecordingExecutor {
    #[allow(clippy::type_complexity)]
    calls: Arc<Mutex<Vec<(String, Vec<String>)>>>,
}

impl RecordingExecutor {
    #[allow(clippy::type_complexity)]
    fn new() -> (Arc<Self>, Arc<Mutex<Vec<(String, Vec<String>)>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (Arc::new(Self { calls: Arc::clone(&calls) }), calls)
    }
}

#[async_trait]
impl CommandExecutorTrait for RecordingExecutor {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        _env: &HashMap<String, String>,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, ExecError> {
        let mut guard = self.calls.lock().await;
        guard.push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));

        // Return canned success output so capabilities don't fail on parse.
        let stdout = match program {
            "df" => "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   20G   30G  40% /\n",
            "du" => "20G\t/\n",
            "ps" => "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  12345  1234 ?        Ss   00:00   0:01 /sbin/init\n",
            "systemctl" => "● nginx.service - A high performance web server\n   Loaded: loaded\n   Active: active (running)\n",
            "find" => "",
            "which" => "",
            _ => "",
        };

        Ok(CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            truncated: false,
        })
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_allow_all_policy() -> Arc<PolicyEvaluator> {
    let allow_all = PolicyRule {
        id: "allow-all".into(),
        name: "Allow All (test)".into(),
        description: "Allow everything for integration tests".into(),
        effect: RuleEffect::Allow,
        conditions: vec![],
        priority: 1000,
        enabled: true,
    };
    Arc::new(PolicyEvaluator::new(vec![allow_all], KillSwitch::new(), vec![]))
}

fn make_registry_from_caps(caps: &[Box<dyn sentinel_core::Capability>]) -> Arc<CapabilityRegistry> {
    let mut registry = CapabilityRegistry::new();
    for cap in caps {
        registry.register(cap.manifest().clone());
    }
    Arc::new(registry)
}

fn fast_config() -> ReasoningConfig {
    ReasoningConfig {
        max_investigation_rounds: 5,
        max_tokens_per_call: 512,
        investigation_timeout_ms: 10_000,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// Verify that with real capabilities wired, `investigate()` calls real code
/// and returns a non-stub observation.
#[tokio::test]
async fn integration_investigate_calls_real_capability() {
    let session_id = Uuid::new_v4();
    let (executor, calls) = RecordingExecutor::new();

    let caps = all_capabilities(executor);
    let registry = make_registry_from_caps(&caps);
    let policy = make_allow_all_policy();
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, None)));

    let backend = SequentialMockBackend::new(vec![
        // Round 1: LLM requests disk_usage
        r#"{"capability_id": "disk_usage", "args": {"path": "/"}, "reasoning": "check disk"}"#,
        // Round 2: LLM declares done
        r#"{"done_investigating": true, "reasoning": "have enough info"}"#,
    ]);

    let loop_ = ReasoningLoop::new(
        Box::new(backend),
        registry,
        policy,
        Arc::clone(&audit),
        fast_config(),
    )
    .with_capabilities(caps);

    let observations = loop_
        .investigate(session_id, "Free up disk space on /", "localhost")
        .await
        .unwrap();

    // One observation recorded.
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].capability_id, "disk_usage");

    // Observation should be a real success (not stub).
    assert!(observations[0].result.is_success());
    if let sentinel_core::CapabilityResult::Success { output } = &observations[0].result {
        // Real DiskUsage returns df_output and du_output, not {"stub": true}.
        assert!(
            output.get("stub").is_none(),
            "result should not be a stub: {output}"
        );
        assert!(output.get("df_output").is_some(), "expected df_output in result");
    }

    // Verify the executor was actually called with df and du.
    let recorded = calls.lock().await;
    let programs: Vec<&str> = recorded.iter().map(|(p, _)| p.as_str()).collect();
    assert!(programs.contains(&"df"), "expected df invocation, got: {programs:?}");
    assert!(programs.contains(&"du"), "expected du invocation, got: {programs:?}");
}

/// Verify the full Investigate → Plan → Execute loop end-to-end.
#[tokio::test]
async fn integration_full_loop_investigate_plan_execute() {
    let session_id = Uuid::new_v4();
    let (executor, calls) = RecordingExecutor::new();

    let caps = all_capabilities(executor);
    let registry = make_registry_from_caps(&caps);
    let policy = make_allow_all_policy();
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, None)));

    let backend = SequentialMockBackend::new(vec![
        // Investigate round 1: check disk
        r#"{"capability_id": "disk_usage", "args": {"path": "/"}, "reasoning": "assess disk"}"#,
        // Investigate round 2: done
        r#"{"done_investigating": true, "reasoning": "ready to plan"}"#,
        // Plan response
        r#"{
            "rationale": "Disk is 40% used. Check service status to see if there are logs to vacuum.",
            "steps": [
                {
                    "capability_id": "disk_usage",
                    "args": {"path": "/var"},
                    "description": "Check /var disk usage",
                    "can_rollback": false,
                    "depends_on": []
                },
                {
                    "capability_id": "service_status",
                    "args": {"service": "nginx"},
                    "description": "Check nginx service status",
                    "can_rollback": false,
                    "depends_on": []
                }
            ]
        }"#,
    ]);

    let loop_ = ReasoningLoop::new(
        Box::new(backend),
        registry,
        policy,
        Arc::clone(&audit),
        fast_config(),
    )
    .with_capabilities(caps);

    // Investigate
    let observations = loop_
        .investigate(session_id, "Diagnose disk usage on /var", "localhost")
        .await
        .unwrap();
    assert_eq!(observations.len(), 1);

    // Plan
    let mut plan = loop_
        .plan(session_id, "Diagnose disk usage on /var", &observations)
        .await
        .unwrap();
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(plan.steps[0].capability_id, "disk_usage");
    assert_eq!(plan.steps[1].capability_id, "service_status");

    // Execute
    let summary = loop_
        .execute_plan(session_id, "localhost", &mut plan, ApprovalDecision::FullApproval)
        .await
        .unwrap();

    assert_eq!(summary.steps_completed, 2);
    assert_eq!(summary.steps_failed, 0);
    assert_eq!(summary.steps_rolled_back, 0);

    // Audit log should have events
    let log = audit.lock().await;
    assert!(log.event_count() > 0, "audit log should contain events");

    // Executor should have been called
    let recorded = calls.lock().await;
    assert!(!recorded.is_empty(), "executor should have been called");
}

/// Verify policy denial is correctly observed during investigation.
#[tokio::test]
async fn integration_policy_deny_in_investigation() {
    let session_id = Uuid::new_v4();
    let (executor, _) = RecordingExecutor::new();

    let caps = all_capabilities(executor);
    let registry = make_registry_from_caps(&caps);

    // Deny-by-default — no rules
    let policy = Arc::new(PolicyEvaluator::new(vec![], KillSwitch::new(), vec![]));
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, None)));

    let backend = SequentialMockBackend::new(vec![
        r#"{"capability_id": "disk_usage", "args": {"path": "/"}, "reasoning": "check disk"}"#,
        r#"{"done_investigating": true, "reasoning": "was denied, stopping"}"#,
    ]);

    let loop_ = ReasoningLoop::new(
        Box::new(backend),
        registry,
        policy,
        audit,
        fast_config(),
    )
    .with_capabilities(caps);

    let observations = loop_
        .investigate(session_id, "check disk", "localhost")
        .await
        .unwrap();

    assert_eq!(observations.len(), 1);
    // Observation should be a failure with "Policy denied" in the error.
    assert!(observations[0].result.is_failure());
    if let sentinel_core::CapabilityResult::Failure { error, .. } = &observations[0].result {
        assert!(error.contains("Policy denied"), "expected policy denial: {error}");
    }
}

/// Verify the audit log chain is valid after a full execution.
#[tokio::test]
async fn integration_audit_chain_valid_after_execution() {
    use sentinel_audit::verifier::AuditVerifier;

    let session_id = Uuid::new_v4();
    let (executor, _) = RecordingExecutor::new();

    let caps = all_capabilities(executor);
    let registry = make_registry_from_caps(&caps);
    let policy = make_allow_all_policy();

    // Use a temp file for the audit log so we can verify it afterward.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, Some(log_path.clone()))));

    let backend = SequentialMockBackend::new(vec![
        r#"{"done_investigating": true, "reasoning": "quick goal"}"#,
        r#"{"rationale": "just check disk", "steps": [{"capability_id": "disk_usage", "args": {"path": "/"}, "description": "check disk", "can_rollback": false, "depends_on": []}]}"#,
    ]);

    let loop_ = ReasoningLoop::new(
        Box::new(backend),
        registry,
        policy,
        Arc::clone(&audit),
        fast_config(),
    )
    .with_capabilities(caps);

    let observations = loop_.investigate(session_id, "check disk", "localhost").await.unwrap();
    let mut plan = loop_.plan(session_id, "check disk", &observations).await.unwrap();
    plan.approve();
    loop_.execute_plan(session_id, "localhost", &mut plan, ApprovalDecision::FullApproval).await.unwrap();

    // Each append is persisted immediately, so the JSONL file is already on disk.
    // Read and verify the JSONL chain
    let content = std::fs::read_to_string(&log_path).unwrap();
    let result = AuditVerifier::verify_jsonl(&content).unwrap();
    assert!(result.valid, "audit chain should be valid after execution");
    assert!(result.events_checked > 0, "should have checked at least one event");
}

/// Verify that 14 capabilities are registered and all have unique IDs.
#[tokio::test]
async fn integration_all_14_capabilities_registered() {
    let (executor, _) = RecordingExecutor::new();
    let caps = all_capabilities(executor);

    assert_eq!(caps.len(), 14, "expected exactly 14 capabilities, got {}", caps.len());

    let mut ids = std::collections::HashSet::new();
    for cap in &caps {
        let id = cap.manifest().id.clone();
        assert!(!id.is_empty(), "capability ID must not be empty");
        assert!(ids.insert(id.clone()), "duplicate capability ID: {id}");
    }
}

/// Verify stub mode still works (no capabilities injected).
#[tokio::test]
async fn integration_stub_mode_still_works() {
    let session_id = Uuid::new_v4();
    let mut registry = CapabilityRegistry::new();
    registry.register(CapabilityManifest {
        id: "disk_usage".into(),
        name: "Disk Usage".into(),
        description: "Check disk".into(),
        kind: sentinel_core::CapabilityKind::ReadOnly,
        risk_tier: RiskTier::Low,
        resource_impact: Default::default(),
        has_inverse: false,
        version: "1.0.0".into(),
    });
    let registry = Arc::new(registry);
    let policy = make_allow_all_policy();
    let audit = Arc::new(Mutex::new(AuditLog::new(session_id, None)));

    let backend = SequentialMockBackend::new(vec![
        r#"{"capability_id": "disk_usage", "args": {}, "reasoning": "check"}"#,
        r#"{"done_investigating": true, "reasoning": "done"}"#,
    ]);

    // No .with_capabilities() call — stub mode
    let loop_ = ReasoningLoop::new(Box::new(backend), registry, policy, audit, fast_config());

    let obs = loop_.investigate(session_id, "goal", "localhost").await.unwrap();
    assert_eq!(obs.len(), 1);
    assert!(obs[0].result.is_success());
    // Stub result contains {"stub": true}
    if let sentinel_core::CapabilityResult::Success { output } = &obs[0].result {
        assert_eq!(output["stub"], true, "expected stub result in stub mode");
    }
}
