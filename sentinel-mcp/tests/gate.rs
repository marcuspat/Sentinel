//! Gate + protocol tests using the real built-in capabilities wired to a
//! counting fake executor, so "never executes" is asserted directly on the
//! number of OS commands that would have been spawned.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use sentinel_audit::AuditVerifier;
use sentinel_capabilities::all_capabilities;
use sentinel_exec::{CommandExecutorTrait, CommandOutput, ExecError};
use sentinel_mcp::{
    execute_approved_plan, index_capabilities, serve, ExecuteError, Gate, GateConfig, McpServer,
    PlanStatus, StoreError, TOOL_NAMES,
};
use sentinel_policy::default_policy;

#[derive(Default)]
struct CountingExecutor {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl CommandExecutorTrait for CountingExecutor {
    async fn run(
        &self,
        _program: &str,
        _args: &[&str],
        _env: &HashMap<String, String>,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, ExecError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CommandOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
        })
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    exec: Arc<CountingExecutor>,
    gate: Gate,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let exec = Arc::new(CountingExecutor::default());
        let caps = all_capabilities(exec.clone());
        let gate = Gate::new(GateConfig::new(dir.path()), caps, default_policy()).unwrap();
        Self {
            _dir: dir,
            exec,
            gate,
        }
    }

    fn exec_calls(&self) -> usize {
        self.exec.calls.load(Ordering::SeqCst)
    }

    fn audit_types(&self) -> Vec<String> {
        let content = std::fs::read_to_string(self.gate.audit().path()).unwrap_or_default();
        content
            .lines()
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                v["event_type"]["type"].as_str().unwrap().to_string()
            })
            .collect()
    }

    fn assert_chain_valid(&self) {
        let content = std::fs::read_to_string(self.gate.audit().path()).unwrap();
        let r = AuditVerifier::verify_jsonl(&content).unwrap();
        assert!(r.valid, "audit chain invalid: {:?}", r.error);
    }
}

async fn init(server: &mut McpServer<'_>) {
    let resp = server
        .handle_message(json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"} }
        }))
        .await
        .unwrap();
    assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
    assert!(server
        .handle_message(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .is_none());
}

async fn call(server: &mut McpServer<'_>, name: &str, args: Value) -> Value {
    server
        .handle_message(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }))
        .await
        .unwrap()
}

#[tokio::test]
async fn initialize_negotiates_and_falls_back_to_latest() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    let resp = s
        .handle_message(json!({"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}))
        .await
        .unwrap();
    assert_eq!(
        resp["result"]["protocolVersion"],
        sentinel_mcp::SUPPORTED_PROTOCOL_VERSIONS[0]
    );
    assert_eq!(resp["result"]["serverInfo"]["name"], "sentinel");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    assert_eq!(resp["id"], "a");
}

#[tokio::test]
async fn tools_require_initialize() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    let resp = s
        .handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32600);
}

#[tokio::test]
async fn tools_list_exposes_exactly_five_tools_and_no_approval() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    let resp = s
        .handle_message(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        .await
        .unwrap();
    let names: Vec<&str> = resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, TOOL_NAMES.to_vec());
    for n in &names {
        assert!(!n.contains("approve") && !n.contains("execute"), "{n}");
    }
    for t in resp["result"]["tools"].as_array().unwrap() {
        assert_eq!(t["inputSchema"]["type"], "object");
    }
}

#[tokio::test]
async fn self_approval_tool_does_not_exist_and_is_audited() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    for name in ["sentinel_approve", "approve", "sentinel_execute"] {
        let resp = call(&mut s, name, json!({"plan_id": "x"})).await;
        assert_eq!(resp["error"]["code"], -32602, "{name}");
    }
    assert_eq!(
        h.audit_types(),
        vec!["McpToolCalled", "McpToolCalled", "McpToolCalled"]
    );
    h.assert_chain_valid();
}

#[tokio::test]
async fn policy_check_is_dry_and_reports_matching_rule() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;

    let resp = call(
        &mut s,
        "sentinel_policy_check",
        json!({"capability_id": "process_kill", "args": {"pid": 4242}}),
    )
    .await;
    let body = &resp["result"]["structuredContent"];
    assert_eq!(resp["result"]["isError"], false);
    assert_eq!(body["decision"], "deny");
    assert_eq!(body["matched_rule"], "deny-high-mutating");
    assert_eq!(body["executed"], false);

    let resp = call(
        &mut s,
        "sentinel_policy_check",
        json!({"capability_id": "log_vacuum", "args": {"log_dir": "/var/log/app", "older_than_days": 7}}),
    )
    .await;
    let body = &resp["result"]["structuredContent"];
    assert_eq!(body["decision"], "require_approval");
    assert_eq!(body["matched_rule"], "require-approval-medium-mutating");
    assert_eq!(body["args_valid"], true);

    let resp = call(
        &mut s,
        "sentinel_policy_check",
        json!({"capability_id": "rm_rf_everything"}),
    )
    .await;
    assert_eq!(resp["result"]["structuredContent"]["decision"], "deny");

    assert_eq!(h.exec_calls(), 0, "policy_check must never execute");
    let types = h.audit_types();
    assert!(types.contains(&"PolicyEvaluated".to_string()));
    assert!(types.contains(&"PolicyDenied".to_string()));
    assert!(!types.contains(&"CapabilityInvoked".to_string()));
    h.assert_chain_valid();
}

#[tokio::test]
async fn investigate_refuses_mutating_capabilities() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    let resp = call(
        &mut s,
        "sentinel_investigate",
        json!({"capability_id": "log_vacuum", "args": {"log_dir": "/var/log/app", "older_than_days": 7}}),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(resp["result"]["structuredContent"]["executed"], false);
    assert_eq!(h.exec_calls(), 0);
    assert!(h.audit_types().contains(&"PolicyDenied".to_string()));
}

#[tokio::test]
async fn investigate_runs_read_only_capability_and_audits_it() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    let resp = call(
        &mut s,
        "sentinel_investigate",
        json!({"capability_id": "process_list"}),
    )
    .await;
    assert_eq!(resp["result"]["structuredContent"]["executed"], true);
    assert!(h.exec_calls() > 0);
    let types = h.audit_types();
    assert_eq!(types[0], "McpToolCalled");
    assert!(types.contains(&"PolicyEvaluated".to_string()));
    assert!(types.contains(&"CapabilityInvoked".to_string()));
    assert!(types.contains(&"ObservationRecorded".to_string()));
    h.assert_chain_valid();
}

#[tokio::test]
async fn propose_plan_stores_pending_and_never_executes() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    let resp = call(
        &mut s,
        "sentinel_propose_plan",
        json!({
            "goal": "free space on /var/log/app",
            "rationale": "logs older than a week are not needed",
            "steps": [
                {"capability_id": "disk_usage", "args": {"path": "/var/log/app"}},
                {"capability_id": "log_vacuum", "args": {"log_dir": "/var/log/app", "older_than_days": 7}}
            ]
        }),
    )
    .await;
    let body = &resp["result"]["structuredContent"];
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert_eq!(body["status"], "PendingApproval");
    assert_eq!(body["executed"], false);
    assert_eq!(body["overall_risk"], "Medium");
    let plan_id = uuid::Uuid::parse_str(body["plan_id"].as_str().unwrap()).unwrap();

    assert_eq!(h.exec_calls(), 0, "propose_plan must never execute");
    let types = h.audit_types();
    assert!(types.contains(&"PlanProposed".to_string()));
    assert!(!types.contains(&"CapabilityInvoked".to_string()));
    assert!(!types.contains(&"PlanApproved".to_string()));

    let rec = h.gate.store().load(plan_id).unwrap();
    assert_eq!(rec.status, PlanStatus::PendingApproval);
    assert!(rec.plan.steps.iter().all(|s| s.requires_approval));

    let status = call(
        &mut s,
        "sentinel_plan_status",
        json!({"plan_id": plan_id.to_string()}),
    )
    .await;
    assert_eq!(
        status["result"]["structuredContent"]["status"],
        "PendingApproval"
    );
    assert_eq!(status["result"]["structuredContent"]["integrity_ok"], true);
    h.assert_chain_valid();
}

#[tokio::test]
async fn propose_plan_rejects_policy_denied_steps_and_stores_nothing() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    let resp = call(
        &mut s,
        "sentinel_propose_plan",
        json!({
            "goal": "kill it",
            "steps": [{"capability_id": "process_kill", "args": {"pid": 4242}}]
        }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(resp["result"]["structuredContent"]["stored"], false);
    assert!(h.gate.store().list().unwrap().is_empty());
    assert_eq!(h.exec_calls(), 0);
    assert!(h.audit_types().contains(&"PolicyDenied".to_string()));
}

#[tokio::test]
async fn propose_plan_ignores_agent_supplied_risk_and_bad_args() {
    let h = Harness::new();
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    // Relative path fails the capability's own validation.
    let resp = call(
        &mut s,
        "sentinel_propose_plan",
        json!({"goal": "x", "steps": [{"capability_id": "log_vacuum", "args": {"log_dir": "var/log", "older_than_days": 1}}]}),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true);
    // Too many steps.
    let steps: Vec<Value> = (0..17)
        .map(|_| json!({"capability_id": "process_list"}))
        .collect();
    let resp = call(
        &mut s,
        "sentinel_propose_plan",
        json!({"goal": "x", "steps": steps}),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true);
    assert!(h.gate.store().list().unwrap().is_empty());
}

async fn propose_vacuum(h: &Harness) -> uuid::Uuid {
    let mut s = McpServer::new(&h.gate);
    init(&mut s).await;
    let resp = call(
        &mut s,
        "sentinel_propose_plan",
        json!({"goal": "vacuum", "steps": [{"capability_id": "log_vacuum", "args": {"log_dir": "/var/log/app", "older_than_days": 7}}]}),
    )
    .await;
    uuid::Uuid::parse_str(
        resp["result"]["structuredContent"]["plan_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn unapproved_plan_cannot_execute_then_runs_after_operator_approval() {
    let h = Harness::new();
    let plan_id = propose_vacuum(&h).await;
    let caps = index_capabilities(all_capabilities(h.exec.clone()));
    let policy = default_policy();
    let state = h.gate.config().state_dir.clone();

    let audit = sentinel_mcp::AuditSink::create(&state, "execute").unwrap();
    let err = execute_approved_plan(h.gate.store(), plan_id, &caps, &policy, &audit, 5_000)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecuteError::NotApproved {
            status: PlanStatus::PendingApproval,
            ..
        }
    ));
    assert_eq!(h.exec_calls(), 0, "unapproved plan must not run");
    assert_eq!(
        h.gate.store().load(plan_id).unwrap().status,
        PlanStatus::PendingApproval
    );

    // Operator approves out-of-band (this is what `sentinel approve` calls).
    h.gate.store().approve(plan_id, "operator", None).unwrap();
    let audit = sentinel_mcp::AuditSink::create(&state, "execute").unwrap();
    let report = execute_approved_plan(h.gate.store(), plan_id, &caps, &policy, &audit, 5_000)
        .await
        .unwrap();
    assert_eq!(report.status, PlanStatus::Executed, "{report:?}");
    assert!(h.exec_calls() > 0);
    let content = std::fs::read_to_string(audit.path()).unwrap();
    assert!(AuditVerifier::verify_jsonl(&content).unwrap().valid);
    assert!(content.contains("CapabilityInvoked"));

    // A plan cannot be executed twice.
    let audit = sentinel_mcp::AuditSink::create(&state, "execute").unwrap();
    assert!(matches!(
        execute_approved_plan(h.gate.store(), plan_id, &caps, &policy, &audit, 5_000).await,
        Err(ExecuteError::NotApproved { .. })
    ));
}

#[tokio::test]
async fn plan_edited_after_approval_is_refused() {
    let h = Harness::new();
    let plan_id = propose_vacuum(&h).await;
    h.gate.store().approve(plan_id, "operator", None).unwrap();

    // Attacker with write access to the state dir swaps the step args and
    // recomputes content_hash — approved_hash still pins the original.
    let mut rec = h.gate.store().load(plan_id).unwrap();
    rec.plan.steps[0].args = json!({"log_dir": "/home", "older_than_days": 0});
    rec.content_hash = rec.recompute_hash();
    h.gate.store().save(&rec).unwrap();

    let caps = index_capabilities(all_capabilities(h.exec.clone()));
    let audit = sentinel_mcp::AuditSink::create(&h.gate.config().state_dir, "execute").unwrap();
    let err = execute_approved_plan(
        h.gate.store(),
        plan_id,
        &caps,
        &default_policy(),
        &audit,
        5_000,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        ExecuteError::Store(StoreError::IntegrityMismatch(_))
    ));
    assert_eq!(h.exec_calls(), 0);
}

#[tokio::test]
async fn stdio_transport_handles_framing_errors_and_notifications() {
    let h = Harness::new();
    let (client, server_side) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (client_read, mut client_write) = tokio::io::split(client);

    let gate = &h.gate;
    let server = serve(gate, BufReader::new(server_read), server_write);

    let client_task = async move {
        let mut lines = BufReader::new(client_read).lines();
        let msgs = [
            "this is not json".to_string(),
            "[]".to_string(),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
            json!({"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}).to_string(),
            json!({"jsonrpc":"2.0","id":8,"method":"ping"}).to_string(),
            json!({"jsonrpc":"2.0","id":9,"method":"resources/list"}).to_string(),
        ];
        let input = msgs.join("\n") + "\n";
        client_write.write_all(input.as_bytes()).await.unwrap();
        // Oversized line.
        let big = "x".repeat(sentinel_mcp::server::MAX_LINE_BYTES + 10);
        client_write.write_all(big.as_bytes()).await.unwrap();
        client_write.write_all(b"\n").await.unwrap();
        client_write.shutdown().await.unwrap();

        let mut out = Vec::new();
        while let Some(line) = lines.next_line().await.unwrap() {
            out.push(serde_json::from_str::<Value>(&line).unwrap());
        }
        out
    };

    let (srv, out) = tokio::join!(server, client_task);
    srv.unwrap();
    assert_eq!(out.len(), 6, "{out:?}");
    assert_eq!(out[0]["error"]["code"], -32700);
    assert_eq!(out[1]["error"]["code"], -32600);
    assert_eq!(out[2]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(out[3]["id"], 8);
    assert!(out[3]["result"].is_object());
    assert_eq!(out[4]["error"]["code"], -32601);
    assert_eq!(out[5]["error"]["code"], -32600);
}
