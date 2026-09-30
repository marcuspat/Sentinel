//! End-to-end test of `sentinel serve --mcp` over real stdio, followed by the
//! operator-side CLI (`execute`, `approve`, `show-plan`, `reject`,
//! `verify-audit`).
//!
//! Only non-executing paths are exercised against the real binary (which
//! uses the real command executor): policy checks, a refused mutating
//! investigation, and a plan proposal.  Execution with a fake executor is
//! covered in `sentinel-mcp/tests/gate.rs`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_sentinel");

fn sentinel(state: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .arg("--state-dir")
        .arg(state)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("SENTINEL_STATE_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sentinel");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn rpc(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

fn tool(id: u64, name: &str, args: Value) -> String {
    rpc(id, "tools/call", json!({"name": name, "arguments": args}))
}

fn audit_files(state: &Path, prefix: &str) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(state.join("audit"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .collect()
}

#[test]
fn mcp_gate_proposes_but_never_executes_or_self_approves() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();

    let input = [
        rpc(
            1,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "it", "version": "0"}}),
        ),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        rpc(2, "tools/list", json!({})),
        tool(
            3,
            "sentinel_policy_check",
            json!({"capability_id": "process_kill", "args": {"pid": 4242}}),
        ),
        tool(
            4,
            "sentinel_investigate",
            json!({"capability_id": "log_vacuum", "args": {"log_dir": "/var/log/app", "older_than_days": 7}}),
        ),
        tool(
            5,
            "sentinel_propose_plan",
            json!({
                "goal": "reclaim space in /var/log/app",
                "steps": [{"capability_id": "log_vacuum", "args": {"log_dir": "/var/log/app", "older_than_days": 7}}]
            }),
        ),
        tool(6, "sentinel_approve", json!({"plan_id": "anything"})),
    ]
    .join("\n")
        + "\n";

    let out = sentinel(state, &["serve", "--mcp"], &input);
    assert!(
        out.status.success(),
        "serve exited with {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout must be pure JSON-RPC: every line parses, logs went to stderr.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let responses: Vec<Value> = stdout
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("non-JSON on stdout: {l:?}: {e}"))
        })
        .collect();
    assert_eq!(responses.len(), 6, "{stdout}");
    let by_id = |id: u64| {
        responses
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no response for id {id}"))
    };

    assert_eq!(by_id(1)["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(by_id(2)["result"]["tools"].as_array().unwrap().len(), 5);
    assert_eq!(
        by_id(3)["result"]["structuredContent"]["decision"],
        "deny",
        "{}",
        by_id(3)
    );
    assert_eq!(by_id(4)["result"]["isError"], true);
    assert_eq!(by_id(4)["result"]["structuredContent"]["executed"], false);
    let proposal = &by_id(5)["result"]["structuredContent"];
    assert_eq!(proposal["status"], "PendingApproval", "{}", by_id(5));
    assert_eq!(proposal["executed"], false);
    assert_eq!(by_id(6)["error"]["code"], -32602);
    let plan_id = proposal["plan_id"].as_str().unwrap().to_string();

    // The MCP session's audit chain: every call recorded, nothing invoked.
    let mcp_logs = audit_files(state, "mcp-");
    assert_eq!(mcp_logs.len(), 1);
    let chain = std::fs::read_to_string(&mcp_logs[0]).unwrap();
    assert_eq!(chain.matches("\"McpToolCalled\"").count(), 4);
    assert!(chain.contains("\"PlanProposed\""));
    assert!(!chain.contains("\"CapabilityInvoked\""));
    assert!(!chain.contains("\"PlanApproved\""));
    let verify = Command::new(BIN)
        .args(["verify-audit"])
        .arg(&mcp_logs[0])
        .output()
        .unwrap();
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("VALID"));

    // An unapproved plan cannot run.
    let exec = sentinel(state, &["execute", &plan_id], "");
    assert!(!exec.status.success());
    assert!(
        String::from_utf8_lossy(&exec.stderr).contains("not approved"),
        "{}",
        String::from_utf8_lossy(&exec.stderr)
    );

    // An agent piping into `sentinel approve` (no TTY) cannot approve.
    let approve = sentinel(
        state,
        &["approve", &plan_id],
        &format!("{}\n", &plan_id[..8]),
    );
    assert!(!approve.status.success());
    assert!(
        String::from_utf8_lossy(&approve.stderr).contains("not an interactive terminal"),
        "{}",
        String::from_utf8_lossy(&approve.stderr)
    );

    let show = sentinel(state, &["show-plan", &plan_id], "");
    assert!(show.status.success());
    let shown: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(shown["status"], "PendingApproval");
    assert_eq!(shown["integrity_ok"], true);

    // Rejection works without a TTY and is terminal.
    let reject = sentinel(state, &["reject", &plan_id, "--reason", "not today"], "");
    assert!(reject.status.success());
    let show = sentinel(state, &["show-plan", &plan_id], "");
    let shown: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(shown["status"], "Rejected");
    let exec = sentinel(state, &["execute", &plan_id], "");
    assert!(!exec.status.success());
}
