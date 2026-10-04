//! `$SENTINEL_METRICS_FILE` through the real binary (ADR-021).

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_sentinel");

#[test]
fn mcp_session_writes_prometheus_metrics_derived_from_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let metrics = dir.path().join("sentinel.prom");

    let input = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "it", "version": "0"}}})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "sentinel_policy_check",
            "arguments": {"capability_id": "process_kill", "args": {"pid": 4242}}}})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "sentinel_policy_check",
            "arguments": {"capability_id": "disk_usage", "args": {"path": "/"}}}})
        .to_string(),
    ]
    .join("\n")
        + "\n";

    let mut child = Command::new(BIN)
        .args(["serve", "--mcp", "--state-dir", state.to_str().unwrap()])
        .env_remove("SENTINEL_POLICY")
        .env_remove("SENTINEL_AUDIT_KEY")
        .env("SENTINEL_METRICS_FILE", &metrics)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&metrics).expect("metrics file written");
    assert!(
        text.contains("sentinel_mcp_tool_calls_total{tool=\"sentinel_policy_check\"} 2"),
        "{text}"
    );

    // The event counter equals the number of lines in the audit chain: the
    // metrics are the audit stream, counted.
    let log = std::fs::read_dir(state.join("audit"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let events = std::fs::read_to_string(log).unwrap().lines().count();
    assert!(
        text.contains(&format!("sentinel_audit_events_total {events}")),
        "expected {events} events in:\n{text}"
    );
}

#[test]
fn no_metrics_file_is_written_unless_configured() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(BIN)
        .args(["policy"])
        .current_dir(dir.path())
        .env_remove("SENTINEL_METRICS_FILE")
        .env_remove("SENTINEL_POLICY")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
