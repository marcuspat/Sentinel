//! `--policy FILE` / `$SENTINEL_POLICY` through the real binary (ADR-018).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_sentinel");

fn run(args: &[&str], policy_env: Option<&Path>, stdin: &str) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("SENTINEL_STATE_DIR")
        .env_remove("SENTINEL_POLICY")
        .env_remove("SENTINEL_AUDIT_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = policy_env {
        cmd.env("SENTINEL_POLICY", p);
    }
    let mut child = cmd.spawn().expect("spawn sentinel");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn write_policy(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("policy.toml");
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

const POLICY: &str = r#"
version = 1

[[rule]]
id = "no-process-list"
description = "Process listings are off limits here"
effect = "deny"
priority = 10
[rule.when]
capability_id = "process_list"

[[guard]]
id = "app-data"
protected_services = ["postgresql"]
"#;

fn policy_check(state: &Path, policy_args: &[&str], policy_env: Option<&Path>) -> Value {
    let input = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "it", "version": "0"}}})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "sentinel_policy_check",
            "arguments": {"capability_id": "process_list", "args": {}}}})
        .to_string(),
    ]
    .join("\n")
        + "\n";
    let mut args = policy_args.to_vec();
    args.extend_from_slice(&["serve", "--mcp", "--state-dir", state.to_str().unwrap()]);
    let out = run(&args, policy_env, &input);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|r| r["id"] == 2)
        .expect("response to the policy check")["result"]["structuredContent"]
        .clone()
}

#[test]
fn policy_file_tightens_what_the_mcp_gate_allows() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(dir.path(), POLICY);

    // Built-in policy: process_list is a low-risk read and is allowed.
    let default = policy_check(&dir.path().join("s1"), &[], None);
    assert_eq!(default["decision"], "allow", "{default}");

    // Same question with the file, given as a flag …
    let flagged = policy_check(
        &dir.path().join("s2"),
        &["--policy", policy.to_str().unwrap()],
        None,
    );
    assert_eq!(flagged["decision"], "deny", "{flagged}");
    assert_eq!(flagged["matched_rule"], "no-process-list");

    // … and through the environment.
    let via_env = policy_check(&dir.path().join("s3"), &[], Some(&policy));
    assert_eq!(via_env["decision"], "deny", "{via_env}");
}

#[test]
fn policy_command_shows_file_rules_and_guards() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(dir.path(), POLICY);
    let out = run(&["--policy", policy.to_str().unwrap(), "policy"], None, "");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Tightening rules from the policy file"),
        "{text}"
    );
    assert!(text.contains("no-process-list"), "{text}");
    assert!(text.contains("app-data"), "{text}");
    // Built-in rules and guards are still listed: nothing was replaced.
    assert!(text.contains("deny-critical"), "{text}");
    assert!(text.contains("system-paths"), "{text}");

    // Without a file there is no tightening section.
    let out = run(&["policy"], None, "");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Default Sentinel policy"));
    assert!(!text.contains("Tightening rules"));
}

#[test]
fn invalid_policy_file_stops_every_command() {
    let dir = tempfile::tempdir().unwrap();
    let bad = write_policy(dir.path(), "version = 1\nrules = []\n");
    let state = dir.path().join("state");

    let out = run(&["--policy", bad.to_str().unwrap(), "policy"], None, "");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown field"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The gate must refuse to start rather than fall back to the default.
    let out = run(
        &[
            "--policy",
            bad.to_str().unwrap(),
            "serve",
            "--mcp",
            "--state-dir",
            state.to_str().unwrap(),
        ],
        None,
        "",
    );
    assert!(!out.status.success());

    let missing = dir.path().join("nope.toml");
    let out = run(&["--policy", missing.to_str().unwrap(), "policy"], None, "");
    assert!(!out.status.success());
}

#[cfg(unix)]
#[test]
fn world_writable_policy_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(dir.path(), POLICY);
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o666)).unwrap();
    let out = run(&["--policy", policy.to_str().unwrap(), "policy"], None, "");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("chmod go-w"));
}

#[test]
fn replace_mode_is_announced() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write_policy(
        dir.path(),
        "version = 1\nmode = \"replace\"\n[[rule]]\nid = \"only-disk\"\neffect = \"allow\"\npriority = 1\n[rule.when]\ncapability_id = \"disk_usage\"\n",
    );
    let out = run(&["--policy", policy.to_str().unwrap(), "policy"], None, "");
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("built-in rules are NOT in force"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("only-disk") && !text.contains("deny-critical"),
        "{text}"
    );
}
