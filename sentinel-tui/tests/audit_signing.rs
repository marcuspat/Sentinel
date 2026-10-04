//! End-to-end test of signed audit checkpoints (ADR-015) through the real
//! binary: `audit-keygen`, a signed `serve --mcp` session, and
//! `verify-audit --pubkey`, including the whole-file rewrite that a bare
//! hash chain cannot detect.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sentinel_audit::{AuditEventType, AuditLog};
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_sentinel");

fn run(args: &[&str], envs: &[(&str, &Path)], stdin: &str) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("SENTINEL_STATE_DIR")
        .env_remove("SENTINEL_AUDIT_KEY")
        .env_remove("SENTINEL_AUDIT_PUBKEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
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

fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
    let key = dir.join(name);
    let out = run(&["audit-keygen", "--out", key.to_str().unwrap()], &[], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let public = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(public.len(), 64, "stdout is exactly the public key");
    (key, public)
}

/// One signed MCP session; returns the audit log path.
fn signed_session(state: &Path, key: &Path) -> PathBuf {
    let input = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "it", "version": "0"}}})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "sentinel_policy_check",
            "arguments": {"capability_id": "process_kill", "args": {"pid": 4242}}}})
        .to_string(),
    ]
    .join("\n")
        + "\n";
    let out = run(
        &["serve", "--mcp", "--state-dir", state.to_str().unwrap()],
        &[("SENTINEL_AUDIT_KEY", key)],
        &input,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut logs: Vec<PathBuf> = std::fs::read_dir(state.join("audit"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    assert_eq!(logs.len(), 1);
    logs.pop().unwrap()
}

fn verify(log: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["verify-audit", log.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args, &[], "")
}

fn sig(log: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", log.display()))
}

#[test]
fn signed_session_verifies_with_the_operator_key() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keygen(dir.path(), "audit.key");
    let log = signed_session(&dir.path().join("state"), &key);
    assert!(sig(&log).exists(), "sidecar written next to the log");

    let out = verify(&log, &["--pubkey", &public, "--require-signature"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("every event covered"), "{stdout}");

    // The key may also be given as a file.
    let pub_file = dir.path().join("audit.pub");
    std::fs::write(&pub_file, format!("{public}\n")).unwrap();
    let out = verify(&log, &["--pubkey", pub_file.to_str().unwrap()]);
    assert!(out.status.success());

    // Without --pubkey the chain still verifies, and says signatures were skipped.
    let out = verify(&log, &[]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("NOT checked"));
}

#[tokio::test]
async fn whole_file_rewrite_passes_the_chain_but_fails_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keygen(dir.path(), "audit.key");
    let log = signed_session(&dir.path().join("state"), &key);

    // Attacker with write access replaces the log with a freshly built,
    // internally consistent chain for the same session.
    let original = std::fs::read_to_string(&log).unwrap();
    let first: serde_json::Value = serde_json::from_str(original.lines().next().unwrap()).unwrap();
    let session_id = first["session_id"].as_str().unwrap().parse().unwrap();
    let event_count = original.lines().count();
    std::fs::remove_file(&log).unwrap();
    let mut forged = AuditLog::new(session_id, Some(log.clone()));
    for _ in 0..event_count {
        forged
            .append(AuditEventType::InvestigationStarted)
            .await
            .unwrap();
    }

    // The bare hash chain is fooled …
    let out = verify(&log, &[]);
    assert!(out.status.success(), "forged chain is self-consistent");

    // … the signature check is not.
    let out = verify(&log, &["--pubkey", &public]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("rewritten"), "{stderr}");
}

#[test]
fn wrong_key_missing_sidecar_and_unsigned_logs_are_handled() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keygen(dir.path(), "audit.key");
    let (_, other_public) = keygen(dir.path(), "other.key");
    let log = signed_session(&dir.path().join("state"), &key);

    // Signed by a key the verifier does not trust.
    let out = verify(&log, &["--pubkey", &other_public]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not verify"));

    // Sidecar deleted: a warning by default, a failure when required.
    std::fs::remove_file(sig(&log)).unwrap();
    let out = verify(&log, &["--pubkey", &public]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("WARNING"));
    let out = verify(&log, &["--pubkey", &public, "--require-signature"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no signed checkpoints"));
}

#[test]
fn keygen_refuses_to_overwrite_and_bad_key_refuses_to_serve() {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = keygen(dir.path(), "audit.key");
    let out = run(&["audit-keygen", "--out", key.to_str().unwrap()], &[], "");
    assert!(!out.status.success(), "must not clobber an existing key");

    // A configured but unusable key must stop the gate, not downgrade it.
    let bad = dir.path().join("bad.key");
    std::fs::write(&bad, "not a key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let state = dir.path().join("state");
    let out = run(
        &["serve", "--mcp", "--state-dir", state.to_str().unwrap()],
        &[("SENTINEL_AUDIT_KEY", &bad)],
        "",
    );
    assert!(!out.status.success());
}
