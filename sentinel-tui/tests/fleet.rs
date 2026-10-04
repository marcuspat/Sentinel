//! `sentinel fleet` and `sentinel agent-exec` through the real binary
//! (ADR-022).  A fake `ssh` on PATH runs the remote command locally, so the
//! controller → host round trip is exercised without a network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_sentinel");

/// Every test here writes an executable (the fake `ssh`) and then spawns
/// processes.  If another thread forks while the script is still open for
/// writing, the child inherits that descriptor and the exec of the script
/// fails with ETXTBSY.  One lock around each test removes the race.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn base(dir: &Path) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir)
        .env_remove("SENTINEL_POLICY")
        .env_remove("SENTINEL_AUDIT_KEY")
        .env_remove("SENTINEL_METRICS_FILE")
        .env("SENTINEL_STATE_DIR", dir.join("state"));
    cmd
}

fn agent_exec(dir: &Path, args: &[&str]) -> (Output, Value) {
    let out = base(dir).arg("agent-exec").args(args).output().unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out, json)
}

fn is_failure(v: &Value) -> Option<String> {
    v.get("Failure")
        .and_then(|f| f.get("error"))
        .and_then(Value::as_str)
        .map(String::from)
}

fn audit_text(dir: &Path) -> String {
    let mut all = String::new();
    if let Ok(entries) = std::fs::read_dir(dir.join("state/audit")) {
        for e in entries {
            all.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap());
        }
    }
    all
}

#[test]
fn agent_exec_runs_a_read_only_capability_and_audits_it() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let (out, json) = agent_exec(dir.path(), &["disk_usage", r#"{"path": "/tmp"}"#]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(json.get("Success").is_some(), "{json}");
    let audit = audit_text(dir.path());
    for kind in [
        "PolicyEvaluated",
        "CapabilityInvoked",
        "CapabilitySucceeded",
    ] {
        assert!(
            audit.contains(kind),
            "{kind} missing from the host's audit log"
        );
    }
}

#[test]
fn agent_exec_needs_approval_for_mutating_capabilities() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    std::fs::create_dir(&logs).unwrap();
    let args = format!(
        r#"{{"log_dir": "{}", "older_than_days": 7}}"#,
        logs.display()
    );

    let (out, json) = agent_exec(dir.path(), &["log_vacuum", &args]);
    assert!(out.status.success());
    let err = is_failure(&json).expect("refused");
    assert!(err.contains("requires operator approval"), "{err}");
    assert!(!audit_text(dir.path()).contains("CapabilityInvoked"));

    let (_, json) = agent_exec(dir.path(), &["--approved", "log_vacuum", &args]);
    assert!(json.get("Success").is_some(), "{json}");
}

#[test]
fn agent_exec_refuses_what_host_policy_denies_even_when_approved() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    // sshd is protected by a built-in resource guard on the host.
    let (out, json) = agent_exec(
        dir.path(),
        &["--approved", "service_stop", r#"{"service": "sshd"}"#],
    );
    assert!(out.status.success());
    let err = is_failure(&json).expect("refused");
    assert!(err.contains("refused by policy on this host"), "{err}");
    let audit = audit_text(dir.path());
    assert!(audit.contains("PolicyDenied"));
    assert!(!audit.contains("CapabilityInvoked"));
}

#[test]
fn agent_exec_rejects_unknown_capabilities_and_bad_arguments() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    for (args, expected) in [
        (vec!["nope", "{}"], "unknown capability"),
        (vec!["disk_usage", "not json"], "not valid JSON"),
        (vec!["disk_usage", "[1]"], "must be a JSON object"),
        (vec!["disk_usage", "{}"], "path"),
        (vec!["a;b", "{}"], "invalid capability id"),
    ] {
        let (_, json) = agent_exec(dir.path(), &args);
        let err = is_failure(&json).unwrap_or_else(|| panic!("{args:?} -> {json}"));
        assert!(err.contains(expected), "{args:?}: {err}");
    }
}

/// A fake `ssh` that ignores the destination and runs the remote command on
/// this machine, with `sentinel` resolving to the binary under test.
fn fake_ssh(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let _ = std::os::unix::fs::symlink(BIN, bin.join("sentinel")); // idempotent
    let script = bin.join("ssh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$FAKE_SSH_LOG\"\nfor last; do :; done\neval \"$last\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn fleet(dir: &Path, args: &[&str]) -> Output {
    let bin = fake_ssh(dir);
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    base(dir)
        .arg("fleet")
        .args(args)
        .env("PATH", path)
        .env("FAKE_SSH_LOG", dir.join("ssh.log"))
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn fleet_round_trip_applies_policy_on_both_ends_and_audits_the_run() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let out = fleet(
        dir.path(),
        &[
            "check disks",
            "--hosts",
            "ops@web-01,db-02:2222",
            "--capability",
            "disk_usage",
            "--args",
            r#"{"path": "/tmp"}"#,
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("2 succeeded, 0 failed, 0 denied"),
        "{stdout}"
    );

    // The destination follows `--`, and the remote command is one argument.
    let ssh_log = std::fs::read_to_string(dir.path().join("ssh.log")).unwrap();
    assert!(ssh_log.contains("--\nops@web-01\n"), "{ssh_log}");
    assert!(
        ssh_log.contains("'sentinel' agent-exec 'disk_usage'"),
        "{ssh_log}"
    );

    // Controller audit chain, in the working directory.
    let controller_log = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .expect("controller audit log");
    let chain = std::fs::read_to_string(&controller_log).unwrap();
    for kind in [
        "GoalSubmitted",
        "PolicyEvaluated",
        "FleetCommandDispatched",
        "SessionCompleted",
    ] {
        assert!(chain.contains(kind), "{kind} missing");
    }
    assert!(chain.contains("disk_usage@web-01") && chain.contains("disk_usage@db-02"));
    let verify = Command::new(BIN)
        .args(["verify-audit"])
        .arg(&controller_log)
        .output()
        .unwrap();
    assert!(verify.status.success());
    // Each host wrote its own chain too.
    assert!(audit_text(dir.path()).contains("CapabilitySucceeded"));
}

#[cfg(unix)]
#[test]
fn fleet_dispatches_nothing_without_approval_for_mutating_capabilities() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    std::fs::create_dir(&logs).unwrap();
    let args = format!(
        r#"{{"log_dir": "{}", "older_than_days": 7}}"#,
        logs.display()
    );
    let common = [
        "vacuum",
        "--hosts",
        "web-01",
        "--capability",
        "log_vacuum",
        "--args",
        &args,
    ];

    let out = fleet(dir.path(), &common);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("nothing was dispatched"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.path().join("ssh.log").exists(),
        "ssh must not be spawned"
    );

    let mut approved = common.to_vec();
    approved.push("--approve");
    let out = fleet(dir.path(), &approved);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let ssh_log = std::fs::read_to_string(dir.path().join("ssh.log")).unwrap();
    assert!(
        ssh_log.contains("agent-exec --approved 'log_vacuum'"),
        "{ssh_log}"
    );
}

#[cfg(unix)]
#[test]
fn fleet_refuses_hostile_hosts_and_capabilities_before_spawning_ssh() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("pwned");
    let evil_host = format!("-oProxyCommand=touch {}", marker.display());
    for args in [
        vec![
            "g",
            "--hosts",
            evil_host.as_str(),
            "--capability",
            "disk_usage",
        ],
        vec![
            "g",
            "--hosts",
            "web-01",
            "--capability",
            "disk_usage; touch x",
        ],
        vec![
            "g",
            "--hosts",
            "web-01",
            "--capability",
            "no_such_capability",
        ],
    ] {
        let out = fleet(dir.path(), &args);
        assert!(!out.status.success(), "{args:?}");
        assert!(!dir.path().join("ssh.log").exists(), "{args:?} reached ssh");
    }
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn fleet_skips_hosts_that_controller_policy_denies() {
    let _serial = serial();
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        "version = 1\n[[rule]]\nid = \"no-prod\"\neffect = \"deny\"\npriority = 1\n[rule.when]\ntarget_host = \"prod-*\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();

    let bin = fake_ssh(dir.path());
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let out = base(dir.path())
        .args([
            "--policy",
            policy.to_str().unwrap(),
            "fleet",
            "g",
            "--hosts",
            "prod-db,staging-1",
        ])
        .args([
            "--capability",
            "disk_usage",
            "--args",
            r#"{"path": "/tmp"}"#,
        ])
        .env("PATH", path)
        .env("FAKE_SSH_LOG", dir.path().join("ssh.log"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("prod-db: DENIED by policy"), "{stdout}");
    assert!(stdout.contains("1 denied"), "{stdout}");
    let ssh_log = std::fs::read_to_string(dir.path().join("ssh.log")).unwrap();
    assert!(
        ssh_log.contains("staging-1") && !ssh_log.contains("prod-db"),
        "{ssh_log}"
    );
    assert!(
        !out.status.success(),
        "a denied host makes the run non-zero"
    );
}
