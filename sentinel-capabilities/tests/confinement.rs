//! Built-in capabilities running through the real `HardenedExecutor`:
//! each command is confined to what its capability is allowed to write.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sentinel_capabilities::filesystem::{DiskUsage, LogVacuum};
use sentinel_core::{Capability, CapabilityResult, ExecutionContext};
use sentinel_exec::{apply_sandbox, HardenedExecutor, LandlockMode, SandboxConfig};
use serde_json::json;
use uuid::Uuid;

fn ctx() -> ExecutionContext {
    ExecutionContext::new(Uuid::new_v4(), "localhost")
}

fn landlock_enforced() -> bool {
    let mut probe = tokio::process::Command::new("true");
    let cfg = SandboxConfig {
        require_enforcement: false,
        ..SandboxConfig::write_restricted(Vec::<std::path::PathBuf>::new())
    };
    let ok = apply_sandbox(&mut probe, &cfg).unwrap().filesystem_enforced;
    if !ok {
        eprintln!("SKIPPED: kernel has no Landlock support");
    }
    ok
}

/// Write `path` and age it by 30 days so `find -mtime +7` matches.
fn old_file(path: &Path) {
    std::fs::write(path, "log line\n").unwrap();
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(30 * 24 * 3600))
        .unwrap();
}

fn removed(result: &CapabilityResult) -> u64 {
    match result {
        CapabilityResult::Success { output, .. } => output["files_removed"].as_u64().unwrap(),
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn log_vacuum_works_under_confinement() {
    let logs = tempfile::tempdir().unwrap();
    old_file(&logs.path().join("a.log"));
    old_file(&logs.path().join("b.log"));
    std::fs::write(logs.path().join("fresh.log"), "new").unwrap();

    let cap = LogVacuum::new(Arc::new(HardenedExecutor::for_builtin_capabilities()));
    let result = cap
        .invoke(
            json!({"log_dir": logs.path().to_str().unwrap(), "older_than_days": 7}),
            &ctx(),
        )
        .await;
    assert_eq!(removed(&result), 2);
    assert!(!logs.path().join("a.log").exists());
    assert!(logs.path().join("fresh.log").exists());
}

/// A file name containing a newline used to be split into two paths, the
/// second of which could point anywhere: `rm -f /elsewhere/victim.log` as
/// whoever runs Sentinel.  The name is now read NUL-separated and the path
/// must sit under `log_dir`.
#[tokio::test]
async fn newline_in_a_file_name_cannot_redirect_the_delete() {
    let logs = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim.log");
    std::fs::write(&victim, "important").unwrap();

    // A directory literally named "evil\n", holding a copy of the victim's
    // absolute path.  `find` prints `<log_dir>/evil\n/<abs path>/victim.log`,
    // whose second line is exactly the victim's real path.
    let decoy_dir = logs
        .path()
        .join("evil\n")
        .join(elsewhere.path().strip_prefix("/").unwrap());
    std::fs::create_dir_all(&decoy_dir).unwrap();
    let decoy = decoy_dir.join("victim.log");
    old_file(&decoy);

    let cap = LogVacuum::new(Arc::new(HardenedExecutor::for_builtin_capabilities()));
    let result = cap
        .invoke(
            json!({"log_dir": logs.path().to_str().unwrap(), "older_than_days": 7}),
            &ctx(),
        )
        .await;
    assert!(victim.exists(), "a file outside log_dir was deleted");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "important");
    assert_eq!(
        removed(&result),
        1,
        "the decoy inside log_dir is what gets removed"
    );
    assert!(!decoy.exists());
}

/// Belt and braces: even when the path list is wrong, the `rm` that
/// `log_vacuum` spawns is confined by the kernel to `log_dir`.
#[tokio::test]
async fn confined_rm_cannot_reach_outside_its_log_dir() {
    if !landlock_enforced() {
        return;
    }
    use sentinel_exec::{CommandExecutorTrait, FsAccess};

    let logs = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim.log");
    std::fs::write(&victim, "important").unwrap();

    let exec =
        HardenedExecutor::for_builtin_capabilities().with_landlock_mode(LandlockMode::Require);
    let out = exec
        .run_confined(
            "rm",
            &["-f", victim.to_str().unwrap()],
            &Default::default(),
            4096,
            &FsAccess::write_under([logs.path()]),
        )
        .await
        .unwrap();
    assert!(!out.success());
    assert!(victim.exists());
}

#[tokio::test]
async fn read_only_capability_still_works_under_confinement() {
    let dir = tempfile::tempdir().unwrap();
    let cap = DiskUsage::new(Arc::new(HardenedExecutor::for_builtin_capabilities()));
    let result = cap
        .invoke(json!({"path": dir.path().to_str().unwrap()}), &ctx())
        .await;
    assert!(
        matches!(result, CapabilityResult::Success { .. }),
        "{result:?}"
    );
}
