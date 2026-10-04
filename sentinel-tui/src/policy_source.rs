//! Where this process gets its policy from.
//!
//! `main` records the `--policy` / `$SENTINEL_POLICY` path once at start-up;
//! every code path that needs an evaluator calls [`load`], so `run`, the TUI,
//! `serve --mcp`, `execute` and `policy` cannot disagree about which policy
//! is in force.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sentinel_policy::{LoadedPolicy, PolicyEvaluator, PolicyMode};

static POLICY_FILE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Record the policy file for this process.  Later calls are ignored.
pub fn set_path(path: Option<PathBuf>) {
    let _ = POLICY_FILE.set(path);
}

/// The configured policy file, if any.
pub fn path() -> Option<&'static Path> {
    POLICY_FILE.get().and_then(|p| p.as_deref())
}

/// Build the evaluator: the built-in policy, with the configured file
/// applied on top when there is one.  A file that is configured but invalid
/// is an error; there is no fallback to the default policy.
pub fn load() -> anyhow::Result<PolicyEvaluator> {
    let Some(path) = path() else {
        return Ok(sentinel_policy::default_policy());
    };
    let loaded = LoadedPolicy::load(path)?;
    if loaded.mode == PolicyMode::Replace {
        tracing::warn!(
            file = %path.display(),
            rules = loaded.rules.len(),
            "policy file uses mode = \"replace\": the built-in rules are NOT in force"
        );
    } else {
        tracing::info!(
            file = %path.display(),
            rules = loaded.rules.len(),
            guards = loaded.guards.len(),
            "policy file loaded (tighten mode)"
        );
    }
    Ok(loaded.into_evaluator())
}
