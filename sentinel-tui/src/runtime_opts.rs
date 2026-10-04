//! Process-wide execution switches set once from the command line.

use std::sync::atomic::{AtomicBool, Ordering};

static NO_ROLLBACK: AtomicBool = AtomicBool::new(false);

/// Record `--no-rollback` / `$SENTINEL_NO_ROLLBACK`.
pub fn set_no_rollback(value: bool) {
    NO_ROLLBACK.store(value, Ordering::SeqCst);
}

/// Whether completed steps are undone after a later step fails.
pub fn rollback_enabled() -> bool {
    !NO_ROLLBACK.load(Ordering::SeqCst)
}
