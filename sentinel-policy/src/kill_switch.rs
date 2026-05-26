//! Global kill switch for the policy engine.
//!
//! When activated, all mutating capabilities are immediately blocked regardless
//! of what the rule set says.  Read-only capabilities are unaffected so that
//! operators can still inspect the system.
//!
//! The kill switch is safe to share across threads: activation uses an
//! [`AtomicBool`] and the reason/timestamp are guarded by [`RwLock`]s.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

use chrono::{DateTime, Utc};

/// Thread-safe global kill switch.
///
/// Create via [`KillSwitch::new`], which returns an `Arc<Self>` ready to be
/// shared across threads and cloned into the [`PolicyEvaluator`].
///
/// [`PolicyEvaluator`]: crate::evaluator::PolicyEvaluator
#[derive(Debug)]
pub struct KillSwitch {
    activated: AtomicBool,
    reason: RwLock<Option<String>>,
    activated_at: RwLock<Option<DateTime<Utc>>>,
}

impl KillSwitch {
    /// Create a new, **deactivated** kill switch wrapped in an `Arc`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            activated: AtomicBool::new(false),
            reason: RwLock::new(None),
            activated_at: RwLock::new(None),
        })
    }

    /// Activate the kill switch with an operator-supplied reason.
    ///
    /// Subsequent calls to [`is_activated`] will return `true`.  If the switch
    /// was already active the reason and timestamp are updated.
    ///
    /// [`is_activated`]: KillSwitch::is_activated
    pub fn activate(&self, reason: impl Into<String>) {
        let reason_str = reason.into();
        // Store the reason and timestamp before flipping the flag so that any
        // concurrent reader that sees the flag as `true` is guaranteed to also
        // see the reason.
        {
            let mut r = self.reason.write().expect("kill_switch reason lock poisoned");
            *r = Some(reason_str);
        }
        {
            let mut a = self
                .activated_at
                .write()
                .expect("kill_switch activated_at lock poisoned");
            *a = Some(Utc::now());
        }
        self.activated.store(true, Ordering::SeqCst);
    }

    /// Deactivate the kill switch.
    ///
    /// Resets the reason and activation timestamp.
    pub fn deactivate(&self) {
        self.activated.store(false, Ordering::SeqCst);
        {
            let mut r = self.reason.write().expect("kill_switch reason lock poisoned");
            *r = None;
        }
        {
            let mut a = self
                .activated_at
                .write()
                .expect("kill_switch activated_at lock poisoned");
            *a = None;
        }
    }

    /// Returns `true` if the kill switch is currently active.
    ///
    /// Uses `SeqCst` ordering to guarantee visibility across threads.
    #[inline]
    pub fn is_activated(&self) -> bool {
        self.activated.load(Ordering::SeqCst)
    }

    /// Returns the reason provided when the kill switch was last activated,
    /// or `None` if it is not currently active.
    pub fn reason(&self) -> Option<String> {
        self.reason
            .read()
            .expect("kill_switch reason lock poisoned")
            .clone()
    }

    /// Returns the UTC timestamp of the last activation, or `None` if not
    /// currently active.
    pub fn activated_at(&self) -> Option<DateTime<Utc>> {
        *self
            .activated_at
            .read()
            .expect("kill_switch activated_at lock poisoned")
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_deactivated() {
        let ks = KillSwitch::new();
        assert!(!ks.is_activated());
        assert!(ks.reason().is_none());
        assert!(ks.activated_at().is_none());
    }

    #[test]
    fn activate_sets_flag_and_reason() {
        let ks = KillSwitch::new();
        ks.activate("operator triggered emergency stop");
        assert!(ks.is_activated());
        assert_eq!(
            ks.reason().as_deref(),
            Some("operator triggered emergency stop")
        );
        assert!(ks.activated_at().is_some());
    }

    #[test]
    fn deactivate_clears_flag_and_reason() {
        let ks = KillSwitch::new();
        ks.activate("test reason");
        assert!(ks.is_activated());

        ks.deactivate();
        assert!(!ks.is_activated());
        assert!(ks.reason().is_none());
        assert!(ks.activated_at().is_none());
    }

    #[test]
    fn reactivate_with_new_reason() {
        let ks = KillSwitch::new();
        ks.activate("first reason");
        ks.deactivate();
        ks.activate("second reason");
        assert!(ks.is_activated());
        assert_eq!(ks.reason().as_deref(), Some("second reason"));
    }

    #[test]
    fn thread_safe_activation() {
        use std::thread;

        let ks = KillSwitch::new();
        let ks2 = Arc::clone(&ks);

        let handle = thread::spawn(move || {
            ks2.activate("from thread");
        });
        handle.join().unwrap();

        assert!(ks.is_activated());
        assert_eq!(ks.reason().as_deref(), Some("from thread"));
    }

    #[test]
    fn activation_timestamp_is_after_before_timestamp() {
        let before = Utc::now();
        let ks = KillSwitch::new();
        ks.activate("timing test");
        let after = Utc::now();

        let ts = ks.activated_at().unwrap();
        assert!(ts >= before, "activated_at should be >= before");
        assert!(ts <= after, "activated_at should be <= after");
    }
}
