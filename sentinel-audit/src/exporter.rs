//! Re-export helpers so callers don't need to reach into sub-modules.
//!
//! The primary export surface lives on `AuditLog` itself (`export_jsonl` and
//! `export_text_report`).  This module exists as an explicit public API point
//! referenced from `lib.rs` and may be extended with streaming or file-based
//! export helpers in the future.

pub use crate::log::AuditLog;
pub use crate::verifier::AuditVerifier;
