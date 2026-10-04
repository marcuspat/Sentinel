//! Thin wrapper around [`sentinel_audit::AuditLog`] used by the gate.
//!
//! Each process that touches the gate (one `serve --mcp` server, one
//! `approve`, one `execute`, …) gets its own session-scoped, hash-chained
//! JSONL file under `<state_dir>/audit/`.  Separate files per process keep
//! every chain linear and independently verifiable with
//! `sentinel verify-audit <file>`; stored plans reference the files that
//! recorded their proposal, decision and execution.

use std::path::{Path, PathBuf};

use sentinel_audit::{AuditError, AuditEventType, AuditLog};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Session-scoped, file-backed, hash-chained audit sink.
pub struct AuditSink {
    session_id: Uuid,
    path: PathBuf,
    log: Mutex<AuditLog>,
}

impl AuditSink {
    /// Create `<state_dir>/audit/<prefix>-<session_id>.jsonl`.
    pub fn create(state_dir: &Path, prefix: &str) -> std::io::Result<Self> {
        let dir = state_dir.join("audit");
        std::fs::create_dir_all(&dir)?;
        crate::store::restrict_dir_permissions(&dir);
        let session_id = Uuid::new_v4();
        let path = dir.join(format!("{prefix}-{session_id}.jsonl"));
        // Signed when $SENTINEL_AUDIT_KEY names a key file (ADR-015).  A
        // configured-but-unusable key refuses to start rather than logging
        // unsigned.
        let log = AuditLog::new(session_id, Some(path.clone()))
            .with_signer_from_env()
            .map_err(std::io::Error::other)?;
        Ok(Self {
            session_id,
            log: Mutex::new(log),
            path,
        })
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn path_string(&self) -> String {
        self.path.display().to_string()
    }

    /// Append an event; returns the new chain head hash.
    pub async fn record(&self, event: AuditEventType) -> Result<String, AuditError> {
        let mut log = self.log.lock().await;
        let ev = log.append(event).await?;
        Ok(ev.this_hash.clone())
    }

    /// Current chain head.
    pub async fn head(&self) -> String {
        self.log.lock().await.last_hash().to_string()
    }

    /// Number of events recorded by this sink.
    pub async fn len(&self) -> usize {
        self.log.lock().await.event_count()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[async_trait::async_trait]
impl sentinel_runner::AuditWriter for AuditSink {
    async fn record(&self, event: AuditEventType) -> Result<(), String> {
        AuditSink::record(self, event)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}
