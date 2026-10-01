//! Ed25519-signed checkpoints over the audit chain head (ADR-015).
//!
//! A hash chain proves *internal* consistency: nobody changed one event
//! without changing every hash after it.  It does not stop someone who can
//! write the file from rewriting the whole chain — the hashes are unkeyed,
//! so a forged chain verifies just as well as the real one.
//!
//! A signed checkpoint closes that gap.  After events are appended, the
//! signer writes a small record to a sidecar file (`<log>.sig`) stating
//! "this session's chain had `event_count` events and head hash `H`",
//! signed with an Ed25519 key.  A verifier holding the *public* key can then
//! tell a genuine chain from a rewritten one, because the attacker cannot
//! produce a signature over the forged head.
//!
//! What this does **not** cover is spelled out in ADR-015: an attacker who
//! can read the signing key can re-sign, and truncating both the log and its
//! sidecar to an earlier checkpoint is only detectable if checkpoints (or
//! just the latest head) are also shipped off-host.

use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{error::AuditError, events::AuditEvent};

/// Environment variable naming the signing-key file.
pub const AUDIT_KEY_ENV: &str = "SENTINEL_AUDIT_KEY";

/// Domain-separation prefix for the signed message.  Changing the checkpoint
/// layout means bumping this, so an old signature can never be replayed as a
/// new-format one.
const DOMAIN: &str = "sentinel-audit-checkpoint-v1";

/// A signed statement about the chain head at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub session_id: Uuid,
    /// Number of events in the chain when this checkpoint was signed.
    pub event_count: u64,
    /// `this_hash` of event `event_count - 1`.
    pub head_hash: String,
    pub signed_at: DateTime<Utc>,
    /// First 16 hex chars of SHA-256(public key).  A lookup hint only.
    pub key_id: String,
    /// Hex Ed25519 public key that produced `signature`.  Informational:
    /// trust comes from the key the *verifier* supplies, never from this.
    pub public_key: String,
    /// Hex Ed25519 signature over [`Checkpoint::signing_message`].
    pub signature: String,
}

impl Checkpoint {
    /// Canonical bytes covered by the signature.
    ///
    /// Newline-delimited fixed-order fields rather than JSON, so the message
    /// does not depend on serializer key order or whitespace.  None of the
    /// fields can contain a newline (UUID, integer, hex, RFC 3339).
    pub fn signing_message(
        session_id: Uuid,
        event_count: u64,
        head_hash: &str,
        signed_at: &DateTime<Utc>,
    ) -> Vec<u8> {
        format!(
            "{DOMAIN}\n{session_id}\n{event_count}\n{head_hash}\n{}",
            signed_at.to_rfc3339_opts(SecondsFormat::Nanos, true)
        )
        .into_bytes()
    }

    fn message(&self) -> Vec<u8> {
        Self::signing_message(
            self.session_id,
            self.event_count,
            &self.head_hash,
            &self.signed_at,
        )
    }

    /// Check the signature against `key`.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let Ok(bytes) = hex::decode(&self.signature) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&bytes) else {
            return false;
        };
        // `verify_strict` rejects small-order keys and non-canonical
        // signatures, which plain `verify` accepts.
        key.verify_strict(&self.message(), &sig).is_ok()
    }
}

/// Holds the Ed25519 signing key and produces checkpoints.
pub struct AuditSigner {
    key: SigningKey,
}

impl std::fmt::Debug for AuditSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("AuditSigner")
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl AuditSigner {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Result<Self, AuditError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| AuditError::Signing(format!("OS random source failed: {e}")))?;
        let signer = Self {
            key: SigningKey::from_bytes(&seed),
        };
        seed.fill(0);
        Ok(signer)
    }

    /// Build a signer from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Load a key file: 64 hex chars (the 32-byte seed), optional trailing
    /// whitespace.  On Unix the file must not be readable by group or other.
    pub fn load(path: &Path) -> Result<Self, AuditError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(AuditError::Signing(format!(
                    "audit key {} has mode {mode:o}; it must not be accessible to group or other (chmod 600)",
                    path.display()
                )));
            }
        }
        let text = std::fs::read_to_string(path)?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| AuditError::Signing(format!("audit key is not hex: {e}")))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuditError::Signing("audit key must be exactly 32 bytes".into()))?;
        Ok(Self::from_seed(seed))
    }

    /// Write the key to `path`, creating it with mode 0600 and refusing to
    /// overwrite an existing file.
    pub fn save(&self, path: &Path) -> Result<(), AuditError> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        file.write_all(hex::encode(self.key.to_bytes()).as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    /// Signer from `$SENTINEL_AUDIT_KEY`, or `None` when the variable is
    /// unset or empty.  A set-but-unusable key is an error, never a silent
    /// downgrade to unsigned logs.
    pub fn from_env() -> Result<Option<Self>, AuditError> {
        match std::env::var_os(AUDIT_KEY_ENV) {
            Some(p) if !p.is_empty() => Self::load(Path::new(&p)).map(Some),
            _ => Ok(None),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Hex-encoded public key — what operators hand to `verify-audit`.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> String {
        key_id(&self.verifying_key())
    }

    /// Sign a checkpoint for the given chain head.
    pub fn sign(&self, session_id: Uuid, event_count: u64, head_hash: &str) -> Checkpoint {
        let signed_at = Utc::now();
        let msg = Checkpoint::signing_message(session_id, event_count, head_hash, &signed_at);
        Checkpoint {
            version: 1,
            session_id,
            event_count,
            head_hash: head_hash.to_string(),
            signed_at,
            key_id: self.key_id(),
            public_key: self.public_key_hex(),
            signature: hex::encode(self.key.sign(&msg).to_bytes()),
        }
    }
}

/// First 16 hex chars of SHA-256(public key).
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.to_bytes()))[..16].to_string()
}

/// Parse a hex Ed25519 public key.
pub fn parse_public_key(hex_key: &str) -> Result<VerifyingKey, AuditError> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| AuditError::Signing(format!("public key is not hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AuditError::Signing("public key must be exactly 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| AuditError::Signing(format!("not a valid Ed25519 public key: {e}")))
}

/// Sidecar path for a log: `<log>.sig` (`audit.jsonl` → `audit.jsonl.sig`).
pub fn sidecar_path(log_path: &Path) -> PathBuf {
    let mut s = log_path.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

/// Parse a sidecar file (one [`Checkpoint`] JSON per line).
pub fn parse_checkpoints(jsonl: &str) -> Result<Vec<Checkpoint>, AuditError> {
    jsonl
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(n, l)| {
            serde_json::from_str::<Checkpoint>(l.trim())
                .map_err(|e| AuditError::InvalidEvent(format!("checkpoint line {}: {e}", n + 1)))
        })
        .collect()
}

/// Outcome of checking a chain against its signed checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerification {
    /// Checkpoints whose signature and head hash both checked out.
    pub checkpoints_verified: usize,
    /// Highest `event_count` covered by a verified checkpoint.
    pub covered_events: u64,
    /// Events after the last verified checkpoint.  Non-zero means the tail of
    /// the chain carries no signature.
    pub unsigned_tail: u64,
    /// `None` when every checkpoint verified.
    pub error: Option<String>,
}

impl SignatureVerification {
    /// Every checkpoint verified and the newest one covers the final event.
    pub fn fully_signed(&self) -> bool {
        self.error.is_none() && self.checkpoints_verified > 0 && self.unsigned_tail == 0
    }
}

/// Verify `checkpoints` against an already hash-verified chain of `events`
/// using the caller-supplied `trusted` key.
///
/// Every checkpoint must: carry a valid signature from `trusted`, belong to
/// the chain's session, and name the `this_hash` of the event it claims to
/// cover.  One bad checkpoint fails the whole verification — a sidecar with a
/// forged line in it is evidence of tampering, not something to skip past.
pub fn verify_checkpoints(
    events: &[AuditEvent],
    checkpoints: &[Checkpoint],
    trusted: &VerifyingKey,
) -> SignatureVerification {
    let total = events.len() as u64;
    let mut covered = 0u64;
    let mut verified = 0usize;

    let fail = |verified: usize, covered: u64, msg: String| SignatureVerification {
        checkpoints_verified: verified,
        covered_events: covered,
        unsigned_tail: total - covered.min(total),
        error: Some(msg),
    };

    for (i, cp) in checkpoints.iter().enumerate() {
        let n = i + 1;
        if cp.version != 1 {
            return fail(
                verified,
                covered,
                format!("checkpoint {n}: unsupported version {}", cp.version),
            );
        }
        if !cp.verify_signature(trusted) {
            return fail(
                verified,
                covered,
                format!(
                    "checkpoint {n}: signature does not verify against trusted key {}",
                    key_id(trusted)
                ),
            );
        }
        if cp.event_count == 0 || cp.event_count > total {
            return fail(
                verified,
                covered,
                format!(
                    "checkpoint {n}: covers {} event(s) but the log has {total} — the log was truncated",
                    cp.event_count
                ),
            );
        }
        let ev = &events[(cp.event_count - 1) as usize];
        if ev.session_id != cp.session_id {
            return fail(
                verified,
                covered,
                format!("checkpoint {n}: signed for a different session"),
            );
        }
        if ev.this_hash != cp.head_hash {
            return fail(
                verified,
                covered,
                format!(
                    "checkpoint {n}: signed head {} but event {} hashes to {} — the chain was rewritten",
                    cp.head_hash, ev.sequence, ev.this_hash
                ),
            );
        }
        verified += 1;
        covered = covered.max(cp.event_count);
    }

    SignatureVerification {
        checkpoints_verified: verified,
        covered_events: covered,
        unsigned_tail: total - covered,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{events::AuditEventType, log::AuditLog};

    async fn chain(n: usize) -> (Uuid, Vec<AuditEvent>) {
        let sid = Uuid::new_v4();
        let mut log = AuditLog::new(sid, None);
        for _ in 0..n {
            log.append(AuditEventType::InvestigationStarted)
                .await
                .unwrap();
        }
        (sid, log.events().to_vec())
    }

    fn sign_all(signer: &AuditSigner, sid: Uuid, events: &[AuditEvent]) -> Vec<Checkpoint> {
        events
            .iter()
            .map(|e| signer.sign(sid, e.sequence + 1, &e.this_hash))
            .collect()
    }

    #[tokio::test]
    async fn signed_chain_verifies() {
        let signer = AuditSigner::generate().unwrap();
        let (sid, events) = chain(4).await;
        let cps = sign_all(&signer, sid, &events);
        let r = verify_checkpoints(&events, &cps, &signer.verifying_key());
        assert!(r.fully_signed(), "{r:?}");
        assert_eq!(r.checkpoints_verified, 4);
        assert_eq!(r.covered_events, 4);
    }

    /// The attack a bare hash chain cannot see: rewrite every event and
    /// recompute every hash.  The chain is self-consistent; the signature
    /// over the old head is what gives it away.
    #[tokio::test]
    async fn wholesale_rewrite_is_detected() {
        let signer = AuditSigner::generate().unwrap();
        let (sid, events) = chain(3).await;
        let cps = sign_all(&signer, sid, &events);

        // Attacker builds a brand-new, internally valid chain for the same
        // session with different content.
        let mut forged = AuditLog::new(sid, None);
        for _ in 0..3 {
            forged
                .append(AuditEventType::KillSwitchActivated {
                    reason: "forged".into(),
                })
                .await
                .unwrap();
        }
        assert!(forged.verify_chain().valid, "forgery passes the hash chain");

        let r = verify_checkpoints(forged.events(), &cps, &signer.verifying_key());
        assert!(!r.fully_signed());
        assert!(r.error.unwrap().contains("rewritten"));
    }

    #[tokio::test]
    async fn attacker_resigning_with_own_key_is_rejected() {
        let operator = AuditSigner::generate().unwrap();
        let attacker = AuditSigner::generate().unwrap();
        let (sid, events) = chain(2).await;
        let cps = sign_all(&attacker, sid, &events);
        let r = verify_checkpoints(&events, &cps, &operator.verifying_key());
        assert!(!r.fully_signed());
        assert!(r.error.unwrap().contains("does not verify"));
    }

    #[tokio::test]
    async fn truncated_log_is_detected_when_sidecar_survives() {
        let signer = AuditSigner::generate().unwrap();
        let (sid, events) = chain(5).await;
        let cps = sign_all(&signer, sid, &events);
        let r = verify_checkpoints(&events[..3], &cps, &signer.verifying_key());
        assert!(r.error.unwrap().contains("truncated"));
    }

    #[tokio::test]
    async fn unsigned_tail_is_reported() {
        let signer = AuditSigner::generate().unwrap();
        let (sid, events) = chain(5).await;
        let cps = sign_all(&signer, sid, &events[..3]);
        let r = verify_checkpoints(&events, &cps, &signer.verifying_key());
        assert!(r.error.is_none());
        assert_eq!(r.unsigned_tail, 2);
        assert!(!r.fully_signed());
    }

    #[tokio::test]
    async fn no_checkpoints_is_not_fully_signed() {
        let signer = AuditSigner::generate().unwrap();
        let (_, events) = chain(2).await;
        let r = verify_checkpoints(&events, &[], &signer.verifying_key());
        assert!(!r.fully_signed());
        assert_eq!(r.unsigned_tail, 2);
    }

    #[tokio::test]
    async fn tampered_checkpoint_fields_break_the_signature() {
        let signer = AuditSigner::generate().unwrap();
        let (sid, events) = chain(2).await;
        let key = signer.verifying_key();

        let mut cp = signer.sign(sid, 2, &events[1].this_hash);
        assert!(cp.verify_signature(&key));
        cp.event_count = 1;
        assert!(!cp.verify_signature(&key), "event_count is signed");

        let mut cp = signer.sign(sid, 2, &events[1].this_hash);
        cp.signed_at += chrono::Duration::seconds(1);
        assert!(!cp.verify_signature(&key), "signed_at is signed");

        let mut cp = signer.sign(sid, 2, &events[1].this_hash);
        cp.session_id = Uuid::new_v4();
        assert!(!cp.verify_signature(&key), "session_id is signed");

        let mut cp = signer.sign(sid, 2, &events[1].this_hash);
        cp.signature = "zz".into();
        assert!(!cp.verify_signature(&key), "garbage signature");
    }

    #[tokio::test]
    async fn checkpoint_from_another_session_is_rejected() {
        let signer = AuditSigner::generate().unwrap();
        let (_, events) = chain(2).await;
        // Validly signed, right hash, wrong session.
        let cp = signer.sign(Uuid::new_v4(), 2, &events[1].this_hash);
        let r = verify_checkpoints(&events, &[cp], &signer.verifying_key());
        assert!(r.error.unwrap().contains("different session"));
    }

    #[test]
    fn key_file_round_trip_and_no_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.key");
        let signer = AuditSigner::generate().unwrap();
        signer.save(&path).unwrap();
        let loaded = AuditSigner::load(&path).unwrap();
        assert_eq!(loaded.public_key_hex(), signer.public_key_hex());
        assert!(signer.save(&path).is_err(), "must not overwrite a key");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_0600_and_loose_modes_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.key");
        AuditSigner::generate().unwrap().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuditSigner::load(&path).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        std::fs::write(&path, "nothex").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(AuditSigner::load(&path).is_err());
        assert!(parse_public_key("abcd").is_err());
        assert!(parse_public_key("xyz").is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let signer = AuditSigner::from_seed([7u8; 32]);
        let dbg = format!("{signer:?}");
        assert!(!dbg.contains(&hex::encode([7u8; 32])));
        assert!(dbg.contains(&signer.key_id()));
    }

    #[test]
    fn sidecar_path_appends_suffix() {
        assert_eq!(
            sidecar_path(Path::new("/var/a/run.jsonl")),
            PathBuf::from("/var/a/run.jsonl.sig")
        );
    }
}
