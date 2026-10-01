# ADR-015: Ed25519-Signed Audit Checkpoints

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Core team  
**Categories:** Security, Audit, Cryptography

---

## Context

ADR-007 gave the audit log a SHA-256 hash chain. A chain proves internal
consistency: changing one event breaks every hash after it. It does not
authenticate the chain. The hashes are unkeyed, so anyone who can write the
file can replace it with a different, fully consistent chain and
`sentinel verify-audit` reports `VALID`. The integration test
`whole_file_rewrite_passes_the_chain_but_fails_the_signature` demonstrates
exactly that against the real binary.

For a tool whose pitch is "auditable", an audit log that its own subject can
silently rewrite is the weakest link.

## Decision

Sign the chain head.

- **Key.** Ed25519 (`ed25519-dalek` 2.x). `sentinel audit-keygen --out FILE`
  writes a 32-byte seed as hex with mode 0600, refuses to overwrite, and prints
  the public key on stdout.
- **Opt-in by environment.** When `SENTINEL_AUDIT_KEY` names a key file, every
  file-backed audit log (`run`, the TUI session, and every MCP gate process:
  `serve`, `approve`, `reject`, `execute`) signs. A key that is set but
  unreadable, malformed, or group/world-accessible stops the process. There is
  no silent fallback to unsigned logging.
- **Checkpoint.** After each append the signer writes one JSON line to the
  sidecar `<log>.sig`: `version`, `session_id`, `event_count`, `head_hash`,
  `signed_at`, `key_id`, `public_key`, `signature`. One checkpoint per event,
  so there is no unsigned window between checkpoints.
- **Signed message.** `sentinel-audit-checkpoint-v1\n<session_id>\n<event_count>\n<head_hash>\n<signed_at RFC 3339, nanoseconds>`.
  Fixed-order, newline-delimited fields rather than JSON, so the bytes do not
  depend on a serializer. The prefix is a domain separator.
- **Sidecar, not inline.** The JSONL event format and the chain hash are
  unchanged; existing logs and external verifiers keep working.
- **Verification.** `sentinel verify-audit PATH --pubkey HEX|FILE` checks the
  chain, then every checkpoint: signature (`verify_strict`) against the
  **caller-supplied** key, session match, and `head_hash` equal to the hash of
  the event it claims to cover. Any bad checkpoint fails the run. The
  `public_key` field inside a checkpoint is never trusted. Events past the last
  checkpoint, or a missing sidecar, produce a warning; `--require-signature`
  turns that into a failure.

## What this does and does not protect

| Attack | Hash chain only | With signed checkpoints |
|---|---|---|
| Edit, delete or reorder events in place | Detected | Detected |
| Rewrite the whole file with a consistent chain | **Not detected** | Detected |
| Rewrite the file and re-sign with the attacker's own key | n/a | Detected (verifier holds the real public key) |
| Truncate the log, keep the sidecar | Not detected | Detected |
| Delete the sidecar | n/a | Detected with `--require-signature` |
| Truncate the log **and** the sidecar to the same earlier point | Not detected | **Not detected** |
| Attacker can read the signing key | n/a | **Not protected** |

The last two rows are real limits, not oversights:

1. **Key custody.** If the process being audited and the attacker share a UID,
   the attacker can read the key and sign anything. The signature is only as
   strong as the separation between the key and whoever might rewrite the log:
   run the gate as a dedicated OS user that owns the key (the deployment
   ADR-013 already recommends). A hardware-backed or remote signer is future
   work.
2. **Rollback.** Signatures prove a head was genuine at some point, not that it
   is the latest. Detecting consistent truncation needs the newest checkpoint
   (or just its `head_hash`) stored somewhere the attacker cannot reach. Shipping
   the `.sig` lines to a remote log collector is enough.

## Consequences

- One extra signature (tens of microseconds) and one ~450-byte sidecar line per
  audit event.
- New dependencies: `ed25519-dalek` and `getrandom` (already in the lock file
  transitively).
- Unsigned operation is unchanged and remains the default; nothing breaks for
  existing users.
- `SECURITY.md` no longer overstates what the hash chain alone guarantees.

## Alternatives considered

- **HMAC over the head.** Simpler, but the verifier would need the same secret
  as the signer, so anyone able to verify could also forge.
- **Embed the signature in each event.** Changes the on-disk event format and
  the hash preimage for every existing consumer.
- **Periodic checkpoints (every N events / at session end).** Smaller sidecar,
  but leaves up to N events unsigned if the process is killed, and those are
  the events an attacker cares about.
- **Transparency log / Merkle tree with inclusion proofs.** The right long-term
  answer for fleet-wide audit; far more machinery than a single-host tool needs
  today.
