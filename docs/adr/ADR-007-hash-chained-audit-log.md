# ADR-007: Append-Only SHA-256 Hash-Chained Audit Log

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Security, Compliance, Audit, Integrity

---

## Context

Sentinel executes privileged operations on production infrastructure at the direction of an LLM reasoning engine. The audit record of these operations has several critical properties that must be met:

**Non-repudiation.** When an incident occurs after a Sentinel session, it must be possible to prove exactly what the agent did, in what order, with what parameters, and with what results. This is both a forensic requirement (debugging) and a compliance requirement (demonstrating to auditors that the system operated within policy bounds).

**Tamper evidence.** The audit log itself is a high-value target. An attacker who has compromised a system and wants to cover their tracks will attempt to modify or delete audit records. A log that provides no tamper-evidence guarantees is insufficient for security-critical applications.

**Completeness.** Every domain event — goal submission, capability invocation, policy decision, approval, execution result, rollback — must be captured. Gaps in the log undermine its value for incident investigation.

**Regulatory compliance.** Many organizations operating infrastructure automation tools are subject to compliance frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA) that require audit logs to be retained for specified periods, protected from modification, and available for export to SIEM systems.

**SIEM integration.** Security operations teams use SIEM platforms (Splunk, Elasticsearch, Datadog) to aggregate and analyze security-relevant events. The audit log must be exportable in standard formats (JSON, CEF, syslog) to support SIEM ingestion.

The `sentinel-audit` crate is responsible for all audit log functionality.

---

## Decision

The `sentinel-audit` crate implements an append-only, hash-chained audit log with the following properties:

**Append-only storage.** Audit log entries are written to an append-only file (or database). No API exists to modify or delete individual entries. Compaction/rotation is only permitted for entries older than a configurable retention window, and rotated archives are themselves hash-chained.

**SHA-256 hash chaining.** Each audit log entry includes a `prev_hash` field containing the SHA-256 hash of the previous entry's serialized form (including that entry's own `prev_hash`). The first entry's `prev_hash` is the all-zero hash (genesis entry). This forms a chain analogous to a blockchain, where modifying any historical entry invalidates all subsequent hashes.

**Entry structure.** Each `AuditEvent` contains:
- `event_id`: A UUID v4 uniquely identifying this event.
- `session_id`: The session this event belongs to.
- `event_type`: A typed enum of event kinds (e.g., `CapabilityInvoked`, `PolicyDenied`, `PlanApproved`).
- `payload`: A JSON blob with event-specific data (capability ID, parameters, result, etc.).
- `timestamp`: An RFC 3339 timestamp with nanosecond precision.
- `actor`: The operator identity or `"agent"` for autonomous actions.
- `prev_hash`: The SHA-256 hash of the previous entry.
- `entry_hash`: The SHA-256 hash of this entry's canonical serialization (excluding `entry_hash` itself).

**Hash chain verification.** The `sentinel-audit` crate exposes a `verify_chain(start: EventId, end: EventId) -> VerificationResult` function that recomputes the hash chain over a range of entries and reports any discontinuities or hash mismatches. This function is surfaced in the TUI and available as a CLI subcommand.

**SIEM export.** The crate provides exporters for JSON Lines (newline-delimited JSON), CEF (Common Event Format), and syslog (RFC 5424). Exports can be streamed to stdout, written to a file, or forwarded to a UDP/TCP syslog receiver.

**Structured event taxonomy.** All domain events that produce audit records are defined as a typed `AuditEventType` enum, ensuring that every event kind has a stable, versioned identifier and a known schema. New event types are added via enum extension with schema versioning.

---

## Rationale

**Hash chaining provides a lightweight tamper-evidence mechanism.** A linked hash chain detects both modification of individual entries and insertion or deletion of entries from the middle of the log. An adversary who modifies entry N must recompute the hash of every subsequent entry to restore chain validity — a computationally infeasible task for long chains. This provides tamper evidence without the operational complexity of a full blockchain or a hardware security module.

**SHA-256 is the correct algorithm choice.** SHA-256 is computationally efficient (well under 1 ms per hash on modern hardware), widely supported, cryptographically sound for integrity (not confidentiality) purposes, and produces output that is directly usable in compliance documentation. MD5 and SHA-1 are excluded due to known collision vulnerabilities. SHA-3 is not required for this use case and has less library support.

**Append-only semantics align with write-once storage.** Many compliance frameworks mandate write-once audit storage. The append-only model maps directly onto this requirement and can be backed by write-once object storage (AWS S3 with Object Lock, Google Cloud Storage with object versioning) for long-term archival.

**Typed event taxonomy enables structured SIEM ingestion.** A log of free-text strings is difficult to parse, query, and alert on in a SIEM. A typed event taxonomy with stable event IDs and known JSON schemas allows SIEM systems to ingest Sentinel events as structured data and create precise alert rules (e.g., "alert when `PolicyDenied` event occurs for a `Critical`-tier capability").

**In-process logging eliminates an external dependency.** The `sentinel-audit` crate writes the log directly within the Sentinel process, without requiring an external logging agent or service. This maintains the single-binary deployment model (ADR-010) and ensures that audit records are written atomically with the events they record.

---

## Consequences

**Positive:**

- Any modification of historical audit records is detectable by chain verification.
- Compliance frameworks requiring tamper-evident, append-only audit logs are supported.
- SIEM integration via JSON Lines, CEF, and syslog export covers the majority of enterprise SIEM platforms.
- Hash chain verification is self-contained — no external service or PKI is required to verify log integrity.
- The typed event taxonomy enables automated SIEM alert rules and forensic queries.
- The `verify_chain` command can be run as part of a regular compliance check to detect tampering.

**Negative:**

- The hash chain makes it impossible to retroactively correct a malformed audit entry — incorrect entries must be followed by corrective entries, which adds complexity to log interpretation.
- Hash chain integrity verification requires sequential access to the full log. For very long-running deployments with millions of entries, full-chain verification is time-consuming. Range-based verification (`verify_chain(start, end)`) mitigates this.
- The append-only model makes storage management more complex — entries cannot be deleted individually, and retention policies require archival of entire chain segments rather than deletion of individual entries.
- The SHA-256 computation adds a small per-entry overhead (< 1 ms), well within the performance budget but notable when writing thousands of entries per second (high-frequency capability invocations in fleet mode).
- This design does not provide confidentiality — audit log entries are not encrypted at rest in the base implementation. Encryption at rest must be provided by the storage layer or an optional encryption wrapper.

---

## Alternatives Considered

**Standard structured logging (tracing + JSON).** Using the `tracing` crate's JSON subscriber to write structured log events to files provides a good structured log format but no tamper evidence. Any process with write access to the log file can modify or delete entries without detection. For a security-critical audit use case, this is insufficient.

**Database-backed audit log (SQLite, PostgreSQL).** Storing audit events in a relational database provides queryability and structured storage. However, databases are not inherently append-only or tamper-evident — entries can be updated or deleted. A hash chain can be implemented over a database, but it adds complexity without adding capability over the flat-file approach. Database dependencies also conflict with the single-binary deployment model.

**External audit service (AWS CloudTrail, Datadog).** Forwarding all audit events to an external managed service would offload tamper-evidence and retention management. This was rejected because it creates an external network dependency that fails in air-gapped environments, introduces a privacy concern (all system state observations are sent externally), and adds an external service dependency that must be operational for the audit log to be written.

**WORM storage without hash chaining.** Write-once-read-many (WORM) storage (e.g., S3 with Object Lock) prevents modification at the storage layer. This provides tamper evidence but requires specific storage infrastructure and does not provide in-process integrity verification. Hash chaining works on any storage medium and can be verified without access to the storage layer's audit controls.

**Merkle tree rather than a linear chain.** A Merkle tree structure would enable O(log n) proofs of inclusion for individual entries rather than requiring sequential hash recomputation. This is the approach used by Certificate Transparency logs. For Sentinel's use case, the additional complexity of Merkle tree management is not justified — sequential verification over the log size typical in a Sentinel deployment is fast, and proofs of individual entry inclusion are not a required feature.
