# ADR-012: Execution State Checkpointing

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Reliability, Crash Recovery, Long-Running Sessions

---

## Context

Sentinel sessions can be long-running operations: an investigation phase may involve dozens of read capabilities gathering system state, a plan may contain tens of steps, and execution may take minutes or hours for operations like package upgrades, data migrations, or rolling fleet updates.

Long-running sessions create a failure recovery challenge:

**Process termination.** Sentinel may be killed by the OS (OOM killer, operator `SIGKILL`, system reboot), by a crash (panic in the execution loop or a Tokio runtime failure), or by network interruption in fleet mode. Without checkpointing, the session state — observations gathered, plan approved, steps completed — is lost, and the operator must restart from scratch.

**Partial execution state.** If Sentinel crashes mid-execution (after step 5 of 10 has completed), the operator needs to know which steps completed successfully, which failed, and which were not attempted. Without a checkpoint, it is impossible to safely resume from where execution stopped — re-executing completed steps may produce duplicate effects or errors (e.g., "file already exists", "service already restarted").

**Long investigation phases.** Gathering comprehensive system state may take several minutes for large or remote systems. If the session crashes during investigation, the operator should be able to resume from the last recorded observation rather than re-running all gather capabilities.

**Fleet session durability.** In fleet mode, a network partition between the controller and an agent should not cause the agent to lose its execution context. The agent should be able to continue executing its approved plan and reconcile with the controller when connectivity is restored.

**LLM context reconstruction.** The LLM reasoning loop accumulates context (observations, plan drafts, revision history) over the course of a session. Reconstructing this context from scratch after a crash would require expensive LLM re-inference. Checkpointing the accumulated context enables efficient resumption.

---

## Decision

Sentinel implements session checkpointing: periodic serialization of the complete `Session` aggregate state to durable storage, enabling crash recovery and session resumption.

**Checkpoint triggers.** Checkpoints are written:
- After every phase transition (Investigating → Planning, Planning → Executing, Executing → Verifying).
- After every capability invocation completes (success or failure) during the Executing phase.
- After every observation is recorded during the Investigating phase (configurable: every N observations or every M seconds).
- After the approval decision is recorded.
- Explicitly when the operator invokes a "checkpoint now" command.

**Checkpoint content.** A checkpoint contains the complete serialized `Session` aggregate:
- `session_id`, `goal`, `created_at`, current `SessionPhase`.
- All recorded `Observation` records from the investigation phase.
- The approved `Plan` (complete list of `PlanStep` records).
- For each step: `ExecutionStatus` (Pending / InProgress / Completed / Failed / Skipped).
- For completed steps: the `CapabilityResult` (success, output, duration).
- The `ApprovalDecision` record.
- The accumulated LLM conversation context (messages list, truncated to the model's context window).
- The last `prev_hash` from the audit chain (for audit log continuity verification on resumption).

**Checkpoint storage.** By default, checkpoints are written to a local file (`~/.sentinel/sessions/<session_id>.checkpoint.json`). The file is written atomically (written to a `.tmp` file and `rename(2)` atomically replaces the previous checkpoint — `rename` is atomic on POSIX filesystems). For fleet sessions, the agent writes checkpoints locally; the controller may also persist a checkpoint copy via the fleet protocol.

**Checkpoint format.** Checkpoints are serialized as JSON (via serde_json) for human-inspectability and debuggability. A checkpoint version field allows format evolution without breaking compatibility with existing checkpoints. Checkpoints are optionally encrypted with a session key derived from the operator's master key (for checkpoints containing sensitive system observations).

**Session resumption.** On startup, Sentinel detects existing checkpoint files for interrupted sessions and presents them to the operator ("Session <UUID> was interrupted at step 3/10 during Executing phase. Resume?"). If the operator chooses to resume, Sentinel loads the checkpoint, reconstructs the `Session` aggregate, and continues from the recorded state. Steps already marked `Completed` are skipped (not re-executed). Steps marked `InProgress` are re-run (they may have partially executed at crash time). Steps marked `Pending` are executed normally.

**Checkpoint garbage collection.** Checkpoints for completed sessions (`Completed` or `Aborted` final phase) are deleted automatically after a configurable retention period (default: 7 days). Checkpoints for sessions older than the maximum retention period are also cleaned up automatically.

---

## Rationale

**Atomic file rename prevents checkpoint corruption.** A crash mid-write would produce a corrupted checkpoint file if written in-place. By writing to a temporary file and using `rename(2)` (which is atomic on POSIX filesystems), Sentinel ensures that the checkpoint file is always either the previous complete checkpoint or the new complete checkpoint — never a partial write. This is the standard pattern for durable state writes in Unix systems.

**Per-step checkpointing enables safe resumption with idempotency context.** Knowing exactly which steps completed (and their results) before a crash is the minimum information needed to safely resume. Without per-step status, resuming requires re-executing all steps from the beginning, risking duplicate effects. With per-step status, resumption correctly skips completed steps.

**JSON format for human-inspectability.** In a failure scenario, the operator may need to manually inspect the checkpoint to understand the session's state. A human-readable JSON format enables this without requiring special tooling. The performance overhead of JSON serialization vs. binary formats (MessagePack, CBOR) is negligible for checkpoint writes, which occur at most a few times per second.

**LLM context in the checkpoint enables efficient resumption.** Re-running the full investigation and planning phases (requiring multiple LLM API calls) after a crash in the execution phase would be wasteful and expensive. Saving the accumulated LLM conversation context allows the reasoning loop to resume with the same context it had at crash time, without re-inference.

**Fleet agent local checkpoints provide partition tolerance.** If the network connection between fleet controller and agent is interrupted during execution, the agent should continue executing its approved plan rather than aborting. Local checkpoints allow the agent to maintain execution context independently of controller connectivity.

---

## Consequences

**Positive:**

- Crashes during long-running sessions do not lose accumulated investigation context or force re-execution of completed steps.
- Per-step status tracking enables safe resumption without re-executing idempotency-violating steps.
- Fleet agents can operate through transient network partitions without losing execution context.
- The checkpoint file provides a human-readable session state snapshot useful for debugging.
- LLM context checkpointing avoids expensive re-inference after recovery.
- Atomic writes ensure checkpoint files are never in a corrupted state.

**Negative:**

- Checkpoint writes on every capability completion add I/O overhead. For very fast capabilities (sub-millisecond read operations), checkpoint write latency may become a bottleneck. The configurable observation checkpoint interval mitigates this for the investigation phase; execution phase checkpoints (one per step completion) should be fast on modern SSDs.
- The checkpoint file contains potentially sensitive system state observations and configuration data. Encryption-at-rest is optional and must be configured explicitly.
- Resuming sessions with a `InProgress` step (crashed mid-execution) may require the operator to assess whether the step's effects need to be rolled back before resuming. This requires operational judgment that the system cannot fully automate.
- Checkpoint version evolution requires careful schema migration. Adding fields to the checkpoint format is backward compatible (old checkpoints deserialize with defaults for new fields), but removing or renaming fields requires migration logic.
- Checkpoint garbage collection for very old sessions must be careful not to delete checkpoints for sessions the operator may want to resume or audit.

---

## Alternatives Considered

**No checkpointing; restart from scratch on crash.** Accepting that a crash requires the operator to start a new session from scratch simplifies the implementation. For short sessions (< 5 minutes, < 10 steps), this is acceptable. For long sessions (fleet-wide rolling updates, major migrations), losing all progress on a crash is operationally unacceptable. Checkpointing is a required feature for production usability.

**Database-backed session state (SQLite).** Storing session state in an embedded SQLite database would provide richer query capabilities and atomic transactions across multiple tables. SQLite's WAL mode provides excellent crash safety. However, SQLite is a C library dependency that conflicts with the musl static binary constraint (see ADR-010) without careful vendoring. A JSON checkpoint file achieves the same durability goals with no additional dependencies.

**External state store (Redis, etcd).** Storing session state in an external key-value store would enable state sharing between multiple Sentinel processes (e.g., controller + agent in fleet mode) and provide HA-grade durability. However, it introduces a required external service dependency, which conflicts with the single-binary deployment model. For fleet mode, the local agent checkpoint plus controller-side replication of the plan state provides sufficient durability without an external store.

**Event sourcing (replay from audit log).** Rather than writing explicit checkpoint snapshots, derive the current session state by replaying the audit log from the beginning of the session. This approach eliminates a separate checkpoint format and ensures that the audit log is the single source of truth. However, replay-based recovery is slow for long sessions with many audit events, and it requires the audit log to contain all state-relevant events (including LLM conversation context), which would significantly increase audit log volume and introduce privacy concerns (raw LLM conversation data in the compliance audit log).

**OS-level process checkpointing (CRIU).** The Linux CRIU (Checkpoint/Restore In Userspace) utility can checkpoint and restore arbitrary processes at the OS level, including all memory state. This would provide complete crash recovery without any application-level checkpointing logic. CRIU requires specific kernel configuration and root privileges, is not supported in all container environments, and produces very large checkpoint images (full process memory). Application-level checkpointing is more portable, more compact, and more understandable.
