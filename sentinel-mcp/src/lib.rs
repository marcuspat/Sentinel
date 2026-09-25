//! `sentinel-mcp` — Sentinel as a policy gate for coding agents.
//!
//! Exposes Sentinel's capability catalogue, deny-by-default policy engine and
//! hash-chained audit log to MCP clients (Claude Code, Cursor, …) over stdio
//! via `sentinel serve --mcp`.
//!
//! The central invariant (ADR-013): **an MCP client can propose plans but can
//! never approve or execute them.**  Approval is an operator action taken
//! out-of-band (`sentinel approve <plan_id>`), and execution
//! (`sentinel execute <plan_id>`) refuses anything that is not approved or
//! whose content changed after approval.
//!
//! # Crate layout
//!
//! * [`gate`]    — tool definitions and handlers ([`Gate`])
//! * [`server`]  — newline-delimited JSON-RPC stdio transport ([`serve`])
//! * [`store`]   — file-backed plan store ([`PlanStore`], [`StoredPlan`])
//! * [`execute`] — operator-side execution of approved plans
//! * [`audit`]   — session-scoped audit sink ([`AuditSink`])

pub mod audit;
pub mod execute;
pub mod gate;
pub mod server;
pub mod store;

use std::path::PathBuf;

pub use audit::AuditSink;
pub use execute::{execute_approved_plan, ExecuteError, ExecuteReport, StepOutcome};
pub use gate::{
    index_capabilities, plan_status_json, CapabilitySet, Gate, GateConfig, GateError, ToolOutcome,
    TOOL_NAMES,
};
pub use server::{serve, McpServer, SUPPORTED_PROTOCOL_VERSIONS};
pub use store::{PlanStatus, PlanStore, StoreError, StoredPlan};

/// Default state directory: `$XDG_STATE_HOME/sentinel`, else
/// `$HOME/.local/state/sentinel`, else `./.sentinel-state`.
pub fn default_state_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(x).join("sentinel");
    }
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(h).join(".local/state/sentinel");
    }
    PathBuf::from(".sentinel-state")
}
