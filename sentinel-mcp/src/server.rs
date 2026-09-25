//! MCP stdio transport: newline-delimited JSON-RPC 2.0.
//!
//! Implements the subset of the Model Context Protocol a tools-only server
//! needs: `initialize`, `notifications/initialized`, `ping`, `tools/list`
//! and `tools/call`.  Messages are read one per line from `reader` and
//! responses written one per line to `writer`.  Nothing else may be written
//! to `writer` (logs go to stderr).
//!
//! Requests are handled sequentially.  JSON-RPC batches (arrays) are
//! rejected, matching MCP 2025-06-18+, which removed batching.

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

use crate::gate::Gate;

/// Protocol revisions this server can speak, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] =
    ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Maximum accepted size of one JSON-RPC message line.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const SERVER_INSTRUCTIONS: &str = "Sentinel is a deny-by-default policy gate for system operations. \
Use sentinel_capabilities to see what exists, sentinel_policy_check to ask whether an action would be allowed, \
sentinel_investigate to run read-only diagnostics, and sentinel_propose_plan to submit changes. \
Proposed plans are NEVER executed by this server: a human operator approves them out-of-band. \
Every call is recorded in a SHA-256 hash-chained audit log.";

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}

fn result_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Per-connection protocol state.
pub struct McpServer<'g> {
    gate: &'g Gate,
    initialized: bool,
}

impl<'g> McpServer<'g> {
    pub fn new(gate: &'g Gate) -> Self {
        Self {
            gate,
            initialized: false,
        }
    }

    /// Handle one raw line.  Returns the response to write, if any
    /// (notifications and client responses produce none).
    pub async fn handle_line(&mut self, line: &str) -> Option<Value> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(error_response(
                    Value::Null,
                    PARSE_ERROR,
                    format!("parse error: {e}"),
                ))
            }
        };
        self.handle_message(msg).await
    }

    /// Handle one parsed JSON-RPC message.
    pub async fn handle_message(&mut self, msg: Value) -> Option<Value> {
        let Some(obj) = msg.as_object() else {
            return Some(error_response(
                Value::Null,
                INVALID_REQUEST,
                "expected a single JSON-RPC object (batches are not supported)",
            ));
        };
        let id = obj.get("id").cloned();
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error_response(
                id.unwrap_or(Value::Null),
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ));
        }
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // A response to a server->client request; we never send any.
            if obj.contains_key("result") || obj.contains_key("error") {
                return None;
            }
            return Some(error_response(
                id.unwrap_or(Value::Null),
                INVALID_REQUEST,
                "missing method",
            ));
        };
        let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));

        let Some(id) = id else {
            // Notification: never answered.
            debug!(method, "notification received");
            return None;
        };
        if !(id.is_string() || id.is_number()) {
            return Some(error_response(
                Value::Null,
                INVALID_REQUEST,
                "id must be a string or number",
            ));
        }

        let reply = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            _ if !self.initialized => Err((
                INVALID_REQUEST,
                "server not initialized: send `initialize` first".to_string(),
            )),
            "tools/list" => Ok(json!({ "tools": self.gate.tool_definitions() })),
            "tools/call" => self.tools_call(&params).await,
            other => Err((METHOD_NOT_FOUND, format!("method not found: {other}"))),
        };
        Some(match reply {
            Ok(result) => result_response(id, result),
            Err((code, message)) => error_response(id, code, message),
        })
    }

    fn initialize(&mut self, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let version = match requested {
            Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
            _ => SUPPORTED_PROTOCOL_VERSIONS[0],
        };
        self.initialized = true;
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "sentinel",
                "title": "Sentinel policy gate",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": SERVER_INSTRUCTIONS,
        })
    }

    async fn tools_call(&self, params: &Value) -> Result<Value, (i64, String)> {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Err((INVALID_PARAMS, "tools/call requires params.name".into()));
        };
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(v @ Value::Object(_)) => v.clone(),
            Some(_) => return Err((INVALID_PARAMS, "params.arguments must be an object".into())),
        };
        let outcome = self
            .gate
            .call_tool(name, arguments)
            .await
            .map_err(|e| (INVALID_PARAMS, e.to_string()))?;
        let text = serde_json::to_string_pretty(&outcome.body).unwrap_or_default();
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": outcome.body,
            "isError": outcome.is_error,
        }))
    }
}

/// Read one `\n`-terminated line of at most `MAX_LINE_BYTES`.
/// Returns `Ok(None)` on EOF, `Ok(Some(Err(())))` for an oversized line
/// (which is consumed and discarded).
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<Result<(), ()>>> {
    buf.clear();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // EOF
            if buf.is_empty() && !oversized {
                return Ok(None);
            }
            return Ok(Some(if oversized { Err(()) } else { Ok(()) }));
        }
        let (chunk, found_newline) = match available.iter().position(|&b| b == b'\n') {
            Some(pos) => (&available[..=pos], true),
            None => (available, false),
        };
        let consumed = chunk.len();
        if !oversized {
            if buf.len() + consumed > MAX_LINE_BYTES + 1 {
                oversized = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        reader.consume(consumed);
        if found_newline {
            return Ok(Some(if oversized { Err(()) } else { Ok(()) }));
        }
    }
}

/// Serve MCP over the given byte streams until EOF on `reader`.
pub async fn serve<R, W>(gate: &Gate, mut reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut server = McpServer::new(gate);
    let mut buf = Vec::with_capacity(4096);
    while let Some(line) = read_bounded_line(&mut reader, &mut buf).await? {
        let response = match line {
            Err(()) => {
                warn!("dropping oversized MCP message (> {MAX_LINE_BYTES} bytes)");
                Some(error_response(
                    Value::Null,
                    INVALID_REQUEST,
                    format!("message exceeds {MAX_LINE_BYTES} bytes"),
                ))
            }
            Ok(()) => {
                let text = String::from_utf8_lossy(&buf);
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    continue;
                }
                server.handle_line(trimmed).await
            }
        };
        if let Some(resp) = response {
            let mut out = serde_json::to_vec(&resp)?;
            out.push(b'\n');
            writer.write_all(&out).await?;
            writer.flush().await?;
        }
    }
    Ok(())
}
