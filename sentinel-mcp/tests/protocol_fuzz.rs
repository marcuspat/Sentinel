//! Property-based fuzzing of the MCP JSON-RPC surface.
//!
//! The server reads lines from an untrusted client (an LLM agent). Whatever
//! arrives, it must not panic, must answer requests with well-formed
//! JSON-RPC, must never run a mutating command without an approved plan, and
//! must leave a verifiable audit chain behind.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use sentinel_audit::AuditVerifier;
use sentinel_capabilities::all_capabilities;
use sentinel_exec::{CommandExecutorTrait, CommandOutput, ExecError};
use sentinel_mcp::{Gate, GateConfig, McpServer, TOOL_NAMES};
use sentinel_policy::default_policy;
use serde_json::{json, Value};

/// Programs that only read. Anything else reaching the executor during a
/// fuzz run means a mutation happened without operator approval.
const READ_ONLY_PROGRAMS: [&str; 12] = [
    "df",
    "du",
    "ps",
    "ss",
    "uptime",
    "free",
    "journalctl",
    "systemctl",
    "find",
    "ls",
    "cat",
    "ip",
];

const INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;

#[derive(Default)]
struct RecordingExecutor {
    calls: AtomicUsize,
    commands: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl CommandExecutorTrait for RecordingExecutor {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        _env: &HashMap<String, String>,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, ExecError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.commands
            .lock()
            .unwrap()
            .push(format!("{program} {}", args.join(" ")));
        Ok(CommandOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
        })
    }
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<f64>().prop_map(|f| json!(f)),
        ".{0,20}".prop_map(Value::from),
        Just(json!("/etc/passwd")),
        Just(json!("sshd")),
        Just(json!("../../etc")),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            prop::collection::btree_map(
                prop_oneof![
                    "[a-z_]{1,8}",
                    Just("path".to_string()),
                    Just("service".to_string()),
                    Just("capability_id".to_string()),
                    Just("plan_id".to_string()),
                    Just("steps".to_string()),
                    Just("args".to_string()),
                    Just("goal".to_string()),
                ],
                inner,
                0..5
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Messages shaped like JSON-RPC, so the fuzzer gets past the envelope and
/// into the tool handlers.
fn rpc_message() -> impl Strategy<Value = Value> {
    let method = prop_oneof![
        3 => Just("tools/call".to_string()),
        1 => Just("tools/list".to_string()),
        1 => Just("initialize".to_string()),
        1 => Just("ping".to_string()),
        1 => Just("notifications/initialized".to_string()),
        1 => "[a-z/_]{0,16}",
    ];
    let tool = prop_oneof![
        4 => prop::sample::select(TOOL_NAMES.to_vec()).prop_map(str::to_string),
        1 => "[a-z_]{0,20}",
    ];
    let id = prop_oneof![
        any::<i64>().prop_map(Value::from),
        "[a-z0-9]{0,8}".prop_map(Value::from),
        Just(Value::Null),
        json_value(),
    ];
    (method, tool, id, json_value(), any::<bool>(), any::<bool>()).prop_map(
        |(method, tool, id, arguments, with_id, well_formed)| {
            let params = if well_formed {
                json!({ "name": tool, "arguments": arguments })
            } else {
                arguments
            };
            let mut msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
            if with_id {
                msg["id"] = id;
            }
            msg
        },
    )
}

/// A `sentinel_propose_plan` / `sentinel_execute_plan` / investigate call
/// built from real capability ids, so the fuzzer reaches the plan store.
fn directed_call() -> impl Strategy<Value = Value> {
    let cap = prop::sample::select(vec![
        "disk_usage",
        "service_restart",
        "log_vacuum",
        "cache_prune",
        "package_upgrade",
        "process_list",
        "nope",
    ]);
    (
        prop::sample::select(TOOL_NAMES.to_vec()),
        prop::collection::vec((cap, json_value()), 0..4),
        "[a-f0-9-]{0,36}",
        any::<i64>(),
    )
        .prop_map(|(tool, steps, plan_id, id)| {
            let steps: Vec<Value> = steps
                .into_iter()
                .map(|(c, a)| json!({ "capability_id": c, "args": a, "description": "x" }))
                .collect();
            let first = steps.first().cloned().unwrap_or(json!({}));
            json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": tool, "arguments": {
                    "goal": "fuzz", "steps": steps, "plan_id": plan_id,
                    "capability_id": first["capability_id"], "args": first["args"],
                }}
            })
        })
}

fn check_response(response: &Value) -> Result<(), TestCaseError> {
    let obj = response.as_object().expect("response is an object");
    prop_assert_eq!(obj.get("jsonrpc"), Some(&json!("2.0")));
    prop_assert!(obj.contains_key("id"), "{}", response);
    prop_assert!(
        obj.contains_key("result") ^ obj.contains_key("error"),
        "exactly one of result/error: {}",
        response
    );
    if let Some(err) = obj.get("error") {
        prop_assert!(err["code"].is_i64(), "{}", response);
        prop_assert!(err["message"].is_string(), "{}", response);
    }
    // Round-trips as a single line: the transport is newline-delimited.
    prop_assert!(!serde_json::to_string(response).unwrap().contains('\n'));
    Ok(())
}

/// Feed `lines` to a fresh server and check the invariants.
fn run(lines: Vec<String>) -> Result<(), TestCaseError> {
    let dir = tempfile::tempdir().unwrap();
    let exec = Arc::new(RecordingExecutor::default());
    let gate = Gate::new(
        GateConfig::new(dir.path()),
        all_capabilities(exec.clone()),
        default_policy(),
    )
    .unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let responses: Vec<Value> = rt.block_on(async {
        let mut server = McpServer::new(&gate);
        let mut out = Vec::new();
        for line in &lines {
            if let Some(r) = server.handle_line(line).await {
                out.push(r);
            }
        }
        out
    });

    for r in &responses {
        check_response(r)?;
    }

    // Nothing was approved (approval is not reachable over MCP), so nothing
    // but read-only investigation may have reached the executor.
    for command in exec.commands.lock().unwrap().iter() {
        let program = command.split(' ').next().unwrap_or("");
        prop_assert!(
            READ_ONLY_PROGRAMS.contains(&program),
            "fuzz input ran a non-read-only command without approval: {}",
            command
        );
        prop_assert!(
            !(program == "systemctl"
                && ["restart", "stop", "start", "reload", "enable", "disable", "mask", "kill"]
                    .iter()
                    .any(|verb| command.split(' ').nth(1) == Some(verb))),
            "fuzz input ran a mutating systemctl verb: {}",
            command
        );
        prop_assert!(
            !(program == "find" && command.contains("-delete")),
            "fuzz input ran a deleting find: {}",
            command
        );
        prop_assert!(
            !(program == "journalctl" && command.contains("--vacuum")),
            "fuzz input vacuumed the journal: {}",
            command
        );
    }

    // Whatever was written to the audit log still forms a valid chain.
    let audit = std::fs::read_to_string(gate.audit().path()).unwrap_or_default();
    let result = AuditVerifier::verify_jsonl(&audit).expect("audit log parses");
    prop_assert!(result.valid, "{:?}", result.error);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Arbitrary text: every line gets a parse error or a valid response.
    #[test]
    fn arbitrary_lines_never_panic(lines in prop::collection::vec(any::<String>(), 1..6)) {
        run(lines)?;
    }

    /// Arbitrary JSON that is not necessarily a JSON-RPC message.
    #[test]
    fn arbitrary_json_never_panics(values in prop::collection::vec(json_value(), 1..6)) {
        run(values.iter().map(|v| v.to_string()).collect())?;
    }

    /// JSON-RPC-shaped messages with hostile ids, tool names and arguments.
    #[test]
    fn rpc_shaped_messages_never_mutate_and_always_answer_well(
        messages in prop::collection::vec(rpc_message(), 1..8),
    ) {
        // Initialise first: before that the server refuses every tool call,
        // and the fuzzer would never reach the handlers.
        let mut lines = vec![INITIALIZE.to_string()];
        lines.extend(messages.iter().map(|m| m.to_string()));
        run(lines)?;
    }

    /// Calls that name real tools and real capabilities with hostile args:
    /// proposals are stored, but nothing mutating runs without approval.
    #[test]
    fn directed_tool_calls_never_mutate_without_approval(
        calls in prop::collection::vec(directed_call(), 1..8),
    ) {
        let mut lines = vec![INITIALIZE.to_string()];
        lines.extend(calls.iter().map(|m| m.to_string()));
        run(lines)?;
    }

    /// Truncated and corrupted versions of a valid request.
    #[test]
    fn mangled_valid_requests_never_panic(
        message in rpc_message(), cut in any::<prop::sample::Index>(), junk in ".{0,6}",
    ) {
        let text = message.to_string();
        let mut at = cut.index(text.len() + 1);
        while !text.is_char_boundary(at) { at -= 1; }
        run(vec![
            INITIALIZE.to_string(),
            text[..at].to_string(),
            format!("{}{}{}", &text[..at], junk, &text[at..]),
        ])?;
    }
}
