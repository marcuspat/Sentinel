//! `sentinel fleet` (controller side) and `sentinel agent-exec` (host side).
//!
//! Both ends apply policy and write an audit chain (ADR-022).  The
//! controller decides whether the run may be dispatched at all; each host
//! then decides again under its own policy, so a controller cannot make a
//! host do what that host's policy denies.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use sentinel_audit::{AuditEventType, AuditLog};
use sentinel_capabilities::all_capabilities;
use sentinel_core::{CapabilityResult, ExecutionContext};
use sentinel_exec::HardenedExecutor;
use sentinel_fleet::{
    execute_on_fleet_with, validate_capability_id, FleetConfig, HostConfig, SshHostExecutor,
};
use sentinel_mcp::{default_state_dir, index_capabilities, AuditSink};
use sentinel_policy::{PolicyEffect, PolicyRequest};
use sentinel_tui::policy_source;
use uuid::Uuid;

/// Wall-clock limit for one capability on the host side.
const AGENT_EXEC_TIMEOUT: Duration = Duration::from_secs(15 * 60);

fn effect_label(effect: &PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allowed => "allow",
        PolicyEffect::Denied { .. } => "deny",
        PolicyEffect::RequiresApproval => "require_approval",
        PolicyEffect::AuditOnly => "audit_only",
    }
}

/// Run one capability on this host on behalf of a fleet controller and print
/// its [`CapabilityResult`] as JSON.
///
/// Exit status is 0 whenever a result was produced, including a `Failure`
/// result: the controller reads the JSON.  A non-zero exit means this
/// command itself could not run (bad policy file, unwritable audit log).
pub async fn agent_exec(
    capability: String,
    args_json: String,
    approved: bool,
    state_dir: Option<PathBuf>,
) -> Result<()> {
    let state_dir = state_dir.unwrap_or_else(default_state_dir);
    let policy = policy_source::load()?;
    let audit = AuditSink::create(&state_dir, "agent-exec")?;
    let result = agent_exec_inner(&capability, &args_json, approved, &policy, &audit).await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

async fn agent_exec_inner(
    capability: &str,
    args_json: &str,
    approved: bool,
    policy: &sentinel_policy::PolicyEvaluator,
    audit: &AuditSink,
) -> Result<CapabilityResult> {
    let refuse = |msg: String| Ok(CapabilityResult::failure(msg, false));

    if let Err(e) = validate_capability_id(capability) {
        return refuse(e);
    }
    let caps = index_capabilities(all_capabilities(Arc::new(
        HardenedExecutor::for_builtin_capabilities(),
    )));
    let Some(cap) = caps.get(capability) else {
        return refuse(format!("unknown capability '{capability}'"));
    };
    let args: serde_json::Value = match serde_json::from_str(args_json) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        Ok(_) => return refuse("arguments must be a JSON object".into()),
        Err(e) => return refuse(format!("arguments are not valid JSON: {e}")),
    };
    if let Err(e) = cap.validate_args(&args) {
        return refuse(e.to_string());
    }

    let m = cap.manifest();
    let decision = policy.evaluate(PolicyRequest {
        session_id: audit.session_id(),
        capability_id: m.id.clone(),
        capability_kind: m.kind,
        risk_tier: m.risk_tier,
        args: args.clone(),
        target_host: "localhost".into(),
        timestamp: chrono::Utc::now(),
        session_phase: Some("FleetAgent".into()),
    });
    audit
        .record(AuditEventType::PolicyEvaluated {
            capability_id: m.id.clone(),
            effect: effect_label(&decision.effect).into(),
            rule_id: decision.matched_rule.clone(),
        })
        .await?;

    let denial = match &decision.effect {
        PolicyEffect::Denied { reason } => Some(reason.clone()),
        PolicyEffect::RequiresApproval if !approved => Some(
            "this host's policy requires operator approval and the controller did not pass \
             --approved"
                .to_string(),
        ),
        _ => None,
    };
    if let Some(reason) = denial {
        audit
            .record(AuditEventType::PolicyDenied {
                capability_id: m.id.clone(),
                reason: reason.clone(),
            })
            .await?;
        return refuse(format!("refused by policy on this host: {reason}"));
    }

    // On record before it runs.
    audit
        .record(AuditEventType::CapabilityInvoked {
            capability_id: m.id.clone(),
            args: args.clone(),
            risk_tier: format!("{:?}", m.risk_tier),
        })
        .await?;
    let ctx = ExecutionContext::new(audit.session_id(), "localhost");
    let t0 = Instant::now();
    let result = match tokio::time::timeout(AGENT_EXEC_TIMEOUT, cap.invoke(args, &ctx)).await {
        Ok(r) => r,
        Err(_) => CapabilityResult::failure(
            format!("timed out after {}s", AGENT_EXEC_TIMEOUT.as_secs()),
            true,
        ),
    };
    match &result {
        CapabilityResult::Success { .. } => {
            audit
                .record(AuditEventType::CapabilitySucceeded {
                    capability_id: m.id.clone(),
                    duration_ms: t0.elapsed().as_millis() as u64,
                })
                .await?;
        }
        other => {
            let error = match other {
                CapabilityResult::Failure { error, .. } => error.clone(),
                _ => "dry-run result".to_string(),
            };
            audit
                .record(AuditEventType::CapabilityFailed {
                    capability_id: m.id.clone(),
                    error,
                })
                .await?;
        }
    }
    Ok(result)
}

/// What the controller decided for one host before dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum HostDecision {
    Dispatch,
    NeedsApproval,
    Denied(String),
}

/// Controller-side policy check for every host.
pub fn decide_hosts(
    policy: &sentinel_policy::PolicyEvaluator,
    manifest: &sentinel_core::CapabilityManifest,
    args: &serde_json::Value,
    hosts: &[HostConfig],
    session_id: Uuid,
) -> Vec<(HostConfig, HostDecision, &'static str, Option<String>)> {
    hosts
        .iter()
        .map(|h| {
            let d = policy.evaluate(PolicyRequest {
                session_id,
                capability_id: manifest.id.clone(),
                capability_kind: manifest.kind,
                risk_tier: manifest.risk_tier,
                args: args.clone(),
                target_host: h.hostname.clone(),
                timestamp: chrono::Utc::now(),
                session_phase: Some("Fleet".into()),
            });
            let decision = match &d.effect {
                PolicyEffect::Denied { reason } => HostDecision::Denied(reason.clone()),
                PolicyEffect::RequiresApproval => HostDecision::NeedsApproval,
                _ => HostDecision::Dispatch,
            };
            (h.clone(), decision, effect_label(&d.effect), d.matched_rule)
        })
        .collect()
}

pub async fn run_fleet(
    goal: String,
    hosts: Vec<String>,
    capability: String,
    args: String,
    approve: bool,
) -> Result<()> {
    if hosts.is_empty() {
        anyhow::bail!("no hosts specified; pass --hosts host1,host2[,...]");
    }
    validate_capability_id(&capability).map_err(|e| anyhow::anyhow!(e))?;
    let parsed_args: HashMap<String, serde_json::Value> = serde_json::from_str(&args)
        .map_err(|e| anyhow::anyhow!("--args must be a JSON object: {e}"))?;
    let args_value = serde_json::to_value(&parsed_args)?;

    let config = FleetConfig::from_specs(&hosts);
    for h in &config.hosts {
        h.validate().map_err(|e| anyhow::anyhow!(e))?;
    }

    // The controller must know the capability to judge it.
    let caps = index_capabilities(all_capabilities(Arc::new(
        HardenedExecutor::for_builtin_capabilities(),
    )));
    let cap = caps
        .get(&capability)
        .ok_or_else(|| anyhow::anyhow!("unknown capability '{capability}'"))?;
    cap.validate_args(&args_value)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let manifest = cap.manifest().clone();

    let session_id = Uuid::new_v4();
    let policy = policy_source::load()?;
    let audit_path = PathBuf::from(format!("sentinel-audit-{session_id}.jsonl"));
    let mut audit = AuditLog::new(session_id, Some(audit_path.clone())).with_signer_from_env()?;
    audit
        .append(AuditEventType::GoalSubmitted {
            goal: goal.clone(),
            host: format!("fleet:{}", hosts.join(",")),
        })
        .await?;

    println!("Fleet run: {goal}");
    println!(
        "Capability : {capability} [{:?}, risk {}]",
        manifest.kind, manifest.risk_tier
    );
    println!("Hosts ({}) : {}", config.len(), hosts.join(", "));
    println!();

    let decisions = decide_hosts(&policy, &manifest, &args_value, &config.hosts, session_id);
    let mut dispatch = Vec::new();
    let mut needs_approval = Vec::new();
    let mut denied = 0usize;
    for (host, decision, label, rule) in decisions {
        let scoped = format!("{capability}@{}", host.hostname);
        audit
            .append(AuditEventType::PolicyEvaluated {
                capability_id: scoped.clone(),
                effect: label.into(),
                rule_id: rule,
            })
            .await?;
        match decision {
            HostDecision::Denied(reason) => {
                denied += 1;
                audit
                    .append(AuditEventType::PolicyDenied {
                        capability_id: scoped,
                        reason: reason.clone(),
                    })
                    .await?;
                println!("x {}: DENIED by policy — {reason}", host.hostname);
            }
            HostDecision::NeedsApproval => {
                needs_approval.push(host.hostname.clone());
                dispatch.push(host);
            }
            HostDecision::Dispatch => dispatch.push(host),
        }
    }

    if !needs_approval.is_empty() && !approve {
        let reason = format!(
            "policy requires operator approval for {capability} on {}; re-run with --approve",
            needs_approval.join(", ")
        );
        audit
            .append(AuditEventType::SessionAborted {
                reason: reason.clone(),
            })
            .await?;
        println!("Audit: {}", audit_path.display());
        anyhow::bail!("nothing was dispatched: {reason}");
    }
    if approve && !needs_approval.is_empty() {
        audit
            .append(AuditEventType::PlanApproved {
                plan_id: session_id,
                approval_mode: format!(
                    "fleet:--approve:{}",
                    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
                ),
            })
            .await?;
    }

    let command_id = Uuid::new_v4();
    audit
        .append(AuditEventType::FleetCommandDispatched {
            command_id,
            host_count: dispatch.len(),
        })
        .await?;
    for h in &dispatch {
        audit
            .append(AuditEventType::CapabilityInvoked {
                capability_id: format!("{capability}@{}", h.hostname),
                args: args_value.clone(),
                risk_tier: format!("{:?}", manifest.risk_tier),
            })
            .await?;
    }

    let started = Instant::now();
    let ctx = ExecutionContext::new(session_id, "fleet");
    let executor = Arc::new(SshHostExecutor::default().with_approval(approve));
    let results = execute_on_fleet_with(
        executor,
        &FleetConfig { hosts: dispatch },
        &capability,
        &parsed_args,
        &ctx,
    )
    .await;

    let mut hostnames: Vec<&String> = results.keys().collect();
    hostnames.sort();
    let (mut ok, mut failed) = (0usize, 0usize);
    for hostname in hostnames {
        let scoped = format!("{capability}@{hostname}");
        match &results[hostname] {
            CapabilityResult::Success { output } => {
                ok += 1;
                audit
                    .append(AuditEventType::CapabilitySucceeded {
                        capability_id: scoped,
                        duration_ms: started.elapsed().as_millis() as u64,
                    })
                    .await?;
                println!("✔ {hostname}: success");
                if let Ok(pretty) = serde_json::to_string(output) {
                    println!("    {pretty}");
                }
            }
            CapabilityResult::Failure { error, .. } => {
                failed += 1;
                audit
                    .append(AuditEventType::CapabilityFailed {
                        capability_id: scoped,
                        error: error.clone(),
                    })
                    .await?;
                println!("x {hostname}: FAILED — {error}");
            }
            CapabilityResult::DryRun { predicted_effect } => {
                ok += 1;
                println!("• {hostname}: dry-run");
                if let Ok(pretty) = serde_json::to_string(predicted_effect) {
                    println!("    {pretty}");
                }
            }
        }
    }
    audit
        .append(AuditEventType::SessionCompleted {
            duration_ms: started.elapsed().as_millis() as u64,
            capabilities_executed: ok as u64,
        })
        .await?;

    println!();
    println!(
        "Fleet summary: {ok} succeeded, {failed} failed, {denied} denied by policy across {} host(s).",
        config.len()
    );
    println!("Audit: {}", audit_path.display());
    if failed + denied > 0 {
        std::process::exit(1);
    }
    Ok(())
}
