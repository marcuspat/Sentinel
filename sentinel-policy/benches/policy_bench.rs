use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sentinel_core::{CapabilityKind, RiskTier};
use sentinel_policy::{default_policy, PolicyRequest};
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;

fn make_request(
    cap_id: &str,
    kind: CapabilityKind,
    risk: RiskTier,
) -> PolicyRequest {
    PolicyRequest {
        session_id: Uuid::new_v4(),
        capability_id: cap_id.to_string(),
        capability_kind: kind,
        risk_tier: risk,
        args: json!({}),
        target_host: "localhost".to_string(),
        timestamp: Utc::now(),
        session_phase: None,
    }
}

fn bench_policy_evaluate_allow(c: &mut Criterion) {
    let evaluator = default_policy();
    let req = make_request("disk_usage", CapabilityKind::ReadOnly, RiskTier::Low);

    c.bench_function("evaluate ReadOnly/Low (allowed)", |b| {
        b.iter(|| {
            evaluator.evaluate(black_box(PolicyRequest {
                session_id: Uuid::new_v4(),
                capability_id: "disk_usage".to_string(),
                capability_kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                args: json!({}),
                target_host: "localhost".to_string(),
                timestamp: Utc::now(),
                session_phase: None,
            }))
        })
    });

    let _ = req;
}

fn bench_policy_evaluate_deny(c: &mut Criterion) {
    let evaluator = default_policy();

    c.bench_function("evaluate Mutating/Critical (denied)", |b| {
        b.iter(|| {
            evaluator.evaluate(black_box(PolicyRequest {
                session_id: Uuid::new_v4(),
                capability_id: "wipe_disk".to_string(),
                capability_kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::Critical,
                args: json!({}),
                target_host: "localhost".to_string(),
                timestamp: Utc::now(),
                session_phase: None,
            }))
        })
    });
}

fn bench_policy_evaluate_approval_required(c: &mut Criterion) {
    let evaluator = default_policy();

    c.bench_function("evaluate Mutating/High (approval required)", |b| {
        b.iter(|| {
            evaluator.evaluate(black_box(PolicyRequest {
                session_id: Uuid::new_v4(),
                capability_id: "service_restart".to_string(),
                capability_kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::High,
                args: json!({}),
                target_host: "localhost".to_string(),
                timestamp: Utc::now(),
                session_phase: None,
            }))
        })
    });
}

fn bench_policy_evaluate_all_tiers(c: &mut Criterion) {
    let evaluator = default_policy();
    let mut group = c.benchmark_group("evaluate_by_risk_tier");

    let cases = [
        ("ReadOnly/Low", CapabilityKind::ReadOnly, RiskTier::Low),
        ("ReadOnly/Medium", CapabilityKind::ReadOnly, RiskTier::Medium),
        ("Mutating/Medium", CapabilityKind::Mutating, RiskTier::Medium),
        ("Mutating/High", CapabilityKind::Mutating, RiskTier::High),
        ("Mutating/Critical", CapabilityKind::Mutating, RiskTier::Critical),
    ];

    for (label, kind, risk) in cases {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(kind, risk),
            |b, &(kind, risk)| {
                b.iter(|| {
                    evaluator.evaluate(PolicyRequest {
                        session_id: Uuid::new_v4(),
                        capability_id: "bench_cap".to_string(),
                        capability_kind: black_box(kind),
                        risk_tier: black_box(risk),
                        args: json!({}),
                        target_host: "localhost".to_string(),
                        timestamp: Utc::now(),
                        session_phase: None,
                    })
                })
            },
        );
    }

    group.finish();
}

fn bench_policy_batch_evaluate(c: &mut Criterion) {
    let evaluator = default_policy();

    c.bench_function("evaluate 100 mixed requests", |b| {
        b.iter(|| {
            let requests: Vec<_> = (0..100)
                .map(|i| {
                    let (kind, risk) = match i % 5 {
                        0 => (CapabilityKind::ReadOnly, RiskTier::Low),
                        1 => (CapabilityKind::ReadOnly, RiskTier::Medium),
                        2 => (CapabilityKind::Mutating, RiskTier::Medium),
                        3 => (CapabilityKind::Mutating, RiskTier::High),
                        _ => (CapabilityKind::Mutating, RiskTier::Critical),
                    };
                    PolicyRequest {
                        session_id: Uuid::new_v4(),
                        capability_id: format!("cap_{}", i),
                        capability_kind: kind,
                        risk_tier: risk,
                        args: json!({}),
                        target_host: "localhost".to_string(),
                        timestamp: Utc::now(),
                        session_phase: None,
                    }
                })
                .collect();
            requests
                .into_iter()
                .map(|r| evaluator.evaluate(r))
                .collect::<Vec<_>>()
        })
    });
}

fn bench_policy_applicable_rules(c: &mut Criterion) {
    let evaluator = default_policy();
    let req = make_request("bench_cap", CapabilityKind::Mutating, RiskTier::Medium);

    c.bench_function("get_applicable_rules Mutating/Medium", |b| {
        b.iter(|| evaluator.get_applicable_rules(black_box(&req)))
    });
}

criterion_group!(
    benches,
    bench_policy_evaluate_allow,
    bench_policy_evaluate_deny,
    bench_policy_evaluate_approval_required,
    bench_policy_evaluate_all_tiers,
    bench_policy_batch_evaluate,
    bench_policy_applicable_rules,
);
criterion_main!(benches);
