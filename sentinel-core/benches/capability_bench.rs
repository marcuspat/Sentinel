use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sentinel_core::{
    CapabilityKind, CapabilityManifest, CapabilityResult, ResourceImpact, RiskTier,
};
use serde_json::json;

fn make_manifest(id: &str, risk: RiskTier, kind: CapabilityKind) -> CapabilityManifest {
    CapabilityManifest {
        id: id.to_string(),
        name: id.to_string(),
        description: "benchmark capability".to_string(),
        kind,
        risk_tier: risk,
        resource_impact: ResourceImpact::default(),
        has_inverse: risk == RiskTier::Medium,
        version: "1.0.0".to_string(),
    }
}

fn bench_capability_result_construction(c: &mut Criterion) {
    let output = json!({"status": "ok", "used_bytes": 1024, "available_bytes": 8192});

    c.bench_function("CapabilityResult::success", |b| {
        b.iter(|| CapabilityResult::success(black_box(output.clone())))
    });

    c.bench_function("CapabilityResult::failure", |b| {
        b.iter(|| {
            CapabilityResult::failure(
                black_box("policy denied: high-risk operation".to_string()),
                black_box(false),
            )
        })
    });

    c.bench_function("CapabilityResult::dry_run", |b| {
        b.iter(|| CapabilityResult::dry_run(black_box(output.clone())))
    });
}

fn bench_capability_result_matching(c: &mut Criterion) {
    let success = CapabilityResult::success(json!({"value": 42}));
    let failure = CapabilityResult::failure("error".to_string(), false);
    let dry = CapabilityResult::dry_run(json!({"predicted": true}));

    c.bench_function("match Success variant", |b| {
        b.iter(|| match black_box(&success) {
            CapabilityResult::Success { output } => output.is_object(),
            _ => false,
        })
    });

    c.bench_function("match Failure variant", |b| {
        b.iter(|| match black_box(&failure) {
            CapabilityResult::Failure { error, .. } => !error.is_empty(),
            _ => false,
        })
    });

    c.bench_function("match DryRun variant", |b| {
        b.iter(|| match black_box(&dry) {
            CapabilityResult::DryRun { predicted_effect } => predicted_effect.is_object(),
            _ => false,
        })
    });
}

fn bench_manifest_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("CapabilityManifest");

    for risk in [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical] {
        group.bench_with_input(
            BenchmarkId::new("construct", format!("{:?}", risk)),
            &risk,
            |b, &risk| {
                b.iter(|| {
                    make_manifest(
                        black_box("test.capability"),
                        black_box(risk),
                        black_box(CapabilityKind::ReadOnly),
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_risk_tier_ordering(c: &mut Criterion) {
    let tiers = [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical];

    c.bench_function("RiskTier max of 4", |b| {
        b.iter(|| {
            black_box(tiers)
                .iter()
                .copied()
                .max()
                .unwrap_or(RiskTier::Low)
        })
    });

    c.bench_function("RiskTier sort 100 items", |b| {
        let mut items: Vec<RiskTier> = (0..100)
            .map(|i| match i % 4 {
                0 => RiskTier::Low,
                1 => RiskTier::Medium,
                2 => RiskTier::High,
                _ => RiskTier::Critical,
            })
            .collect();
        b.iter(|| {
            let mut v = black_box(items.clone());
            v.sort();
            v
        });
        let _ = items.pop();
    });
}

fn bench_result_serialization(c: &mut Criterion) {
    let result = CapabilityResult::success(json!({
        "hostname": "web-01.prod",
        "services": [
            {"name": "nginx", "status": "active", "pid": 1234},
            {"name": "postgres", "status": "active", "pid": 5678},
        ],
        "disk": {"used_gb": 45.2, "free_gb": 154.8, "total_gb": 200.0},
        "load": [0.42, 0.38, 0.31],
    }));

    c.bench_function("serialize CapabilityResult", |b| {
        b.iter(|| serde_json::to_string(black_box(&result)).unwrap())
    });

    let serialized = serde_json::to_string(&result).unwrap();
    c.bench_function("deserialize CapabilityResult", |b| {
        b.iter(|| {
            serde_json::from_str::<CapabilityResult>(black_box(&serialized)).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_capability_result_construction,
    bench_capability_result_matching,
    bench_manifest_construction,
    bench_risk_tier_ordering,
    bench_result_serialization,
);
criterion_main!(benches);
