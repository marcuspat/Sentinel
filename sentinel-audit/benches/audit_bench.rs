use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sentinel_audit::{
    events::{AuditEvent, AuditEventType},
    log::AuditLog,
    verifier::AuditVerifier,
};
use uuid::Uuid;

fn build_log_sync(n: usize) -> AuditLog {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let session_id = Uuid::new_v4();
        let mut log = AuditLog::new(session_id, None);

        log.append(AuditEventType::GoalSubmitted {
            goal: "bench".to_string(),
            host: "localhost".to_string(),
        })
        .await
        .unwrap();

        for i in 0..n {
            log.append(AuditEventType::CapabilityInvoked {
                capability_id: format!("cap_{}", i),
                args: serde_json::json!({"index": i}),
                risk_tier: "Low".to_string(),
            })
            .await
            .unwrap();
            log.append(AuditEventType::CapabilitySucceeded {
                capability_id: format!("cap_{}", i),
                duration_ms: 5,
            })
            .await
            .unwrap();
        }

        log.append(AuditEventType::SessionCompleted {
            duration_ms: 1000,
            capabilities_executed: n as u64,
        })
        .await
        .unwrap();

        log
    })
}

fn bench_append_single(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("AuditLog::append single event", |b| {
        b.iter(|| {
            rt.block_on(async {
                let session_id = Uuid::new_v4();
                let mut log = AuditLog::new(session_id, None);
                log.append(black_box(AuditEventType::InvestigationStarted))
                    .await
                    .unwrap();
            })
        })
    });
}

fn bench_append_chain(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("AuditLog append chain");

    for n in [10usize, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let session_id = Uuid::new_v4();
                    let mut log = AuditLog::new(session_id, None);
                    for i in 0..n {
                        log.append(AuditEventType::CapabilityInvoked {
                            capability_id: format!("cap_{}", i),
                            args: serde_json::json!({}),
                            risk_tier: "Low".to_string(),
                        })
                        .await
                        .unwrap();
                    }
                    log
                })
            })
        });
    }

    group.finish();
}

fn bench_verify_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("AuditLog verify chain");

    for n in [10usize, 50, 100, 500] {
        let log = build_log_sync(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &log, |b, log| {
            b.iter(|| log.verify_chain())
        });
    }

    group.finish();
}

fn bench_export_jsonl(c: &mut Criterion) {
    let mut group = c.benchmark_group("AuditLog export_jsonl");

    for n in [10usize, 100, 500] {
        let log = build_log_sync(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &log, |b, log| {
            b.iter(|| log.export_jsonl())
        });
    }

    group.finish();
}

fn bench_verify_jsonl(c: &mut Criterion) {
    let mut group = c.benchmark_group("AuditVerifier::verify_jsonl");

    for n in [10usize, 100, 500] {
        let log = build_log_sync(n);
        let jsonl = log.export_jsonl();
        group.bench_with_input(BenchmarkId::from_parameter(n), &jsonl, |b, jsonl| {
            b.iter(|| AuditVerifier::verify_jsonl(black_box(jsonl)).unwrap())
        });
    }

    group.finish();
}

fn bench_hash_computation(c: &mut Criterion) {
    let event_type = AuditEventType::CapabilityInvoked {
        capability_id: "sentinel.fs.read_file".to_string(),
        args: serde_json::json!({"path": "/etc/nginx/nginx.conf"}),
        risk_tier: "Medium".to_string(),
    };
    let prev_hash = "0".repeat(64);
    let event_id = Uuid::new_v4();
    let timestamp = chrono::Utc::now();
    let session_id = Uuid::new_v4();

    c.bench_function("AuditEvent::compute_hash", |b| {
        b.iter(|| {
            AuditEvent::compute_hash(
                black_box(&prev_hash),
                black_box(&event_type),
                black_box(event_id),
                black_box(42),
                black_box(&timestamp),
                black_box(session_id),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_append_single,
    bench_append_chain,
    bench_verify_chain,
    bench_export_jsonl,
    bench_verify_jsonl,
    bench_hash_computation,
);
criterion_main!(benches);
