use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use sentinel_core::{
    capability::ResourceImpact, Capability, CapabilityKind, CapabilityManifest, CapabilityResult,
    CoreError, ExecutionContext, RiskTier,
};
use sentinel_exec::CommandExecutorTrait;

const VALID_METRICS: &[&str] = &["cpu", "memory", "disk", "load"];

// ─── SystemMetrics ───────────────────────────────────────────────────────────

pub struct SystemMetrics {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl SystemMetrics {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "system_metrics".into(),
                name: "System Metrics".into(),
                description: "Reads system metrics: load average, memory, swap, and uptime from /proc.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: ResourceImpact::default(),
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }

    pub fn parse_loadavg(raw: &str) -> (f64, f64, f64) {
        let parts: Vec<&str> = raw.split_whitespace().collect();
        let parse = |s: &str| s.parse::<f64>().unwrap_or(0.0);
        (
            parts.first().map(|s| parse(s)).unwrap_or(0.0),
            parts.get(1).map(|s| parse(s)).unwrap_or(0.0),
            parts.get(2).map(|s| parse(s)).unwrap_or(0.0),
        )
    }

    pub fn parse_meminfo(raw: &str) -> Value {
        let mut total_kb: u64 = 0;
        let mut free_kb: u64 = 0;
        let mut available_kb: u64 = 0;
        let mut swap_total_kb: u64 = 0;
        let mut swap_free_kb: u64 = 0;

        for line in raw.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let value: u64 = parts[1].parse().unwrap_or(0);
            match parts[0] {
                "MemTotal:"     => total_kb = value,
                "MemFree:"      => free_kb = value,
                "MemAvailable:" => available_kb = value,
                "SwapTotal:"    => swap_total_kb = value,
                "SwapFree:"     => swap_free_kb = value,
                _ => {}
            }
        }

        let kb_to_mb = |kb: u64| kb / 1024;
        json!({
            "mem_total_mb":     kb_to_mb(total_kb),
            "mem_free_mb":      kb_to_mb(free_kb),
            "mem_available_mb": kb_to_mb(available_kb),
            "mem_used_mb":      kb_to_mb(total_kb.saturating_sub(available_kb)),
            "swap_total_mb":    kb_to_mb(swap_total_kb),
            "swap_used_mb":     kb_to_mb(swap_total_kb.saturating_sub(swap_free_kb))
        })
    }

    pub fn parse_uptime(raw: &str) -> u64 {
        raw.split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|f| f as u64)
            .unwrap_or(0)
    }
}

#[async_trait]
impl Capability for SystemMetrics {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        if let Some(include) = args.get("include") {
            let arr = include
                .as_array()
                .ok_or_else(|| CoreError::InvalidArgs("'include' must be an array".into()))?;
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| CoreError::InvalidArgs("'include' items must be strings".into()))?;
                if !VALID_METRICS.contains(&s) {
                    return Err(CoreError::InvalidArgs(format!(
                        "'{}' is not a valid metric; valid values: {:?}",
                        s, VALID_METRICS
                    )));
                }
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }

        let include: Vec<&str> = args
            .get("include")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_else(|| VALID_METRICS.to_vec());

        let mut result = serde_json::Map::new();

        if include.contains(&"load") || include.contains(&"cpu") {
            debug!("SystemMetrics: reading /proc/loadavg");
            let out = match self
                .executor
                .run("cat", &["/proc/loadavg"], &ctx.env_overrides, 4096)
                .await
            {
                Ok(o) => o,
                Err(e) => return CapabilityResult::failure(e.to_string(), true),
            };
            let (l1, l5, l15) = Self::parse_loadavg(&out.stdout);
            result.insert("load_avg_1m".into(), json!(l1));
            result.insert("load_avg_5m".into(), json!(l5));
            result.insert("load_avg_15m".into(), json!(l15));
        }

        if include.contains(&"memory") {
            debug!("SystemMetrics: reading /proc/meminfo");
            let out = match self
                .executor
                .run("cat", &["/proc/meminfo"], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
                .await
            {
                Ok(o) => o,
                Err(e) => return CapabilityResult::failure(e.to_string(), true),
            };
            let mem = Self::parse_meminfo(&out.stdout);
            if let Value::Object(mem_map) = mem {
                result.extend(mem_map);
            }
        }

        if include.contains(&"load") {
            debug!("SystemMetrics: reading /proc/uptime");
            let out = match self
                .executor
                .run("cat", &["/proc/uptime"], &ctx.env_overrides, 4096)
                .await
            {
                Ok(o) => o,
                Err(e) => return CapabilityResult::failure(e.to_string(), true),
            };
            result.insert("uptime_secs".into(), json!(Self::parse_uptime(&out.stdout)));
        }

        if include.contains(&"disk") {
            debug!("SystemMetrics: running df for disk metrics");
            let out = match self
                .executor
                .run("df", &["-h", "--total"], &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
                .await
            {
                Ok(o) => o,
                Err(e) => return CapabilityResult::failure(e.to_string(), true),
            };
            result.insert("disk_raw".into(), json!(out.stdout));
        }

        CapabilityResult::success(Value::Object(result))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        CapabilityResult::dry_run(json!({
            "predicted_structure": {
                "load_avg_1m":    0.42,
                "load_avg_5m":    0.35,
                "load_avg_15m":   0.28,
                "mem_total_mb":   16384,
                "mem_used_mb":    8192,
                "mem_free_mb":    4096,
                "mem_available_mb": 6144,
                "swap_total_mb":  2048,
                "swap_used_mb":   128,
                "uptime_secs":    86400
            },
            "note": "Dry-run: no /proc reads performed"
        }))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sentinel_exec::{CommandExecutorTrait, CommandOutput};

    struct DummyExecutor;
    #[async_trait::async_trait]
    impl CommandExecutorTrait for DummyExecutor {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _env: &HashMap<String, String>,
            _max_output_bytes: usize,
        ) -> Result<CommandOutput, sentinel_exec::ExecError> {
            panic!("DummyExecutor::run should not be called in validate_args tests")
        }
    }

    fn make_executor() -> Arc<dyn CommandExecutorTrait> {
        Arc::new(DummyExecutor)
    }

    #[test]
    fn system_metrics_no_args() {
        let cap = SystemMetrics::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_ok());
    }

    #[test]
    fn system_metrics_valid_include() {
        let cap = SystemMetrics::new(make_executor());
        assert!(cap.validate_args(&json!({ "include": ["cpu", "memory"] })).is_ok());
    }

    #[test]
    fn system_metrics_all_valid() {
        let cap = SystemMetrics::new(make_executor());
        assert!(cap
            .validate_args(&json!({ "include": ["cpu", "memory", "disk", "load"] }))
            .is_ok());
    }

    #[test]
    fn system_metrics_invalid_metric() {
        let cap = SystemMetrics::new(make_executor());
        assert!(cap.validate_args(&json!({ "include": ["network"] })).is_err());
    }

    #[test]
    fn system_metrics_include_not_array() {
        let cap = SystemMetrics::new(make_executor());
        assert!(cap.validate_args(&json!({ "include": "cpu" })).is_err());
    }

    #[test]
    fn system_metrics_include_non_string_item() {
        let cap = SystemMetrics::new(make_executor());
        assert!(cap.validate_args(&json!({ "include": [1, 2] })).is_err());
    }

    #[test]
    fn parse_loadavg_happy_path() {
        let (l1, l5, l15) = SystemMetrics::parse_loadavg("0.42 0.35 0.28 1/512 4567");
        assert!((l1 - 0.42).abs() < 1e-9);
        assert!((l5 - 0.35).abs() < 1e-9);
        assert!((l15 - 0.28).abs() < 1e-9);
    }

    #[test]
    fn parse_meminfo_happy_path() {
        let raw = "MemTotal:       16384 kB\nMemFree:        4096 kB\nMemAvailable:   6144 kB\nSwapTotal:      2048 kB\nSwapFree:       1024 kB\n";
        let v = SystemMetrics::parse_meminfo(raw);
        assert_eq!(v["mem_total_mb"], 16u64);
        assert_eq!(v["swap_used_mb"], 1u64);
    }

    #[test]
    fn parse_uptime_happy_path() {
        let secs = SystemMetrics::parse_uptime("86400.00 12345.67");
        assert_eq!(secs, 86400);
    }
}
