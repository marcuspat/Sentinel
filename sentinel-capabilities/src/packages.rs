use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use sentinel_core::{
    capability::ResourceImpact, Capability, CapabilityKind, CapabilityManifest, CapabilityResult,
    CoreError, ExecutionContext, RiskTier,
};
use sentinel_exec::CommandExecutorTrait;

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PkgManager {
    Apt,
    Yum,
    Dnf,
    Pacman,
}

impl PkgManager {
    fn name(self) -> &'static str {
        match self {
            PkgManager::Apt => "apt",
            PkgManager::Yum => "yum",
            PkgManager::Dnf => "dnf",
            PkgManager::Pacman => "pacman",
        }
    }

    fn list_args(self) -> Vec<&'static str> {
        match self {
            PkgManager::Apt => vec!["list", "--installed"],
            PkgManager::Yum | PkgManager::Dnf => vec!["list", "installed"],
            PkgManager::Pacman => vec!["-Q"],
        }
    }

    fn upgrade_all_args(self) -> Vec<&'static str> {
        match self {
            PkgManager::Apt => vec!["upgrade", "-y"],
            PkgManager::Yum => vec!["update", "-y"],
            PkgManager::Dnf => vec!["upgrade", "-y"],
            PkgManager::Pacman => vec!["-Syu", "--noconfirm"],
        }
    }

    fn upgrade_pkg_args<'a>(self, pkgs: &'a [&'a str]) -> Vec<&'a str> {
        match self {
            PkgManager::Apt => {
                let mut a = vec!["install", "--only-upgrade", "-y"];
                a.extend_from_slice(pkgs);
                a
            }
            PkgManager::Yum | PkgManager::Dnf => {
                let mut a = vec!["update", "-y"];
                a.extend_from_slice(pkgs);
                a
            }
            PkgManager::Pacman => {
                let mut a = vec!["-S", "--noconfirm"];
                a.extend_from_slice(pkgs);
                a
            }
        }
    }
}

async fn detect_pkg_manager(
    executor: &dyn CommandExecutorTrait,
    env: &std::collections::HashMap<String, String>,
) -> Option<PkgManager> {
    let candidates = [
        ("apt", PkgManager::Apt),
        ("dnf", PkgManager::Dnf),
        ("yum", PkgManager::Yum),
        ("pacman", PkgManager::Pacman),
    ];
    for (prog, variant) in candidates {
        if let Ok(out) = executor.run("which", &[prog], env, 4096).await {
            if out.success() {
                return Some(variant);
            }
        }
    }
    None
}

// ─── PackageList ─────────────────────────────────────────────────────────────

pub struct PackageList {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl PackageList {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "package_list".into(),
                name: "Package List".into(),
                description: "Lists installed packages using the system package manager.".into(),
                kind: CapabilityKind::ReadOnly,
                risk_tier: RiskTier::Low,
                resource_impact: ResourceImpact::default(),
                has_inverse: false,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for PackageList {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        if let Some(f) = args.get("filter") {
            if !f.is_string() {
                return Err(CoreError::InvalidArgs("'filter' must be a string".into()));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        let filter = args.get("filter").and_then(Value::as_str);

        let pm = match detect_pkg_manager(self.executor.as_ref(), &ctx.env_overrides).await {
            Some(pm) => pm,
            None => return CapabilityResult::failure("No supported package manager found", true),
        };

        debug!("PackageList: using {:?}", pm);
        let list_args = pm.list_args();
        let out = match self
            .executor
            .run(pm.name(), &list_args, &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
            .await
        {
            Ok(o) => o,
            Err(e) => return CapabilityResult::failure(e.to_string(), true),
        };

        let packages: Vec<Value> = out
            .stdout
            .lines()
            .filter(|line| {
                if let Some(f) = filter {
                    line.to_lowercase().contains(&f.to_lowercase())
                } else {
                    true
                }
            })
            .map(|line| json!({ "raw": line }))
            .collect();

        let count = packages.len();
        CapabilityResult::success(json!({
            "package_manager": pm.name(),
            "packages": packages,
            "count": count
        }))
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        CapabilityResult::dry_run(json!({
            "predicted_structure": {
                "package_manager": "<detected>",
                "packages": [{ "raw": "example-pkg/stable 1.0.0 amd64" }],
                "count": 1
            },
            "note": "Dry-run: no commands executed"
        }))
    }
}

// ─── PackageUpgrade ──────────────────────────────────────────────────────────

pub struct PackageUpgrade {
    manifest: CapabilityManifest,
    executor: Arc<dyn CommandExecutorTrait>,
}

impl PackageUpgrade {
    pub fn new(executor: Arc<dyn CommandExecutorTrait>) -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "package_upgrade".into(),
                name: "Package Upgrade".into(),
                description: "Upgrades one or more packages (or all packages) via the system package manager.".into(),
                kind: CapabilityKind::Mutating,
                risk_tier: RiskTier::High,
                resource_impact: ResourceImpact {
                    network_required: true,
                    io_intensive: true,
                    ..Default::default()
                },
                has_inverse: true,
                version: "1.0.0".into(),
            },
            executor,
        }
    }
}

#[async_trait]
impl Capability for PackageUpgrade {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn validate_args(&self, args: &Value) -> Result<(), CoreError> {
        let has_packages = args.get("packages").is_some();
        let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);

        if !has_packages && !all {
            return Err(CoreError::InvalidArgs(
                "Either 'packages' (array) or 'all': true must be specified".into(),
            ));
        }
        if let Some(pkgs) = args.get("packages") {
            if !pkgs.is_array() {
                return Err(CoreError::InvalidArgs("'packages' must be an array".into()));
            }
        }
        if let Some(a) = args.get("all") {
            if !a.is_boolean() {
                return Err(CoreError::InvalidArgs("'all' must be a boolean".into()));
            }
        }
        Ok(())
    }

    async fn invoke(&self, args: Value, ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }

        let pm = match detect_pkg_manager(self.executor.as_ref(), &ctx.env_overrides).await {
            Some(pm) => pm,
            None => return CapabilityResult::failure("No supported package manager found", true),
        };

        let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);

        let out = if all {
            let upgrade_args = pm.upgrade_all_args();
            match self
                .executor
                .run(pm.name(), &upgrade_args, &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
                .await
            {
                Ok(o) => o,
                Err(e) => return CapabilityResult::failure(e.to_string(), true),
            }
        } else {
            let pkg_list: Vec<String> = args["packages"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            let pkg_refs: Vec<&str> = pkg_list.iter().map(String::as_str).collect();
            let upgrade_args = pm.upgrade_pkg_args(&pkg_refs);
            match self
                .executor
                .run(pm.name(), &upgrade_args, &ctx.env_overrides, ctx.resource_limits.max_output_bytes)
                .await
            {
                Ok(o) => o,
                Err(e) => return CapabilityResult::failure(e.to_string(), true),
            }
        };

        if out.success() {
            CapabilityResult::success(json!({
                "package_manager": pm.name(),
                "success": true,
                "upgraded_packages": out.stdout.lines().take(50).collect::<Vec<_>>()
            }))
        } else {
            CapabilityResult::failure(
                format!("Package upgrade failed: {}", out.stderr.trim()),
                true,
            )
        }
    }

    async fn dry_run(&self, args: Value, _ctx: &ExecutionContext) -> CapabilityResult {
        if let Err(e) = self.validate_args(&args) {
            return CapabilityResult::failure(e.to_string(), false);
        }
        CapabilityResult::dry_run(json!({
            "args": args,
            "note": "Dry-run: no packages upgraded"
        }))
    }

    async fn invoke_inverse(&self, _args: Value, _ctx: &ExecutionContext) -> Option<CapabilityResult> {
        Some(CapabilityResult::failure(
            "Automatic rollback of package upgrades is not supported. \
             Use your package manager's downgrade command manually.",
            false,
        ))
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
    fn package_list_no_filter() {
        let cap = PackageList::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_ok());
    }

    #[test]
    fn package_list_with_filter() {
        let cap = PackageList::new(make_executor());
        assert!(cap.validate_args(&json!({ "filter": "nginx" })).is_ok());
    }

    #[test]
    fn package_list_bad_filter() {
        let cap = PackageList::new(make_executor());
        assert!(cap.validate_args(&json!({ "filter": 42 })).is_err());
    }

    #[test]
    fn package_upgrade_all_true() {
        let cap = PackageUpgrade::new(make_executor());
        assert!(cap.validate_args(&json!({ "all": true })).is_ok());
    }

    #[test]
    fn package_upgrade_specific_packages() {
        let cap = PackageUpgrade::new(make_executor());
        assert!(cap
            .validate_args(&json!({ "packages": ["nginx", "openssl"] }))
            .is_ok());
    }

    #[test]
    fn package_upgrade_neither() {
        let cap = PackageUpgrade::new(make_executor());
        assert!(cap.validate_args(&json!({})).is_err());
    }

    #[test]
    fn package_upgrade_packages_not_array() {
        let cap = PackageUpgrade::new(make_executor());
        assert!(cap.validate_args(&json!({ "packages": "nginx" })).is_err());
    }

    #[test]
    fn package_upgrade_all_not_bool() {
        let cap = PackageUpgrade::new(make_executor());
        assert!(cap.validate_args(&json!({ "all": "yes" })).is_err());
    }
}
