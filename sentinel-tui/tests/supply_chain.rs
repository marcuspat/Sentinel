//! Guards on the build and release pipeline itself.
//!
//! These read the workflow files, `deny.toml` and `Cargo.lock` from the
//! repository and fail when a supply-chain control is quietly dropped: an
//! action referenced by a movable tag, a toolchain that drifts between CI and
//! release, a git dependency, a workflow with default (write) permissions.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate lives in the workspace root")
        .to_path_buf()
}

fn workflows() -> Vec<(String, String)> {
    let dir = repo_root().join(".github/workflows");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("workflows directory") {
        let path = entry.unwrap().path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "yml" || ext == "yaml" {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
    assert!(!out.is_empty(), "no workflow files found in {dir:?}");
    out
}

/// The value of a `uses:` line, without a trailing comment.
fn uses_refs(text: &str) -> Vec<(usize, String, Option<String>)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let line = line.trim().trim_start_matches("- ");
            let rest = line.strip_prefix("uses:")?;
            let (value, comment) = match rest.split_once('#') {
                Some((v, c)) => (v.trim(), Some(c.trim().to_string())),
                None => (rest.trim(), None),
            };
            Some((i + 1, value.to_string(), comment))
        })
        .collect()
}

fn toolchain_env(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let v = l.trim().strip_prefix("RUST_TOOLCHAIN:")?;
        let v = v.split('#').next().unwrap().trim().trim_matches('"');
        Some(v.to_string())
    })
}

#[test]
fn every_action_is_pinned_to_a_full_commit_sha() {
    let mut seen = 0;
    for (file, text) in workflows() {
        for (line, value, comment) in uses_refs(&text) {
            seen += 1;
            // Local actions (`./…`) are part of this repository's own tree.
            if value.starts_with("./") {
                continue;
            }
            let (action, reference) = value
                .split_once('@')
                .unwrap_or_else(|| panic!("{file}:{line}: `{value}` has no @ref"));
            assert!(
                reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()),
                "{file}:{line}: {action} is referenced by `{reference}`, not a 40-character \
                 commit SHA — a tag or branch can be moved to different code"
            );
            assert!(
                comment.as_deref().is_some_and(|c| !c.is_empty()),
                "{file}:{line}: {action} needs a trailing `# <version>` comment so the pin \
                 is reviewable"
            );
        }
    }
    assert!(
        seen >= 10,
        "expected the workflows to use actions, saw {seen}"
    );
}

#[test]
fn ci_and_release_use_the_same_pinned_toolchain() {
    let flows = workflows();
    let versions: Vec<(String, String)> = flows
        .iter()
        .map(|(file, text)| {
            let v =
                toolchain_env(text).unwrap_or_else(|| panic!("{file}: no RUST_TOOLCHAIN in env"));
            (file.clone(), v)
        })
        .collect();
    for (file, v) in &versions {
        let parts: Vec<&str> = v.split('.').collect();
        assert!(
            parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
            "{file}: RUST_TOOLCHAIN `{v}` must be an exact x.y.z release, not a channel"
        );
        assert_eq!(v, &versions[0].1, "{file} and {} disagree", versions[0].0);
    }
    // Every toolchain install goes through that variable.
    for (file, text) in &flows {
        let installs = text.matches("dtolnay/rust-toolchain@").count();
        let pinned = text.matches("toolchain: ${{ env.RUST_TOOLCHAIN }}").count();
        assert_eq!(
            installs, pinned,
            "{file}: every rust-toolchain step must set `toolchain: ${{{{ env.RUST_TOOLCHAIN }}}}`"
        );
    }
}

#[test]
fn pinned_toolchain_is_not_older_than_the_declared_msrv() {
    let manifest = fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    let msrv = manifest
        .lines()
        .find_map(|l| l.trim().strip_prefix("rust-version"))
        .map(|v| {
            v.trim_start_matches([' ', '='])
                .trim()
                .trim_matches('"')
                .to_string()
        })
        .expect("workspace declares rust-version");
    let num = |s: &str| -> Vec<u32> { s.split('.').map(|p| p.parse().unwrap()).collect() };
    for (file, text) in workflows() {
        let pinned = toolchain_env(&text).unwrap();
        assert!(
            num(&pinned) >= num(&msrv),
            "{file}: toolchain {pinned} is older than rust-version {msrv}"
        );
    }
}

#[test]
fn workflows_default_to_read_only_permissions() {
    for (file, text) in workflows() {
        // The top-level block: `permissions:` at column 0 followed by
        // `contents: read`.
        let mut lines = text.lines();
        let found = loop {
            match lines.next() {
                Some("permissions:") => {
                    break lines.next().map(str::trim) == Some("contents: read")
                }
                Some(_) => continue,
                None => break false,
            }
        };
        assert!(
            found,
            "{file}: needs a top-level `permissions:` block starting with `contents: read`; \
             without one the token gets the repository default, which may be write-all"
        );
        assert!(!text.contains("write-all"), "{file}: write-all permissions");
    }
}

#[test]
fn release_builds_are_locked_attested_and_ship_an_sbom() {
    let text = fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    for line in text.lines().map(str::trim) {
        if line.starts_with("run: cargo build")
            || line.starts_with("run: cargo test")
            || line.starts_with("run: cargo clippy")
        {
            assert!(
                line.contains("--locked"),
                "release step is not --locked: {line}"
            );
        }
    }
    assert!(text.contains("cargo build --release --locked"));
    assert!(text.contains("actions/attest-build-provenance@"));
    assert!(text.contains("id-token: write") && text.contains("attestations: write"));
    assert!(text.contains("cargo cyclonedx"));
    // The SBOM tool is itself version-pinned and installed from the lockfile
    // it was published with.
    assert!(text.contains("cargo install cargo-cyclonedx --locked --version"));
}

#[test]
fn ci_runs_cargo_deny() {
    let text = fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    assert!(text.contains("EmbarkStudios/cargo-deny-action@"));
    assert!(text.contains("command: check"));
}

#[test]
fn deny_config_keeps_the_strict_settings() {
    let text = fs::read_to_string(repo_root().join("deny.toml")).unwrap();
    let cfg: toml::Value = toml::from_str(&text).expect("deny.toml parses");
    assert_eq!(cfg["advisories"]["yanked"].as_str(), Some("deny"));
    assert_eq!(cfg["sources"]["unknown-registry"].as_str(), Some("deny"));
    assert_eq!(cfg["sources"]["unknown-git"].as_str(), Some("deny"));
    assert!(cfg["sources"]["allow-git"].as_array().unwrap().is_empty());
    assert_eq!(cfg["bans"]["wildcards"].as_str(), Some("deny"));

    let allowed: Vec<&str> = cfg["licenses"]["allow"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(allowed.contains(&"MIT"));
    for l in &allowed {
        for copyleft in ["GPL", "AGPL", "LGPL", "MPL", "EUPL", "SSPL", "CDDL"] {
            assert!(
                !l.contains(copyleft),
                "copyleft licence `{l}` in the allow-list"
            );
        }
    }
    // An ignored advisory must say why.
    for entry in cfg["advisories"]["ignore"].as_array().unwrap() {
        let reason = entry.get("reason").and_then(|r| r.as_str()).unwrap_or("");
        assert!(
            !reason.trim().is_empty(),
            "ignored advisory without a reason: {entry}"
        );
    }
}

#[test]
fn lockfile_resolves_only_from_crates_io() {
    let text = fs::read_to_string(repo_root().join("Cargo.lock")).unwrap();
    let lock: toml::Value = toml::from_str(&text).expect("Cargo.lock parses");
    let packages = lock["package"].as_array().unwrap();
    assert!(packages.len() > 100);
    for p in packages {
        let name = p["name"].as_str().unwrap();
        match p.get("source").and_then(|s| s.as_str()) {
            // Workspace members have no source.
            None => assert!(name.starts_with("sentinel-"), "{name} has no source"),
            Some(src) => {
                assert_eq!(
                    src, "registry+https://github.com/rust-lang/crates.io-index",
                    "{name} comes from {src}"
                );
                assert!(
                    p.get("checksum").is_some(),
                    "{name} has no checksum in Cargo.lock"
                );
            }
        }
    }
}

#[test]
fn unmaintained_pem_parser_stays_out_of_the_tree() {
    // RUSTSEC-2025-0134: replaced by rustls-pki-types' own PEM support.
    let text = fs::read_to_string(repo_root().join("Cargo.lock")).unwrap();
    assert!(!text.contains("name = \"rustls-pemfile\""));
}
