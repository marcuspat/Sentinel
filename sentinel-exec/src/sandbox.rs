//! Sandbox configuration and enforcement for spawned subprocesses.
//!
//! Three mechanisms, all applied in the child between `fork` and `execve`
//! so the parent needs no privilege:
//!
//! * **rlimits** — `RLIMIT_NOFILE`, `RLIMIT_CORE`, optionally `RLIMIT_NPROC`.
//! * **`PR_SET_NO_NEW_PRIVS`** — the child (and everything it execs) can never
//!   gain privilege through setuid/setgid binaries or file capabilities.
//! * **Landlock** (Linux ≥ 5.13) — a kernel-enforced filesystem allowlist
//!   built from [`SandboxConfig::read_only_paths`] and
//!   [`SandboxConfig::writable_paths`].  Once applied it cannot be removed and
//!   is inherited by every descendant.
//!
//! The Landlock ruleset is built in the parent (opening paths allocates and
//! is not async-signal-safe); the `pre_exec` hook only issues raw
//! `prctl` / `landlock_restrict_self` / `setrlimit` syscalls.

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::process::Command;
use tracing::warn;

use crate::error::ExecError;

/// Sandbox configuration for process isolation.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Paths (files or directory trees) the child may read and execute.
    /// Kernel-enforced with Landlock when this or `writable_paths` is
    /// non-empty.
    pub read_only_paths: Vec<PathBuf>,
    /// Paths (files or directory trees) the child may read, write, create
    /// and delete under.  Kernel-enforced with Landlock.
    pub writable_paths: Vec<PathBuf>,
    /// NOT enforced yet — requires Landlock network rules or seccomp BPF;
    /// setting this field emits a warning.
    pub deny_network: bool,
    /// If `true`, `RLIMIT_NPROC` is set to 64 to prevent fork bombs.
    pub deny_new_processes: bool,
    /// Retained for API compatibility.  Privilege *gain* is blocked by
    /// `no_new_privs`; dropping capabilities the process already holds is not
    /// implemented.
    pub drop_capabilities: bool,
    /// Set `PR_SET_NO_NEW_PRIVS` on the child.  Always on when Landlock is
    /// used (the kernel requires it for unprivileged callers).
    pub no_new_privs: bool,
    /// When a filesystem allowlist was requested but the kernel cannot
    /// enforce it: `true` refuses to spawn, `false` warns and runs without
    /// it.
    pub require_enforcement: bool,
}

impl SandboxConfig {
    /// Read and execute anywhere, write only under `writable`.
    ///
    /// The practical profile for a command that needs the whole system's
    /// binaries, libraries and config but should only modify a known place.
    /// `/dev/null` stays writable because nearly every tool opens it.
    pub fn write_restricted<I, P>(writable: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let mut writable_paths: Vec<PathBuf> = writable.into_iter().map(Into::into).collect();
        writable_paths.push(PathBuf::from("/dev/null"));
        Self {
            read_only_paths: vec![PathBuf::from("/")],
            writable_paths,
            no_new_privs: true,
            require_enforcement: true,
            ..Default::default()
        }
    }

    fn wants_landlock(&self) -> bool {
        !self.read_only_paths.is_empty() || !self.writable_paths.is_empty()
    }
}

/// What the sandbox will actually enforce for a prepared command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SandboxReport {
    /// Landlock ABI version of the running kernel; `None` when unavailable.
    pub landlock_abi: Option<u32>,
    /// The filesystem allowlist is kernel-enforced for this child.
    pub filesystem_enforced: bool,
    /// `PR_SET_NO_NEW_PRIVS` will be set on this child.
    pub no_new_privs: bool,
}

/// Apply sandbox constraints to a `tokio::process::Command` before spawning.
///
/// rlimits applied unconditionally: `RLIMIT_NOFILE` → 256, `RLIMIT_CORE` → 0;
/// with [`SandboxConfig::deny_new_processes`], `RLIMIT_NPROC` → 64.
///
/// Returns what will be enforced, or an error when
/// [`SandboxConfig::require_enforcement`] is set and the kernel cannot
/// enforce the requested filesystem allowlist.
pub fn apply_sandbox(
    cmd: &mut Command,
    config: &SandboxConfig,
) -> Result<SandboxReport, ExecError> {
    if config.deny_network {
        warn!(
            "deny_network is set but NOT enforced; \
             network isolation requires Landlock network rules or seccomp BPF"
        );
    }

    let mut report = SandboxReport {
        landlock_abi: landlock::abi(),
        ..Default::default()
    };

    let ruleset: Option<Arc<OwnedFd>> = if config.wants_landlock() {
        match landlock::build_ruleset(config) {
            Ok(fd) => {
                report.filesystem_enforced = true;
                Some(Arc::new(fd))
            }
            Err(reason) if config.require_enforcement => {
                return Err(ExecError::SandboxUnavailable(reason));
            }
            Err(reason) => {
                warn!(
                    %reason,
                    "filesystem allowlist requested but NOT enforced; the child runs without Landlock"
                );
                None
            }
        }
    } else {
        None
    };

    let no_new_privs = config.no_new_privs || ruleset.is_some();
    report.no_new_privs = no_new_privs && cfg!(target_os = "linux");
    let deny_new_processes = config.deny_new_processes;

    // SAFETY: pre_exec runs after fork(), before execve().  Only
    // async-signal-safe operations are performed: raw prctl, setrlimit and
    // landlock_restrict_self syscalls.  No allocation, no locks.  The ruleset
    // fd was created in the parent and is merely read here.
    unsafe {
        cmd.pre_exec(move || {
            use nix::sys::resource::{setrlimit, Resource};

            let map_err = |e: nix::errno::Errno| std::io::Error::from_raw_os_error(e as i32);

            setrlimit(Resource::RLIMIT_NOFILE, 256, 256).map_err(map_err)?;
            setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(map_err)?;
            if deny_new_processes {
                setrlimit(Resource::RLIMIT_NPROC, 64, 64).map_err(map_err)?;
            }

            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;

                if no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Last: after this the child can only touch allowed paths, so
                // a failure here must abort the spawn rather than run
                // unconfined.
                if let Some(fd) = ruleset.as_ref() {
                    if libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = (&ruleset, no_new_privs);

            Ok(())
        });
    }

    Ok(report)
}

/// Raw Landlock bindings.  Kept local and small: three syscalls and the
/// access-right bit masks from `linux/landlock.h`.
#[cfg(target_os = "linux")]
mod landlock {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::SandboxConfig;

    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: libc::c_int = 1;

    const FS_EXECUTE: u64 = 1 << 0;
    const FS_WRITE_FILE: u64 = 1 << 1;
    const FS_READ_FILE: u64 = 1 << 2;
    const FS_READ_DIR: u64 = 1 << 3;
    // Bits 4..=12: REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR, MAKE_REG,
    // MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM.
    const FS_ABI_V1: u64 = (1 << 13) - 1;
    const FS_REFER: u64 = 1 << 13; // ABI 2
    const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
    const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5

    const READ_ONLY: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
    /// Rights that only make sense on directories; the kernel rejects them
    /// (EINVAL) in a rule whose parent fd is a regular file.
    const DIR_ONLY: u64 = FS_ABI_V1 & !(FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE) | FS_REFER;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: libc::c_int,
    }

    /// Landlock ABI version, or `None` when the kernel lacks Landlock or has
    /// it disabled.
    pub fn abi() -> Option<u32> {
        // SAFETY: documented probe form — NULL attr, size 0, VERSION flag.
        let v = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        (v >= 1).then_some(v as u32)
    }

    /// Every filesystem right this kernel can handle.  Handling a right means
    /// "deny unless a rule allows it", so handling all of them is the
    /// strictest ruleset the kernel supports.
    fn handled_fs(abi: u32) -> u64 {
        let mut mask = FS_ABI_V1;
        if abi >= 2 {
            mask |= FS_REFER;
        }
        if abi >= 3 {
            mask |= FS_TRUNCATE;
        }
        if abi >= 5 {
            mask |= FS_IOCTL_DEV;
        }
        mask
    }

    fn add_rule(ruleset: &OwnedFd, path: &Path, access: u64) -> Result<(), String> {
        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return Err(format!("path contains a NUL byte: {}", path.display()));
        };
        // SAFETY: c_path is a valid NUL-terminated string.
        let raw = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            let err = std::io::Error::last_os_error();
            // A path that does not exist cannot be granted; skipping it only
            // makes the sandbox stricter.
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(format!("cannot open {}: {err}", path.display()));
        }
        // SAFETY: raw is a freshly opened, owned descriptor.
        let parent = unsafe { OwnedFd::from_raw_fd(raw) };

        let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
        let allowed_access = if is_dir { access } else { access & !DIR_ONLY };

        let attr = PathBeneathAttr {
            allowed_access,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: attr is a correctly laid out landlock_path_beneath_attr.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(format!(
                "landlock_add_rule({}) failed: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Create a ruleset fd granting `config`'s paths.  The fd is CLOEXEC, so
    /// it does not leak into the sandboxed program.
    pub fn build_ruleset(config: &SandboxConfig) -> Result<OwnedFd, String> {
        let Some(abi) = abi() else {
            return Err("this kernel does not support Landlock".into());
        };
        let handled = handled_fs(abi);
        let attr = RulesetAttr {
            handled_access_fs: handled,
        };
        // SAFETY: attr is a valid landlock_ruleset_attr prefix of the given size.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if raw < 0 {
            return Err(format!(
                "landlock_create_ruleset failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: raw is a freshly created, owned descriptor.
        let ruleset = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };

        for path in &config.read_only_paths {
            add_rule(&ruleset, path, READ_ONLY & handled)?;
        }
        for path in &config.writable_paths {
            add_rule(&ruleset, path, handled)?;
        }
        Ok(ruleset)
    }
}

/// Non-Linux stand-in: Landlock does not exist, so a requested allowlist is
/// reported as unenforceable and `require_enforcement` decides what happens.
#[cfg(not(target_os = "linux"))]
mod landlock {
    use std::os::fd::OwnedFd;

    use super::SandboxConfig;

    pub fn abi() -> Option<u32> {
        None
    }

    pub fn build_ruleset(_config: &SandboxConfig) -> Result<OwnedFd, String> {
        Err("Landlock is only available on Linux".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn default_sandbox_config() {
        let cfg = SandboxConfig::default();
        assert!(!cfg.deny_network);
        assert!(!cfg.deny_new_processes);
        assert!(!cfg.drop_capabilities);
        assert!(!cfg.no_new_privs);
        assert!(!cfg.require_enforcement);
        assert!(cfg.read_only_paths.is_empty());
        assert!(cfg.writable_paths.is_empty());
    }

    #[tokio::test]
    async fn apply_sandbox_does_not_crash_on_simple_command() {
        let cfg = SandboxConfig {
            deny_new_processes: true,
            ..Default::default()
        };
        let mut cmd = Command::new("true");
        let report = apply_sandbox(&mut cmd, &cfg).unwrap();
        assert!(!report.filesystem_enforced);
        assert!(!report.no_new_privs);
        let status = cmd.status().await.expect("spawn failed");
        assert!(status.success());
    }

    /// Run `sh -c script` under `cfg`; returns (success, stdout, stderr).
    async fn sh(cfg: &SandboxConfig, script: &str) -> (bool, String, String) {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_sandbox(&mut cmd, cfg).unwrap();
        let out = cmd.output().await.expect("spawn failed");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Skip (with a visible note) on kernels without Landlock, so the suite
    /// stays green there without pretending the property was checked.
    fn landlock_available() -> bool {
        let ok = landlock::abi().is_some();
        if !ok {
            eprintln!("SKIPPED: kernel has no Landlock support");
        }
        ok
    }

    #[tokio::test]
    async fn landlock_blocks_writes_outside_the_writable_paths() {
        if !landlock_available() {
            return;
        }
        let allowed = tempfile::tempdir().unwrap();
        let forbidden = tempfile::tempdir().unwrap();
        let cfg = SandboxConfig::write_restricted([allowed.path()]);

        let inside = allowed.path().join("ok.txt");
        let outside = forbidden.path().join("nope.txt");

        let (ok, _, err) = sh(&cfg, &format!("echo hi > {}", inside.display())).await;
        assert!(ok, "write inside the allowed dir must work: {err}");
        assert_eq!(std::fs::read_to_string(&inside).unwrap(), "hi\n");

        let (ok, _, err) = sh(&cfg, &format!("echo hi > {}", outside.display())).await;
        assert!(!ok, "write outside the allowed dir must fail");
        assert!(err.contains("ermission denied"), "{err}");
        assert!(!outside.exists(), "nothing may be created outside");
    }

    #[tokio::test]
    async fn landlock_blocks_deleting_and_renaming_outside() {
        if !landlock_available() {
            return;
        }
        let allowed = tempfile::tempdir().unwrap();
        let forbidden = tempfile::tempdir().unwrap();
        let victim = forbidden.path().join("victim.log");
        std::fs::write(&victim, "keep me").unwrap();
        let cfg = SandboxConfig::write_restricted([allowed.path()]);

        let (ok, _, _) = sh(&cfg, &format!("rm -f {}", victim.display())).await;
        assert!(!ok);
        let (ok, _, _) = sh(
            &cfg,
            &format!("mv {} {}/x", victim.display(), allowed.path().display()),
        )
        .await;
        assert!(!ok);
        let (ok, _, _) = sh(&cfg, &format!(": > {}", victim.display())).await;
        assert!(!ok, "truncation must be blocked too");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");

        // Reading is still allowed everywhere under this profile.
        let (ok, out, _) = sh(&cfg, &format!("cat {}", victim.display())).await;
        assert!(ok);
        assert_eq!(out, "keep me");
    }

    #[tokio::test]
    async fn landlock_read_allowlist_hides_everything_else() {
        if !landlock_available() {
            return;
        }
        let secret_dir = tempfile::tempdir().unwrap();
        let secret = secret_dir.path().join("secret");
        std::fs::write(&secret, "s3cret").unwrap();

        // Enough of the system to exec a shell and `cat`, but not the secret.
        let cfg = SandboxConfig {
            read_only_paths: ["/bin", "/usr", "/lib", "/lib64", "/etc"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            writable_paths: vec![PathBuf::from("/dev/null")],
            require_enforcement: true,
            ..Default::default()
        };
        let (ok, out, err) = sh(&cfg, &format!("cat {}", secret.display())).await;
        assert!(!ok, "unlisted path must not be readable; stdout={out}");
        assert!(err.contains("ermission denied"), "{err}");

        let (ok, _, err) = sh(
            &cfg,
            "cat /etc/hostname >/dev/null || cat /etc/passwd >/dev/null",
        )
        .await;
        assert!(ok, "listed paths stay readable: {err}");
    }

    #[tokio::test]
    async fn restrictions_are_inherited_by_grandchildren() {
        if !landlock_available() {
            return;
        }
        let allowed = tempfile::tempdir().unwrap();
        let forbidden = tempfile::tempdir().unwrap();
        let outside = forbidden.path().join("nope.txt");
        let cfg = SandboxConfig::write_restricted([allowed.path()]);
        let (ok, _, _) = sh(
            &cfg,
            &format!(
                "/bin/sh -c '/bin/sh -c \"echo hi > {}\"'",
                outside.display()
            ),
        )
        .await;
        assert!(!ok);
        assert!(!outside.exists());
    }

    #[tokio::test]
    async fn no_new_privs_is_set_in_the_child() {
        let cfg = SandboxConfig {
            no_new_privs: true,
            ..Default::default()
        };
        let (ok, out, _) = sh(&cfg, "grep NoNewPrivs /proc/self/status").await;
        assert!(ok);
        assert!(out.trim_end().ends_with('1'), "{out}");

        let (_, out, _) = sh(
            &SandboxConfig::default(),
            "grep NoNewPrivs /proc/self/status",
        )
        .await;
        assert!(out.trim_end().ends_with('0'), "off by default: {out}");
    }

    #[tokio::test]
    async fn report_states_what_is_enforced() {
        let mut cmd = Command::new("true");
        let report = apply_sandbox(&mut cmd, &SandboxConfig::default()).unwrap();
        assert_eq!(report.landlock_abi, landlock::abi());
        assert!(!report.filesystem_enforced);

        if landlock_available() {
            let dir = tempfile::tempdir().unwrap();
            let mut cmd = Command::new("true");
            let report =
                apply_sandbox(&mut cmd, &SandboxConfig::write_restricted([dir.path()])).unwrap();
            assert!(report.filesystem_enforced);
            assert!(report.no_new_privs, "Landlock implies no_new_privs");
        }
    }

    #[tokio::test]
    async fn missing_allowlisted_paths_are_skipped_not_granted() {
        if !landlock_available() {
            return;
        }
        let cfg = SandboxConfig::write_restricted(["/definitely/not/here"]);
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        let (ok, _, _) = sh(&cfg, &format!("echo x > {}", target.display())).await;
        assert!(!ok);
    }
}
