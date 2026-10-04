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
    /// Deny Internet and raw-packet sockets (`AF_INET`, `AF_INET6`,
    /// `AF_PACKET`) with a seccomp filter.  Unix and netlink sockets keep
    /// working.  Enforced on Linux x86_64 and aarch64.
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
    /// Internet sockets are denied to this child by a seccomp filter.
    pub network_denied: bool,
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

    let net_filter: Option<Arc<seccomp::Filter>> = if config.deny_network {
        match seccomp::deny_inet_filter() {
            Ok(filter) => {
                report.network_denied = true;
                Some(Arc::new(filter))
            }
            Err(reason) if config.require_enforcement => {
                return Err(ExecError::SandboxUnavailable(reason));
            }
            Err(reason) => {
                warn!(%reason, "deny_network requested but NOT enforced; the child keeps network access");
                None
            }
        }
    } else {
        None
    };

    let no_new_privs = config.no_new_privs || ruleset.is_some() || net_filter.is_some();
    report.no_new_privs = no_new_privs && cfg!(target_os = "linux");
    let deny_new_processes = config.deny_new_processes;

    // SAFETY: pre_exec runs after fork(), before execve().  Only
    // async-signal-safe operations are performed: raw prctl (no_new_privs,
    // seccomp), setrlimit and landlock_restrict_self syscalls.  No allocation, no locks.  The ruleset
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

                // Needs no_new_privs (set above) for unprivileged callers.
                if let Some(filter) = net_filter.as_ref() {
                    if libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        filter.as_fprog_ptr(),
                    ) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
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
            let _ = (&ruleset, &net_filter, no_new_privs);

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

/// A minimal seccomp-BPF filter that denies creating Internet sockets.
///
/// Classic BPF over `struct seccomp_data { nr, arch, ip, args[6] }`.  The
/// program is assembled in the parent; the child only hands the kernel a
/// pointer to it.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod seccomp {
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K

    const OFF_NR: u32 = 0;
    const OFF_ARCH: u32 = 4;
    const OFF_ARG0: u32 = 16; // low 32 bits; both supported targets are little-endian

    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO: u32 = 0x0005_0000;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    /// x32 syscalls carry this bit on x86_64; no aarch64 syscall is this high.
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    pub struct Filter {
        // Boxed so the address handed to the kernel stays put.
        _insns: Box<[libc::sock_filter]>,
        prog: libc::sock_fprog,
    }

    // SAFETY: the raw pointer in `prog` refers to `_insns`, which is owned by
    // the same value and never mutated after construction.
    unsafe impl Send for Filter {}
    unsafe impl Sync for Filter {}

    impl Filter {
        pub fn as_fprog_ptr(&self) -> *const libc::sock_fprog {
            &self.prog
        }

        #[cfg(test)]
        pub fn len(&self) -> usize {
            self.prog.len as usize
        }

        #[cfg(test)]
        pub fn insns(&self) -> &[libc::sock_filter] {
            &self._insns
        }
    }

    const fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// Deny `socket(AF_INET | AF_INET6 | AF_PACKET, …)` with `EACCES`, and
    /// `io_uring_setup` with `ENOSYS` (io_uring can open sockets without
    /// passing through the `socket` syscall).  Everything else is allowed.
    pub fn deny_inet_filter() -> Result<Filter, String> {
        // SAFETY: PR_GET_SECCOMP takes no pointers; it fails with EINVAL on
        // kernels built without seccomp.
        if unsafe { libc::prctl(libc::PR_GET_SECCOMP) } < 0 {
            return Err("this kernel does not support seccomp".into());
        }

        let eacces = RET_ERRNO | libc::EACCES as u32;
        let enosys = RET_ERRNO | libc::ENOSYS as u32;
        // Jump offsets are relative to the next instruction.
        let insns: Box<[libc::sock_filter]> = Box::new([
            /*  0 */ stmt(LD_W_ABS, OFF_ARCH),
            /*  1 */ jump(JEQ_K, AUDIT_ARCH, 1, 0),
            /*  2 */ stmt(RET_K, RET_KILL_PROCESS), // foreign-ABI syscall
            /*  3 */ stmt(LD_W_ABS, OFF_NR),
            /*  4 */ jump(JGE_K, X32_SYSCALL_BIT, 8, 0), // → 13
            /*  5 */ jump(JEQ_K, libc::SYS_io_uring_setup as u32, 7, 0), // → 13
            /*  6 */ jump(JEQ_K, libc::SYS_socket as u32, 0, 4), // else → 11
            /*  7 */ stmt(LD_W_ABS, OFF_ARG0),
            /*  8 */ jump(JEQ_K, libc::AF_INET as u32, 3, 0), // → 12
            /*  9 */ jump(JEQ_K, libc::AF_INET6 as u32, 2, 0), // → 12
            /* 10 */ jump(JEQ_K, libc::AF_PACKET as u32, 1, 0), // → 12
            /* 11 */ stmt(RET_K, RET_ALLOW),
            /* 12 */ stmt(RET_K, eacces),
            /* 13 */ stmt(RET_K, enosys),
        ]);
        let prog = libc::sock_fprog {
            len: insns.len() as libc::c_ushort,
            filter: insns.as_ptr() as *mut libc::sock_filter,
        };
        Ok(Filter {
            _insns: insns,
            prog,
        })
    }
}

/// Stand-in for targets without the seccomp filter above.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod seccomp {
    pub struct Filter;

    impl Filter {
        #[allow(dead_code)]
        pub fn as_fprog_ptr(&self) -> *const std::ffi::c_void {
            std::ptr::null()
        }
    }

    pub fn deny_inet_filter() -> Result<Filter, String> {
        Err("network denial needs Linux on x86_64 or aarch64".into())
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

    #[tokio::test]
    async fn deny_network_blocks_inet_sockets_but_not_unix_or_netlink() {
        let cfg = SandboxConfig {
            deny_network: true,
            ..Default::default()
        };
        let mut probe = Command::new("true");
        let report = apply_sandbox(&mut probe, &cfg).unwrap();
        if !report.network_denied {
            eprintln!("SKIPPED: seccomp network filter unavailable on this target");
            return;
        }
        assert!(report.no_new_privs, "seccomp implies no_new_privs");

        // python3 is the most portable way to ask for specific socket
        // families; skip quietly where it is missing.
        let have_python = std::process::Command::new("python3")
            .arg("-c")
            .arg("pass")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !have_python {
            eprintln!("SKIPPED: python3 not installed");
            return;
        }
        let py = |code: &'static str| {
            let cfg = cfg.clone();
            async move {
                let mut cmd = Command::new("python3");
                cmd.arg("-c")
                    .arg(code)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                apply_sandbox(&mut cmd, &cfg).unwrap();
                let out = cmd.output().await.unwrap();
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
        };

        let probe_family = |family: &'static str| {
            match family {
            "inet" => "import socket\ntry:\n socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('ok')\nexcept OSError as e: print(e.errno)",
            "inet_udp" => "import socket\ntry:\n socket.socket(socket.AF_INET, socket.SOCK_DGRAM); print('ok')\nexcept OSError as e: print(e.errno)",
            "inet6" => "import socket\ntry:\n socket.socket(socket.AF_INET6, socket.SOCK_STREAM); print('ok')\nexcept OSError as e: print(e.errno)",
            "unix" => "import socket\ntry:\n socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('ok')\nexcept OSError as e: print(e.errno)",
            _ => "import socket\ntry:\n socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); print('ok')\nexcept OSError as e: print(e.errno)",
        }
        };

        let eacces = libc::EACCES.to_string();
        assert_eq!(py(probe_family("inet")).await, eacces);
        assert_eq!(
            py(probe_family("inet_udp")).await,
            eacces,
            "UDP is covered too"
        );
        assert_eq!(py(probe_family("inet6")).await, eacces);
        assert_eq!(py(probe_family("unix")).await, "ok");
        assert_eq!(
            py(probe_family("netlink")).await,
            "ok",
            "ss/ip need netlink"
        );
    }

    #[tokio::test]
    async fn network_is_untouched_without_deny_network() {
        let mut cmd = Command::new("true");
        let report = apply_sandbox(&mut cmd, &SandboxConfig::default()).unwrap();
        assert!(!report.network_denied);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn seccomp_jump_targets_land_in_bounds_on_ret_instructions() {
        // gate r1/r4: a length assertion cannot fail for an off-by-one jt/jf —
        // exactly the bug this test exists to catch. Jump targets MAY legally
        // land on a BPF_LD (the socket branch falls through to load ARG0),
        // so the enforceable invariants are: (1) every jt/jf target stays in
        // bounds, (2) the documented as-built targets hold — any offset edit
        // lands somewhere else and fails here with a readable message — and
        // (3) the three terminals are RET instructions.
        let filter = seccomp::deny_inet_filter().unwrap();
        let insns = filter.insns();
        let len = insns.len();
        assert!(len >= 3, "filter suspiciously short: {len}");
        let mut jumps = 0;
        for (i, f) in insns.iter().enumerate() {
            // BPF class mask 0x07: 0x05 = BPF_JMP (conditional, carries jt/jf)
            if f.code & 0x07 == 0x05 {
                jumps += 1;
                for (name, target) in [
                    ("jt", i + 1 + f.jt as usize),
                    ("jf", i + 1 + f.jf as usize),
                ] {
                    assert!(
                        target < len,
                        "instruction {i} {name} target {target} out of bounds (len {len})"
                    );
                }
            }
        }
        // the filter is jumps + loads + returns; with no jumps this test
        // verified nothing
        assert!(jumps >= 5, "expected the documented jump chain, walked {jumps}");
        // as-built targets (indices match the /* n */ comments in the filter):
        // 4 x32-bit → 13 ENOSYS · 5 io_uring_setup → 13 · 6 socket else → 11
        // ALLOW · 8/9/10 AF_INET/6/PACKET → 12 EACCES
        let t = |i: usize, jt: u8| i + 1 + jt as usize;
        assert_eq!(t(4, insns[4].jt), 13, "x32-bit jump must reach ENOSYS");
        assert_eq!(t(5, insns[5].jt), 13, "io_uring_setup jump must reach ENOSYS");
        assert_eq!(t(6, insns[6].jf), 11, "non-socket fall-through must reach ALLOW");
        assert_eq!(t(8, insns[8].jt), 12, "AF_INET must reach EACCES");
        assert_eq!(t(9, insns[9].jt), 12, "AF_INET6 must reach EACCES");
        assert_eq!(t(10, insns[10].jt), 12, "AF_PACKET must reach EACCES");
        // terminals: BPF_RET class = 0x06
        for idx in [11, 12, 13] {
            assert_eq!(
                insns[idx].code & 0x07,
                0x06,
                "terminal instruction {idx} is not a RET"
            );
        }
    }
}
