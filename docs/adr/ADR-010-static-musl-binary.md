# ADR-010: Single Statically-Linked musl Binary

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Deployment, Security, Portability, Operations

---

## Context

Sentinel is a system administration tool designed to run on Linux servers in diverse environments: bare metal, VMs, containers, air-gapped networks, minimal base images, and restricted corporate environments. The deployment model has significant implications for:

**Installation simplicity.** Requiring a package manager (`apt`, `yum`, `pip`), a language runtime (Python, Node.js, JVM), or specific shared libraries (`glibc`, `libssl`, `libcurl`) creates friction and compatibility issues across diverse Linux distributions and versions.

**Security posture.** Every shared library dependency is an additional attack surface. A vulnerability in a shared library used by Sentinel is a vulnerability in Sentinel's attack surface. Dynamic linking also enables certain attack techniques (LD_PRELOAD injection, shared library hijacking) that are not applicable to statically linked binaries.

**Container deployment.** Sentinel should be deployable in minimal container base images (scratch, distroless) without requiring a full Linux distribution. This reduces the container attack surface and image size significantly.

**Dependency conflicts.** Shared library version conflicts (DLL hell on Linux: `glibc` version mismatches, `libssl` version conflicts) are a common source of deployment failures. A statically linked binary eliminates these conflicts entirely.

**Air-gapped environments.** Environments without internet access cannot install packages from external repositories. A single binary that can be copied and executed without any additional installation steps is essential for these deployments.

**Reproducible deployments.** When troubleshooting incidents, it is important to be certain that the Sentinel binary on a production host is exactly what was built and tested, with no variation from dynamic library differences between hosts.

---

## Decision

All Sentinel release binaries are built as statically-linked executables targeting the `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` Rust targets.

**musl libc** is used as the C standard library (replacing glibc). musl is a lightweight, standards-conformant C library designed for static linking. Unlike glibc, musl is designed to be statically linked into the final binary without the `NSS` dynamic loading issues that make glibc static builds problematic for DNS resolution and user database lookups.

**All Rust crates must be compatible with musl.** Crates that link to C libraries via `cc` (e.g., ring, openssl-sys) must be replaced with pure-Rust alternatives or built with musl-compatible static builds. Specifically:
- TLS: `rustls` (pure Rust, no OpenSSL) — see ADR-008
- Process management: `nix` crate (pure Rust syscall wrappers)
- HTTP: `reqwest` with `rustls-tls` feature (no OpenSSL)

**Build process.** Release builds use the `cross` tool or a musl-enabled Docker build container (Alpine-based) to cross-compile for both architectures. The resulting binaries are stripped (`strip = true` in `[profile.release]`) and compressed with `upx` for distribution. LTO (`lto = "fat"`) and `codegen-units = 1` are used to maximize optimization and minimize binary size.

**Binary verification.** The build pipeline produces SHA-256 checksums and signs binaries with a GPG key or Sigstore cosign. Operators can verify binary integrity before deployment.

**Size targets.** The complete Sentinel binary (all crates, including TUI, fleet, and LLM backends) should remain under 20 MB before compression and under 10 MB after UPX compression. The fleet agent variant (without TUI and LLM backends) should be under 5 MB.

---

## Rationale

**musl static linking is the correct choice for a single-binary Linux tool.** The `x86_64-unknown-linux-musl` target is the standard Rust target for producing portable Linux binaries. It is supported by the Rust project, extensively tested in production by the wider Rust ecosystem (tools like ripgrep, fd, bat, exa all ship musl static binaries), and runs on any Linux kernel version since 2.6.

**Eliminates glibc version compatibility issues.** The most common reason that a Linux binary "doesn't work" on a different distribution is a glibc version mismatch. musl static linking eliminates this class of failure entirely — the binary only depends on the kernel ABI (syscall interface), which is stable across Linux distributions and kernel versions.

**Reduces attack surface via fewer shared libraries.** A statically linked binary cannot be compromised via shared library replacement or injection. LD_PRELOAD and LD_LIBRARY_PATH attacks that could intercept Sentinel's cryptographic operations or policy evaluation are not applicable to a statically linked executable.

**Enables scratch/distroless container deployment.** A musl static binary can be placed directly in a `FROM scratch` container image with no Linux distribution layer at all. The resulting container image contains only the Sentinel binary and any required configuration files. This produces the smallest possible container image and the smallest possible container attack surface.

**Simplifies fleet agent deployment.** Deploying the fleet agent to a new host requires only copying one file and making it executable. No package manager, no runtime installation, no dependency resolution. For fleet deployments that bootstrap new hosts programmatically, this simplicity is essential.

**Consistent behavior across environments.** A self-contained binary with no external library dependencies behaves identically across all Linux environments. When Sentinel does X on the CI build host, it does exactly the same X on a production server, regardless of what libraries are installed on either machine.

---

## Consequences

**Positive:**

- Deploy to any Linux host by copying a single binary — no package manager or runtime required.
- Eliminates glibc version compatibility issues across distributions.
- Enables scratch/distroless container deployment with minimal attack surface.
- LD_PRELOAD and shared library injection attacks do not apply.
- Binary integrity is verifiable via checksum without concerns about dynamic library substitution.
- Fleet agent deployment is maximally simple.

**Negative:**

- Any Rust crate that wraps a C library (openssl-sys, libgit2-sys, etc.) requires either a pure-Rust alternative or musl-compatible static linking of the C library. This constrains dependency choices and requires auditing new dependencies for C library linkage.
- musl's C library implementation has some differences from glibc that can surface in edge cases. Most importantly, musl uses a different DNS resolver implementation that does not support `/etc/nsswitch.conf`. Sentinel's hostname resolution behavior must be tested specifically on musl.
- Building for musl targets requires a musl-enabled toolchain (either a cross-compilation container or a musl system). This adds CI/CD complexity compared to native glibc builds.
- UPX compression, while useful for reducing distribution size, adds startup decompression time (typically 50–200 ms). For an interactive tool, this is acceptable. The uncompressed binary should also be available for environments where startup latency matters.
- Some system administration operations (PAM, NSS-based user lookups) behave differently under musl. Capabilities that interact with these subsystems must be tested on musl-linked builds specifically.
- Debugging symbols are stripped in release builds. Remote debugging on production hosts requires a separate debug build or a DWARF external symbol file.

---

## Alternatives Considered

**glibc static linking.** Building Sentinel with glibc statically linked is technically possible but problematic in practice. glibc's `NSS` (Name Service Switch) subsystem is designed around dynamic plugin loading — a statically linked glibc binary cannot load NSS modules at runtime, which breaks DNS resolution and user/group lookups in many environments. glibc itself recommends against static linking. musl is explicitly designed for static linking and does not have this problem.

**glibc dynamic linking (standard Linux shared library binary).** Building a standard dynamically-linked binary is the simplest approach and produces the smallest binary size (dependencies are shared with other processes). However, it reintroduces all the dependency and version compatibility problems that static linking solves, cannot run in scratch containers, and is vulnerable to shared library attacks. For a security-critical infrastructure tool, these trade-offs are not acceptable.

**AppImage / Flatpak.** Container-like packaging formats (AppImage, Flatpak, Snap) bundle dependencies with the application and provide portable deployment across Linux distributions. These formats are significantly more complex than a single binary, require specific runtime support (AppImage requires FUSE), and are oriented toward desktop application use cases rather than server-side tools. A musl static binary is simpler and more portable.

**Docker container as the deployment unit.** Distributing Sentinel as a pre-built Docker image (rather than a binary) would provide dependency isolation and simplify deployment in containerized environments. However, it requires Docker to be installed on the target host, adds container management overhead, and is unnecessary complexity when a statically linked binary achieves the same isolation goals with lower overhead. The static binary can itself be placed in a Docker image when desired.

**macOS and Windows support.** Extending the static binary approach to macOS (using macOS SDK) and Windows (MSVC or MinGW targets) was considered. macOS does not support fully static binaries (the macOS kernel requires dynamic linking of libSystem). Windows MSVC static linking is complex. For Sentinel's primary use case (Linux server administration), Linux-only musl static binaries cover all target environments. macOS support is provided for development (dynamic build, not a release artifact).
