# ADR-001: Use Rust as the Implementation Language

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Language, Safety, Performance

---

## Context

Sentinel is a security-critical, autonomous system administration tool that executes privileged operations on production infrastructure. The language choice directly affects the following properties:

- **Memory safety**: Undefined behavior, buffer overflows, and use-after-free vulnerabilities are particularly dangerous in a tool that manages system processes and files with elevated privileges.
- **Performance**: The agent loop overhead must stay below 50 ms per capability invocation, and idle RAM must remain below 50 MB. Garbage-collected runtimes introduce unpredictable latency spikes and baseline memory overhead.
- **Deployment model**: The target is a single statically-linked binary for Linux x86-64 and arm64. Interpreted or VM-based languages make this cumbersome or impossible.
- **Concurrency**: Fleet mode requires managing hundreds of concurrent host connections. Efficient async I/O is essential.
- **Ecosystem**: Cryptographic primitives (SHA-256 hash chaining, TLS), terminal UI (Ratatui), Prometheus metrics, and gRPC/HTTP clients all require mature library support.
- **Long-term maintenance**: The codebase is expected to grow to multiple specialized crates and be maintained by a small team that values compiler-enforced correctness over runtime debugging.

The alternatives considered were Go, C/C++, Python, and TypeScript/Deno. Each was evaluated against the constraints above.

---

## Decision

Rust is chosen as the sole implementation language for all Sentinel crates.

The capability trait system, policy engine, execution sandbox, LLM reasoning loop, TUI, fleet controller, and audit log are all written in Rust and compiled in a single Cargo workspace.

---

## Rationale

**Memory safety without a garbage collector.** Rust's ownership and borrow-checker system guarantees at compile time that there are no dangling pointers, data races, or use-after-free errors. For a tool that runs as root and manipulates process trees and filesystems, this eliminates an entire class of security vulnerabilities — without the latency penalty of a runtime GC.

**Predictable performance.** Rust compiles to native machine code with zero-cost abstractions. Async Rust via Tokio provides cooperative multitasking with negligible overhead compared to OS threads, making the < 50 ms capability overhead budget easy to meet. The < 50 MB idle RAM target is achievable because there is no GC heap, no JIT compiler, and no large runtime to carry.

**Single statically-linked binary.** Using the `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets, the entire Sentinel binary — including all dependencies — can be compiled into a single, self-contained executable with no shared library dependencies beyond the kernel ABI. This makes deployment to air-gapped or minimal container environments trivial.

**Type system prevents whole categories of bugs.** The capability abstraction relies on Rust's trait system to enforce that every action is explicitly typed, validated, and routed through the policy engine. The type system makes it impossible to bypass policy checks at compile time by construction — you cannot call an execution function with an unvalidated capability argument.

**Mature async ecosystem.** Tokio, reqwest, tokio-rustls, and tonic provide production-grade async I/O, HTTP, TLS, and gRPC. The entire networking stack for fleet mode (mTLS, certificate pinning) is built on well-audited Rust libraries.

**`thiserror`/`anyhow` error handling.** Rust's `Result<T, E>` type forces explicit error handling at every boundary. Combined with `thiserror` for structured errors at crate boundaries and `anyhow` for application-level context, this prevents silent failures — a critical property for an autonomous agent.

---

## Consequences

**Positive:**

- Compile-time memory safety eliminates buffer overflows, dangling pointers, and data races across the entire codebase.
- Native performance with no GC pauses meets the < 50 ms and < 50 MB budgets comfortably.
- Single musl binary enables deployment to any Linux system without a package manager or container runtime.
- The borrow checker makes the capability ownership and policy gating model naturally expressible and enforced by the type system.
- Reproducible builds with cargo are straightforward; SBOM generation is supported by `cargo cyclonedx` and similar tools.
- Rust's `async`/`await` on Tokio handles hundreds of fleet connections efficiently without thread-per-connection overhead.

**Negative:**

- Rust has a steeper learning curve than Go or Python. New contributors require ramp-up time on the borrow checker, lifetimes, and async patterns.
- Compile times are longer than Go. Incremental compilation and `sccache` mitigate this, but cold builds across the full workspace take time.
- The ecosystem, while mature, is younger than C++ or Python. Some domain-specific libraries (e.g., certain SNMP or proprietary vendor APIs) may be unavailable or require FFI wrappers.
- Cross-compilation to musl targets requires careful management of C dependencies; any crate pulling in a C library via `cc` can break the static binary goal and must be audited.

---

## Alternatives Considered

**Go:** Go produces self-contained binaries (CGO disabled), has excellent concurrency support, and has a gentler learning curve. However, Go's GC introduces unpredictable latency and higher baseline memory usage. Go's type system is less expressive — the capability trait pattern with associated types and blanket implementations is not naturally representable. Go also lacks the compile-time safety guarantees that are central to Sentinel's security model.

**C/C++:** C/C++ would meet performance and binary size requirements, but provides no memory safety guarantees. Writing a security-critical agent in C/C++ would require extensive manual auditing and would likely introduce CVEs over time. The development velocity for a small team is also significantly lower.

**Python:** Python is excellent for rapid prototyping and has rich libraries, but it cannot produce a single statically-linked binary, cannot meet the < 50 MB RAM idle target (the Python interpreter alone exceeds this), and has inherently poor performance for tight execution loops. Python's dynamic typing makes the capability contract system difficult to enforce.

**TypeScript/Deno:** Deno can produce single-file executables but they include the V8 JavaScript engine (~80 MB). The async model is good, but memory safety is not guaranteed, and the V8 GC reintroduces latency. The systems programming ecosystem (process management via `nix`, direct syscalls) is far less mature than Rust's.
