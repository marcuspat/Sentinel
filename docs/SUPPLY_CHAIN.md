# Supply chain

What stands between a dependency or a CI action and the binary a user runs,
and what to do when one of the checks fails.

## Controls

| Control | Where | What it catches |
|---|---|---|
| `Cargo.lock` committed, builds `--locked` | `ci.yml`, `release.yml` | A build silently resolving a newer crate than the one that was tested |
| `cargo deny check` on every push | `ci.yml` job `supply-chain`, `deny.toml` | Known vulnerabilities and unmaintained/yanked crates (RustSec database), non-permissive licences, git or non-crates.io sources, wildcard version requirements |
| `cargo audit` before a release | `release.yml` job `verify` | The same database, re-checked on release day |
| Actions pinned to commit SHAs | every `uses:` line | A tag (`@v4`) being moved to different code |
| Read-only token by default | top-level `permissions:` | A compromised step pushing to the repository |
| Pinned Rust toolchain | `RUST_TOOLCHAIN` in both workflows | CI going red, or a release being built, with a compiler nobody tested |
| CycloneDX SBOM per binary | `release.yml`, `sentinel-<target>.cdx.json` | Not knowing what is inside a published binary when an advisory lands later |
| Build provenance attestation | `release.yml`, `actions/attest-build-provenance` | A binary that was not built by this repository's release workflow |
| SHA-256 files | `release.yml`, `sentinel-<target>.sha256` | Corruption in transit |

`sentinel-tui/tests/supply_chain.rs` fails the test suite if a workflow
references an action by tag, the two workflows disagree on the toolchain, a
workflow loses its `permissions:` block, the lockfile gains a non-crates.io
source, or `deny.toml` is loosened.

## Verifying a release

```sh
sha256sum -c sentinel-x86_64-unknown-linux-gnu.sha256
gh attestation verify sentinel-x86_64-unknown-linux-gnu --repo marcuspat/Sentinel
```

The attestation ties the binary's digest to the workflow run and commit that
produced it. The SBOM next to the binary lists every crate compiled in.

## When `cargo deny` fails

Run it locally: `cargo install cargo-deny --locked && cargo deny check`.

- **Advisory with a fix:** `cargo update -p <crate>`, run the tests, commit the
  lockfile.
- **Advisory with no fix:** replace the crate if it is ours to replace (this is
  how `rustls-pemfile` left the tree). Otherwise add it to `ignore` in
  `deny.toml` with a `reason` that says why Sentinel is not affected, and remove
  it when a fix ships. An entry without a reason fails the test suite.
- **Licence:** only permissive licences are allowed, because Sentinel ships as
  one static MIT binary. Adding a licence to `allow` is a decision for the
  maintainer, not a way to make CI green.
- **Source:** dependencies come from crates.io. A git dependency is not
  reproducible from the lockfile checksum and is denied.

## Bumping the Rust toolchain

CI is pinned to an exact release, not `stable`, because each stable release
adds clippy lints and `-D warnings` then fails for code nobody changed.

1. Change `RUST_TOOLCHAIN` in **both** `ci.yml` and `release.yml` (a test
   checks they match).
2. Push to a branch; read new lint failures from the check annotations.
3. Fix them, or `#[allow]` at the narrowest scope with a comment when the lint
   fires inside macro output we do not control.
4. Bump at least once per quarter so the gap never becomes a migration.

Known blocker for 1.99: `clippy::double_must_use` fires on the code
`async-trait` generates for `Capability` methods in
`sentinel-core/src/capability.rs`. It has not been resolved from this branch
because Rust 1.99 could not be installed in the environment where the work was
done; whether a newer `async-trait` fixes it is unverified.

## Updating a pinned action

```sh
git ls-remote https://github.com/actions/checkout 'refs/tags/v4*'
```

Use the commit SHA (for an annotated tag, the `^{}` line), and keep the
`# vX.Y.Z` comment in step. `dtolnay/rust-toolchain` has no version tags; it is
pinned to a `master` commit and the toolchain is chosen by the `toolchain:`
input.

## Not covered

- No reproducible-build verification: two builds of the same commit are not
  compared byte for byte.
- `cargo-cyclonedx` and `cargo-deny` are version-pinned but downloaded at run
  time; they are trusted, not vendored.
- No `cargo vet` / crate-level audit of the dependencies' source.
- The published SBOM is CycloneDX 1.3 JSON and is not itself signed; its
  integrity rests on the GitHub release.
