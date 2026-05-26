# ADR-008: Fleet Mode with Mutual TLS and Certificate Pinning

**Status:** Accepted  
**Date:** 2026-05-26  
**Deciders:** Core team  
**Categories:** Security, Fleet, Networking, Authentication

---

## Context

Sentinel's fleet mode enables a single controller instance to orchestrate agents running across multiple hosts simultaneously. This architecture introduces a network communication layer between the controller and each host agent that must address:

**Authentication.** The controller must be certain it is communicating with a legitimate Sentinel agent and not an impersonator. Agents must be certain they are receiving commands from a legitimate controller and not an attacker who has intercepted the communication channel.

**Authorization.** Even within a legitimate controller-agent pair, agents must not accept commands from controllers they were not explicitly configured to trust. Fleet deployments in multi-tenant environments or across organizational boundaries require strong isolation.

**Confidentiality.** Fleet commands carry sensitive information: capability parameters, system observations, and potentially credentials or configuration data. All communication must be encrypted in transit.

**Integrity.** Commands must not be modifiable in transit. A man-in-the-middle attacker who can modify fleet commands could substitute safe operations with destructive ones.

**Zero-trust alignment.** Modern infrastructure security postures assume that the network is hostile. The fleet communication model must provide security guarantees that do not depend on network-level controls (VPNs, firewalls, private subnets). This means authenticating at the application layer.

**Certificate authority independence.** Many fleet deployments operate in air-gapped environments without access to a public CA or an internal PKI infrastructure. The fleet authentication mechanism must work without depending on an external CA.

The `sentinel-fleet` crate implements the controller-agent protocol and is responsible for all fleet networking.

---

## Decision

Fleet mode communication uses mutual TLS (mTLS) with certificate pinning. The specific design choices are:

**Mutual TLS for authentication and encryption.** Both the controller and each agent present X.509 certificates during the TLS handshake. The controller verifies the agent's certificate, and the agent verifies the controller's certificate. Both sides must present a valid certificate to establish a connection — one-sided TLS (where only the server authenticates) is insufficient for zero-trust fleet communication.

**Self-signed certificates via `rcgen`.** The `rcgen` crate is used to generate self-signed X.509 certificates for both the controller and agents at initialization time. This eliminates the dependency on an external CA while providing the full cryptographic security of X.509 certificates. Each Sentinel instance (controller or agent) generates its own keypair and certificate during `sentinel-fleet init`.

**Certificate pinning.** Rather than building a CA trust chain (which would require managing a CA and issuing signed certificates), the fleet uses explicit certificate pinning. Each agent is configured with the SHA-256 fingerprint of the controller certificate it trusts. The controller is configured with the fingerprints of all trusted agent certificates. A connection is rejected if the presented certificate's fingerprint does not match the pinned value, regardless of whether the certificate is otherwise technically valid.

**Certificate pinning enforcement in `tokio-rustls`.** The `tokio-rustls` crate provides the async TLS implementation. Certificate pinning is enforced via a custom `ServerCertVerifier` implementation that checks the presented certificate's fingerprint against the pinned set before accepting the connection. This check occurs during the TLS handshake before any application data is exchanged.

**Certificate rotation protocol.** A certificate rotation ceremony is defined: the operator generates a new certificate on the entity being rotated, adds the new fingerprint to the trusting party's configuration alongside the old fingerprint (dual-pin window), deploys the new certificate, confirms connectivity, and then removes the old fingerprint. This zero-downtime rotation protocol ensures that certificate expiry or compromise can be addressed without fleet connectivity interruption.

**Fleet agent registration.** New agents are registered with the controller via a `sentinel-fleet register` command, which exchanges certificate fingerprints over an authenticated out-of-band channel (or a temporary bootstrap token). Registered agent fingerprints are stored in the controller's fleet manifest.

---

## Rationale

**Mutual TLS provides the strongest widely-deployed authentication primitive.** mTLS is the standard for service-to-service authentication in zero-trust architectures (used by Kubernetes, Istio, and most enterprise service meshes). It combines encryption, authentication, and integrity in a single well-understood protocol with strong implementation support in Rust's `rustls` library.

**Certificate pinning eliminates CA dependency.** In air-gapped or small-scale fleet deployments, maintaining a certificate authority is operationally burdensome. Certificate pinning provides equivalent trust guarantees (I only talk to this specific certificate) without requiring any PKI infrastructure. The trade-off is manual rotation management, which the rotation protocol addresses.

**`rustls` + `tokio-rustls` provides a pure-Rust TLS stack.** `rustls` is a memory-safe TLS implementation written entirely in Rust, with no dependency on OpenSSL or other C TLS libraries. This is essential for maintaining the single-statically-linked musl binary (ADR-010): OpenSSL's dynamic linking requirements would break the static build. `rustls` also eliminates the entire class of OpenSSL CVEs from Sentinel's attack surface.

**`rcgen` eliminates PKI bootstrap complexity.** Self-signed certificate generation via `rcgen` means that fleet initialization requires no external tooling — `sentinel-fleet init` generates the complete PKI artifacts locally. This dramatically simplifies the deployment workflow.

**Zero-trust by construction.** Because authentication happens at the TLS handshake level within the application, it is independent of network topology. A fleet agent deployed in a public cloud, on a private network, or behind a corporate proxy all have the same security properties. There is no "secure internal network" assumption.

---

## Consequences

**Positive:**

- Both controller and agent are authenticated in every connection, preventing impersonation attacks in both directions.
- All fleet communication is encrypted, protecting sensitive capability parameters and system observations from eavesdropping.
- Certificate pinning provides explicit, auditable trust relationships — the fleet manifest is a complete record of which agents are trusted.
- No external CA or PKI infrastructure is required, enabling deployment in air-gapped environments.
- The pure-Rust TLS stack (`rustls`) eliminates OpenSSL CVEs and maintains the static binary constraint.
- Mutual authentication is enforced at the protocol level — it cannot be accidentally disabled in application code.

**Negative:**

- Certificate pinning requires operational discipline for certificate rotation. Allowing a certificate to expire without completing the rotation ceremony will cause fleet connectivity to drop. Monitoring and alerting on certificate expiry dates are required.
- The dual-pin rotation window means that during rotation, both old and new certificates are trusted simultaneously, creating a brief window of potentially broader trust.
- Adding new agents to the fleet requires the operator to exchange certificate fingerprints out-of-band and update the controller's fleet manifest. This is more manual than a CA-signed PKI flow for large fleets.
- The custom `ServerCertVerifier` implementation is security-critical code that must be carefully reviewed. An incorrect implementation could silently disable certificate validation.
- For very large fleets (thousands of hosts), the per-connection TLS handshake and certificate fingerprint lookup overhead must be managed. Connection pooling and persistent connections mitigate this for long-running agent deployments.

---

## Alternatives Considered

**TLS with a private CA.** Using a private Certificate Authority (internal CA via step-ca, HashiCorp Vault PKI, or similar) would allow certificate issuance and revocation without explicit fingerprint management. Certificate revocation via OCSP or CRL provides a way to immediately invalidate a compromised certificate without manual deregistration. This was rejected for initial implementation due to the operational complexity of running and maintaining a CA, but is noted as a future enhancement path for large-scale fleet deployments.

**SSH with host key verification.** SSH provides strong mutual authentication via host keys and client key authentication, and is widely understood by infrastructure engineers. However, implementing a custom SSH protocol layer in Rust would require implementing or wrapping the SSH protocol directly, which is significantly more complex than TLS. `russh` and `ssh2` crates exist but are less mature than `rustls`. SSH also requires a more complex session establishment protocol than TLS.

**WireGuard VPN.** Placing all fleet communication on a WireGuard VPN mesh provides network-layer encryption and authentication. This was considered as an alternative to application-layer TLS. It was rejected because WireGuard requires kernel module support (unavailable in some container environments), requires a separate VPN management plane, and moves the security responsibility outside the Sentinel binary. The application-layer mTLS approach does not require any kernel modules.

**API key / bearer token authentication.** A simpler authentication scheme using API keys or bearer tokens in HTTP headers would be easier to implement and manage. This was rejected because it provides no client authentication (the agent cannot verify the controller's identity), provides no protection if the token is intercepted (replay attacks), and requires a separate encryption layer for confidentiality. mTLS provides all three properties in a single primitive.

**gRPC with mTLS.** Using gRPC (on top of HTTP/2 with TLS) for the fleet protocol would provide a well-defined RPC framework, Protocol Buffers schemas for all messages, and strong ecosystem support. The mTLS and certificate pinning decisions would remain the same. gRPC was considered for the protocol layer but the additional dependency (tonic, prost) and the binary Protocol Buffers format were judged to add complexity without proportionate benefit at the current scale. A bespoke protocol over bare TLS streams is simpler to audit and maintain.
