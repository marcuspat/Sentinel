use std::sync::Arc;

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::error::FleetError;

/// TLS utilities for the Sentinel fleet.
///
/// All certificates use self-signed, rcgen-generated X.509v3 material.  The
/// fleet uses a shared CA cert for mutual TLS: every node cert is signed by
/// the fleet CA, and connections are verified against that CA.
pub struct FleetTls;

impl FleetTls {
    /// Generate a self-signed CA certificate for the fleet.
    ///
    /// Returns the `rcgen::Certificate` (which retains the private key) and
    /// the PEM-encoded CA certificate string for distribution.
    pub fn generate_ca(common_name: &str) -> Result<(Certificate, String), FleetError> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, common_name);
        params.distinguished_name = dn;

        let cert = Certificate::from_params(params)
            .map_err(|e| FleetError::Certificate(e.to_string()))?;

        let pem = cert
            .serialize_pem()
            .map_err(|e| FleetError::Certificate(e.to_string()))?;

        Ok((cert, pem))
    }

    /// Generate a node (end-entity) certificate signed by the given CA.
    ///
    /// `san_ips` is a list of IP address strings (e.g. `["192.168.1.1"]`) to
    /// embed as Subject Alternative Names alongside the node's DNS name.
    ///
    /// Returns `(cert_pem, key_pem)`.
    pub fn generate_node_cert(
        ca_cert: &Certificate,
        node_id: &str,
        san_ips: Vec<String>,
    ) -> Result<(String, String), FleetError> {
        let mut params = CertificateParams::new(vec![node_id.to_string()]);

        // Add explicit IP SANs if provided.
        for ip_str in &san_ips {
            if let Ok(addr) = ip_str.parse() {
                params.subject_alt_names.push(SanType::IpAddress(addr));
            }
        }

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, node_id);
        params.distinguished_name = dn;

        let cert = Certificate::from_params(params)
            .map_err(|e| FleetError::Certificate(e.to_string()))?;

        let cert_pem = cert
            .serialize_pem_with_signer(ca_cert)
            .map_err(|e| FleetError::Certificate(e.to_string()))?;

        let key_pem = cert.serialize_private_key_pem();

        Ok((cert_pem, key_pem))
    }

    /// Compute the SHA-256 fingerprint of a PEM-encoded certificate.
    ///
    /// The fingerprint is returned as a lowercase colon-separated hex string
    /// (e.g. `"aa:bb:cc:..."`), matching the format used by most TLS tooling.
    pub fn cert_fingerprint(cert_pem: &str) -> Result<String, FleetError> {
        // Extract the DER bytes from the PEM.
        let der = Self::pem_to_der(cert_pem)?;

        let mut hasher = Sha256::new();
        hasher.update(&der);
        let digest = hasher.finalize();

        let hex: String = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");

        Ok(hex)
    }

    /// Build a rustls `ServerConfig` for fleet agents.
    ///
    /// The server requires client certificates signed by `ca_cert_pem`.
    pub fn server_config(
        cert_pem: &str,
        key_pem: &str,
        ca_cert_pem: &str,
    ) -> Result<Arc<rustls::ServerConfig>, FleetError> {
        let cert_der = Self::pem_to_der(cert_pem)?;
        let key_der = Self::pem_key_to_der(key_pem)?;
        let ca_der = Self::pem_to_der(ca_cert_pem)?;

        let cert_chain = vec![CertificateDer::from(cert_der)];
        let private_key =
            PrivateKeyDer::try_from(key_der).map_err(|e| FleetError::Tls(e.to_string()))?;

        // Build client verifier: clients must present a cert signed by our CA.
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_der))
            .map_err(|e| FleetError::Tls(e.to_string()))?;

        let client_verifier = rustls::server::WebPkiClientVerifier::builder(root_store.into())
            .build()
            .map_err(|e| FleetError::Tls(e.to_string()))?;

        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| FleetError::Tls(e.to_string()))?;

        Ok(Arc::new(config))
    }

    /// Build a rustls `ClientConfig` for fleet controllers.
    ///
    /// Presents `cert_pem`/`key_pem` as a client certificate.  Server
    /// certificates are accepted only if their fingerprint matches
    /// `pinned_fingerprint` (colon-separated SHA-256 hex string).
    pub fn client_config(
        cert_pem: &str,
        key_pem: &str,
        pinned_fingerprint: &str,
    ) -> Result<Arc<rustls::ClientConfig>, FleetError> {
        let cert_der = Self::pem_to_der(cert_pem)?;
        let key_der = Self::pem_key_to_der(key_pem)?;

        let cert_chain = vec![CertificateDer::from(cert_der)];
        let private_key =
            PrivateKeyDer::try_from(key_der).map_err(|e| FleetError::Tls(e.to_string()))?;

        // We use a pinned-fingerprint verifier rather than a CA-based one so
        // that the controller can trust the specific server cert it issued.
        let verifier = PinnedFingerprintVerifier::new(pinned_fingerprint.to_string());

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| FleetError::Tls(e.to_string()))?;

        Ok(Arc::new(config))
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Decode the first PEM block in `pem` and return the raw DER bytes.
    fn pem_to_der(pem: &str) -> Result<Vec<u8>, FleetError> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let items = rustls_pemfile::read_all(&mut reader)
            .map_err(|e| FleetError::Certificate(e.to_string()))?;

        for item in items {
            if let rustls_pemfile::Item::X509Certificate(der) = item {
                return Ok(der);
            }
        }
        Err(FleetError::Certificate(
            "no X.509 certificate found in PEM input".into(),
        ))
    }

    /// Decode a PEM-encoded private key and return the raw DER bytes.
    fn pem_key_to_der(pem: &str) -> Result<Vec<u8>, FleetError> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let items = rustls_pemfile::read_all(&mut reader)
            .map_err(|e| FleetError::Certificate(e.to_string()))?;

        for item in items {
            match item {
                rustls_pemfile::Item::RSAKey(k) => return Ok(k),
                rustls_pemfile::Item::PKCS8Key(k) => return Ok(k),
                rustls_pemfile::Item::ECKey(k) => return Ok(k),
                _ => continue,
            }
        }
        Err(FleetError::Certificate(
            "no private key found in PEM input".into(),
        ))
    }
}

// ── Pinned fingerprint verifier ───────────────────────────────────────────────

/// A custom `ServerCertVerifier` that accepts a server certificate only if its
/// SHA-256 fingerprint matches the pre-configured value.
///
/// This avoids the need to distribute a CA bundle on the controller side while
/// still providing strong certificate binding.
#[derive(Debug)]
struct PinnedFingerprintVerifier {
    pinned: String,
}

impl PinnedFingerprintVerifier {
    fn new(pinned: String) -> Self {
        Self { pinned }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let digest = hasher.finalize();
        let fingerprint = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");

        // Note: the FleetTls::cert_fingerprint computes SHA-256 of the DER bytes
        // (same as what we compute here from CertificateDer).
        if fingerprint == self.pinned {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {} got {}",
                self.pinned, fingerprint
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CA generation ─────────────────────────────────────────────────────────

    #[test]
    fn generate_ca_returns_valid_pem() {
        let (_, pem) = FleetTls::generate_ca("fleet-ca").expect("generate CA");
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn generate_ca_pem_is_parseable() {
        let (_, pem) = FleetTls::generate_ca("sentinel-fleet-ca").unwrap();
        // Should be able to extract DER bytes without error.
        let der = FleetTls::pem_to_der(&pem).unwrap();
        assert!(!der.is_empty());
    }

    // ── Node cert generation ──────────────────────────────────────────────────

    #[test]
    fn generate_node_cert_returns_cert_and_key() {
        let (ca, _ca_pem) = FleetTls::generate_ca("fleet-ca").unwrap();
        let (cert_pem, key_pem) =
            FleetTls::generate_node_cert(&ca, "node-1", vec!["127.0.0.1".into()]).unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(
            key_pem.contains("BEGIN")
                && (key_pem.contains("PRIVATE KEY") || key_pem.contains("EC PARAMETERS"))
        );
    }

    #[test]
    fn generate_node_cert_pem_is_parseable() {
        let (ca, _) = FleetTls::generate_ca("fleet-ca").unwrap();
        let (cert_pem, _) = FleetTls::generate_node_cert(&ca, "node-2", vec![]).unwrap();
        let der = FleetTls::pem_to_der(&cert_pem).unwrap();
        assert!(!der.is_empty());
    }

    // ── Fingerprint ───────────────────────────────────────────────────────────

    #[test]
    fn cert_fingerprint_is_stable() {
        let (ca, ca_pem) = FleetTls::generate_ca("fp-ca").unwrap();
        let (cert_pem, _) = FleetTls::generate_node_cert(&ca, "fp-node", vec![]).unwrap();

        let fp1 = FleetTls::cert_fingerprint(&cert_pem).unwrap();
        let fp2 = FleetTls::cert_fingerprint(&cert_pem).unwrap();
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");

        // CA fingerprint should differ from node cert fingerprint.
        let ca_fp = FleetTls::cert_fingerprint(&ca_pem).unwrap();
        assert_ne!(fp1, ca_fp);
    }

    #[test]
    fn cert_fingerprint_format_is_colon_separated_hex() {
        let (_, ca_pem) = FleetTls::generate_ca("fmt-ca").unwrap();
        let fp = FleetTls::cert_fingerprint(&ca_pem).unwrap();
        // SHA-256 produces 32 bytes → 32 pairs separated by 31 colons.
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 32);
        for part in &parts {
            assert_eq!(part.len(), 2, "each octet must be two hex chars");
        }
    }

    #[test]
    fn cert_fingerprint_error_on_empty_input() {
        let result = FleetTls::cert_fingerprint("not a certificate");
        assert!(result.is_err());
    }

    // ── Server config ─────────────────────────────────────────────────────────

    #[test]
    fn server_config_builds_without_error() {
        let (ca, ca_pem) = FleetTls::generate_ca("server-ca").unwrap();
        let (cert_pem, key_pem) =
            FleetTls::generate_node_cert(&ca, "server-node", vec![]).unwrap();

        FleetTls::server_config(&cert_pem, &key_pem, &ca_pem)
            .expect("server_config must build");
    }

    // ── Client config ─────────────────────────────────────────────────────────

    #[test]
    fn client_config_builds_without_error() {
        let (ca, _) = FleetTls::generate_ca("client-ca").unwrap();
        let (client_pem, client_key) =
            FleetTls::generate_node_cert(&ca, "client-node", vec![]).unwrap();
        let (server_pem, _) = FleetTls::generate_node_cert(&ca, "server-node", vec![]).unwrap();

        // Compute fingerprint of the server cert from its DER bytes.
        let server_der = FleetTls::pem_to_der(&server_pem).unwrap();
        let mut h = sha2::Sha256::new();
        h.update(&server_der);
        let digest = h.finalize();
        let fp = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");

        FleetTls::client_config(&client_pem, &client_key, &fp)
            .expect("client_config must build");
    }
}
