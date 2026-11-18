//! Rustls client configuration builder (`PLAN.md` §2, §6, §7).
//!
//! Security invariants:
//! - `DisabledVerifier` (`get_disabled_verifier`) is **deleted**; unverified TLS without an
//!   explicit SHA-256 server certificate pin is rejected at configuration time.
//! - On macOS, `verify = true` validates server certificates against the macOS System Keychain via
//!   `rustls-platform-verifier` (Security.framework). On other platforms, `rustls-platform-verifier`
//!   is tried first with `webpki-roots` fallback when host CA bundles are absent.
//! - When `server_fingerprints` (SHA-256 leaf pin) is set, `ServerFingerprintVerifier` enforces an
//!   exact SHA-256 match on the end-entity certificate DER.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;

use crate::config::TlsKeyExchangeGroups;

pub fn try_create_client_config(
    verify_system_roots: bool,
    server_fingerprints: Vec<String>,
    alpn_protocols: Vec<String>,
    enable_sni: bool,
    client_key_and_cert: Option<(Vec<u8>, Vec<u8>)>,
    tls13_only: bool,
    key_exchange_groups: &TlsKeyExchangeGroups,
) -> std::io::Result<rustls::ClientConfig> {
    let provider = crypto_provider_with_groups(key_exchange_groups);
    let builder =
        rustls::ClientConfig::builder_with_details(provider.clone(), crate::clock::time_provider());
    let builder = if tls13_only || key_exchange_groups.requires_hybrid() {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(std::io::Error::other)?;

    let builder = if verify_system_roots {
        let root_verifier = build_system_or_test_verifier(provider)?;
        if !server_fingerprints.is_empty() {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                    supported_algs: get_supported_algorithms(),
                    server_fingerprints: process_fingerprints(&server_fingerprints)?,
                    chain_verifier: Some(root_verifier),
                }))
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(root_verifier)
        }
    } else if !server_fingerprints.is_empty() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                supported_algs: get_supported_algorithms(),
                server_fingerprints: process_fingerprints(&server_fingerprints)?,
                chain_verifier: None,
            }))
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS certificate verification cannot be disabled without a SHA-256 server certificate pin",
        ));
    };

    let mut config = match client_key_and_cert {
        Some((key_bytes, cert_bytes)) => {
            let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(std::io::Error::other)?;
            let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_bytes)
                .map_err(std::io::Error::other)?;
            builder
                .with_client_auth_cert(certs, privkey)
                .map_err(std::io::Error::other)?
        }
        None => builder.with_no_client_auth(),
    };

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.enable_sni = enable_sni;
    if key_exchange_groups.requires_hybrid() {
        config.enable_early_data = false;
    }
    Ok(config)
}

fn build_system_or_test_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> std::io::Result<Arc<dyn rustls::client::danger::ServerCertVerifier>> {
    #[cfg(test)]
    if let Some(roots) = TEST_ROOTS.with_borrow(Clone::clone) {
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(std::io::Error::other)?;
        return Ok(verifier);
    }

    #[cfg(target_os = "macos")]
    {
        let verifier =
            rustls_platform_verifier::Verifier::new(provider).map_err(std::io::Error::other)?;
        Ok(Arc::new(verifier))
    }

    #[cfg(not(target_os = "macos"))]
    {
        match rustls_platform_verifier::Verifier::new(provider.clone()) {
            Ok(verifier) => Ok(Arc::new(verifier)),
            Err(_) => {
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    get_webpki_root_cert_store(),
                    provider,
                )
                .build()
                .map_err(std::io::Error::other)?;
                Ok(verifier)
            }
        }
    }
}

#[derive(Debug)]
pub struct ServerFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    server_fingerprints: BTreeSet<Vec<u8>>,
    chain_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

impl rustls::client::danger::ServerCertVerifier for ServerFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref verifier) = self.chain_verifier {
            let _ = verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.server_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown server certificate SHA-256 fingerprint: {hex_fingerprint}"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

pub(crate) fn process_fingerprints(fingerprints: &[String]) -> std::io::Result<BTreeSet<Vec<u8>>> {
    let mut result = BTreeSet::new();
    for raw in fingerprints {
        let pin = vless_ipc::parse_sha256_pin(raw)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        result.insert(pin.to_vec());
    }
    Ok(result)
}

pub(crate) fn get_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTANCE: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

fn get_supported_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    get_crypto_provider().signature_verification_algorithms
}

fn crypto_provider_with_groups(
    groups: &TlsKeyExchangeGroups,
) -> Arc<rustls::crypto::CryptoProvider> {
    let Some(groups) = groups.groups() else {
        return get_crypto_provider();
    };
    let mut provider = (*get_crypto_provider()).clone();
    provider.kx_groups = groups.iter().map(|group| group.rustls_group()).collect();
    Arc::new(provider)
}

#[cfg(not(target_os = "macos"))]
fn get_webpki_root_cert_store() -> Arc<rustls::RootCertStore> {
    static INSTANCE: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(root_store)
        })
        .clone()
}

#[cfg(test)]
thread_local! {
    static TEST_ROOTS: std::cell::RefCell<Option<Arc<rustls::RootCertStore>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_roots<T>(roots: rustls::RootCertStore, build: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<rustls::RootCertStore>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_ROOTS.set(self.0.take());
        }
    }
    let _restore = Restore(TEST_ROOTS.replace(Some(Arc::new(roots))));
    build()
}

#[cfg(test)]
pub fn try_create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
    tls13_only: bool,
) -> std::io::Result<rustls::ServerConfig> {
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)?;
    let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes)
        .map_err(std::io::Error::other)?;

    let builder = rustls::ServerConfig::builder_with_details(
        get_crypto_provider(),
        crate::clock::time_provider(),
    );
    let builder = if tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(std::io::Error::other)?;

    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(certs, privkey)
        .map_err(std::io::Error::other)?;
    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_tls_without_pin_is_rejected() {
        let err = try_create_client_config(
            false,
            vec![],
            vec!["http/1.1".into()],
            true,
            None,
            true,
            &TlsKeyExchangeGroups::default(),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sha256_pin_creates_client_config_and_rejects_mismatch_on_handshake() {
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert.cert.der().as_ref());
        let matching_pin = vless_ipc::format_sha256_pin_hex(digest.as_ref().try_into().unwrap());
        let wrong_pin = "00".repeat(32);

        let ok_cfg = try_create_client_config(
            false,
            vec![matching_pin],
            vec!["http/1.1".into()],
            true,
            None,
            true,
            &TlsKeyExchangeGroups::default(),
        )
        .unwrap();
        let bad_cfg = try_create_client_config(
            false,
            vec![wrong_pin],
            vec!["http/1.1".into()],
            true,
            None,
            true,
            &TlsKeyExchangeGroups::default(),
        )
        .unwrap();

        let server_cfg = Arc::new(
            try_create_server_config(
                cert.cert.pem().as_bytes(),
                cert.signing_key.serialize_pem().as_bytes(),
                &["http/1.1".into()],
                true,
            )
            .unwrap(),
        );

        let complete_handshake = |client_cfg: rustls::ClientConfig| -> Result<(), rustls::Error> {
            let mut client = rustls::ClientConnection::new(
                Arc::new(client_cfg),
                "example.com".try_into().unwrap(),
            )?;
            let mut server = rustls::ServerConnection::new(server_cfg.clone())?;
            for _ in 0..8 {
                let mut buf = Vec::new();
                client.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    server.read_tls(&mut buf.as_slice()).unwrap();
                    server.process_new_packets()?;
                }
                buf.clear();
                server.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    client.read_tls(&mut buf.as_slice()).unwrap();
                    client.process_new_packets()?;
                }
                if !client.is_handshaking() && !server.is_handshaking() {
                    break;
                }
            }
            Ok(())
        };

        assert!(complete_handshake(ok_cfg).is_ok());
        let err = complete_handshake(bad_cfg).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown server certificate SHA-256 fingerprint")
        );
    }
}
