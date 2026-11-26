use std::io::{Error, ErrorKind, Result};

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use rcgen::SignatureAlgorithm;

struct HmacSigningKey {
    hmac_key: hmac::Key,
    public_key: [u8; 32],
}

impl rcgen::SigningKey for HmacSigningKey {
    fn sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let tag = hmac::sign(&self.hmac_key, &self.public_key);
        Ok(tag.as_ref().to_vec())
    }
}

impl rcgen::PublicKeyData for HmacSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

pub fn generate_hmac_certificate(
    auth_key: &[u8; 32],
    hostname: &str,
) -> Result<(rcgen::Certificate, Ed25519KeyPair)> {
    let ed25519_keypair = Ed25519KeyPair::generate()
        .map_err(|_| Error::other("Failed to generate Ed25519 keypair"))?;

    let public_key: [u8; 32] = ed25519_keypair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Ed25519 public key is not 32 bytes"))?;

    let hmac_key = HmacSigningKey {
        hmac_key: hmac::Key::new(hmac::HMAC_SHA512, auth_key),
        public_key,
    };

    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names =
        vec![rcgen::SanType::DnsName(hostname.try_into().map_err(
            |_| Error::new(ErrorKind::InvalidInput, "Invalid hostname"),
        )?)];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0u8]));

    let cert = params
        .self_signed(&hmac_key)
        .map_err(|e| Error::other(format!("Failed to create certificate: {e}")))?;

    Ok((cert, ed25519_keypair))
}

#[cfg(test)]
mod tests {
    use super::super::reality_certificate_verify::verify_certificate_hmac;
    use super::*;

    #[test]
    fn test_generate_and_verify_hmac_certificate() {
        let auth_key = [0x42u8; 32];
        let (cert, signing_key) = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let verified = verify_certificate_hmac(cert.der(), &auth_key).unwrap();
        assert_eq!(&verified, signing_key.public_key().as_ref());
    }
}
