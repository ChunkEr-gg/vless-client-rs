//! REALITY certificate authentication (HMAC-SHA512 over Ed25519 SPKI).
//!
//! Uses a strict minimal ASN.1 DER X.509 parser so `vless-engine` does not pull in `x509-parser`.

use std::io;

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq;

/// OID `1.3.101.112` (`id-Ed25519`) DER content bytes.
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

struct ParsedRealityCert<'a> {
    ed25519_public_key: [u8; 32],
    signature_bytes: &'a [u8],
}

fn read_der_tlv(input: &[u8]) -> io::Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DER tag"))?;
    let (&len_first, rest) = rest
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DER length"))?;

    let (len, after_len) = if len_first < 0x80 {
        (usize::from(len_first), rest)
    } else if len_first == 0x80 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "indefinite DER length is invalid",
        ));
    } else {
        let num_octets = usize::from(len_first & 0x7f);
        if num_octets == 0 || num_octets > 4 || rest.len() < num_octets {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid long-form DER length",
            ));
        }
        if rest[0] == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-canonical DER length with leading zero",
            ));
        }
        let mut len = 0usize;
        for &b in &rest[..num_octets] {
            len = (len << 8) | usize::from(b);
        }
        if len < 0x80 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-minimal DER long-form length",
            ));
        }
        (len, &rest[num_octets..])
    };

    if after_len.len() < len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DER element exceeds buffer",
        ));
    }
    Ok((tag, &after_len[..len], &after_len[len..]))
}

fn expect_der_tag(input: &[u8], expected_tag: u8) -> io::Result<(&[u8], &[u8])> {
    let (tag, value, rest) = read_der_tlv(input)?;
    if tag != expected_tag {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected DER tag 0x{tag:02x} (expected 0x{expected_tag:02x})"),
        ));
    }
    Ok((value, rest))
}

fn read_der_bit_string(input: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let (value, rest) = expect_der_tag(input, 0x03)?;
    let (&unused_bits, bits) = value
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty DER BIT STRING"))?;
    if unused_bits != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BIT STRING has non-zero unused bits",
        ));
    }
    Ok((bits, rest))
}

fn parse_reality_cert(cert_der: &[u8]) -> io::Result<ParsedRealityCert<'_>> {
    let (cert_body, remaining) = expect_der_tag(cert_der, 0x30)?;
    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing certificate bytes",
        ));
    }

    let (mut tbs, after_tbs) = expect_der_tag(cert_body, 0x30)?;
    let (_sig_alg, after_sig_alg) = expect_der_tag(after_tbs, 0x30)?;
    let (signature_bytes, cert_tail) = read_der_bit_string(after_sig_alg)?;
    if !cert_tail.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing fields inside Certificate SEQUENCE",
        ));
    }

    // Optional [0] EXPLICIT Version
    if tbs.first().copied() == Some(0xa0) {
        let (_, rest) = expect_der_tag(tbs, 0xa0)?;
        tbs = rest;
    }
    // serialNumber INTEGER (0x02)
    let (_, tbs) = expect_der_tag(tbs, 0x02)?;
    // signature AlgorithmIdentifier SEQUENCE (0x30)
    let (_, tbs) = expect_der_tag(tbs, 0x30)?;
    // issuer Name SEQUENCE (0x30)
    let (_, tbs) = expect_der_tag(tbs, 0x30)?;
    // validity Validity SEQUENCE (0x30)
    let (_, tbs) = expect_der_tag(tbs, 0x30)?;
    // subject Name SEQUENCE (0x30)
    let (_, tbs) = expect_der_tag(tbs, 0x30)?;
    // subjectPublicKeyInfo SEQUENCE (0x30)
    let (spki, _tbs_extensions) = expect_der_tag(tbs, 0x30)?;

    let (spki_alg, spki_rest) = expect_der_tag(spki, 0x30)?;
    let (oid_bytes, spki_alg_tail) = expect_der_tag(spki_alg, 0x06)?;
    let (pubkey_data, spki_tail) = read_der_bit_string(spki_rest)?;
    if !spki_tail.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing bytes in SubjectPublicKeyInfo",
        ));
    }

    if oid_bytes != OID_ED25519 || !spki_alg_tail.is_empty() || pubkey_data.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Ed25519 public key (32 bytes), got {} bytes",
                pubkey_data.len()
            ),
        ));
    }

    let mut ed25519_public_key = [0u8; 32];
    ed25519_public_key.copy_from_slice(pubkey_data);
    Ok(ParsedRealityCert {
        ed25519_public_key,
        signature_bytes,
    })
}

/// Verifies the certificate HMAC and returns the authenticated Ed25519 public key.
#[inline]
pub fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> io::Result<[u8; 32]> {
    let parsed = parse_reality_cert(cert_der)?;
    let signature = parsed.signature_bytes;

    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected 64-byte signature for HMAC-SHA512 verification, got {} bytes",
                signature.len()
            ),
        ));
    }

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_tag = hmac::sign(&hmac_key, &parsed.ed25519_public_key);
    let expected_signature = hmac_tag.as_ref();

    if expected_signature.ct_eq(signature).unwrap_u8() == 0 {
        log::warn!(
            "REALITY CLIENT: Certificate HMAC mismatch - not a REALITY server (possible MITM or misconfiguration)"
        );
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Certificate HMAC verification failed - not a REALITY-signed certificate",
        ));
    }

    log::debug!("REALITY CLIENT: Certificate HMAC verified successfully");
    Ok(parsed.ed25519_public_key)
}

/// Extract the Ed25519 public key from a DER-encoded certificate.
#[inline]
pub fn extract_ed25519_public_key(cert_der: &[u8]) -> io::Result<[u8; 32]> {
    Ok(parse_reality_cert(cert_der)?.ed25519_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    #[test]
    fn test_verify_certificate_hmac_with_real_cert() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let mut cert_der = cert.der().to_vec();

        let signing_key =
            aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(key_pair.serialized_der()).unwrap();
        let public_key_bytes = signing_key.public_key().as_ref();

        let sig_offset = {
            let parsed = parse_reality_cert(&cert_der).unwrap();
            parsed.signature_bytes.as_ptr() as usize - cert_der.as_ptr() as usize
        };

        let auth_key = [0x42u8; 32];
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let hmac_tag = hmac::sign(&hmac_key, public_key_bytes);
        cert_der[sig_offset..sig_offset + 64].copy_from_slice(hmac_tag.as_ref());

        let authenticated_key = verify_certificate_hmac(&cert_der, &auth_key).unwrap();
        assert_eq!(authenticated_key, public_key_bytes);

        let mut trailing = cert_der.clone();
        trailing.push(0);
        assert_eq!(
            verify_certificate_hmac(&trailing, &auth_key)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn test_verify_certificate_hmac_invalid_signature() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let result = verify_certificate_hmac(cert.der(), &[0x42u8; 32]);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_verify_certificate_hmac_invalid_der() {
        let result = verify_certificate_hmac(&[0x30, 0x00], &[0x11u8; 32]);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_extract_ed25519_public_key() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let public_key = extract_ed25519_public_key(cert.der()).unwrap();
        let signing_key =
            aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(key_pair.serialized_der()).unwrap();
        assert_eq!(public_key, signing_key.public_key().as_ref());
    }
}
