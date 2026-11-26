//! VLESS profile model, `vless://` URI parser/serializer, and strict validator.

use std::fmt;
use std::net::IpAddr;

use base64::engine::{
    Engine as _,
    general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Url};
use uuid::Uuid;

/// Required VLESS flow value for REALITY Vision connections.
pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// Default ALPN protocol used for kTLS profiles when `alpn` is omitted.
pub const DEFAULT_KTLS_ALPN: &str = "http/1.1";

/// User-facing warning emitted when importing `security=tls` with `flow=xtls-rprx-vision`.
pub const TLS_VISION_PROBE_WARNING: &str =
    "this server treats Vision on the TLS port as a probe; the connection will look dead";

/// Percent-encode set for query parameter values in generated `vless://` links.
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'=')
    .add(b'?')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Percent-encode set for URL `#fragment` profile names.
const FRAGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`');

/// Security configuration for a [`Profile`], corresponding to one of `reality-ktls`'s two
/// listener types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileSecurity {
    /// VLESS + REALITY + `xtls-rprx-vision`.
    Reality {
        public_key: [u8; 32],
        public_key_b64: String,
        short_id: [u8; 8],
        short_id_hex: String,
        sni: String,
        fingerprint: Option<String>,
    },
    /// VLESS over plain TLS 1.3 (`kTLS` server listener), with empty VLESS wire flow.
    Ktls {
        sni: String,
        alpn: Vec<String>,
        cert_sha256_pin: Option<[u8; 32]>,
        fingerprint: Option<String>,
    },
}

impl ProfileSecurity {
    /// Returns the TLS Server Name Indication (SNI) hostname.
    pub fn sni(&self) -> &str {
        match self {
            Self::Reality { sni, .. } | Self::Ktls { sni, .. } => sni,
        }
    }

    /// Returns the optional client TLS fingerprint name (`fp`), if configured.
    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            Self::Reality { fingerprint, .. } | Self::Ktls { fingerprint, .. } => {
                fingerprint.as_deref()
            }
        }
    }

    /// Returns the VLESS wire flow string (`"xtls-rprx-vision"` for REALITY, `""` for kTLS).
    pub fn wire_flow(&self) -> &'static str {
        match self {
            Self::Reality { .. } => VISION_FLOW,
            Self::Ktls { .. } => "",
        }
    }

    /// Returns `true` if this profile targets a REALITY listener.
    pub fn is_reality(&self) -> bool {
        matches!(self, Self::Reality { .. })
    }

    /// Returns `true` if this profile targets a plain TLS 1.3 (`kTLS`) listener.
    pub fn is_ktls(&self) -> bool {
        matches!(self, Self::Ktls { .. })
    }
}

/// A validated VLESS client profile targeting either a REALITY or kTLS listener.
///
/// Custom [`fmt::Debug`] intentionally redacts `uuid` so debug logs never leak user credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    pub server_host: String,
    pub server_port: u16,
    pub uuid: Uuid,
    pub security: ProfileSecurity,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("uuid", &"<redacted>")
            .field("security", &self.security)
            .finish()
    }
}

/// Result of importing a `vless://` link, carrying the parsed [`Profile`] and any non-fatal warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    pub profile: Profile,
    pub warnings: Vec<String>,
}

/// Errors returned when parsing a `vless://` link or validating a [`Profile`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ProfileError {
    #[error("empty VLESS link")]
    EmptyLink,

    #[error("unsupported URI scheme {0:?}: expected \"vless://\"")]
    InvalidScheme(String),

    #[error("invalid VLESS URL: {0}")]
    InvalidUrl(String),

    #[error("missing VLESS user UUID before '@'")]
    MissingUuid,

    #[error("invalid VLESS user UUID: {0}")]
    InvalidUuid(String),

    #[error("missing server host")]
    MissingHost,

    #[error("invalid server host {0:?}: expected a DNS hostname or IP address")]
    InvalidHost(String),

    #[error("missing server port: expected 1..=65535")]
    MissingPort,

    #[error("invalid server port: {0}")]
    InvalidPort(String),

    #[error("profile name must not be empty or contain control characters")]
    InvalidProfileName,

    #[error("invalid percent-encoded UTF-8 in {field}: {detail}")]
    InvalidEncoding { field: &'static str, detail: String },

    #[error("unsupported VLESS encryption {0:?}: only \"none\" is supported")]
    UnsupportedEncryption(String),

    #[error("unsupported transport type {0:?}: only \"tcp\" is supported")]
    UnsupportedTransport(String),

    #[error("missing \"security\" parameter: expected \"reality\" or \"tls\"")]
    MissingSecurity,

    #[error("unsupported security {0:?}: expected \"reality\" or \"tls\"")]
    UnsupportedSecurity(String),

    #[error("missing required SNI (\"sni\") parameter")]
    MissingSni,

    #[error("invalid SNI {0:?}: SNI must be a valid DNS hostname, not an IP address")]
    InvalidSni(String),

    #[error("missing REALITY public key (\"pbk\") parameter")]
    MissingPublicKey,

    #[error("invalid REALITY public key (\"pbk\"): {0}")]
    InvalidPublicKey(String),

    #[error("invalid REALITY short ID (\"sid\"): {0}")]
    InvalidShortId(String),

    #[error("missing REALITY flow: expected flow=\"xtls-rprx-vision\"")]
    MissingFlow,

    #[error("unsupported VLESS flow {0:?}: expected \"xtls-rprx-vision\"")]
    InvalidFlow(String),

    #[error("invalid ALPN list: {0}")]
    InvalidAlpn(String),

    #[error("invalid certificate SHA-256 pin: {0}")]
    InvalidCertPin(String),

    #[error("invalid TLS fingerprint (\"fp\"): {0}")]
    InvalidFingerprint(String),
}

impl Profile {
    /// Parses and validates a `vless://` share link.
    pub fn from_vless_link(link: &str) -> Result<ImportOutcome, ProfileError> {
        parse_vless_link(link)
    }

    /// Formats `server_host:server_port`, wrapping IPv6 literals in `[...]`.
    pub fn server_addr_display(&self) -> String {
        format_host_port(&self.server_host, self.server_port)
    }

    /// Formats this profile as a canonical `vless://` URI.
    pub fn to_vless_link(&self) -> String {
        let host_port = self.server_addr_display();
        let mut query = String::from("encryption=none&type=tcp");

        match &self.security {
            ProfileSecurity::Reality {
                public_key_b64,
                short_id_hex,
                sni,
                fingerprint,
                ..
            } => {
                query.push_str("&security=reality&flow=");
                query.push_str(VISION_FLOW);
                push_query_param(&mut query, "sni", sni);
                push_query_param(&mut query, "pbk", public_key_b64);
                if !short_id_hex.is_empty() {
                    push_query_param(&mut query, "sid", short_id_hex);
                }
                if let Some(fp) = fingerprint
                    && !fp.is_empty()
                {
                    push_query_param(&mut query, "fp", fp);
                }
            }
            ProfileSecurity::Ktls {
                sni,
                alpn,
                cert_sha256_pin,
                fingerprint,
            } => {
                query.push_str("&security=tls");
                push_query_param(&mut query, "sni", sni);
                if !alpn.is_empty() {
                    let joined = alpn.join(",");
                    push_query_param(&mut query, "alpn", &joined);
                }
                if let Some(pin) = cert_sha256_pin {
                    let hex_pin = format_sha256_pin_hex(pin);
                    push_query_param(&mut query, "pcs", &hex_pin);
                }
                if let Some(fp) = fingerprint
                    && !fp.is_empty()
                {
                    push_query_param(&mut query, "fp", fp);
                }
            }
        }

        let mut out = format!("vless://{}@{}?{}", self.uuid, host_port, query);
        if !self.name.is_empty() {
            let encoded_name = utf8_percent_encode(&self.name, FRAGMENT_ENCODE_SET);
            out.push('#');
            out.push_str(&encoded_name.to_string());
        }
        out
    }

    /// Validates all fields of this [`Profile`], ensuring direct struct edits in the UI satisfy
    /// the exact same invariants as `parse_vless_link`.
    pub fn validate(&self) -> Result<Vec<String>, ProfileError> {
        if self.name.trim().is_empty() || self.name.chars().any(char::is_control) {
            return Err(ProfileError::InvalidProfileName);
        }

        validate_server_host(&self.server_host)?;

        if self.server_port == 0 {
            return Err(ProfileError::InvalidPort(
                "port must be between 1 and 65535".to_string(),
            ));
        }

        match &self.security {
            ProfileSecurity::Reality {
                public_key,
                public_key_b64,
                short_id,
                short_id_hex,
                sni,
                fingerprint,
            } => {
                validate_dns_name(sni)?;

                if public_key_b64.is_empty() {
                    return Err(ProfileError::MissingPublicKey);
                }
                let (decoded_pk, _) = decode_public_key(public_key_b64)?;
                if &decoded_pk != public_key {
                    return Err(ProfileError::InvalidPublicKey(
                        "public_key bytes do not match public_key_b64".to_string(),
                    ));
                }

                let decoded_sid = decode_short_id(short_id_hex)?;
                if &decoded_sid != short_id {
                    return Err(ProfileError::InvalidShortId(
                        "short_id bytes do not match short_id_hex".to_string(),
                    ));
                }

                validate_optional_fingerprint(fingerprint.as_deref())?;
            }
            ProfileSecurity::Ktls {
                sni,
                alpn,
                cert_sha256_pin: _,
                fingerprint,
            } => {
                validate_dns_name(sni)?;

                if alpn.is_empty() {
                    return Err(ProfileError::InvalidAlpn(
                        "at least one ALPN protocol is required".to_string(),
                    ));
                }
                for proto in alpn {
                    validate_alpn_token(proto)?;
                }

                validate_optional_fingerprint(fingerprint.as_deref())?;
            }
        }

        Ok(Vec::new())
    }
}

/// Imports a plaintext list of share links or a base64-encoded VLESS subscription body.
/// Every link must validate before the caller receives any profiles.
pub fn parse_profile_list(text: &str) -> Result<Vec<ImportOutcome>, ProfileError> {
    decode_profile_list(text)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(parse_vless_link)
        .collect()
}

/// Returns the original link text for callers that preserve share-link spelling.
pub fn decode_profile_list(text: &str) -> Result<std::borrow::Cow<'_, str>, ProfileError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(ProfileError::EmptyLink);
    }
    let links = if text.contains("://") {
        std::borrow::Cow::Borrowed(text)
    } else {
        let encoded: String = text.split_ascii_whitespace().collect();
        let bytes = [
            base64::engine::general_purpose::STANDARD,
            STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            URL_SAFE_NO_PAD,
        ]
        .iter()
        .find_map(|engine| engine.decode(&encoded).ok())
        .ok_or_else(|| ProfileError::InvalidUrl("invalid subscription encoding".into()))?;
        let decoded = String::from_utf8(bytes).map_err(|_| {
            ProfileError::InvalidUrl("subscription must contain UTF-8 links".into())
        })?;
        std::borrow::Cow::Owned(decoded)
    };
    if links.trim().is_empty() {
        return Err(ProfileError::EmptyLink);
    }
    Ok(links)
}

/// Parses and validates a `vless://` link into an [`ImportOutcome`].
pub fn parse_vless_link(link: &str) -> Result<ImportOutcome, ProfileError> {
    let link = link.trim();
    if link.is_empty() {
        return Err(ProfileError::EmptyLink);
    }

    if let Some((scheme, _)) = link.split_once("://")
        && !scheme.eq_ignore_ascii_case("vless")
    {
        return Err(ProfileError::InvalidScheme(scheme.to_string()));
    }

    let url = Url::parse(link).map_err(|err| match err {
        url::ParseError::InvalidPort => {
            ProfileError::InvalidPort("port is not a valid u16 integer".to_string())
        }
        other => ProfileError::InvalidUrl(other.to_string()),
    })?;

    if url.scheme() != "vless" {
        return Err(ProfileError::InvalidScheme(url.scheme().to_string()));
    }

    if url.password().is_some() {
        return Err(ProfileError::InvalidUuid(
            "unexpected password in URL userinfo".to_string(),
        ));
    }

    let raw_user = url.username();
    if raw_user.is_empty() {
        return Err(ProfileError::MissingUuid);
    }
    let decoded_user = percent_decode_utf8(raw_user, "uuid")?;
    let uuid =
        Uuid::parse_str(&decoded_user).map_err(|err| ProfileError::InvalidUuid(err.to_string()))?;

    let raw_host = match url.host() {
        Some(Host::Ipv6(v6)) => v6.to_string(),
        Some(Host::Ipv4(v4)) => v4.to_string(),
        Some(Host::Domain(domain)) => {
            let decoded = percent_decode_utf8(domain, "host")?;
            normalize_host_case(&decoded)
        }
        None => return Err(ProfileError::MissingHost),
    };
    if raw_host.is_empty() {
        return Err(ProfileError::MissingHost);
    }
    validate_server_host(&raw_host)?;

    let server_port = match url.port() {
        Some(0) => {
            return Err(ProfileError::InvalidPort(
                "port must be between 1 and 65535".to_string(),
            ));
        }
        Some(port) => port,
        None => return Err(ProfileError::MissingPort),
    };

    let params = parse_raw_query(url.query())?;

    // `encryption`: defaults to `"none"`; anything else is an error.
    if let Some(enc) = find_param(&params, "encryption")
        && enc != "none"
    {
        return Err(ProfileError::UnsupportedEncryption(enc.to_string()));
    }

    // `type`: defaults to `"tcp"`; anything else (`ws`, `grpc`, `xhttp`, `quic`, `http`, ...) is an error.
    if let Some(transport) = find_param(&params, "type")
        && !matches!(transport, "tcp" | "raw")
    {
        return Err(ProfileError::UnsupportedTransport(transport.to_string()));
    }

    // `spx` is explicitly ignored if present.
    let _ignored_spx = find_param(&params, "spx");

    let fingerprint = match find_param(&params, "fp") {
        Some("") | None => None,
        Some(fp) => {
            validate_optional_fingerprint(Some(fp))?;
            Some(fp.to_string())
        }
    };

    let mut warnings = Vec::new();

    let security_param = find_param(&params, "security").ok_or(ProfileError::MissingSecurity)?;
    let security = match security_param {
        "reality" => {
            let flow = find_param(&params, "flow").ok_or(ProfileError::MissingFlow)?;
            if flow.is_empty() {
                return Err(ProfileError::MissingFlow);
            }
            if flow != VISION_FLOW {
                return Err(ProfileError::InvalidFlow(flow.to_string()));
            }

            let raw_sni = find_param(&params, "sni").ok_or(ProfileError::MissingSni)?;
            if raw_sni.is_empty() {
                return Err(ProfileError::MissingSni);
            }
            validate_dns_name(raw_sni)?;
            let sni = raw_sni.to_ascii_lowercase();

            let raw_pbk = find_param(&params, "pbk").ok_or(ProfileError::MissingPublicKey)?;
            if raw_pbk.is_empty() {
                return Err(ProfileError::MissingPublicKey);
            }
            let (public_key, public_key_b64) = decode_public_key(raw_pbk)?;

            let raw_sid = find_param(&params, "sid").unwrap_or("");
            let short_id = decode_short_id(raw_sid)?;
            let short_id_hex = raw_sid.to_ascii_lowercase();

            ProfileSecurity::Reality {
                public_key,
                public_key_b64,
                short_id,
                short_id_hex,
                sni,
                fingerprint,
            }
        }
        "tls" => {
            if let Some(flow) = find_param(&params, "flow")
                && !flow.is_empty()
            {
                if flow == VISION_FLOW {
                    warnings.push(TLS_VISION_PROBE_WARNING.to_string());
                } else {
                    return Err(ProfileError::InvalidFlow(flow.to_string()));
                }
            }

            let raw_sni = find_param(&params, "sni").ok_or(ProfileError::MissingSni)?;
            if raw_sni.is_empty() {
                return Err(ProfileError::MissingSni);
            }
            validate_dns_name(raw_sni)?;
            let sni = raw_sni.to_ascii_lowercase();

            let alpn = match find_param(&params, "alpn") {
                None | Some("") => vec![DEFAULT_KTLS_ALPN.to_string()],
                Some(raw_alpn) => {
                    let mut parsed = Vec::new();
                    for item in raw_alpn.split(',') {
                        let trimmed = item.trim();
                        validate_alpn_token(trimmed)?;
                        parsed.push(trimmed.to_string());
                    }
                    if parsed.is_empty() {
                        vec![DEFAULT_KTLS_ALPN.to_string()]
                    } else {
                        parsed
                    }
                }
            };

            let cert_sha256_pin = extract_cert_pin(&params)?;

            ProfileSecurity::Ktls {
                sni,
                alpn,
                cert_sha256_pin,
                fingerprint,
            }
        }
        other => return Err(ProfileError::UnsupportedSecurity(other.to_string())),
    };

    let fallback_name = format_host_port(&raw_host, server_port);
    let name = match url.fragment() {
        Some(frag) if !frag.is_empty() => {
            let decoded = percent_decode_utf8(frag, "fragment")?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                fallback_name
            } else if trimmed.chars().any(char::is_control) {
                return Err(ProfileError::InvalidProfileName);
            } else {
                trimmed.to_string()
            }
        }
        _ => fallback_name,
    };

    let profile = Profile {
        id: Uuid::new_v4(),
        name,
        server_host: raw_host,
        server_port,
        uuid,
        security,
    };

    profile.validate()?;

    Ok(ImportOutcome { profile, warnings })
}

/// Decodes a REALITY base64url public key (`URL_SAFE_NO_PAD`, tolerating up to two `'='` pad
/// characters) into a 32-byte key and its canonical unpadded base64url string.
///
/// Matches `shoes::reality_config::decode_public_key` while normalizing optional `'='` padding.
pub fn decode_public_key(encoded: &str) -> Result<([u8; 32], String), ProfileError> {
    let unpadded = strip_optional_b64_padding(encoded)
        .map_err(|msg| ProfileError::InvalidPublicKey(msg.to_string()))?;

    let decoded = URL_SAFE_NO_PAD
        .decode(unpadded)
        .map_err(|err| ProfileError::InvalidPublicKey(format!("invalid base64url: {err}")))?;

    if decoded.len() != 32 {
        return Err(ProfileError::InvalidPublicKey(format!(
            "invalid public key length: {} bytes (expected 32)",
            decoded.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    let canonical_b64 = URL_SAFE_NO_PAD.encode(key);
    Ok((key, canonical_b64))
}

/// Decodes a hex-encoded REALITY short ID (`0..=16` ASCII hex chars) with right-side `'0'`
/// padding up to 16 hex digits (`[u8; 8]`).
///
/// Matches `shoes::reality_config::decode_short_id` 100%.
pub fn decode_short_id(hex: &str) -> Result<[u8; 8], ProfileError> {
    if hex.len() > 16 {
        return Err(ProfileError::InvalidShortId(format!(
            "short ID too long: {} chars (max 16 hex digits)",
            hex.len()
        )));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProfileError::InvalidShortId(
            "short ID must contain only ASCII hex digits (0-9, a-f, A-F)".to_string(),
        ));
    }

    let padded = format!("{hex:0<16}");
    let mut short_id = [0u8; 8];
    decode_hex_exact(&padded, &mut short_id)
        .map_err(|msg| ProfileError::InvalidShortId(msg.to_string()))?;
    Ok(short_id)
}

/// Validates that `name` is a syntactically valid ASCII DNS hostname and NOT an IPv4/IPv6 literal.
///
/// Matches `shoes::reality_config::parse_server_name` (`ServerName::DnsName`).
pub fn validate_dns_name(name: &str) -> Result<(), ProfileError> {
    if name.is_empty()
        || name.ends_with('.')
        || name.starts_with('[')
        || name.ends_with(']')
        || name.parse::<IpAddr>().is_ok()
    {
        return Err(ProfileError::InvalidSni(name.to_string()));
    }

    match ServerName::try_from(name) {
        Ok(ServerName::DnsName(_)) => Ok(()),
        _ => Err(ProfileError::InvalidSni(name.to_string())),
    }
}

/// Validates that `host` is either a valid `IpAddr` literal (unbracketed) or a valid DNS hostname.
pub fn validate_server_host(host: &str) -> Result<(), ProfileError> {
    if host.is_empty() || host.starts_with('[') || host.ends_with(']') {
        return Err(ProfileError::InvalidHost(host.to_string()));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if !host.ends_with('.') && matches!(ServerName::try_from(host), Ok(ServerName::DnsName(_))) {
        return Ok(());
    }
    Err(ProfileError::InvalidHost(host.to_string()))
}

/// Parses a leaf-certificate SHA-256 pin from 64 hex chars (with optional `:` separators) or
/// 32-byte standard/URL-safe base64.
pub fn parse_sha256_pin(input: &str) -> Result<[u8; 32], ProfileError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ProfileError::InvalidCertPin("empty pin".to_string()));
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ProfileError::InvalidCertPin(
            "pin must not contain whitespace or control characters".to_string(),
        ));
    }

    let body = strip_optional_sha256_prefix(trimmed);

    // 1. Try 64 hex digits (with optional ':' byte separators).
    if body.contains(':') {
        let parts: Vec<&str> = body.split(':').collect();
        if parts.len() != 32
            || parts
                .iter()
                .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ProfileError::InvalidCertPin(
                "colon-separated SHA-256 pin must have 32 two-digit hex octets".to_string(),
            ));
        }
        let clean: String = parts.concat();
        let mut out = [0u8; 32];
        decode_hex_exact(&clean, &mut out)
            .map_err(|msg| ProfileError::InvalidCertPin(msg.to_string()))?;
        return Ok(out);
    }

    if body.len() == 64 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        decode_hex_exact(body, &mut out)
            .map_err(|msg| ProfileError::InvalidCertPin(msg.to_string()))?;
        return Ok(out);
    }

    // 2. Try 32-byte base64 or base64url (with or without '=' padding).
    let unpadded = strip_optional_b64_padding(body)
        .map_err(|msg| ProfileError::InvalidCertPin(msg.to_string()))?;

    let decoded = URL_SAFE_NO_PAD
        .decode(unpadded)
        .or_else(|_| STANDARD_NO_PAD.decode(unpadded))
        .map_err(|_| {
            ProfileError::InvalidCertPin(
                "expected 64 hex chars or 32-byte base64/base64url SHA-256 digest".to_string(),
            )
        })?;

    if decoded.len() != 32 {
        return Err(ProfileError::InvalidCertPin(format!(
            "decoded pin length is {} bytes (expected 32)",
            decoded.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Formats a 32-byte SHA-256 digest as 64 lowercase hexadecimal characters.
pub fn format_sha256_pin_hex(pin: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in pin {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn extract_cert_pin(params: &[(String, String)]) -> Result<Option<[u8; 32]>, ProfileError> {
    let mut resolved: Option<[u8; 32]> = None;
    for key in ["pcs", "pin", "sha256", "pinnedPeerCertSha256"] {
        if let Some(val) = find_param(params, key)
            && !val.is_empty()
        {
            let parsed = parse_sha256_pin(val)?;
            if let Some(prev) = resolved
                && prev != parsed
            {
                return Err(ProfileError::InvalidCertPin(
                    "conflicting certificate pins in query parameters".to_string(),
                ));
            }
            resolved = Some(parsed);
        }
    }
    Ok(resolved)
}

fn strip_optional_sha256_prefix(s: &str) -> &str {
    if let Some(prefix) = s.get(..7) {
        if prefix.eq_ignore_ascii_case("sha256:") || prefix.eq_ignore_ascii_case("sha256/") {
            return &s[7..];
        }
    }
    s
}

fn strip_optional_b64_padding(encoded: &str) -> Result<&str, &'static str> {
    let unpadded = encoded.trim_end_matches('=');
    let pad_len = encoded.len() - unpadded.len();
    if pad_len > 2 {
        return Err("invalid base64 padding");
    }
    if unpadded.is_empty() || unpadded.contains('=') {
        return Err("invalid base64 encoding");
    }
    Ok(unpadded)
}

fn decode_hex_exact(hex: &str, out: &mut [u8]) -> Result<(), &'static str> {
    if hex.len() != out.len() * 2 {
        return Err("invalid hex length");
    }
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("invalid hex length");
    }
    for (idx, &[hi_ch, lo_ch]) in pairs.iter().enumerate() {
        let hi = hex_nibble(hi_ch)?;
        let lo = hex_nibble(lo_ch)?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex digit"),
    }
}

fn validate_alpn_token(token: &str) -> Result<(), ProfileError> {
    if token.is_empty() || token.len() > 255 {
        return Err(ProfileError::InvalidAlpn(
            "ALPN protocol token must be 1..=255 bytes".to_string(),
        ));
    }
    if !token.is_ascii() || token.chars().any(char::is_control) {
        return Err(ProfileError::InvalidAlpn(format!(
            "ALPN token {token:?} must be printable ASCII"
        )));
    }
    Ok(())
}

fn validate_optional_fingerprint(fp: Option<&str>) -> Result<(), ProfileError> {
    if let Some(fp) = fp {
        if fp.is_empty() || fp.len() > 64 {
            return Err(ProfileError::InvalidFingerprint(
                "fingerprint must be 1..=64 characters".to_string(),
            ));
        }
        if !fp.is_ascii()
            || fp
                .chars()
                .any(|c| c.is_control() || c.is_ascii_whitespace())
        {
            return Err(ProfileError::InvalidFingerprint(
                "fingerprint must be printable non-whitespace ASCII".to_string(),
            ));
        }
    }
    Ok(())
}

fn parse_raw_query(query: Option<&str>) -> Result<Vec<(String, String)>, ProfileError> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::new();
    let mut keys = std::collections::HashSet::new();
    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = segment.split_once('=').unwrap_or((segment, ""));
        let key = percent_decode_utf8(raw_k, "query key")?;
        if !keys.insert(key.clone()) {
            return Err(ProfileError::InvalidUrl(
                "duplicate VLESS link parameter".into(),
            ));
        }
        let val = percent_decode_utf8(raw_v, "query value")?;
        pairs.push((key, val));
    }
    Ok(pairs)
}

fn find_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn percent_decode_utf8(input: &str, field: &'static str) -> Result<String, ProfileError> {
    percent_decode_str(input)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|err| ProfileError::InvalidEncoding {
            field,
            detail: err.to_string(),
        })
}

fn normalize_host_case(host: &str) -> String {
    if host.parse::<IpAddr>().is_ok() {
        host.to_string()
    } else {
        host.to_ascii_lowercase()
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn push_query_param(query: &mut String, key: &str, value: &str) {
    query.push('&');
    query.push_str(key);
    query.push('=');
    query.push_str(&utf8_percent_encode(value, QUERY_ENCODE_SET).to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn imports_draft_client_raw_tcp_and_rejects_ambiguous_parameters() {
        let link =
            format!("vless://{SAMPLE_UUID}@example.com:443?security=tls&sni=example.com&type=raw");
        parse_vless_link(&link).expect("raw TCP alias");
        assert!(matches!(
            parse_vless_link(&format!("{link}&%74ype=tcp")),
            Err(ProfileError::InvalidUrl(_))
        ));
    }

    #[test]
    fn imports_plain_and_encoded_subscription_lists_atomically() {
        let link = format!("vless://{SAMPLE_UUID}@example.com:443?security=tls&sni=example.com");
        let list = format!("{link}#First\r\n\r\n{link}#Second");
        for input in [
            list.clone(),
            URL_SAFE_NO_PAD.encode(&list),
            base64::engine::general_purpose::STANDARD.encode(&list),
        ] {
            let imports = parse_profile_list(&input).unwrap();
            assert_eq!(
                imports
                    .iter()
                    .map(|entry| entry.profile.name.as_str())
                    .collect::<Vec<_>>(),
                ["First", "Second"]
            );
        }
        assert!(parse_profile_list(&format!("{list}\nbad")).is_err());
    }

    #[test]
    fn honors_draft_clients_certificate_pin_parameter() {
        let pin = "ab".repeat(32);
        let link = format!(
            "vless://{SAMPLE_UUID}@example.com:443?security=tls&sni=example.com&pinnedPeerCertSha256={pin}"
        );
        let profile = parse_vless_link(&link).unwrap().profile;
        assert!(
            matches!(profile.security, ProfileSecurity::Ktls { cert_sha256_pin: Some(value), .. } if value == [0xab; 32])
        );
        assert!(parse_sha256_pin("123456é0").is_err());
    }

    fn sample_pbk() -> ([u8; 32], String) {
        let key = [0x42u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(key);
        (key, b64)
    }

    #[test]
    fn parses_valid_reality_link_and_roundtrips() {
        let (expected_pk, pbk) = sample_pbk();
        let link = format!(
            "vless://{SAMPLE_UUID}@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={pbk}&sid=0123abcdef&type=tcp&spx=%2F#Tokyo%20Node%201"
        );

        let outcome = parse_vless_link(&link).expect("valid REALITY link");
        assert!(outcome.warnings.is_empty());
        assert_eq!(outcome.profile.name, "Tokyo Node 1");
        assert_eq!(outcome.profile.server_host, "example.com");
        assert_eq!(outcome.profile.server_port, 443);
        assert_eq!(
            outcome.profile.uuid,
            Uuid::parse_str(SAMPLE_UUID).expect("uuid")
        );

        match &outcome.profile.security {
            ProfileSecurity::Reality {
                public_key,
                public_key_b64,
                short_id,
                short_id_hex,
                sni,
                fingerprint,
            } => {
                assert_eq!(public_key, &expected_pk);
                assert_eq!(public_key_b64, &pbk);
                assert_eq!(short_id, &[0x01, 0x23, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00]);
                assert_eq!(short_id_hex, "0123abcdef");
                assert_eq!(sni, "www.microsoft.com");
                assert_eq!(fingerprint.as_deref(), Some("chrome"));
            }
            other => panic!("expected Reality, got {other:?}"),
        }
        assert_eq!(outcome.profile.security.wire_flow(), VISION_FLOW);

        // Debug redacts UUID
        let debug_repr = format!("{:?}", outcome.profile);
        assert!(!debug_repr.contains(SAMPLE_UUID));
        assert!(debug_repr.contains("<redacted>"));

        // Round-trip formatting
        let exported = outcome.profile.to_vless_link();
        let reimported = parse_vless_link(&exported).expect("round-trip link");
        assert_eq!(reimported.profile.name, outcome.profile.name);
        assert_eq!(reimported.profile.server_host, outcome.profile.server_host);
        assert_eq!(reimported.profile.server_port, outcome.profile.server_port);
        assert_eq!(reimported.profile.uuid, outcome.profile.uuid);
        assert_eq!(reimported.profile.security, outcome.profile.security);
    }

    #[test]
    fn tolerates_padded_base64url_pbk_and_short_id_variants() {
        let key_bytes = [0x9au8; 32];
        let padded_pbk = format!("{}=", URL_SAFE_NO_PAD.encode(key_bytes));

        // Odd-length short_id ("abc") + empty short_id + IPv6 server host + default name fallback
        let link = format!(
            "vless://{SAMPLE_UUID}@[2001:db8::1]:8443/?security=reality&flow=xtls-rprx-vision&sni=cover.example.org&pbk={padded_pbk}&sid=AbC"
        );

        let outcome = parse_vless_link(&link).expect("padded pbk + IPv6 host");
        assert_eq!(outcome.profile.name, "[2001:db8::1]:8443");
        assert_eq!(outcome.profile.server_host, "2001:db8::1");
        assert_eq!(outcome.profile.server_port, 8443);

        match &outcome.profile.security {
            ProfileSecurity::Reality {
                public_key,
                public_key_b64,
                short_id,
                short_id_hex,
                ..
            } => {
                assert_eq!(public_key, &key_bytes);
                assert_eq!(public_key_b64, &URL_SAFE_NO_PAD.encode(key_bytes));
                assert_eq!(short_id, &[0xab, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(short_id_hex, "abc");
            }
            other => panic!("expected Reality, got {other:?}"),
        }

        // Round-trip IPv6 link
        let roundtrip = parse_vless_link(&outcome.profile.to_vless_link()).expect("roundtrip ipv6");
        assert_eq!(roundtrip.profile.server_host, "2001:db8::1");
        assert_eq!(roundtrip.profile.server_port, 8443);

        // Omitted sid defaults to all zeros
        let link_no_sid = format!(
            "vless://{SAMPLE_UUID}@198.51.100.7:443?security=reality&flow=xtls-rprx-vision&sni=cover.example.org&pbk={padded_pbk}"
        );
        let no_sid = parse_vless_link(&link_no_sid).expect("omitted sid");
        match no_sid.profile.security {
            ProfileSecurity::Reality {
                short_id,
                short_id_hex,
                ..
            } => {
                assert_eq!(short_id, [0u8; 8]);
                assert_eq!(short_id_hex, "");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parses_ktls_defaults_pins_and_vision_probe_warning() {
        let pin_bytes = [0x5au8; 32];
        let colon_hex_pin = pin_bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");

        let link = format!(
            "vless://{SAMPLE_UUID}@edge.example.net:443?security=tls&sni=edge.example.net&flow=xtls-rprx-vision&pcs={colon_hex_pin}#kTLS"
        );
        let outcome = parse_vless_link(&link).expect("kTLS with vision flow warning");
        assert_eq!(outcome.warnings, vec![TLS_VISION_PROBE_WARNING.to_string()]);
        assert_eq!(outcome.profile.security.wire_flow(), "");

        match &outcome.profile.security {
            ProfileSecurity::Ktls {
                sni,
                alpn,
                cert_sha256_pin,
                fingerprint,
            } => {
                assert_eq!(sni, "edge.example.net");
                assert_eq!(alpn, &vec!["http/1.1".to_string()]);
                assert_eq!(cert_sha256_pin, &Some(pin_bytes));
                assert_eq!(fingerprint, &None);
            }
            other => panic!("expected Ktls, got {other:?}"),
        }

        // Standard base64 pin containing '+' must survive raw query parsing (not turn '+' into ' ')
        let mut tricky_pin = [0xffu8; 32];
        tricky_pin[0] = 0xfb; // 0xfb -> '+/...' in standard base64
        let std_b64_pin = base64::engine::general_purpose::STANDARD.encode(tricky_pin);
        assert!(std_b64_pin.contains('+'));
        let link_b64_pin = format!(
            "vless://{SAMPLE_UUID}@edge.example.net:443?security=tls&sni=edge.example.net&alpn=h2,http/1.1&pin={std_b64_pin}"
        );
        let parsed_b64 = parse_vless_link(&link_b64_pin).expect("standard b64 pin with '+'");
        assert!(parsed_b64.warnings.is_empty());
        match parsed_b64.profile.security {
            ProfileSecurity::Ktls {
                alpn,
                cert_sha256_pin,
                ..
            } => {
                assert_eq!(alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
                assert_eq!(cert_sha256_pin, Some(tricky_pin));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_invalid_links_and_direct_struct_mutations() {
        let (_, pbk) = sample_pbk();

        let bad_cases = [
            // Wrong scheme
            format!("vmess://{SAMPLE_UUID}@example.com:443?security=tls&sni=example.com"),
            // Bad UUID
            "vless://not-a-uuid@example.com:443?security=tls&sni=example.com".to_string(),
            // Missing port / port 0
            format!("vless://{SAMPLE_UUID}@example.com?security=tls&sni=example.com"),
            format!("vless://{SAMPLE_UUID}@example.com:0?security=tls&sni=example.com"),
            // Unsupported encryption
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?encryption=mlkem768&security=tls&sni=example.com"
            ),
            // Unsupported transports
            format!("vless://{SAMPLE_UUID}@example.com:443?type=ws&security=tls&sni=example.com"),
            format!("vless://{SAMPLE_UUID}@example.com:443?type=grpc&security=tls&sni=example.com"),
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?type=xhttp&security=tls&sni=example.com"
            ),
            format!("vless://{SAMPLE_UUID}@example.com:443?type=quic&security=tls&sni=example.com"),
            format!("vless://{SAMPLE_UUID}@example.com:443?type=http&security=tls&sni=example.com"),
            // Unsupported / missing security
            format!("vless://{SAMPLE_UUID}@example.com:443?sni=example.com"),
            format!("vless://{SAMPLE_UUID}@example.com:443?security=none&sni=example.com"),
            format!("vless://{SAMPLE_UUID}@example.com:443?security=xtls&sni=example.com"),
            // IP literal as SNI (IPv4 & IPv6)
            format!(
                "vless://{SAMPLE_UUID}@1.2.3.4:443?security=reality&flow=xtls-rprx-vision&sni=1.2.3.4&pbk={pbk}"
            ),
            format!("vless://{SAMPLE_UUID}@[::1]:443?security=tls&sni=::1"),
            // REALITY missing or wrong flow
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?security=reality&sni=example.com&pbk={pbk}"
            ),
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?security=reality&flow=xtls-rprx-direct&sni=example.com&pbk={pbk}"
            ),
            // REALITY bad pbk length or sid > 16 hex chars
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?security=reality&flow=xtls-rprx-vision&sni=example.com&pbk=short"
            ),
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?security=reality&flow=xtls-rprx-vision&sni=example.com&pbk={pbk}&sid=0123456789abcdef0"
            ),
            // TLS unknown non-empty flow
            format!(
                "vless://{SAMPLE_UUID}@example.com:443?security=tls&sni=example.com&flow=xtls-rprx-direct"
            ),
        ];

        for case in &bad_cases {
            assert!(
                parse_vless_link(case).is_err(),
                "expected error for invalid link: {case}"
            );
        }

        // Direct struct edits caught by Profile::validate()
        let mut valid = parse_vless_link(&format!(
            "vless://{SAMPLE_UUID}@example.com:443?security=reality&flow=xtls-rprx-vision&sni=example.com&pbk={pbk}"
        ))
        .unwrap()
        .profile;
        valid.server_port = 0;
        assert!(valid.validate().is_err());
        valid.server_port = 443;
        if let ProfileSecurity::Reality { sni, .. } = &mut valid.security {
            *sni = "127.0.0.1".to_string();
        }
        assert!(valid.validate().is_err());
    }
}
