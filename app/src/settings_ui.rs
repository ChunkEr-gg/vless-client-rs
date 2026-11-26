//! Short-lived Settings window process (`vless-tray --settings`, `PLAN.md` §7).
//!
//! Architectural highlights:
//! - Runs in an isolated process (`vless-tray --settings`) and exits completely when closed so the
//!   menu-bar agent never loads a GPU/renderer context.
//! - Strict `0%` idle CPU repaint discipline: never calls `ctx.request_repaint()` unconditionally;
//!   only requests a `1s` slow repaint while the **Logs** tab is actively visible.
//! - Separates deterministic state, validation, atomic `0600` persistence, and incremental log
//!   tailing ([`SettingsState`]) from `egui` widget rendering so every action is unit-testable
//!   headlessly on Linux as well as via `egui::Context::run`.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use uuid::Uuid;
use vless_ipc::{
    AppConfig, BUILTIN_SYSTEM_PROXY_EXCEPTIONS, BUILTIN_TUN_BYPASS_CIDR_STRS, BypassEntry,
    ConfigError, ConfigStore, DEFAULT_DNS_RESOLVER, DEFAULT_KTLS_ALPN, DEFAULT_SYSTEM_PROXY_PORT,
    LogLevel, Profile, ProfileError, ProfileSecurity, decode_public_key, decode_short_id,
    format_sha256_pin_hex, parse_bypass_entry, parse_profile_list, parse_sha256_pin,
    validate_dns_name, validate_server_host, write_atomic_0600,
};

use crate::supervisor::{ENGINE_LOG_FILE_NAME, ParsedLogLine, parse_engine_log_line};
use crate::tray_icons::format_mode_label;

/// Maximum number of parsed log lines retained in the Settings UI memory buffer.
const MAX_UI_LOG_LINES: usize = 2_000;

/// Top-level navigation tabs in the Settings window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SettingsTab {
    #[default]
    Profiles,
    BypassList,
    DnsAndProxy,
    Logs,
}

/// Protocol selector in the manual Add / Edit Profile form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProfileKindDraft {
    #[default]
    Reality,
    Ktls,
}

/// Minimum severity filter for the live log viewer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogFilter {
    #[default]
    All,
    InfoPlus,
    WarnPlus,
    ErrorOnly,
}

impl LogFilter {
    /// Returns `true` if a log line of `level` passes this filter.
    pub fn matches(self, level: LogLevel) -> bool {
        match self {
            Self::All => true,
            Self::InfoPlus => level >= LogLevel::Info,
            Self::WarnPlus => level >= LogLevel::Warn,
            Self::ErrorOnly => level >= LogLevel::Error,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::InfoPlus => "Info+",
            Self::WarnPlus => "Warn+",
            Self::ErrorOnly => "Error",
        }
    }
}

/// Editable draft state for creating or modifying a REALITY or kTLS [`Profile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDraft {
    /// `Some(id)` when editing an existing profile; `None` when creating a new profile.
    pub editing_id: Option<Uuid>,
    pub kind: ProfileKindDraft,
    pub name: String,
    pub server_host: String,
    pub server_port: String,
    pub uuid: String,
    // REALITY fields
    pub pbk: String,
    pub sid: String,
    // Shared TLS SNI + optional fingerprint
    pub sni: String,
    pub fp: String,
    // kTLS fields
    pub alpn: String,
    pub cert_sha256_pin: String,
}

impl ProfileDraft {
    /// Creates a fresh draft pre-populated with sensible defaults for adding a new profile.
    pub fn new_blank() -> Self {
        Self {
            editing_id: None,
            kind: ProfileKindDraft::Reality,
            name: String::new(),
            server_host: String::new(),
            server_port: "443".to_string(),
            uuid: Uuid::new_v4().to_string(),
            pbk: String::new(),
            sid: String::new(),
            sni: String::new(),
            fp: "chrome".to_string(),
            alpn: DEFAULT_KTLS_ALPN.to_string(),
            cert_sha256_pin: String::new(),
        }
    }

    /// Populates a draft from an existing stored [`Profile`] for editing.
    pub fn from_profile(profile: &Profile) -> Self {
        match &profile.security {
            ProfileSecurity::Reality {
                public_key_b64,
                short_id_hex,
                sni,
                fingerprint,
                ..
            } => Self {
                editing_id: Some(profile.id),
                kind: ProfileKindDraft::Reality,
                name: profile.name.clone(),
                server_host: profile.server_host.clone(),
                server_port: profile.server_port.to_string(),
                uuid: profile.uuid.to_string(),
                pbk: public_key_b64.clone(),
                sid: short_id_hex.clone(),
                sni: sni.clone(),
                fp: fingerprint.clone().unwrap_or_default(),
                alpn: DEFAULT_KTLS_ALPN.to_string(),
                cert_sha256_pin: String::new(),
            },
            ProfileSecurity::Ktls {
                sni,
                alpn,
                cert_sha256_pin,
                fingerprint,
            } => Self {
                editing_id: Some(profile.id),
                kind: ProfileKindDraft::Ktls,
                name: profile.name.clone(),
                server_host: profile.server_host.clone(),
                server_port: profile.server_port.to_string(),
                uuid: profile.uuid.to_string(),
                pbk: String::new(),
                sid: String::new(),
                sni: sni.clone(),
                fp: fingerprint.clone().unwrap_or_default(),
                alpn: if alpn.is_empty() {
                    DEFAULT_KTLS_ALPN.to_string()
                } else {
                    alpn.join(", ")
                },
                cert_sha256_pin: cert_sha256_pin
                    .as_ref()
                    .map(format_sha256_pin_hex)
                    .unwrap_or_default(),
            },
        }
    }

    /// Validates all draft inputs and constructs a [`Profile`] verified via [`Profile::validate`].
    pub fn build_validated_profile(&self) -> Result<Profile, ProfileError> {
        let name = self.name.trim().to_string();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(ProfileError::InvalidProfileName);
        }

        let raw_host = self.server_host.trim();
        if raw_host.is_empty() {
            return Err(ProfileError::MissingHost);
        }
        // Accept bracketed IPv6 literals like `[2001:db8::1]` in the GUI form and normalize to bare IPv6.
        let unbracketed_host = raw_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .filter(|inner| inner.parse::<Ipv6Addr>().is_ok())
            .unwrap_or(raw_host);
        let normalized_host = if unbracketed_host.parse::<IpAddr>().is_ok() {
            unbracketed_host.to_string()
        } else {
            unbracketed_host.to_ascii_lowercase()
        };
        validate_server_host(&normalized_host)?;

        let port_str = self.server_port.trim();
        if port_str.is_empty() {
            return Err(ProfileError::MissingPort);
        }
        let server_port = port_str
            .parse::<u16>()
            .map_err(|e| ProfileError::InvalidPort(e.to_string()))?;
        if server_port == 0 {
            return Err(ProfileError::InvalidPort(
                "port must be between 1 and 65535".to_string(),
            ));
        }

        let uuid_str = self.uuid.trim();
        if uuid_str.is_empty() {
            return Err(ProfileError::MissingUuid);
        }
        let uuid =
            Uuid::parse_str(uuid_str).map_err(|e| ProfileError::InvalidUuid(e.to_string()))?;

        let raw_sni = self.sni.trim();
        if raw_sni.is_empty() {
            return Err(ProfileError::MissingSni);
        }
        validate_dns_name(raw_sni)?;
        let sni = raw_sni.to_ascii_lowercase();

        let fingerprint = {
            let trimmed_fp = self.fp.trim();
            if trimmed_fp.is_empty() {
                None
            } else {
                Some(trimmed_fp.to_string())
            }
        };

        let security = match self.kind {
            ProfileKindDraft::Reality => {
                let raw_pbk = self.pbk.trim();
                if raw_pbk.is_empty() {
                    return Err(ProfileError::MissingPublicKey);
                }
                let (public_key, public_key_b64) = decode_public_key(raw_pbk)?;
                let raw_sid = self.sid.trim();
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
            ProfileKindDraft::Ktls => {
                let raw_alpn = self.alpn.trim();
                let alpn = if raw_alpn.is_empty() {
                    vec![DEFAULT_KTLS_ALPN.to_string()]
                } else {
                    raw_alpn
                        .split(',')
                        .map(|tok| tok.trim().to_string())
                        .filter(|tok| !tok.is_empty())
                        .collect::<Vec<_>>()
                };

                let raw_pin = self.cert_sha256_pin.trim();
                let cert_sha256_pin = if raw_pin.is_empty() {
                    None
                } else {
                    Some(parse_sha256_pin(raw_pin)?)
                };

                ProfileSecurity::Ktls {
                    sni,
                    alpn,
                    cert_sha256_pin,
                    fingerprint,
                }
            }
        };

        let profile = Profile {
            id: self.editing_id.unwrap_or_else(Uuid::new_v4),
            name,
            server_host: normalized_host,
            server_port,
            uuid,
            security,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// Validates the TUN DNS resolver IP string, rejecting unspecified (`0.0.0.0`/`::`), loopback
/// (`127.0.0.0/8`/`::1`), multicast (`224.0.0.0/4`/`ff00::/8`), and broadcast (`255.255.255.255`).
pub fn validate_tun_dns_resolver_str(input: &str) -> Result<IpAddr, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("DNS resolver IP must not be empty".to_string());
    }
    let ip = trimmed
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid IP address {trimmed:?}: expected IPv4 or IPv6 literal"))?;
    validate_tun_dns_resolver_ip(ip)?;
    Ok(ip)
}

/// Validates a parsed [`IpAddr`] for use as the tunnelled TUN DNS resolver (`PLAN.md` §5.4).
pub fn validate_tun_dns_resolver_ip(ip: IpAddr) -> Result<(), String> {
    if ip.is_unspecified() {
        return Err(format!(
            "DNS resolver {ip} cannot be an unspecified address"
        ));
    }
    if ip.is_loopback() {
        return Err(format!(
            "DNS resolver {ip} cannot be a loopback address (must be routable through TUN)"
        ));
    }
    if ip.is_multicast() {
        return Err(format!("DNS resolver {ip} cannot be a multicast address"));
    }
    if let IpAddr::V4(v4) = ip
        && v4.is_broadcast()
    {
        return Err(format!("DNS resolver {ip} cannot be the broadcast address"));
    }
    Ok(())
}

/// Validates the System Proxy local port string (`1..=65535`).
pub fn validate_proxy_port_str(input: &str) -> Result<u16, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("System Proxy port must not be empty".to_string());
    }
    let port = trimmed
        .parse::<u16>()
        .map_err(|_| format!("invalid port {trimmed:?}: expected an integer 1..=65535"))?;
    if port == 0 {
        return Err("System Proxy port must be between 1 and 65535".to_string());
    }
    Ok(port)
}

/// Incremental file tailer reading `<config_dir>/engine.log` by byte offset.
#[derive(Debug)]
pub struct LogTailer {
    log_path: PathBuf,
    read_offset: u64,
    partial_line: String,
    lines: VecDeque<ParsedLogLine>,
}

impl LogTailer {
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            read_offset: 0,
            partial_line: String::new(),
            lines: VecDeque::new(),
        }
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    pub fn lines(&self) -> &VecDeque<ParsedLogLine> {
        &self.lines
    }

    /// Reads any newly appended bytes from `engine.log` since `read_offset`.
    ///
    /// Handles missing files and atomic truncation/rotation (`file_len < read_offset`) seamlessly.
    pub fn poll_incremental(&mut self) -> io::Result<usize> {
        let meta = match fs::metadata(&self.log_path) {
            Ok(m) => m,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                self.read_offset = 0;
                self.partial_line.clear();
                self.lines.clear();
                return Ok(0);
            }
            Err(err) => return Err(err),
        };

        let file_len = meta.len();
        if file_len < self.read_offset {
            // File was rotated or cleared: reset to beginning.
            self.read_offset = 0;
            self.partial_line.clear();
            self.lines.clear();
        }

        if file_len == self.read_offset {
            return Ok(0);
        }

        // If opening a huge pre-existing file from offset 0, jump near the tail so we never read
        // megabytes on startup.
        let max_initial_window = 512 * 1024_u64;
        let mut skip_first_partial = false;
        if self.read_offset == 0 && file_len > max_initial_window {
            self.read_offset = file_len - max_initial_window;
            skip_first_partial = true;
        }

        let to_read = (file_len - self.read_offset) as usize;
        let mut file = File::open(&self.log_path)?;
        file.seek(SeekFrom::Start(self.read_offset))?;

        let mut buf = Vec::with_capacity(to_read.min(64 * 1024));
        let n = file.take(to_read as u64).read_to_end(&mut buf)?;
        self.read_offset += n as u64;

        let chunk = String::from_utf8_lossy(&buf);
        self.partial_line.push_str(&chunk);

        let mut added = 0usize;
        while let Some(nl_idx) = self.partial_line.find('\n') {
            let complete: String = self.partial_line.drain(..=nl_idx).collect();
            if skip_first_partial {
                skip_first_partial = false;
                continue;
            }
            let parsed = parse_engine_log_line(&complete);
            if !parsed.raw_line.is_empty() {
                if self.lines.len() >= MAX_UI_LOG_LINES {
                    self.lines.pop_front();
                }
                self.lines.push_back(parsed);
                added += 1;
            }
        }

        Ok(added)
    }

    /// Truncates `engine.log` atomically (`0600`) and clears the in-memory log buffer.
    pub fn clear(&mut self) -> io::Result<()> {
        if self.log_path.exists() {
            write_atomic_0600(&self.log_path, b"")?;
        }
        self.read_offset = 0;
        self.partial_line.clear();
        self.lines.clear();
        Ok(())
    }
}

/// Metadata fingerprint (`dev`, `ino`, `len`, `mtime`) used to detect atomic `write_atomic_0600`
/// updates to `config.json` across `vless-tray` and `vless-tray --settings` even when two writes
/// land within the same filesystem timestamp tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

/// Computes the [`FileFingerprint`] of `path`, returning `None` if `path` does not exist.
#[cfg(unix)]
pub fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    Some(FileFingerprint {
        dev: meta.dev(),
        ino: meta.ino(),
        len: meta.len(),
        mtime_sec: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
    })
}

#[cfg(not(unix))]
pub fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    let meta = fs::metadata(path).ok()?;
    let dur = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .unwrap_or_default();
    Some(FileFingerprint {
        dev: 0,
        ino: 0,
        len: meta.len(),
        mtime_sec: dur.as_secs() as i64,
        mtime_nsec: i64::from(dur.subsec_nanos()),
    })
}

/// Reads UTF-8 text from the system clipboard (`arboard`, with `/usr/bin/pbpaste` UTF-8 locale
/// fallback on macOS `.app` bundles where `LANG`/`LC_CTYPE` may be unset).
pub fn read_clipboard_utf8() -> Result<String, String> {
    if let Ok(mut clipboard) = arboard::Clipboard::new()
        && let Ok(text) = clipboard.get_text()
    {
        return Ok(text);
    }

    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/pbpaste")
            .env("LANG", "en_US.UTF-8")
            .env("LC_CTYPE", "UTF-8")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|err| format!("Clipboard unavailable: {err}"))?;
        if out.status.success() {
            return String::from_utf8(out.stdout)
                .map_err(|_| "Clipboard does not contain valid UTF-8 text".to_string());
        }
    }

    Err("Clipboard does not contain UTF-8 text".to_string())
}

/// Writes UTF-8 text to the system clipboard (`arboard`, with `/usr/bin/pbcopy` UTF-8 locale
/// fallback on macOS).
pub fn write_clipboard_utf8(text: &str) -> Result<(), String> {
    if let Ok(mut clipboard) = arboard::Clipboard::new()
        && clipboard.set_text(text.to_owned()).is_ok()
    {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        let mut child = std::process::Command::new("/usr/bin/pbcopy")
            .env("LANG", "en_US.UTF-8")
            .env("LC_CTYPE", "UTF-8")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|err| format!("Failed writing clipboard: {err}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(text.as_bytes())
                .map_err(|err| format!("Failed writing clipboard bytes: {err}"))?;
        }
        let status = child
            .wait()
            .map_err(|err| format!("Failed waiting on pbcopy: {err}"))?;
        if status.success() {
            return Ok(());
        }
    }

    Err("Clipboard unavailable".to_string())
}

/// Redacts sensitive VLESS / REALITY / kTLS credentials (`UUID`, `pbk`/`publicKey`, `sid`/`shortId`,
/// `pcs` SHA-256 certificate pins, and `vless://<userinfo>@` URIs) from diagnostic log output.
pub fn redact_sensitive_text(input: &str, profiles: &[Profile]) -> String {
    let mut out = redact_vless_uri_userinfo(input);
    out = redact_hyphenated_uuids(&out);
    out = redact_secret_key_values(&out);

    let mut literals: Vec<String> = Vec::new();
    for p in profiles {
        literals.push(p.uuid.simple().to_string());
        match &p.security {
            ProfileSecurity::Reality {
                public_key_b64,
                short_id_hex,
                ..
            } => {
                if !public_key_b64.is_empty() {
                    literals.push(public_key_b64.clone());
                    let rem = public_key_b64.len() % 4;
                    if rem != 0 {
                        let mut padded = public_key_b64.clone();
                        for _ in 0..(4 - rem) {
                            padded.push('=');
                        }
                        literals.push(padded);
                    }
                }
                if short_id_hex.len() >= 4 {
                    literals.push(short_id_hex.clone());
                }
            }
            ProfileSecurity::Ktls {
                cert_sha256_pin: Some(pin),
                ..
            } => {
                let hex_pin = format_sha256_pin_hex(pin);
                literals.push(hex_pin);
            }
            ProfileSecurity::Ktls {
                cert_sha256_pin: None,
                ..
            } => {}
        }
    }

    // Replace longer secrets first so prefixes never partially mask full tokens.
    literals.sort_by_key(|b| std::cmp::Reverse(b.len()));
    literals.dedup();
    for secret in literals {
        if secret.len() >= 4 {
            out = out.replace(&secret, "<redacted>");
            let upper = secret.to_ascii_uppercase();
            if upper != secret {
                out = out.replace(&upper, "<redacted>");
            }
        }
    }

    out
}

fn redact_vless_uri_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("vless://") {
        out.push_str(&rest[..pos]);
        out.push_str("vless://");
        let after_scheme = &rest[pos + "vless://".len()..];
        let boundary = after_scheme
            .find(['@', ' ', '\t', '\r', '\n', '"', '\''])
            .unwrap_or(after_scheme.len());
        if after_scheme[boundary..].starts_with('@') {
            out.push_str("<redacted>@");
            rest = &after_scheme[boundary + 1..];
        } else {
            rest = after_scheme;
        }
    }
    out.push_str(rest);
    out
}

fn redact_hyphenated_uuids(input: &str) -> String {
    let bytes = input.as_bytes();
    if bytes.len() < 36 {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let mut last_copied = 0usize;
    while i + 36 <= bytes.len() {
        let candidate = &bytes[i..i + 36];
        let boundary_before = i == 0 || !bytes[i - 1].is_ascii_hexdigit();
        let boundary_after = i + 36 == bytes.len() || !bytes[i + 36].is_ascii_hexdigit();
        if boundary_before && boundary_after && is_ascii_uuid_36(candidate) {
            out.push_str(&input[last_copied..i]);
            out.push_str("<redacted-uuid>");
            i += 36;
            last_copied = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&input[last_copied..]);
    out
}

fn is_ascii_uuid_36(b: &[u8]) -> bool {
    if b.len() != 36 {
        return false;
    }
    for (idx, &ch) in b.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if ch != b'-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn redact_secret_key_values(input: &str) -> String {
    const KEYS: &[&str] = &[
        "publicKey=",
        "public_key=",
        "pbk=",
        "shortId=",
        "short_id=",
        "sid=",
        "pcs=",
        "cert_sha256_pin=",
    ];
    let mut current = input.to_string();
    for key in KEYS {
        let mut next = String::with_capacity(current.len());
        let mut rest = current.as_str();
        while let Some(idx) = rest.find(key) {
            let valid_boundary = idx == 0
                || !rest.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    && rest.as_bytes()[idx - 1] != b'_';
            if !valid_boundary {
                next.push_str(&rest[..idx + key.len()]);
                rest = &rest[idx + key.len()..];
                continue;
            }
            next.push_str(&rest[..idx]);
            next.push_str(key);
            next.push_str("<redacted>");
            let after_key = &rest[idx + key.len()..];
            let val_end = after_key
                .find(['&', '#', ' ', '\t', '\r', '\n', '"', '\'', ',', ';', ')'])
                .unwrap_or(after_key.len());
            rest = &after_key[val_end..];
        }
        next.push_str(rest);
        current = next;
    }
    current
}

/// Pure, UI-framework-independent controller for all Settings state, validation, and persistence.
pub struct SettingsState {
    pub store: ConfigStore,
    pub config: AppConfig,
    pub active_tab: SettingsTab,

    // Banners & messages
    pub status_message: Option<String>,
    pub error_message: Option<String>,
    pub import_warnings: Vec<String>,

    // Profiles tab state
    pub import_link_input: String,
    pub import_error: Option<String>,
    pub editor: Option<ProfileDraft>,
    pub editor_error: Option<String>,

    // Bypass List tab state
    pub bypass_input: String,
    pub bypass_error: Option<String>,

    // DNS & Proxy tab state
    pub dns_resolver_input: String,
    pub proxy_port_input: String,
    pub dns_proxy_error: Option<String>,

    // Logs tab state
    pub log_tailer: LogTailer,
    pub log_filter: LogFilter,
    pub log_auto_scroll: bool,

    // Tracks the last loaded/saved `config.json` inode/mtime so concurrent menu-bar mode switches
    // (`Off` / `SystemProxy` / `Tun`) are never overwritten when saving settings from this window.
    last_disk_fingerprint: Option<FileFingerprint>,
}

impl SettingsState {
    /// Loads [`AppConfig`] from `store` (or initializes defaults if missing) and prepares UI state.
    pub fn load(store: ConfigStore) -> Self {
        let mut initial_error = None;
        let last_disk_fingerprint = file_fingerprint(&store.config_path());
        let config = match store.load() {
            Ok(cfg) => cfg,
            Err(err) => {
                initial_error = Some(format!("Failed to load existing config.json: {err}"));
                AppConfig::default()
            }
        };

        let dns_resolver_input = config.dns_resolver.to_string();
        let proxy_port_input = config.system_proxy_port.to_string();
        let log_path = store.dir().join(ENGINE_LOG_FILE_NAME);
        let mut log_tailer = LogTailer::new(log_path);
        let _ = log_tailer.poll_incremental();

        Self {
            store,
            config,
            active_tab: SettingsTab::Profiles,
            status_message: None,
            error_message: initial_error,
            import_warnings: Vec::new(),
            import_link_input: String::new(),
            import_error: None,
            editor: None,
            editor_error: None,
            bypass_input: String::new(),
            bypass_error: None,
            dns_resolver_input,
            proxy_port_input,
            dns_proxy_error: None,
            log_tailer,
            log_filter: LogFilter::All,
            log_auto_scroll: true,
            last_disk_fingerprint,
        }
    }

    /// Synchronizes external changes written to `config.json` by the menu-bar process (such as
    /// connection `mode`, active profile selection, or clipboard imports) without clobbering any
    /// open in-progress editor draft. Returns `true` if external changes were merged.
    pub fn sync_external_changes(&mut self) -> bool {
        let current_fp = file_fingerprint(&self.store.config_path());
        if current_fp == self.last_disk_fingerprint {
            return false;
        }
        let Ok(disk_cfg) = self.store.load() else {
            return false;
        };
        self.last_disk_fingerprint = current_fp;

        let dns_clean = self.dns_resolver_input.trim() == self.config.dns_resolver.to_string();
        let port_clean = self.proxy_port_input.trim() == self.config.system_proxy_port.to_string();

        self.config.mode = disk_cfg.mode;
        self.config.profiles = disk_cfg.profiles;
        self.config.selected_profile_id = disk_cfg.selected_profile_id;
        self.config.bypass_list = disk_cfg.bypass_list;

        if dns_clean {
            self.config.dns_resolver = disk_cfg.dns_resolver;
            self.dns_resolver_input = disk_cfg.dns_resolver.to_string();
        }
        if port_clean {
            self.config.system_proxy_port = disk_cfg.system_proxy_port;
            self.proxy_port_input = disk_cfg.system_proxy_port.to_string();
        }
        true
    }

    fn save_preserving_external_state(
        &mut self,
        preserve_external_profiles: bool,
        preserve_external_selection: bool,
    ) -> Result<(), ConfigError> {
        let current_fp = file_fingerprint(&self.store.config_path());
        if current_fp != self.last_disk_fingerprint
            && let Ok(disk_cfg) = self.store.load()
        {
            // `SettingsState` never edits `mode`; always preserve the menu bar's latest `mode`!
            self.config.mode = disk_cfg.mode;

            if preserve_external_profiles {
                self.config.profiles = disk_cfg.profiles;
                self.config.selected_profile_id = disk_cfg.selected_profile_id;
            } else if preserve_external_selection
                && let Some(ext_sel) = disk_cfg.selected_profile_id
                && self.config.profiles.iter().any(|p| p.id == ext_sel)
            {
                self.config.selected_profile_id = Some(ext_sel);
            }
        }

        self.store.save(&self.config)?;
        self.last_disk_fingerprint = file_fingerprint(&self.store.config_path());
        Ok(())
    }

    /// Switches the active tab, immediately polling `engine.log` when switching to `Logs`.
    pub fn set_tab(&mut self, tab: SettingsTab) {
        self.active_tab = tab;
        if tab == SettingsTab::Logs {
            let _ = self.log_tailer.poll_incremental();
        }
    }

    /// Imports a VLESS share link or subscription body, surfacing errors and warnings
    /// (including `TLS_VISION_PROBE_WARNING`) and persisting to `config.json` (`0600`).
    pub fn import_vless_link(&mut self, raw_link: &str) -> Result<Uuid, String> {
        self.import_error = None;
        self.error_message = None;

        let imports = match parse_profile_list(raw_link) {
            Ok(ok) => ok,
            Err(err) => {
                self.import_error = Some(err.to_string());
                return Err(err.to_string());
            }
        };

        let profile_id = imports[0].profile.id;
        let count = imports.len();
        let old_count = self.config.profiles.len();
        let old_selection = self.config.selected_profile_id;
        let mut warnings = Vec::new();
        for entry in imports {
            self.config.profiles.push(entry.profile);
            warnings.extend(entry.warnings);
        }
        if self.config.selected_profile_id.is_none() {
            self.config.selected_profile_id = Some(profile_id);
        }

        if let Err(save_err) = self.save_preserving_external_state(false, true) {
            self.config.profiles.truncate(old_count);
            self.config.selected_profile_id = old_selection;
            let message = format!("Failed saving config: {save_err}");
            self.error_message = Some(message.clone());
            return Err(message);
        }

        self.import_link_input.clear();
        self.import_warnings = warnings;
        self.status_message = Some(format!("Imported {count} profile(s)"));
        Ok(profile_id)
    }

    /// Reads clipboard text via [`read_clipboard_utf8`] and imports it as a `vless://` link.
    pub fn import_from_system_clipboard(&mut self) -> Result<Uuid, String> {
        let text = read_clipboard_utf8()?;
        self.import_link_input = text.trim().to_string();
        self.import_vless_link(&text)
    }

    /// Selects a profile by `id` and saves `config.json` (`0600`).
    pub fn select_profile(&mut self, id: Uuid) -> Result<(), String> {
        if !self.config.profiles.iter().any(|p| p.id == id) {
            return Err("Profile no longer exists".to_string());
        }
        self.config.selected_profile_id = Some(id);
        self.persist_with_status("Updated active profile", false, false)
    }

    /// Deletes a profile by `id`, updating `selected_profile_id` cleanly and saving `0600`.
    pub fn delete_profile(&mut self, id: Uuid) -> Result<(), String> {
        let Some(pos) = self.config.profiles.iter().position(|p| p.id == id) else {
            return Err("Profile not found".to_string());
        };
        let removed = self.config.profiles.remove(pos);
        if self.config.selected_profile_id == Some(id) {
            self.config.selected_profile_id = self.config.profiles.first().map(|p| p.id);
        }
        if self
            .editor
            .as_ref()
            .is_some_and(|draft| draft.editing_id == Some(id))
        {
            self.editor = None;
            self.editor_error = None;
        }
        self.persist_with_status(
            &format!("Deleted profile \"{}\"", removed.name),
            false,
            true,
        )
    }

    /// Opens the Profile Editor for adding a new profile.
    pub fn start_new_profile(&mut self) {
        self.editor = Some(ProfileDraft::new_blank());
        self.editor_error = None;
    }

    /// Opens the Profile Editor populated with an existing profile's fields.
    pub fn start_edit_profile(&mut self, id: Uuid) {
        if let Some(profile) = self.config.profiles.iter().find(|p| p.id == id) {
            self.editor = Some(ProfileDraft::from_profile(profile));
            self.editor_error = None;
        }
    }

    /// Cancels and closes the Profile Editor without saving.
    pub fn cancel_profile_editor(&mut self) {
        self.editor = None;
        self.editor_error = None;
    }

    /// Validates the open [`ProfileDraft`], updates or inserts the [`Profile`], and saves `0600`.
    pub fn save_profile_draft(&mut self) -> Result<Uuid, ProfileError> {
        let Some(draft) = self.editor.as_ref() else {
            return Err(ProfileError::InvalidProfileName);
        };

        let validated = match draft.build_validated_profile() {
            Ok(p) => p,
            Err(err) => {
                self.editor_error = Some(err.to_string());
                return Err(err);
            }
        };

        let id = validated.id;
        let name = validated.name.clone();
        let is_edit = draft.editing_id.is_some();

        if let Some(existing_slot) = self.config.profiles.iter_mut().find(|p| p.id == id) {
            *existing_slot = validated;
        } else {
            self.config.profiles.push(validated);
            if self.config.selected_profile_id.is_none() {
                self.config.selected_profile_id = Some(id);
            }
        }

        match self.save_preserving_external_state(false, true) {
            Ok(()) => {
                self.editor = None;
                self.editor_error = None;
                self.error_message = None;
                self.status_message = Some(if is_edit {
                    format!("Saved changes to \"{name}\"")
                } else {
                    format!("Added profile \"{name}\"")
                });
            }
            Err(err) => {
                self.editor_error = Some(format!("Failed saving config: {err}"));
            }
        }

        Ok(id)
    }

    /// Exports a profile's canonical `vless://` share URI.
    pub fn export_profile_link(&self, id: Uuid) -> Option<String> {
        self.config
            .profiles
            .iter()
            .find(|p| p.id == id)
            .map(Profile::to_vless_link)
    }

    /// Live-validates `self.bypass_input` without mutating `config.bypass_list`.
    pub fn preview_bypass_input(&self) -> Option<Result<BypassEntry, String>> {
        let trimmed = self.bypass_input.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(parse_bypass_entry(trimmed).map_err(|e| e.to_string()))
    }

    /// Validates `self.bypass_input`, normalizes & deduplicates it, appends it to
    /// `config.bypass_list`, and saves atomically (`0600`).
    pub fn add_bypass_from_input(&mut self) -> Result<String, String> {
        self.bypass_error = None;
        let parsed = parse_bypass_entry(&self.bypass_input).map_err(|err| {
            let msg = err.to_string();
            self.bypass_error = Some(msg.clone());
            msg
        })?;

        let canonical = parsed.to_canonical_string();
        if self.config.bypass_list.contains(&canonical) {
            let msg = format!("Bypass entry \"{canonical}\" is already in the list");
            self.bypass_error = Some(msg.clone());
            return Err(msg);
        }

        self.config.bypass_list.push(canonical.clone());
        if let Err(err) = self.save_preserving_external_state(true, true) {
            self.config.bypass_list.pop();
            let msg = format!("Failed saving bypass list: {err}");
            self.bypass_error = Some(msg.clone());
            return Err(msg);
        }

        self.bypass_input.clear();
        self.status_message = Some(format!("Added bypass rule \"{canonical}\""));
        Ok(canonical)
    }

    /// Removes the custom bypass entry at `index` and saves atomically (`0600`).
    pub fn remove_bypass_at(&mut self, index: usize) -> Result<String, String> {
        if index >= self.config.bypass_list.len() {
            return Err("Bypass index out of bounds".to_string());
        }
        let removed = self.config.bypass_list.remove(index);
        self.persist_with_status(&format!("Removed bypass rule \"{removed}\""), true, true)?;
        Ok(removed)
    }

    /// Validates `dns_resolver_input` and `proxy_port_input` and saves atomically (`0600`).
    pub fn save_dns_and_proxy(&mut self) -> Result<(), String> {
        self.dns_proxy_error = None;

        let resolver = match validate_tun_dns_resolver_str(&self.dns_resolver_input) {
            Ok(ip) => ip,
            Err(msg) => {
                self.dns_proxy_error = Some(msg.clone());
                return Err(msg);
            }
        };

        let port = match validate_proxy_port_str(&self.proxy_port_input) {
            Ok(p) => p,
            Err(msg) => {
                self.dns_proxy_error = Some(msg.clone());
                return Err(msg);
            }
        };

        let prev_dns = self.config.dns_resolver;
        let prev_port = self.config.system_proxy_port;
        self.config.dns_resolver = resolver;
        self.config.system_proxy_port = port;

        if let Err(err) = self.save_preserving_external_state(true, true) {
            self.config.dns_resolver = prev_dns;
            self.config.system_proxy_port = prev_port;
            let msg = format!("Failed saving DNS & Proxy settings: {err}");
            self.dns_proxy_error = Some(msg.clone());
            return Err(msg);
        }

        self.dns_resolver_input = resolver.to_string();
        self.proxy_port_input = port.to_string();
        self.status_message = Some(format!(
            "Saved DNS resolver ({resolver}) and System Proxy port ({port})"
        ));
        Ok(())
    }

    /// Resets TUN DNS resolver (`1.1.1.1`) and System Proxy port (`2080`) to defaults and saves.
    pub fn reset_dns_and_proxy_defaults(&mut self) -> Result<(), String> {
        self.dns_resolver_input = DEFAULT_DNS_RESOLVER.to_string();
        self.proxy_port_input = DEFAULT_SYSTEM_PROXY_PORT.to_string();
        self.save_dns_and_proxy()
    }

    /// Incrementally polls new lines from `<config_dir>/engine.log`.
    pub fn refresh_logs_incremental(&mut self) {
        if let Err(err) = self.log_tailer.poll_incremental() {
            self.error_message = Some(format!("Log read error: {err}"));
        }
    }

    /// Clears `<config_dir>/engine.log` and the in-memory log buffer.
    pub fn clear_logs(&mut self) {
        match self.log_tailer.clear() {
            Ok(()) => {
                self.status_message = Some("Cleared engine logs".to_string());
            }
            Err(err) => {
                self.error_message = Some(format!("Failed clearing engine.log: {err}"));
            }
        }
    }

    /// Builds a diagnostic bundle with all UUIDs, REALITY `pbk`/`sid`, and kTLS `pcs` pins redacted.
    pub fn build_redacted_diagnostics(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str(&format!(
            "vless-tray {} ({}/{})\n",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
        out.push_str(&format!(
            "mode: {} | dns_resolver: {} | system_proxy_port: {} | custom_bypass_entries: {}\n",
            format_mode_label(self.config.mode),
            self.config.dns_resolver,
            self.config.system_proxy_port,
            self.config.bypass_list.len()
        ));
        out.push_str(&format!("profiles ({}):\n", self.config.profiles.len()));
        for p in &self.config.profiles {
            let active_marker = if self.config.selected_profile_id == Some(p.id) {
                "*"
            } else {
                " "
            };
            let sec_desc = match &p.security {
                ProfileSecurity::Reality {
                    sni, fingerprint, ..
                } => format!(
                    "REALITY sni={sni} fp={} pbk=<redacted> sid=<redacted>",
                    fingerprint.as_deref().unwrap_or("-")
                ),
                ProfileSecurity::Ktls {
                    sni,
                    alpn,
                    cert_sha256_pin,
                    fingerprint,
                } => format!(
                    "kTLS sni={sni} alpn=[{}] fp={} pcs={}",
                    alpn.join(","),
                    fingerprint.as_deref().unwrap_or("-"),
                    if cert_sha256_pin.is_some() {
                        "<redacted>"
                    } else {
                        "system-roots"
                    }
                ),
            };
            out.push_str(&format!(
                "  [{active_marker}] \"{}\" {} ({sec_desc})\n",
                p.name,
                p.server_addr_display()
            ));
        }

        out.push_str("\n--- engine.log (redacted) ---\n");
        let mut raw_logs = String::new();
        for entry in self.log_tailer.lines() {
            if self.log_filter.matches(entry.level) {
                raw_logs.push_str(&entry.raw_line);
                raw_logs.push('\n');
            }
        }
        if raw_logs.is_empty() {
            out.push_str("(no log entries)\n");
        } else {
            out.push_str(&redact_sensitive_text(&raw_logs, &self.config.profiles));
        }
        out
    }

    fn persist_with_status(
        &mut self,
        ok_msg: &str,
        preserve_external_profiles: bool,
        preserve_external_selection: bool,
    ) -> Result<(), String> {
        self.save_preserving_external_state(
            preserve_external_profiles,
            preserve_external_selection,
        )
        .map_err(|err| {
            let msg = format!("Failed saving config.json: {err}");
            self.error_message = Some(msg.clone());
            msg
        })?;
        self.error_message = None;
        self.status_message = Some(ok_msg.to_string());
        Ok(())
    }
}

/// `eframe::App` wrapper rendering [`SettingsState`] using `egui`.
pub struct SettingsApp {
    pub state: SettingsState,
    launch_focus_frames: u8,
    was_window_focused: bool,
    raise_requested: Arc<AtomicBool>,
}

impl SettingsApp {
    pub fn new(state: SettingsState) -> Self {
        Self::with_raise_flag(state, Arc::new(AtomicBool::new(false)))
    }

    pub fn with_raise_flag(state: SettingsState, raise_requested: Arc<AtomicBool>) -> Self {
        Self {
            state,
            launch_focus_frames: 0,
            was_window_focused: true,
            raise_requested,
        }
    }

    /// Renders the complete Settings UI into `ctx`.
    ///
    /// Separated as a direct method on `SettingsApp` so both `eframe::App::update` and headless
    /// `egui::Context::run` unit tests execute the exact same UI code.
    pub fn render_ui(&mut self, ctx: &egui::Context) {
        // `eframe` creates the native `winit` window hidden during frame 0 and makes it visible
        // immediately after frame 0 completes; issuing `Focus` across frames 0 and 1 ensures
        // `NSWindow::makeKeyAndOrderFront` runs once `isVisible() == true`, while frame 2+ stays
        // completely idle (`Duration::MAX`).
        if self.launch_focus_frames < 2 {
            self.launch_focus_frames += 1;
            activate_settings_window_macos();
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        if self.raise_requested.swap(false, Ordering::AcqRel) {
            let _ = self.state.sync_external_changes();
            activate_settings_window_macos();
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        let is_focused = ctx.input(|i| i.viewport().focused).unwrap_or(true);
        if is_focused && !self.was_window_focused {
            let _ = self.state.sync_external_changes();
        }
        self.was_window_focused = is_focused;

        // Strict 0% idle CPU discipline (`PLAN.md` §7):
        // ONLY schedule a slow 1s repaint when the Logs tab is actively visible!
        if self.state.active_tab == SettingsTab::Logs {
            self.state.refresh_logs_incremental();
            ctx.request_repaint_after(Duration::from_secs(1));
        }

        egui::TopBottomPanel::top("settings_top_bar")
            .frame(
                egui::Frame::side_top_panel(&ctx.style())
                    .inner_margin(egui::Margin::symmetric(14, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("VLESS Tray Settings");
                    ui.add_space(16.0);

                    for (tab, label) in [
                        (SettingsTab::Profiles, "Profiles"),
                        (SettingsTab::BypassList, "Bypass List"),
                        (SettingsTab::DnsAndProxy, "DNS & Proxy"),
                        (SettingsTab::Logs, "Logs"),
                    ] {
                        let selected = self.state.active_tab == tab;
                        if ui.selectable_label(selected, label).clicked() {
                            self.state.set_tab(tab);
                        }
                    }
                });
            });

        if self.state.status_message.is_some()
            || self.state.error_message.is_some()
            || !self.state.import_warnings.is_empty()
        {
            egui::TopBottomPanel::bottom("settings_status_bar")
                .frame(
                    egui::Frame::side_top_panel(&ctx.style())
                        .inner_margin(egui::Margin::symmetric(14, 8)),
                )
                .show(ctx, |ui| {
                    self.render_banners(ui);
                });
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(egui::Margin::same(16)))
            .show(ctx, |ui| match self.state.active_tab {
                SettingsTab::Profiles => self.render_profiles_tab(ui),
                SettingsTab::BypassList => self.render_bypass_tab(ui),
                SettingsTab::DnsAndProxy => self.render_dns_proxy_tab(ui),
                SettingsTab::Logs => self.render_logs_tab(ui),
            });
    }

    fn render_banners(&mut self, ui: &mut egui::Ui) {
        if !self.state.import_warnings.is_empty() {
            let warnings_joined = self.state.import_warnings.join("\n• ");
            egui::Frame::group(ui.style())
                .fill(egui::Color32::from_rgb(72, 52, 12))
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    egui::Color32::from_rgb(230, 175, 45),
                ))
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(
                            egui::Color32::from_rgb(255, 215, 100),
                            format!("⚠ Warning: {warnings_joined}"),
                        );
                        if ui.small_button("Dismiss").clicked() {
                            self.state.import_warnings.clear();
                        }
                    });
                });
        }

        if let Some(err) = self.state.error_message.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(235, 85, 85),
                    format!("Error: {err}"),
                );
                if ui.small_button("Dismiss").clicked() {
                    self.state.error_message = None;
                }
            });
        } else if let Some(msg) = self.state.status_message.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::from_rgb(95, 200, 120), msg);
                if ui.small_button("×").clicked() {
                    self.state.status_message = None;
                }
            });
        }
    }

    fn render_profiles_tab(&mut self, ui: &mut egui::Ui) {
        // 1. Share-link import bar (`vless://...` + Clipboard import)
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Import Share Link");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Import from Clipboard").clicked()
                            && let Err(err) = self.state.import_from_system_clipboard()
                        {
                            self.state.import_error = Some(err);
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.state.import_link_input)
                            .hint_text("vless://uuid@host:443?security=reality&flow=xtls-rprx-vision&sni=...&pbk=...#Name")
                            .desired_width(ui.available_width() - 76.0),
                    );
                    let enter_pressed =
                        resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Import").clicked() || enter_pressed {
                        let link = self.state.import_link_input.clone();
                        let _ = self.state.import_vless_link(&link);
                    }
                });

                if let Some(err) = &self.state.import_error {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                }
            });

        ui.add_space(10.0);

        // 2. If Profile Editor is open, render the full REALITY / kTLS form
        if self.state.editor.is_some() {
            self.render_profile_editor(ui);
            return;
        }

        // 3. Profiles list header + Add button
        ui.horizontal(|ui| {
            ui.strong(format!(
                "Saved Profiles ({})",
                self.state.config.profiles.len()
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("+ Add Profile").clicked() {
                    self.state.start_new_profile();
                }
            });
        });
        ui.add_space(6.0);

        if self.state.config.profiles.is_empty() {
            ui.weak("No profiles configured yet. Paste a vless:// link above or click \"+ Add Profile\".");
            return;
        }

        let profiles_snapshot = self.state.config.profiles.clone();
        let selected_id = self.state.config.selected_profile_id;

        egui::ScrollArea::vertical()
            .id_salt("profiles_scroll")
            .show(ui, |ui| {
                for profile in &profiles_snapshot {
                    let is_selected = selected_id == Some(profile.id);
                    let (proto_label, proto_color) = match &profile.security {
                        ProfileSecurity::Reality { .. } => {
                            ("REALITY", egui::Color32::from_rgb(70, 155, 245))
                        }
                        ProfileSecurity::Ktls { .. } => {
                            ("kTLS", egui::Color32::from_rgb(165, 120, 245))
                        }
                    };

                    egui::Frame::group(ui.style())
                        .inner_margin(egui::Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if is_selected {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(80, 205, 120),
                                        "● Active",
                                    );
                                }
                                ui.colored_label(proto_color, format!("[{proto_label}]"));
                                ui.strong(&profile.name);
                                ui.monospace(profile.server_addr_display());
                                ui.weak(format!("SNI: {}", profile.security.sni()));

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.button("Delete").clicked() {
                                            let _ = self.state.delete_profile(profile.id);
                                        }
                                        if ui.button("Copy vless://").clicked()
                                            && let Some(uri) =
                                                self.state.export_profile_link(profile.id)
                                        {
                                            let _ = write_clipboard_utf8(&uri);
                                            ui.ctx().copy_text(uri);
                                            self.state.status_message = Some(format!(
                                                "Copied vless:// link for \"{}\"",
                                                profile.name
                                            ));
                                        }
                                        if ui.button("Edit").clicked() {
                                            self.state.start_edit_profile(profile.id);
                                        }
                                        if !is_selected && ui.button("Select").clicked() {
                                            let _ = self.state.select_profile(profile.id);
                                        }
                                    },
                                );
                            });
                        });
                    ui.add_space(4.0);
                }
            });
    }

    fn render_profile_editor(&mut self, ui: &mut egui::Ui) {
        let mut save_clicked = false;
        let mut cancel_clicked = false;

        if let Some(draft) = self.state.editor.as_mut() {
            let heading = if draft.editing_id.is_some() {
                "Edit Profile"
            } else {
                "New Profile"
            };

            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.heading(heading);
                    ui.add_space(8.0);

                    egui::ScrollArea::vertical()
                        .id_salt("profile_editor_scroll")
                        .show(ui, |ui| {
                            egui::Grid::new("profile_editor_grid")
                                .num_columns(2)
                                .spacing([12.0, 8.0])
                                .striped(false)
                                .show(ui, |ui| {
                                    ui.label("Listener Protocol:");
                                    ui.horizontal(|ui| {
                                        ui.selectable_value(
                                            &mut draft.kind,
                                            ProfileKindDraft::Reality,
                                            "REALITY (Vision + XUDP)",
                                        );
                                        ui.selectable_value(
                                            &mut draft.kind,
                                            ProfileKindDraft::Ktls,
                                            "kTLS (TLS 1.3 + XUDP)",
                                        );
                                    });
                                    ui.end_row();

                                    ui.label("Profile Name:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut draft.name)
                                            .hint_text("e.g. Tokyo REALITY")
                                            .desired_width(360.0),
                                    );
                                    ui.end_row();

                                    ui.label("Server Host:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut draft.server_host)
                                            .hint_text("edge.example.com or 198.51.100.10")
                                            .desired_width(360.0),
                                    );
                                    ui.end_row();

                                    ui.label("Server Port:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut draft.server_port)
                                            .hint_text("443")
                                            .desired_width(110.0),
                                    );
                                    ui.end_row();

                                    ui.label("User UUID:");
                                    ui.horizontal(|ui| {
                                        ui.add(
                                            egui::TextEdit::singleline(&mut draft.uuid)
                                                .desired_width(290.0),
                                        );
                                        if ui.button("Generate").clicked() {
                                            draft.uuid = Uuid::new_v4().to_string();
                                        }
                                    });
                                    ui.end_row();

                                    ui.label("SNI (DNS Name):");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut draft.sni)
                                            .hint_text("www.apple.com")
                                            .desired_width(360.0),
                                    );
                                    ui.end_row();

                                    match draft.kind {
                                        ProfileKindDraft::Reality => {
                                            ui.label("Public Key (pbk):");
                                            ui.add(
                                                egui::TextEdit::singleline(&mut draft.pbk)
                                                    .hint_text("32-byte base64url public key")
                                                    .desired_width(360.0),
                                            );
                                            ui.end_row();

                                            ui.label("Short ID (sid):");
                                            ui.add(
                                                egui::TextEdit::singleline(&mut draft.sid)
                                                    .hint_text("0..=16 hex chars (optional)")
                                                    .desired_width(220.0),
                                            );
                                            ui.end_row();
                                        }
                                        ProfileKindDraft::Ktls => {
                                            ui.label("ALPN:");
                                            ui.add(
                                                egui::TextEdit::singleline(&mut draft.alpn)
                                                    .hint_text("http/1.1")
                                                    .desired_width(220.0),
                                            );
                                            ui.end_row();

                                            ui.label("Cert SHA-256 Pin:");
                                            ui.add(
                                                egui::TextEdit::singleline(
                                                    &mut draft.cert_sha256_pin,
                                                )
                                                .hint_text(
                                                    "Optional 64-hex or base64 SHA-256 leaf digest",
                                                )
                                                .desired_width(360.0),
                                            );
                                            ui.end_row();
                                        }
                                    }

                                    ui.label("Fingerprint (fp):");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut draft.fp)
                                            .hint_text("chrome (optional)")
                                            .desired_width(180.0),
                                    );
                                    ui.end_row();
                                });

                            let live_validation = draft.build_validated_profile();
                            if let Some(err) = &self.state.editor_error {
                                ui.add_space(8.0);
                                ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                            } else if let Err(live_err) = &live_validation {
                                ui.add_space(8.0);
                                ui.colored_label(
                                    egui::Color32::from_rgb(235, 165, 85),
                                    format!("Validation: {live_err}"),
                                );
                            }

                            ui.add_space(12.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        live_validation.is_ok(),
                                        egui::Button::new("Save Profile"),
                                    )
                                    .clicked()
                                {
                                    save_clicked = true;
                                }
                                if ui.button("Cancel").clicked() {
                                    cancel_clicked = true;
                                }
                            });
                        });
                });
        }

        if save_clicked {
            let _ = self.state.save_profile_draft();
        } else if cancel_clicked {
            self.state.cancel_profile_editor();
        }
    }

    fn render_bypass_tab(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.strong("Built-in Always-On Bypass Ranges (Read-Only)");
                ui.add_space(4.0);
                ui.label(format!(
                    "TUN Routes: {}",
                    BUILTIN_TUN_BYPASS_CIDR_STRS.join(", ")
                ));
                ui.label(format!(
                    "System Proxy Exceptions: {}",
                    BUILTIN_SYSTEM_PROXY_EXCEPTIONS.join(", ")
                ));
            });

        ui.add_space(10.0);

        let preview = self.state.preview_bypass_input();
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.strong("Add Custom Bypass Rule (CIDR, IP, or Domain Pattern)");
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.state.bypass_input)
                            .hint_text("e.g. 100.64.0.0/10, 203.0.113.5, *.corp.example.com, .lan")
                            .desired_width(ui.available_width() - 72.0),
                    );
                    let can_add = matches!(preview, Some(Ok(_)));
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.add_enabled(can_add, egui::Button::new("Add")).clicked()
                        || (enter && can_add)
                    {
                        let _ = self.state.add_bypass_from_input();
                    }
                });

                match &preview {
                    Some(Ok(BypassEntry::Cidr(net))) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(95, 200, 120),
                            format!("✓ Valid CIDR bypass route: {net}"),
                        );
                    }
                    Some(Ok(BypassEntry::Domain(dom))) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(95, 200, 120),
                            format!("✓ Valid domain bypass pattern (SNI/Host): {dom}"),
                        );
                    }
                    Some(Err(err)) => {
                        ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                    }
                    None => {
                        if let Some(err) = &self.state.bypass_error {
                            ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                        }
                    }
                }
            });

        ui.add_space(10.0);
        ui.strong(format!(
            "Custom Bypass Entries ({})",
            self.state.config.bypass_list.len()
        ));
        ui.add_space(4.0);

        if self.state.config.bypass_list.is_empty() {
            ui.weak("No custom bypass rules added.");
            return;
        }

        let entries_snapshot = self.state.config.bypass_list.clone();
        let mut remove_idx = None;
        egui::ScrollArea::vertical()
            .id_salt("bypass_list_scroll")
            .show(ui, |ui| {
                for (idx, item) in entries_snapshot.iter().enumerate() {
                    let kind_tag = match parse_bypass_entry(item) {
                        Ok(BypassEntry::Cidr(_)) => "[CIDR]",
                        Ok(BypassEntry::Domain(_)) => "[Domain]",
                        Err(_) => "[Invalid]",
                    };
                    ui.horizontal(|ui| {
                        ui.weak(kind_tag);
                        ui.monospace(item);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Remove").clicked() {
                                remove_idx = Some(idx);
                            }
                        });
                    });
                    ui.separator();
                }
            });

        if let Some(idx) = remove_idx {
            let _ = self.state.remove_bypass_at(idx);
        }
    }

    fn render_dns_proxy_tab(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.heading("TUN DNS & Local System Proxy");
                ui.add_space(8.0);

                egui::Grid::new("dns_proxy_grid")
                    .num_columns(2)
                    .spacing([14.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("TUN DNS Resolver IP:");
                        ui.vertical(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.state.dns_resolver_input)
                                    .hint_text("1.1.1.1")
                                    .desired_width(220.0),
                            );
                            ui.weak(
                                "Intercepted on port 53 inside TUN and multiplexed over a single long-lived XUDP stream.",
                            );
                        });
                        ui.end_row();

                        ui.label("System Proxy Port:");
                        ui.vertical(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.state.proxy_port_input)
                                    .hint_text("2080")
                                    .desired_width(120.0),
                            );
                            ui.weak(
                                "Mixed HTTP + SOCKS5 (with UDP ASSOCIATE) listener on 127.0.0.1:<port>.",
                            );
                        });
                        ui.end_row();
                    });

                // Live validation feedback
                let dns_check = validate_tun_dns_resolver_str(&self.state.dns_resolver_input);
                let port_check = validate_proxy_port_str(&self.state.proxy_port_input);
                if let Err(err) = &dns_check {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                } else if let Err(err) = &port_check {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                } else if let Some(err) = &self.state.dns_proxy_error {
                    ui.add_space(6.0);
                    ui.colored_label(egui::Color32::from_rgb(235, 85, 85), err);
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let valid = dns_check.is_ok() && port_check.is_ok();
                    if ui
                        .add_enabled(valid, egui::Button::new("Save Settings"))
                        .clicked()
                    {
                        let _ = self.state.save_dns_and_proxy();
                    }
                    if ui.button("Reset to Defaults").clicked() {
                        let _ = self.state.reset_dns_and_proxy_defaults();
                    }
                });
            });
    }

    fn render_logs_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Level:");
            for filter in [
                LogFilter::All,
                LogFilter::InfoPlus,
                LogFilter::WarnPlus,
                LogFilter::ErrorOnly,
            ] {
                if ui
                    .selectable_label(self.state.log_filter == filter, filter.label())
                    .clicked()
                {
                    self.state.log_filter = filter;
                }
            }

            ui.separator();
            ui.checkbox(&mut self.state.log_auto_scroll, "Auto-scroll");

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear Logs").clicked() {
                    self.state.clear_logs();
                }
                if ui.button("Copy Diagnostics").clicked() {
                    self.state.refresh_logs_incremental();
                    let diag = self.state.build_redacted_diagnostics();
                    let _ = write_clipboard_utf8(&diag);
                    ui.ctx().copy_text(diag);
                    self.state.status_message = Some(
                        "Copied diagnostics to clipboard (UUID, pbk, sid, and pins redacted)"
                            .to_string(),
                    );
                }
                if ui.button("Refresh").clicked() {
                    self.state.refresh_logs_incremental();
                }
            });
        });

        ui.weak(format!(
            "Source: {}",
            self.state.log_tailer.log_path().display()
        ));
        ui.add_space(6.0);

        let filter = self.state.log_filter;
        let auto_scroll = self.state.log_auto_scroll;

        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("engine_logs_scroll")
                    .auto_shrink([false, false])
                    .stick_to_bottom(auto_scroll)
                    .show(ui, |ui| {
                        let mut shown = 0usize;
                        for entry in self.state.log_tailer.lines() {
                            if !filter.matches(entry.level) {
                                continue;
                            }
                            shown += 1;
                            let color = match entry.level {
                                LogLevel::Error => egui::Color32::from_rgb(240, 90, 90),
                                LogLevel::Warn => egui::Color32::from_rgb(235, 185, 75),
                                LogLevel::Info => ui.visuals().text_color(),
                                LogLevel::Debug | LogLevel::Trace => ui.visuals().weak_text_color(),
                            };
                            ui.colored_label(
                                color,
                                egui::RichText::new(&entry.raw_line).monospace().size(12.0),
                            );
                        }
                        if shown == 0 {
                            ui.weak("No log entries matching the selected filter.");
                        }
                    });
            });
    }
}

impl eframe::App for SettingsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.render_ui(ctx);
    }
}

#[cfg(target_os = "macos")]
fn activate_settings_window_macos() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationOptions, NSRunningApplication};

    if let Some(mtm) = MainThreadMarker::new() {
        let app = NSApplication::sharedApplication(mtm);
        app.activate();
    }
    let current = NSRunningApplication::currentApplication();
    let _ = current.activateWithOptions(NSApplicationActivationOptions::ActivateAllWindows);
}

#[cfg(not(target_os = "macos"))]
fn activate_settings_window_macos() {}

/// Launches the native `eframe` Settings window (`vless-tray --settings`) and exits cleanly when
/// the window closes.
pub fn run_settings_window(config_dir: PathBuf) -> Result<(), String> {
    let store = ConfigStore::new(config_dir);
    let state = SettingsState::load(store);

    let viewport = egui::ViewportBuilder::default()
        .with_title("VLESS Tray — Settings")
        .with_app_id("io.vless-tray.settings")
        .with_inner_size([760.0, 540.0])
        .with_min_inner_size([620.0, 440.0]);

    #[allow(unused_mut)]
    let mut native_options = eframe::NativeOptions {
        viewport,
        persist_window: false,
        run_and_return: false,
        ..eframe::NativeOptions::default()
    };

    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        native_options.event_loop_builder = Some(Box::new(|builder| {
            builder
                .with_activation_policy(ActivationPolicy::Regular)
                .with_activate_ignoring_other_apps(true);
        }));
    }

    let raise_flag = Arc::new(AtomicBool::new(false));
    let raise_for_app = Arc::clone(&raise_flag);

    eframe::run_native(
        "VLESS Tray — Settings",
        native_options,
        Box::new(move |cc| {
            spawn_sigusr1_raise_listener(cc.egui_ctx.clone(), raise_flag);
            Ok(Box::new(SettingsApp::with_raise_flag(state, raise_for_app)))
        }),
    )
    .map_err(|err| format!("Settings window error: {err}"))
}

#[cfg(unix)]
fn spawn_sigusr1_raise_listener(egui_ctx: egui::Context, raise_flag: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("vless-settings-raise".to_string())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                use tokio::signal::unix::{SignalKind, signal};
                let Ok(mut sigusr1) = signal(SignalKind::user_defined1()) else {
                    return;
                };
                while sigusr1.recv().await.is_some() {
                    raise_flag.store(true, Ordering::Release);
                    egui_ctx.request_repaint();
                }
            });
        })
        .ok();
}

#[cfg(not(unix))]
fn spawn_sigusr1_raise_listener(_egui_ctx: egui::Context, _raise_flag: Arc<AtomicBool>) {}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use std::sync::Mutex;

    use vless_ipc::TLS_VISION_PROBE_WARNING;

    use super::*;
    use crate::supervisor::{append_engine_log_entry, format_engine_log_line};

    const SAMPLE_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const SAMPLE_PBK: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

    #[test]
    fn settings_state_import_warnings_manual_crud_bypass_dns_and_0600_persistence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::new(temp.path().join("vless-tray"));
        let mut state = SettingsState::load(store.clone());

        // 1. Import kTLS link carrying flow=xtls-rprx-vision -> succeeds AND populates TLS_VISION_PROBE_WARNING!
        let probe_link = format!(
            "vless://{SAMPLE_UUID}@ktls.example.com:443?security=tls&sni=ktls.example.com&flow=xtls-rprx-vision#kTLS-Warn"
        );
        let ktls_id = state
            .import_vless_link(&probe_link)
            .expect("import ktls link with warning");
        assert_eq!(
            state.import_warnings,
            vec![TLS_VISION_PROBE_WARNING.to_string()]
        );
        assert_eq!(state.config.selected_profile_id, Some(ktls_id));

        // Verify 0600 permissions on config.json
        let cfg_meta = fs::metadata(store.config_path()).expect("config.json metadata");
        assert_eq!(cfg_meta.mode() & 0o777, 0o600);

        // 2. Invalid link populates import_error without corrupting stored profiles
        assert!(state.import_vless_link("vmess://bad").is_err());
        assert!(state.import_error.is_some());
        assert_eq!(state.config.profiles.len(), 1);

        // 3. Manual REALITY profile creation & validation via ProfileDraft
        state.start_new_profile();
        {
            let draft = state.editor.as_mut().unwrap();
            draft.kind = ProfileKindDraft::Reality;
            draft.name = "Manual REALITY".to_string();
            draft.server_host = "reality.example.org".to_string();
            draft.server_port = "8443".to_string();
            draft.uuid = SAMPLE_UUID.to_string();
            draft.sni = "198.51.100.1".to_string(); // Invalid IP literal SNI -> must fail!
            draft.pbk = SAMPLE_PBK.to_string();
            draft.sid = "0123abcd".to_string();
        }
        assert!(state.save_profile_draft().is_err());
        assert!(state.editor_error.is_some());

        // Fix SNI -> saves cleanly
        state.editor.as_mut().unwrap().sni = "www.microsoft.com".to_string();
        let reality_id = state.save_profile_draft().expect("valid manual REALITY");
        assert!(state.editor.is_none());
        assert_eq!(state.config.profiles.len(), 2);

        // Select and edit the REALITY profile, then export its vless:// link
        state.select_profile(reality_id).unwrap();
        assert_eq!(state.config.selected_profile_id, Some(reality_id));
        let exported = state.export_profile_link(reality_id).unwrap();
        assert!(exported.starts_with("vless://"));
        assert_eq!(
            vless_ipc::parse_vless_link(&exported).unwrap().profile.name,
            "Manual REALITY"
        );

        // Delete active profile -> falls back to remaining profile
        state.delete_profile(reality_id).unwrap();
        assert_eq!(state.config.profiles.len(), 1);
        assert_eq!(state.config.selected_profile_id, Some(ktls_id));

        // 4. Bypass list live validation + normalization + deduplication + remove
        state.bypass_input = "0.0.0.0/0".to_string();
        assert!(state.add_bypass_from_input().is_err());

        state.bypass_input = "*.Corp.Example.COM".to_string();
        let added = state.add_bypass_from_input().unwrap();
        assert_eq!(added, "*.corp.example.com");
        // Duplicate rejected
        state.bypass_input = "*.corp.example.com".to_string();
        assert!(state.add_bypass_from_input().is_err());

        state.bypass_input = "192.0.2.99/24".to_string();
        assert_eq!(state.add_bypass_from_input().unwrap(), "192.0.2.0/24");
        assert_eq!(state.config.bypass_list.len(), 2);
        state.remove_bypass_at(0).unwrap();
        assert_eq!(state.config.bypass_list, vec!["192.0.2.0/24".to_string()]);

        // 5. DNS & Proxy validation (rejects loopback, unspecified, multicast, port 0)
        for bad_dns in [
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
        ] {
            state.dns_resolver_input = bad_dns.to_string();
            state.proxy_port_input = "2080".to_string();
            assert!(
                state.save_dns_and_proxy().is_err(),
                "expected DNS resolver {bad_dns} to be rejected"
            );
        }
        state.dns_resolver_input = "9.9.9.9".to_string();
        state.proxy_port_input = "0".to_string();
        assert!(state.save_dns_and_proxy().is_err());

        state.proxy_port_input = "10808".to_string();
        state.save_dns_and_proxy().expect("valid DNS & port");

        let reloaded = store.load().expect("reload from disk");
        assert_eq!(reloaded.dns_resolver, "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(reloaded.system_proxy_port, 10808);
        assert_eq!(
            fs::metadata(store.config_path()).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn incremental_log_tailer_and_headless_egui_idle_repaint_discipline() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::new(temp.path().join("vless-tray"));
        let log_path = store.dir().join(ENGINE_LOG_FILE_NAME);
        let lock = Mutex::new(());

        append_engine_log_entry(
            &log_path,
            &format_engine_log_line(1_700_000_000_000, LogLevel::Debug, "test", "debug-1"),
            65536,
            &lock,
        )
        .unwrap();
        append_engine_log_entry(
            &log_path,
            &format_engine_log_line(1_700_000_000_100, LogLevel::Info, "test", "info-1"),
            65536,
            &lock,
        )
        .unwrap();

        let state = SettingsState::load(store);
        let mut app = SettingsApp::new(state);
        assert_eq!(app.state.log_tailer.lines().len(), 2);
        let offset_after_two = app.state.log_tailer.read_offset();
        assert!(offset_after_two > 0);

        // Append one Error line -> incremental poll reads ONLY the new delta bytes!
        append_engine_log_entry(
            &log_path,
            &format_engine_log_line(1_700_000_000_200, LogLevel::Error, "test", "boom-1"),
            65536,
            &lock,
        )
        .unwrap();
        let added = app.state.log_tailer.poll_incremental().unwrap();
        assert_eq!(added, 1);
        assert_eq!(app.state.log_tailer.lines().len(), 3);
        assert!(app.state.log_tailer.read_offset() > offset_after_two);

        // Filter verification
        assert!(LogFilter::ErrorOnly.matches(LogLevel::Error));
        assert!(!LogFilter::ErrorOnly.matches(LogLevel::Warn));
        assert!(LogFilter::InfoPlus.matches(LogLevel::Info));
        assert!(!LogFilter::InfoPlus.matches(LogLevel::Debug));

        // Exercise full headless `egui::Context::run` across all 4 tabs and verify repaint discipline!
        let ctx = egui::Context::default();
        let make_input = || egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(760.0, 540.0),
            )),
            ..egui::RawInput::default()
        };

        // Warm-up pass
        let _ = ctx.run(make_input(), |ctx| app.render_ui(ctx));

        for idle_tab in [
            SettingsTab::Profiles,
            SettingsTab::BypassList,
            SettingsTab::DnsAndProxy,
        ] {
            app.state.set_tab(idle_tab);
            // Initial 2 passes converge newly mounted Grid / ScrollArea geometry;
            // steady-state idle frames thereafter must sleep indefinitely (`Duration::MAX`).
            let _ = ctx.run(make_input(), |ctx| app.render_ui(ctx));
            let _ = ctx.run(make_input(), |ctx| app.render_ui(ctx));
            let out = ctx.run(make_input(), |ctx| app.render_ui(ctx));
            let root_vp = out
                .viewport_output
                .get(&egui::ViewportId::ROOT)
                .expect("root viewport output");
            assert_eq!(
                root_vp.repaint_delay,
                Duration::MAX,
                "expected 0% idle CPU (Duration::MAX repaint_delay) on tab {idle_tab:?}, got {:?}",
                root_vp.repaint_delay
            );
        }

        // On Logs tab, steady-state schedules a slow 1s tail repaint
        app.state.set_tab(SettingsTab::Logs);
        let _ = ctx.run(make_input(), |ctx| app.render_ui(ctx));
        let logs_out = ctx.run(make_input(), |ctx| app.render_ui(ctx));
        let logs_vp = logs_out
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .expect("root viewport output");
        assert!(
            logs_vp.repaint_delay > Duration::ZERO
                && logs_vp.repaint_delay <= Duration::from_secs(1),
            "expected (0, 1s] repaint delay on Logs tab, got {:?}",
            logs_vp.repaint_delay
        );

        // Clear logs resets offset to 0 and keeps 0600 permissions
        app.state.clear_logs();
        assert_eq!(app.state.log_tailer.read_offset(), 0);
        assert!(app.state.log_tailer.lines().is_empty());
        assert_eq!(fs::metadata(&log_path).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn cross_process_save_preserves_tray_mode_and_diagnostics_redact_all_secrets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::new(temp.path().join("vless-tray"));
        let mut settings = SettingsState::load(store.clone());

        let reality_link = format!(
            "vless://{SAMPLE_UUID}@[2001:db8::42]:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={SAMPLE_PBK}&sid=0f#IPv6-Edge"
        );
        let pid = settings.import_vless_link(&reality_link).unwrap();

        // Simulate `vless-tray` menu bar concurrently switching `mode` to `Tun` on disk while Settings is open!
        let mut tray_cfg = store.load().unwrap();
        assert_eq!(tray_cfg.mode, vless_ipc::ConnectionMode::Off);
        tray_cfg.mode = vless_ipc::ConnectionMode::Tun;
        store.save(&tray_cfg).unwrap();

        // Now user adds a bypass rule inside the already-open Settings window -> MUST NOT revert `mode` to `Off`!
        settings.bypass_input = "*.internal.corp".to_string();
        settings.add_bypass_from_input().unwrap();

        let disk_after_bypass = store.load().unwrap();
        assert_eq!(
            disk_after_bypass.mode,
            vless_ipc::ConnectionMode::Tun,
            "saving bypass list in Settings must preserve external Tun mode set by tray"
        );
        assert_eq!(
            disk_after_bypass.bypass_list,
            vec!["*.internal.corp".to_string()]
        );

        // Bracketed IPv6 literal `[2001:db8::99]` in manual ProfileDraft normalizes cleanly
        settings.start_edit_profile(pid);
        settings.editor.as_mut().unwrap().server_host = "[2001:db8::99]".to_string();
        settings.save_profile_draft().unwrap();
        assert_eq!(settings.config.profiles[0].server_host, "2001:db8::99");
        assert_eq!(store.load().unwrap().mode, vless_ipc::ConnectionMode::Tun);

        // Append log lines containing UUID (hyphenated & simple), pbk, 2-char sid=0f, and vless:// link
        let log_path = store.dir().join(ENGINE_LOG_FILE_NAME);
        let lock = Mutex::new(());
        let simple_uuid = SAMPLE_UUID.replace('-', "");
        append_engine_log_entry(
            &log_path,
            &format_engine_log_line(
                1_700_000_001_000,
                LogLevel::Warn,
                "vless_engine",
                &format!(
                    "dial failed for {SAMPLE_UUID} ({simple_uuid}) pbk={SAMPLE_PBK} sid=0f uri={reality_link}"
                ),
            ),
            65536,
            &lock,
        )
        .unwrap();
        settings.refresh_logs_incremental();

        let diag = settings.build_redacted_diagnostics();
        assert!(
            !diag.contains(SAMPLE_UUID),
            "leaked hyphenated UUID: {diag}"
        );
        assert!(!diag.contains(&simple_uuid), "leaked simple UUID: {diag}");
        assert!(!diag.contains(SAMPLE_PBK), "leaked REALITY pbk: {diag}");
        assert!(
            !diag.contains("sid=0f"),
            "leaked 2-char REALITY sid: {diag}"
        );
        assert!(diag.contains("<redacted>"));
        assert!(diag.contains("2001:db8::99"));
    }
}
