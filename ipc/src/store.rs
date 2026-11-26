//! Application settings, bypass list parsing/validation, and atomic `0600` file persistence.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::profile::{Profile, ProfileError};

/// Default local mixed (HTTP + SOCKS5) proxy port in System Proxy mode.
pub const DEFAULT_SYSTEM_PROXY_PORT: u16 = 2080;

/// Default DNS resolver tunnelled over XUDP in TUN mode (`PLAN.md` §5.4).
pub const DEFAULT_DNS_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// File name inside the application configuration directory.
pub const CONFIG_FILE_NAME: &str = "config.json";

/// Built-in private, link-local, multicast, and ULA CIDRs bypassed in TUN mode (`PLAN.md` §5.2).
pub const BUILTIN_TUN_BYPASS_CIDR_STRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "fc00::/7",
    "fe80::/10",
];

/// Built-in proxy exception entries applied to enabled network services in System Proxy mode
/// (`PLAN.md` §5.3).
pub const BUILTIN_SYSTEM_PROXY_EXCEPTIONS: &[&str] = &[
    "*.local",
    "169.254.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1",
    "::1",
    "localhost",
];

/// Active client connection mode (`PLAN.md` §1, §5, §7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    #[default]
    Off,
    SystemProxy,
    Tun,
}

/// Parsed and normalized item from the bypass list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BypassEntry {
    /// IPv4/IPv6 CIDR (or single host normalized to `/32` or `/128`).
    Cidr(IpNetwork),
    /// Exact domain (`example.com`), wildcard (`*.example.com`), or suffix (`.example.com`).
    Domain(String),
}

impl BypassEntry {
    /// Formats the entry back into its canonical string representation.
    pub fn to_canonical_string(&self) -> String {
        match self {
            Self::Cidr(net) => match net {
                IpNetwork::V4(v4) if v4.prefix() == 32 => v4.ip().to_string(),
                IpNetwork::V6(v6) if v6.prefix() == 128 => v6.ip().to_string(),
                other => other.to_string(),
            },
            Self::Domain(domain) => domain.clone(),
        }
    }
}

/// Validation errors for user bypass list entries.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BypassValidationError {
    #[error("bypass entry must not be empty")]
    Empty,

    #[error("bypass entry {entry:?} must not contain whitespace or control characters")]
    InvalidCharacters { entry: String },

    #[error("invalid CIDR bypass entry {entry:?}: {reason}")]
    InvalidCidr { entry: String, reason: String },

    #[error("invalid domain bypass pattern {entry:?}: {reason}")]
    InvalidDomain { entry: String, reason: String },
}

/// Errors encountered when loading, validating, or saving [`AppConfig`].
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error accessing config store: {0}")]
    Io(#[from] io::Error),

    #[error("invalid config JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid profile in config: {0}")]
    Profile(#[from] ProfileError),

    #[error("invalid bypass entry: {0}")]
    Bypass(#[from] BypassValidationError),

    #[error("duplicate profile ID {0} in config")]
    DuplicateProfileId(Uuid),

    #[error("selected_profile_id {0} does not match any stored profile")]
    UnknownSelectedProfile(Uuid),

    #[error("system_proxy_port must be between 1 and 65535")]
    InvalidProxyPort,

    #[error(
        "dns_resolver {0} must be a unicast IP address (not unspecified, multicast, or broadcast)"
    )]
    InvalidDnsResolver(IpAddr),
}

const fn default_system_proxy_port() -> u16 {
    DEFAULT_SYSTEM_PROXY_PORT
}

const fn default_dns_resolver() -> IpAddr {
    DEFAULT_DNS_RESOLVER
}

/// Persistent user configuration stored in `config.json` (`0600`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub selected_profile_id: Option<Uuid>,
    #[serde(default)]
    pub mode: ConnectionMode,
    #[serde(default = "default_system_proxy_port")]
    pub system_proxy_port: u16,
    #[serde(default = "default_dns_resolver")]
    pub dns_resolver: IpAddr,
    #[serde(default)]
    pub bypass_list: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            selected_profile_id: None,
            mode: ConnectionMode::Off,
            system_proxy_port: DEFAULT_SYSTEM_PROXY_PORT,
            dns_resolver: DEFAULT_DNS_RESOLVER,
            bypass_list: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Returns a reference to the currently selected [`Profile`], if any.
    pub fn selected_profile(&self) -> Option<&Profile> {
        let id = self.selected_profile_id?;
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Validates all profiles, settings, and bypass rules in this [`AppConfig`].
    pub fn validate(&self) -> Result<Vec<String>, ConfigError> {
        let mut warnings = Vec::new();
        let mut seen_ids = HashSet::with_capacity(self.profiles.len());

        for profile in &self.profiles {
            if !seen_ids.insert(profile.id) {
                return Err(ConfigError::DuplicateProfileId(profile.id));
            }
            let mut profile_warnings = profile.validate()?;
            warnings.append(&mut profile_warnings);
        }

        if let Some(selected) = self.selected_profile_id
            && !seen_ids.contains(&selected)
        {
            return Err(ConfigError::UnknownSelectedProfile(selected));
        }

        if self.system_proxy_port == 0 {
            return Err(ConfigError::InvalidProxyPort);
        }

        if !is_valid_unicast_ip(&self.dns_resolver) {
            return Err(ConfigError::InvalidDnsResolver(self.dns_resolver));
        }

        for item in &self.bypass_list {
            let _ = parse_bypass_entry(item)?;
        }

        Ok(warnings)
    }
}

/// Manages loading and atomically saving [`AppConfig`] inside a `0700` directory with `0600` files.
#[derive(Clone, Debug)]
pub struct ConfigStore {
    dir: PathBuf,
}

impl ConfigStore {
    /// Creates a [`ConfigStore`] backed by the specified directory path.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Creates a [`ConfigStore`] at the platform default path:
    /// - macOS: `~/Library/Application Support/vless-tray`
    /// - Linux/other Unix: `$XDG_CONFIG_HOME/vless-tray` or `~/.config/vless-tray`
    pub fn default_location() -> io::Result<Self> {
        Ok(Self::new(default_config_dir()?))
    }

    /// Returns the directory managed by this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the full path to `config.json`.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE_NAME)
    }

    /// Loads and validates `config.json`, returning [`AppConfig::default()`] if the file does not
    /// exist yet.
    pub fn load(&self) -> Result<AppConfig, ConfigError> {
        let path = self.config_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(AppConfig::default()),
            Err(err) => return Err(ConfigError::Io(err)),
        };

        let config: AppConfig = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates `config` and writes it atomically to `config.json` with mode `0600`.
    pub fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
        config.validate()?;
        let mut serialized = serde_json::to_vec_pretty(config)?;
        serialized.push(b'\n');
        write_atomic_0600(&self.config_path(), &serialized)?;
        Ok(())
    }
}

/// Resolves the platform default directory for user configuration.
pub fn default_config_dir() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME");
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    resolve_config_dir(home.as_deref(), xdg.as_deref())
}

fn resolve_config_dir(
    home: Option<&OsStr>,
    xdg_config_home: Option<&OsStr>,
) -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_config_home;
        let home = home.filter(|h| !h.is_empty()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME environment variable is not set",
            )
        })?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("vless-tray"))
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = xdg_config_home
            && !xdg.is_empty()
        {
            return Ok(PathBuf::from(xdg).join("vless-tray"));
        }
        let home = home.filter(|h| !h.is_empty()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "neither XDG_CONFIG_HOME nor HOME is set",
            )
        })?;
        Ok(PathBuf::from(home).join(".config").join("vless-tray"))
    }
}

/// Parses and validates a single bypass list entry as either a CIDR/IP or a domain pattern.
pub fn parse_bypass_entry(raw: &str) -> Result<BypassEntry, BypassValidationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BypassValidationError::Empty);
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(BypassValidationError::InvalidCharacters {
            entry: raw.to_string(),
        });
    }

    // 1. Explicit CIDR (`ip/prefix`).
    if trimmed.contains('/') {
        let parsed =
            trimmed
                .parse::<IpNetwork>()
                .map_err(|err| BypassValidationError::InvalidCidr {
                    entry: trimmed.to_string(),
                    reason: err.to_string(),
                })?;
        return normalize_and_check_cidr(parsed, trimmed).map(BypassEntry::Cidr);
    }

    // 2. Single IPv4 or IPv6 literal -> host `/32` or `/128` CIDR.
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if ip.is_unspecified() {
            return Err(BypassValidationError::InvalidCidr {
                entry: trimmed.to_string(),
                reason: "unspecified address cannot be used as a bypass target".to_string(),
            });
        }
        return Ok(BypassEntry::Cidr(IpNetwork::from(ip)));
    }

    // 3. Domain pattern (`example.com`, `*.example.com`, `.example.com`, `localhost`, `*.local`).
    let normalized_domain = validate_and_normalize_domain_pattern(trimmed)?;
    Ok(BypassEntry::Domain(normalized_domain))
}

/// Returns the built-in TUN bypass CIDRs (`PLAN.md` §5.2).
pub fn builtin_tun_bypass_cidrs() -> Vec<IpNetwork> {
    BUILTIN_TUN_BYPASS_CIDR_STRS
        .iter()
        .map(|s| s.parse::<IpNetwork>().expect("valid built-in CIDR"))
        .collect()
}

/// Returns the built-in System Proxy exception strings (`PLAN.md` §5.3).
pub fn builtin_system_proxy_exceptions() -> Vec<String> {
    BUILTIN_SYSTEM_PROXY_EXCEPTIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Parses user bypass entries into separate `(cidrs, domains)` vectors without built-in defaults.
pub fn parse_bypass_list(
    entries: &[String],
) -> Result<(Vec<IpNetwork>, Vec<String>), BypassValidationError> {
    let mut cidrs = Vec::new();
    let mut domains = Vec::new();

    for raw in entries {
        match parse_bypass_entry(raw)? {
            BypassEntry::Cidr(net) => {
                if !cidrs.contains(&net) {
                    cidrs.push(net);
                }
            }
            BypassEntry::Domain(dom) => {
                if !domains.contains(&dom) {
                    domains.push(dom);
                }
            }
        }
    }

    Ok((cidrs, domains))
}

/// Combines built-in TUN bypass CIDRs (`PLAN.md` §5.2) with validated user CIDRs and domains.
pub fn effective_tun_bypass(
    user_entries: &[String],
) -> Result<(Vec<IpNetwork>, Vec<String>), BypassValidationError> {
    let mut cidrs = builtin_tun_bypass_cidrs();
    let (user_cidrs, domains) = parse_bypass_list(user_entries)?;
    for net in user_cidrs {
        if !cidrs.contains(&net) {
            cidrs.push(net);
        }
    }
    Ok((cidrs, domains))
}

/// Combines built-in System Proxy exceptions (`PLAN.md` §5.3) with validated user bypass entries.
pub fn effective_system_proxy_exceptions(
    user_entries: &[String],
) -> Result<Vec<String>, BypassValidationError> {
    let mut out = builtin_system_proxy_exceptions();
    for raw in user_entries {
        let entry = parse_bypass_entry(raw)?;
        let canonical = entry.to_canonical_string();
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

/// Atomically writes `bytes` to `path` with mode `0600` (`rw-------`).
///
/// Steps:
/// 1. Ensures the parent directory exists (creating missing directories with mode `0700`).
/// 2. Creates a unique sibling temporary file with `O_CREAT | O_EXCL` and mode `0600`.
/// 3. Explicitly sets `0600` permissions on the descriptor, writes all `bytes`, and calls `fsync`
///    (`File::sync_all`).
/// 4. Atomically renames the temporary file over `path`.
/// 5. Best-effort `fsync`s the parent directory so the rename directory entry is durable.
pub fn write_atomic_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target path must have a parent directory",
            )
        })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid target file name"))?;

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;

    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        ".{file_name}.tmp.{}.{}.{}",
        std::process::id(),
        seq,
        Uuid::new_v4()
    );
    let tmp_path = parent.join(tmp_name);

    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;

        file.set_permissions(Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    // Best-effort parent directory fsync.
    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

fn normalize_and_check_cidr(
    parsed: IpNetwork,
    raw: &str,
) -> Result<IpNetwork, BypassValidationError> {
    if parsed.prefix() < 2 {
        return Err(BypassValidationError::InvalidCidr {
            entry: raw.to_string(),
            reason: "CIDR prefix must be >= 2 (cannot override default or /1 tunnel routes)"
                .to_string(),
        });
    }
    let network_addr = parsed.network();
    if network_addr.is_unspecified() {
        return Err(BypassValidationError::InvalidCidr {
            entry: raw.to_string(),
            reason: "CIDR network address cannot be unspecified".to_string(),
        });
    }
    IpNetwork::new(network_addr, parsed.prefix()).map_err(|err| {
        BypassValidationError::InvalidCidr {
            entry: raw.to_string(),
            reason: err.to_string(),
        }
    })
}

pub(crate) fn validate_and_normalize_domain_pattern(
    input: &str,
) -> Result<String, BypassValidationError> {
    if input.len() > 253 || !input.is_ascii() {
        return Err(BypassValidationError::InvalidDomain {
            entry: input.to_string(),
            reason: "domain pattern must be 1..=253 ASCII characters".to_string(),
        });
    }

    let (prefix, body) = if let Some(rest) = input.strip_prefix("*.") {
        ("*.", rest)
    } else if let Some(rest) = input.strip_prefix('.') {
        (".", rest)
    } else {
        ("", input)
    };

    let body = body.strip_suffix('.').unwrap_or(body);
    if body.is_empty() {
        return Err(BypassValidationError::InvalidDomain {
            entry: input.to_string(),
            reason: "missing domain name after prefix".to_string(),
        });
    }

    let labels: Vec<&str> = body.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(BypassValidationError::InvalidDomain {
                entry: input.to_string(),
                reason: "domain labels must be 1..=63 characters".to_string(),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(BypassValidationError::InvalidDomain {
                entry: input.to_string(),
                reason: "domain labels must not start or end with '-'".to_string(),
            });
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(BypassValidationError::InvalidDomain {
                entry: input.to_string(),
                reason: format!("invalid character in domain label {label:?}"),
            });
        }
    }

    if let Some(last) = labels.last()
        && last.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(BypassValidationError::InvalidDomain {
            entry: input.to_string(),
            reason: "top-level label must not be all-numeric".to_string(),
        });
    }

    Ok(format!("{prefix}{}", body.to_ascii_lowercase()))
}

fn is_valid_unicast_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::MetadataExt;

    use base64::Engine as _;

    use super::*;
    use crate::profile::parse_vless_link;

    #[test]
    fn write_atomic_0600_enforces_permissions_and_atomic_overwrite() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let nested_dir = tempdir.path().join("sub").join("vless-tray");
        let target = nested_dir.join("config.json");

        write_atomic_0600(&target, b"{\"first\":1}\n").expect("first write");
        let meta_dir = fs::metadata(&nested_dir).expect("dir metadata");
        assert_eq!(meta_dir.mode() & 0o777, 0o700);

        let meta_file = fs::metadata(&target).expect("file metadata");
        assert_eq!(meta_file.mode() & 0o777, 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"{\"first\":1}\n");

        // Atomic overwrite preserves 0600 and leaves no temp siblings behind
        write_atomic_0600(&target, b"{\"second\":2}\n").expect("second write");
        let meta_file2 = fs::metadata(&target).expect("file metadata after overwrite");
        assert_eq!(meta_file2.mode() & 0o777, 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"{\"second\":2}\n");

        let entries: Vec<_> = fs::read_dir(&nested_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn config_store_roundtrip_and_validation() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::new(tempdir.path().join("store"));

        // Missing file loads default cleanly
        let initial = store.load().expect("default load");
        assert_eq!(initial, AppConfig::default());

        let pbk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        let link = format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@node.example.com:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={pbk}#MacProfile"
        );
        let profile = parse_vless_link(&link).unwrap().profile;
        let profile_id = profile.id;

        let cfg = AppConfig {
            profiles: vec![profile],
            selected_profile_id: Some(profile_id),
            mode: ConnectionMode::Tun,
            system_proxy_port: 2080,
            dns_resolver: "1.1.1.1".parse().unwrap(),
            bypass_list: vec![
                "100.64.0.0/10".to_string(),
                "*.corp.example.com".to_string(),
                ".internal.lan".to_string(),
                "example.org".to_string(),
            ],
        };

        store.save(&cfg).expect("save valid config");
        let mode = fs::metadata(store.config_path()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let loaded = store.load().expect("reload saved config");
        assert_eq!(loaded, cfg);
        assert_eq!(loaded.selected_profile().unwrap().id, profile_id);

        // Reject invalid port or unknown selected_profile_id
        let mut bad_cfg = loaded.clone();
        bad_cfg.system_proxy_port = 0;
        assert!(store.save(&bad_cfg).is_err());

        let mut bad_sel = loaded;
        bad_sel.selected_profile_id = Some(Uuid::new_v4());
        assert!(bad_sel.validate().is_err());
    }

    #[test]
    fn bypass_entries_and_builtin_lists_work() {
        assert_eq!(
            parse_bypass_entry("192.168.10.5/24").unwrap(),
            BypassEntry::Cidr("192.168.10.0/24".parse().unwrap())
        );
        assert_eq!(
            parse_bypass_entry("203.0.113.9").unwrap(),
            BypassEntry::Cidr("203.0.113.9/32".parse().unwrap())
        );
        assert_eq!(
            parse_bypass_entry("*.Example.COM").unwrap(),
            BypassEntry::Domain("*.example.com".to_string())
        );
        assert_eq!(
            parse_bypass_entry(".Corp.Local").unwrap(),
            BypassEntry::Domain(".corp.local".to_string())
        );

        for invalid in [
            "",
            "0.0.0.0/0",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "::/0",
            "999.999.999.999",
            "bad domain.com",
            "-bad.example.com",
            "http://example.com",
        ] {
            assert!(
                parse_bypass_entry(invalid).is_err(),
                "expected error for {invalid:?}"
            );
        }

        let (tun_cidrs, tun_domains) = effective_tun_bypass(&[
            "10.0.0.0/8".to_string(),
            "100.64.0.0/10".to_string(),
            "*.corp.example".to_string(),
        ])
        .unwrap();
        assert_eq!(tun_cidrs.len(), BUILTIN_TUN_BYPASS_CIDR_STRS.len() + 1);
        assert_eq!(tun_domains, vec!["*.corp.example".to_string()]);

        assert!(BUILTIN_SYSTEM_PROXY_EXCEPTIONS.contains(&"::1"));
        let sys_exceptions = effective_system_proxy_exceptions(&[
            "localhost".to_string(),
            "::1".to_string(),
            "*.corp.example".to_string(),
        ])
        .unwrap();
        assert!(sys_exceptions.contains(&"::1".to_string()));
        assert_eq!(
            sys_exceptions.len(),
            BUILTIN_SYSTEM_PROXY_EXCEPTIONS.len() + 1
        );
    }

    #[test]
    fn resolve_config_dir_handles_env_inputs() {
        let home = OsString::from("/Users/alice");
        let xdg = OsString::from("/tmp/xdg");
        let resolved = resolve_config_dir(Some(&home), Some(&xdg)).expect("dir");
        #[cfg(target_os = "macos")]
        assert_eq!(
            resolved,
            PathBuf::from("/Users/alice/Library/Application Support/vless-tray")
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(resolved, PathBuf::from("/tmp/xdg/vless-tray"));
    }
}
