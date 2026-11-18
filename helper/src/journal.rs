//! Crash-safe `0600` state journal (`helper-state.json`) and rollback/recovery routines
//! (`PLAN.md` §5.1).

use std::fs::{self, File};
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use vless_ipc::{
    HelperValidationError, MAX_BYPASS_CIDRS, MAX_PROXY_EXCEPTIONS, MAX_SERVER_IPS, validate_cidr,
    validate_exception_entry, validate_interface_name, validate_server_ip, write_atomic_0600,
};

use crate::backend::{
    DefaultGatewayV4, DefaultGatewayV6, DnsSnapshot, RouteSpec, ServiceProxySnapshot, SystemBackend,
};
use crate::error::HelperError;

/// Current schema version for `helper-state.json`.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

const fn default_journal_version() -> u32 {
    JOURNAL_SCHEMA_VERSION
}

/// Persistent root-owned (`0600`) state journal written BEFORE mutating system routes, DNS, or
/// network service proxies (`PLAN.md` §5.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum HelperJournal {
    /// Active or planned TUN session state.
    Tun {
        #[serde(default = "default_journal_version")]
        version: u32,
        utun_name: String,
        v4_gateway: Option<DefaultGatewayV4>,
        v6_gateway: Option<DefaultGatewayV6>,
        dns_snapshots: Vec<DnsSnapshot>,
        dns_resolver: IpAddr,
        server_ips: Vec<IpAddr>,
        bypass_cidrs: Vec<IpNetwork>,
        routes: Vec<RouteSpec>,
    },
    /// Active or planned System Proxy session state.
    SystemProxy {
        #[serde(default = "default_journal_version")]
        version: u32,
        listen_port: u16,
        exceptions: Vec<String>,
        services: Vec<ServiceProxySnapshot>,
    },
}

impl HelperJournal {
    /// Validates every stored network identifier, route, DNS snapshot, and proxy configuration
    /// before saving or executing recovery commands.
    pub fn validate(&self) -> Result<(), HelperError> {
        match self {
            Self::Tun {
                version,
                utun_name,
                v4_gateway,
                v6_gateway,
                dns_snapshots,
                dns_resolver,
                server_ips,
                bypass_cidrs,
                routes,
            } => {
                if *version != JOURNAL_SCHEMA_VERSION {
                    return Err(HelperError::Journal(format!(
                        "unsupported journal version {version} (expected {JOURNAL_SCHEMA_VERSION})"
                    )));
                }
                validate_interface_name(utun_name)?;
                if let Some(gw4) = v4_gateway {
                    gw4.validate()?;
                }
                if let Some(gw6) = v6_gateway {
                    gw6.validate()?;
                }
                for snap in dns_snapshots {
                    snap.validate()?;
                }
                validate_server_ip(dns_resolver)?;
                if server_ips.is_empty() || server_ips.len() > MAX_SERVER_IPS {
                    return Err(HelperError::Journal(format!(
                        "journal server_ips count {} outside 1..={MAX_SERVER_IPS}",
                        server_ips.len()
                    )));
                }
                for ip in server_ips {
                    validate_server_ip(ip)?;
                }
                // Builtin + user bypass CIDRs
                if bypass_cidrs.len() > MAX_BYPASS_CIDRS + 16 {
                    return Err(HelperError::Journal(format!(
                        "journal bypass_cidrs count {} exceeds limit",
                        bypass_cidrs.len()
                    )));
                }
                for cidr in bypass_cidrs {
                    validate_cidr(cidr)?;
                }
                for route in routes {
                    route.validate()?;
                }
                Ok(())
            }
            Self::SystemProxy {
                version,
                listen_port,
                exceptions,
                services,
            } => {
                if *version != JOURNAL_SCHEMA_VERSION {
                    return Err(HelperError::Journal(format!(
                        "unsupported journal version {version} (expected {JOURNAL_SCHEMA_VERSION})"
                    )));
                }
                if *listen_port == 0 {
                    return Err(HelperError::Validation(
                        HelperValidationError::InvalidListenPort,
                    ));
                }
                if exceptions.len() > MAX_PROXY_EXCEPTIONS + 16 {
                    return Err(HelperError::Journal(format!(
                        "journal exceptions count {} exceeds limit",
                        exceptions.len()
                    )));
                }
                for exc in exceptions {
                    validate_exception_entry(exc)?;
                }
                for svc in services {
                    svc.validate()?;
                }
                Ok(())
            }
        }
    }
}

/// Validates and atomically writes `journal` to `path` with mode `0600` (`write_atomic_0600`).
pub fn save_journal(path: &Path, journal: &HelperJournal) -> Result<(), HelperError> {
    journal.validate()?;
    let mut bytes = serde_json::to_vec_pretty(journal)?;
    bytes.push(b'\n');
    write_atomic_0600(path, &bytes)?;
    Ok(())
}

/// Loads and validates `helper-state.json` from `path`, returning `Ok(None)` if the file does not
/// exist. Rejects symlinks, group/world-accessible permissions, and (when running as `root` on
/// macOS) non-root file ownership.
pub fn load_journal(path: &Path) -> Result<Option<HelperJournal>, HelperError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(HelperError::Io(err)),
    };

    if meta.file_type().is_symlink() {
        return Err(HelperError::Journal(format!(
            "refusing to read symlinked journal file {}",
            path.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(HelperError::Journal(format!(
            "journal path {} is not a regular file",
            path.display()
        )));
    }

    let mode = meta.permissions().mode();
    if (mode & 0o077) != 0 {
        return Err(HelperError::Journal(format!(
            "refusing to read journal file {} with insecure permissions {:04o}; group/other bits must be 0",
            path.display(),
            mode & 0o777
        )));
    }

    #[cfg(target_os = "macos")]
    {
        // SAFETY: `libc::geteuid()` has no preconditions and is always thread-safe.
        if unsafe { libc::geteuid() } == 0 {
            let file_uid = std::os::unix::fs::MetadataExt::uid(&meta);
            if file_uid != 0 {
                return Err(HelperError::Journal(format!(
                    "refusing to read journal file {} not owned by root (found uid {file_uid})",
                    path.display()
                )));
            }
        }
    }

    let bytes = fs::read(path)?;
    let journal: HelperJournal = serde_json::from_slice(&bytes)?;
    journal.validate()?;
    Ok(Some(journal))
}

/// Removes `helper-state.json` if present and best-effort `fsync`s the parent directory.
pub fn delete_journal(path: &Path) -> Result<(), HelperError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(HelperError::Io(err)),
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Restores all OS networking state recorded in `journal` without short-circuiting on individual
/// item failures so every route, DNS key, and network service gets a restore attempt.
pub fn restore_from_journal<B: SystemBackend>(
    backend: &B,
    journal: &HelperJournal,
) -> Result<(), HelperError> {
    journal.validate()?;
    let mut first_err: Option<HelperError> = None;

    match journal {
        HelperJournal::Tun {
            dns_snapshots,
            routes,
            ..
        } => {
            // 1. Restore ephemeral dynamic-store DNS entries first.
            for dns_snap in dns_snapshots {
                if let Err(err) = backend.restore_dns_override(dns_snap) {
                    log::warn!(
                        "failed to restore DNS override for service {}: {err}",
                        dns_snap.service_id
                    );
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }

            // 2. Delete routes in reverse installation order (removing `/1` tunnel capture routes
            //    before physical gateway bypass/server routes).
            for route in routes.iter().rev() {
                if let Err(err) = backend.delete_route(route) {
                    log::warn!("failed to delete route {route:?}: {err}");
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        HelperJournal::SystemProxy { services, .. } => {
            for snap in services {
                if let Err(err) = backend.restore_service_proxies(snap) {
                    log::warn!(
                        "failed to restore proxy settings on service {:?}: {err}",
                        snap.service
                    );
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
    }

    if let Some(err) = first_err {
        return Err(err);
    }
    Ok(())
}

/// Checks `state_path` at startup or `--recover-only`; if a leftover `helper-state.json` exists,
/// restores all recorded settings and deletes the journal file.
///
/// Returns `Ok(true)` if a leftover journal was found and recovered, or `Ok(false)` if no journal
/// file existed.
pub fn recover_if_present<B: SystemBackend>(
    backend: &B,
    state_path: &Path,
) -> Result<bool, HelperError> {
    let Some(journal) = load_journal(state_path)? else {
        return Ok(false);
    };

    log::info!(
        "found leftover helper journal at {}; restoring system network state",
        state_path.display()
    );

    if let Err(err) = restore_from_journal(backend, &journal) {
        log::warn!(
            "completed journal recovery with non-fatal error ({err}); removing journal {}",
            state_path.display()
        );
    }

    delete_journal(state_path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn load_journal_accepts_0600_and_rejects_symlinks_and_loose_permissions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let journal_path = tmp.path().join("helper-state.json");
        let journal = HelperJournal::SystemProxy {
            version: JOURNAL_SCHEMA_VERSION,
            listen_port: 2080,
            exceptions: vec!["*.local".to_string()],
            services: Vec::new(),
        };

        // Missing journal returns Ok(None)
        assert_eq!(load_journal(&journal_path).unwrap(), None);

        // Atomic 0600 journal loads cleanly
        save_journal(&journal_path, &journal).unwrap();
        assert_eq!(load_journal(&journal_path).unwrap(), Some(journal.clone()));

        // Symlinked journal path must be rejected
        let link_path = tmp.path().join("symlink-state.json");
        symlink(&journal_path, &link_path).unwrap();
        assert!(matches!(
            load_journal(&link_path),
            Err(HelperError::Journal(_))
        ));

        // Group/world-accessible permissions (0644 and 0640) must be rejected
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_journal(&journal_path),
            Err(HelperError::Journal(_))
        ));
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            load_journal(&journal_path),
            Err(HelperError::Journal(_))
        ));

        // Restoring 0600 allows loading again
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_journal(&journal_path).unwrap(), Some(journal));
    }
}
