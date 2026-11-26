//! Caller UID authentication (`getpeereid` / `SO_PEERCRED` against root-owned `owner-uid` file,
//! `PLAN.md` §4).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tokio::net::UnixStream as TokioUnixStream;
use vless_ipc::tokio_peer_uid;

use crate::error::HelperError;

/// Maximum valid macOS console user UID (excludes `(uid_t)-2` = `nobody` and `(uid_t)-1`).
pub const MAX_VALID_OWNER_UID: u32 = 4_294_967_293;

/// Policy used by `vless-tray-helper` to determine the single authorized peer UID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerUidPolicy {
    /// Read the authorized non-zero UID from `path` (default `/Library/Application Support/vless-tray/owner-uid`).
    OwnerFile {
        path: PathBuf,
        /// When `true` (production default on macOS), requires `st_uid == 0` and
        /// `(st_mode & 0o077) == 0`.
        enforce_root_owner_file: bool,
    },
    /// Fixed UID configured explicitly via `--owner-uid <uid>` for standalone/integration testing.
    FixedUid(u32),
}

impl OwnerUidPolicy {
    /// Resolves the currently authorized caller UID according to this policy.
    pub fn resolve_expected_uid(&self) -> Result<u32, HelperError> {
        match self {
            Self::OwnerFile {
                path,
                enforce_root_owner_file,
            } => read_owner_uid_file(path, *enforce_root_owner_file),
            Self::FixedUid(uid) => Ok(*uid),
        }
    }

    /// Authenticates an accepted Unix domain stream connection before reading any bytes.
    pub fn authenticate_stream(&self, stream: &TokioUnixStream) -> Result<u32, HelperError> {
        let expected_uid = self.resolve_expected_uid()?;
        let caller_uid = tokio_peer_uid(stream)?;
        if caller_uid != expected_uid {
            return Err(HelperError::Unauthorized(format!(
                "peer UID {caller_uid} does not match authorized owner UID {expected_uid}"
            )));
        }
        Ok(caller_uid)
    }
}

/// Reads, validates ownership/permissions, and parses a non-zero `u32` UID from `owner-uid`.
pub fn read_owner_uid_file(path: &Path, enforce_root_owner_file: bool) -> Result<u32, HelperError> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        HelperError::OwnerUidConfig(format!("cannot stat {}: {err}", path.display()))
    })?;

    validate_owner_file_metadata(
        path,
        meta.uid(),
        meta.mode(),
        meta.file_type().is_file(),
        meta.file_type().is_symlink(),
        enforce_root_owner_file,
    )?;

    let raw = fs::read_to_string(path).map_err(|err| {
        HelperError::OwnerUidConfig(format!("cannot read {}: {err}", path.display()))
    })?;

    parse_owner_uid_contents(&raw)
}

/// Validates file type, owner UID (`0` = root), and mode (`0o077` mask clear) on `owner-uid`.
pub fn validate_owner_file_metadata(
    path: &Path,
    file_uid: u32,
    file_mode: u32,
    is_regular_file: bool,
    is_symlink: bool,
    enforce_root_owner_file: bool,
) -> Result<(), HelperError> {
    if is_symlink {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid path {} must not be a symlink",
            path.display()
        )));
    }
    if !is_regular_file {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid path {} must be a regular file",
            path.display()
        )));
    }
    if (file_mode & 0o077) != 0 {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid file {} has insecure permissions {:04o}; group/other bits must be 0",
            path.display(),
            file_mode & 0o777
        )));
    }
    if enforce_root_owner_file && file_uid != 0 {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid file {} must be owned by root (uid 0), found uid {file_uid}",
            path.display()
        )));
    }
    Ok(())
}

/// Parses and validates a strict base-10 non-zero `u32` UID from `owner-uid` text.
pub fn parse_owner_uid_contents(raw: &str) -> Result<u32, HelperError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(HelperError::OwnerUidConfig(
            "owner-uid file is empty".into(),
        ));
    }
    if !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid {trimmed:?} must contain only ASCII base-10 digits"
        )));
    }
    if trimmed.len() > 1 && trimmed.starts_with('0') {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid {trimmed:?} must not have leading zeros"
        )));
    }

    let uid: u32 = trimmed
        .parse()
        .map_err(|_| HelperError::OwnerUidConfig(format!("owner-uid {trimmed:?} overflows u32")))?;
    if uid == 0 || uid > MAX_VALID_OWNER_UID {
        return Err(HelperError::OwnerUidConfig(format!(
            "owner-uid {uid} must be between 1 and {MAX_VALID_OWNER_UID}"
        )));
    }
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn owner_uid_metadata_and_parsing_enforce_root_and_0600_rules() {
        let p = Path::new("/Library/Application Support/vless-tray/owner-uid");

        // Valid root-owned 0600 regular file
        assert!(validate_owner_file_metadata(p, 0, 0o100600, true, false, true).is_ok());

        // Reject non-root when enforce_root_owner_file = true
        assert!(validate_owner_file_metadata(p, 501, 0o100600, true, false, true).is_err());

        // Allow current user when enforce_root_owner_file = false, provided mode is 0600
        assert!(validate_owner_file_metadata(p, 501, 0o100600, true, false, false).is_ok());

        // Reject group/world readable or writable (0644 / 0660)
        assert!(validate_owner_file_metadata(p, 0, 0o100644, true, false, true).is_err());
        assert!(validate_owner_file_metadata(p, 0, 0o100660, true, false, false).is_err());

        // Reject symlinks
        assert!(validate_owner_file_metadata(p, 0, 0o120600, false, true, true).is_err());

        // Valid non-zero UIDs
        assert_eq!(parse_owner_uid_contents("501\n").unwrap(), 501);
        assert_eq!(parse_owner_uid_contents("1000").unwrap(), 1000);

        // Reject 0, leading zeros, nobody/max, negative, non-numeric
        for bad in [
            "",
            "0",
            "0501",
            "-1",
            "501 extra",
            "4294967294",
            "4294967295",
        ] {
            assert!(
                parse_owner_uid_contents(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }

        // File round-trip test with atomic 0600 write
        let tmp = tempfile::tempdir().unwrap();
        let uid_file = tmp.path().join("owner-uid");
        vless_ipc::write_atomic_0600(&uid_file, b"501\n").unwrap();
        assert_eq!(read_owner_uid_file(&uid_file, false).unwrap(), 501);

        // Loosening permissions to 0644 must fail even with enforce_root_owner_file = false
        fs::set_permissions(&uid_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owner_uid_file(&uid_file, false).is_err());
    }
}
