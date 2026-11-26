//! Privileged root helper library (`vless-tray-helper`) for `utun` interface creation, routing,
//! ephemeral `SCDynamicStore` DNS overrides, `networksetup` system proxy management, `PF_ROUTE`
//! change tracking, and `helper-state.json` crash recovery (`PLAN.md` §4, §5.1–§5.5).

pub mod auth;
pub mod backend;
pub mod daemon;
pub mod error;
pub mod journal;
pub mod launchd;
#[cfg(target_os = "macos")]
pub mod macos_backend;
pub mod mock_backend;
pub mod parsers;
pub mod state_machine;

use std::path::PathBuf;

use vless_ipc::{DEFAULT_HELPER_OWNER_UID_PATH, DEFAULT_HELPER_STATE_PATH};

pub use auth::{MAX_VALID_OWNER_UID, OwnerUidPolicy};
pub use backend::{
    DefaultGatewayV4, DefaultGatewayV6, DnsSnapshot, NetworkSnapshot, ProxyEndpointConfig,
    RouteAddResult, RouteDestination, RouteSpec, RouteTarget, ServiceProxySnapshot, SystemBackend,
    TUN_CAPTURE_CIDR_STRS, UTUN_IPV4_ADDR, UTUN_IPV4_NETMASK, UTUN_IPV4_PEER, UTUN_IPV4_SUBNET_STR,
    UTUN_IPV6_ADDR, UTUN_IPV6_PREFIXLEN, UTUN_MTU, UtunConfig,
};
pub use daemon::{
    DEFAULT_LAUNCHD_IDLE_TIMEOUT, DaemonLifecycle, HelperConfig, run_daemon_entrypoint,
    run_recover_only, serve_activated_listener_fd, serve_bound_socket_path, serve_tokio_listener,
};
pub use error::HelperError;
pub use journal::{
    HelperJournal, JOURNAL_SCHEMA_VERSION, delete_journal, load_journal, recover_if_present,
    restore_from_journal, save_journal,
};
#[cfg(target_os = "macos")]
pub use macos_backend::MacosSystemBackend;
pub use mock_backend::{
    MockFailPoint, MockNetworkService, MockOperation, MockServiceDnsState, MockSystemBackend,
    MockUtunDevice, encode_mock_dns_xml,
};
pub use state_machine::{CommandOutcome, HelperStateMachine};

/// Parsed command-line arguments for the `vless-tray-helper` binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliAction {
    /// Print `--help` text and exit `0`.
    Help,
    /// Print `--version` text and exit `0`.
    Version,
    /// Restore and delete `helper-state.json` if present, then exit `0`.
    RecoverOnly { state_path: PathBuf },
    /// Run the helper daemon (`launchd` socket activation by default, or standalone `--socket`).
    RunDaemon {
        socket_path: Option<PathBuf>,
        config: HelperConfig,
    },
}

/// Usage banner printed for `vless-tray-helper --help`.
pub const CLI_USAGE: &str = "\
Usage: vless-tray-helper [OPTIONS]

Privileged launchd socket-activated helper daemon for VLESS Tray.

Options:
  --recover-only            Restore leftover helper-state.json if present, delete it, and exit 0
  --socket <path>           Bind and listen on an explicit Unix socket path (standalone/test mode)
  --state-path <path>       Override path to helper-state.json
                            (default: /Library/Application Support/vless-tray/helper-state.json)
  --owner-uid <uid>         Explicitly authorize a numeric peer UID instead of reading owner-uid
  --owner-uid-file <path>   Override path to root-owned owner-uid file
                            (default: /Library/Application Support/vless-tray/owner-uid)
  -h, --help                Print this help message and exit
  -V, --version             Print version and exit
";

/// Strictly parses command-line arguments (excluding `argv[0]`).
pub fn parse_cli_args<I, S>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut recover_only = false;
    let mut socket_path: Option<PathBuf> = None;
    let mut state_path = PathBuf::from(DEFAULT_HELPER_STATE_PATH);
    let mut owner_uid: Option<u32> = None;
    let mut owner_uid_file = PathBuf::from(DEFAULT_HELPER_OWNER_UID_PATH);

    let vec_args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut idx = 0;

    while idx < vec_args.len() {
        let arg = &vec_args[idx];
        match arg.as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "-V" | "--version" => return Ok(CliAction::Version),
            "--recover-only" => {
                recover_only = true;
                idx += 1;
            }
            "--socket" => {
                idx += 1;
                let val = vec_args
                    .get(idx)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "--socket requires a non-empty path argument".to_string())?;
                socket_path = Some(PathBuf::from(val));
                idx += 1;
            }
            _ if arg.starts_with("--socket=") => {
                let val = &arg["--socket=".len()..];
                if val.is_empty() {
                    return Err("--socket requires a non-empty path argument".to_string());
                }
                socket_path = Some(PathBuf::from(val));
                idx += 1;
            }
            "--state-path" => {
                idx += 1;
                let val = vec_args
                    .get(idx)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "--state-path requires a non-empty path argument".to_string())?;
                state_path = PathBuf::from(val);
                idx += 1;
            }
            _ if arg.starts_with("--state-path=") => {
                let val = &arg["--state-path=".len()..];
                if val.is_empty() {
                    return Err("--state-path requires a non-empty path argument".to_string());
                }
                state_path = PathBuf::from(val);
                idx += 1;
            }
            "--owner-uid" => {
                idx += 1;
                let val = vec_args
                    .get(idx)
                    .ok_or_else(|| "--owner-uid requires a numeric UID argument".to_string())?;
                let parsed: u32 = val
                    .parse()
                    .map_err(|_| format!("invalid --owner-uid {val:?}: expected u32"))?;
                owner_uid = Some(parsed);
                idx += 1;
            }
            _ if arg.starts_with("--owner-uid=") => {
                let val = &arg["--owner-uid=".len()..];
                let parsed: u32 = val
                    .parse()
                    .map_err(|_| format!("invalid --owner-uid {val:?}: expected u32"))?;
                owner_uid = Some(parsed);
                idx += 1;
            }
            "--owner-uid-file" => {
                idx += 1;
                let val = vec_args.get(idx).filter(|s| !s.is_empty()).ok_or_else(|| {
                    "--owner-uid-file requires a non-empty path argument".to_string()
                })?;
                owner_uid_file = PathBuf::from(val);
                idx += 1;
            }
            _ if arg.starts_with("--owner-uid-file=") => {
                let val = &arg["--owner-uid-file=".len()..];
                if val.is_empty() {
                    return Err("--owner-uid-file requires a non-empty path argument".to_string());
                }
                owner_uid_file = PathBuf::from(val);
                idx += 1;
            }
            unknown => {
                return Err(format!(
                    "unknown argument {unknown:?} (pass --help for usage)"
                ));
            }
        }
    }

    if recover_only {
        return Ok(CliAction::RecoverOnly { state_path });
    }

    let owner_uid_policy = match owner_uid {
        Some(uid) => OwnerUidPolicy::FixedUid(uid),
        None => OwnerUidPolicy::OwnerFile {
            path: owner_uid_file,
            enforce_root_owner_file: cfg!(target_os = "macos"),
        },
    };

    let lifecycle = if socket_path.is_some() {
        DaemonLifecycle::StandaloneSocket
    } else {
        DaemonLifecycle::LaunchdSocketActivated {
            idle_grace_timeout: DEFAULT_LAUNCHD_IDLE_TIMEOUT,
        }
    };

    Ok(CliAction::RunDaemon {
        socket_path,
        config: HelperConfig {
            state_path,
            owner_uid_policy,
            lifecycle,
        },
    })
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn cli_parser_handles_default_recover_only_and_standalone_flags() {
        let default_action = parse_cli_args(std::iter::empty::<&str>()).unwrap();
        match default_action {
            CliAction::RunDaemon {
                socket_path,
                config,
            } => {
                assert!(socket_path.is_none());
                assert_eq!(config.state_path, PathBuf::from(DEFAULT_HELPER_STATE_PATH));
                assert!(matches!(
                    config.lifecycle,
                    DaemonLifecycle::LaunchdSocketActivated { .. }
                ));
            }
            other => panic!("unexpected default action: {other:?}"),
        }

        let recover = parse_cli_args(["--recover-only", "--state-path=/tmp/custom-state.json"])
            .expect("parse recover-only");
        assert_eq!(
            recover,
            CliAction::RecoverOnly {
                state_path: PathBuf::from("/tmp/custom-state.json"),
            }
        );

        let standalone = parse_cli_args([
            "--socket",
            "/tmp/helper.sock",
            "--state-path",
            "/tmp/state.json",
            "--owner-uid",
            "501",
        ])
        .expect("parse standalone");
        assert_eq!(
            standalone,
            CliAction::RunDaemon {
                socket_path: Some(PathBuf::from("/tmp/helper.sock")),
                config: HelperConfig {
                    state_path: PathBuf::from("/tmp/state.json"),
                    owner_uid_policy: OwnerUidPolicy::FixedUid(501),
                    lifecycle: DaemonLifecycle::StandaloneSocket,
                },
            }
        );

        assert!(parse_cli_args(["--bogus"]).is_err());
        assert!(parse_cli_args(["--owner-uid", "notanumber"]).is_err());
    }
}
