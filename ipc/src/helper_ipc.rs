//! Fixed-command IPC protocol and input validators between `vless-engine` and `vless-tray-helper`.
//!
//! `vless-tray-helper` runs as `root` via `launchd` socket activation (`PLAN.md` §4). It never
//! parses network traffic and accepts ONLY the five strongly-typed [`HelperCommand`] variants,
//! validating every field before invoking system networking APIs or binaries.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::store::validate_and_normalize_domain_pattern;

/// Default Unix domain socket path managed by `launchd` for `vless-tray-helper`.
pub const DEFAULT_HELPER_SOCKET_PATH: &str = "/var/run/vless-tray.sock";

/// Root-owned application support directory used by `vless-tray-helper`.
pub const DEFAULT_HELPER_SUPPORT_DIR: &str = "/Library/Application Support/vless-tray";

/// Root-owned (`0600`) state journal written before mutating system routes/DNS/proxies.
pub const DEFAULT_HELPER_STATE_PATH: &str =
    "/Library/Application Support/vless-tray/helper-state.json";

/// Root-owned file recording the UID of the authorized console user who installed the helper.
pub const DEFAULT_HELPER_OWNER_UID_PATH: &str = "/Library/Application Support/vless-tray/owner-uid";

/// Maximum frame payload size (64 KiB) over the Engine <-> Helper Unix domain socket.
pub const MAX_HELPER_FRAME_BYTES: usize = 64 * 1024;

/// Maximum number of resolved server IP addresses accepted in `StartTun` / `UpdateServerRoute`.
pub const MAX_SERVER_IPS: usize = 32;

/// Maximum number of bypass CIDR blocks accepted in `StartTun`.
pub const MAX_BYPASS_CIDRS: usize = 512;

/// Maximum number of proxy exception strings accepted in `StartSystemProxy`.
pub const MAX_PROXY_EXCEPTIONS: usize = 512;

/// Fixed command set accepted by `vless-tray-helper` (`PLAN.md` §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperCommand {
    /// Create a `utun` interface, configure routes + DNS override, and return the `utun` fd via
    /// `SCM_RIGHTS`.
    StartTun {
        server_ips: Vec<IpAddr>,
        bypass_cidrs: Vec<IpNetwork>,
        dns_resolver: IpAddr,
    },
    /// Configure HTTP, HTTPS, and SOCKS5 system proxies (`127.0.0.1:<listen_port>`) across enabled
    /// macOS network services.
    StartSystemProxy {
        listen_port: u16,
        exceptions: Vec<String>,
    },
    /// Re-point server host routes after server DNS re-resolution or network change.
    UpdateServerRoute { server_ips: Vec<IpAddr> },
    /// Tear down active TUN/proxy configuration and restore original system state from journal.
    Stop,
    /// Query current helper mode and physical interface metadata.
    Status,
}

/// Active mode reported by `vless-tray-helper`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperMode {
    #[default]
    Idle,
    Tun,
    SystemProxy,
}

/// Current status snapshot returned by [`HelperResponse::Status`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperStatus {
    pub mode: HelperMode,
    pub utun_name: Option<String>,
    pub outbound_if_index: Option<u32>,
    pub outbound_if_name: Option<String>,
    pub original_dns_servers: Vec<IpAddr>,
}

/// Synchronous command replies sent by `vless-tray-helper` to `vless-engine`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperResponse {
    /// Sent together with the newly created `utun` file descriptor over `SCM_RIGHTS`.
    TunReady {
        utun_name: String,
        outbound_if_index: u32,
        outbound_if_name: String,
        original_dns_servers: Vec<IpAddr>,
    },
    /// System proxy settings applied to the listed network services.
    SystemProxyReady { services: Vec<String> },
    /// Host routes to the VLESS server updated on the physical gateway.
    ServerRouteUpdated {
        outbound_if_index: u32,
        outbound_if_name: String,
        original_dns_servers: Vec<IpAddr>,
    },
    /// Active session torn down and system settings restored.
    Stopped,
    /// Current helper status snapshot.
    Status(HelperStatus),
    /// Command rejected or execution failed.
    Error { message: String },
}

/// Envelope for all Helper -> Engine frames over the session Unix socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum HelperMessage {
    /// Direct reply to a [`HelperCommand`].
    Response(HelperResponse),
    /// Asynchronous push notification emitted when `PF_ROUTE` detects a physical gateway or
    /// interface transition (`PLAN.md` §5.5).
    NetworkChanged {
        outbound_if_index: u32,
        outbound_if_name: String,
        original_dns_servers: Vec<IpAddr>,
    },
}

/// Validation errors for [`HelperCommand`] fields and OS network identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HelperValidationError {
    #[error("server_ips must not be empty")]
    EmptyServerIps,

    #[error("too many server_ips ({count}, max {MAX_SERVER_IPS})")]
    TooManyServerIps { count: usize },

    #[error("invalid server or DNS IP {0}: must not be unspecified, multicast, or broadcast")]
    InvalidServerIp(IpAddr),

    #[error("too many bypass_cidrs ({count}, max {MAX_BYPASS_CIDRS})")]
    TooManyBypassCidrs { count: usize },

    #[error("invalid CIDR {cidr}: {reason}")]
    InvalidCidr {
        cidr: IpNetwork,
        reason: &'static str,
    },

    #[error("listen_port must be between 1 and 65535")]
    InvalidListenPort,

    #[error("too many proxy exceptions ({count}, max {MAX_PROXY_EXCEPTIONS})")]
    TooManyExceptions { count: usize },

    #[error("invalid proxy exception entry {entry:?}: {reason}")]
    InvalidExceptionEntry { entry: String, reason: String },

    #[error("invalid interface name {0:?}: expected ASCII ^([a-z]{{2,12}}|pdp_ip)[0-9]{{1,4}}$")]
    InvalidInterfaceName(String),

    #[error(
        "invalid network service name {0:?}: expected 1..=128 printable UTF-8 chars without control chars"
    )]
    InvalidServiceName(String),
}

impl HelperCommand {
    /// Strictly validates every parameter of this command before execution in the root helper.
    pub fn validate(&self) -> Result<(), HelperValidationError> {
        match self {
            Self::StartTun {
                server_ips,
                bypass_cidrs,
                dns_resolver,
            } => {
                validate_server_ip_list(server_ips)?;
                if bypass_cidrs.len() > MAX_BYPASS_CIDRS {
                    return Err(HelperValidationError::TooManyBypassCidrs {
                        count: bypass_cidrs.len(),
                    });
                }
                for cidr in bypass_cidrs {
                    validate_cidr(cidr)?;
                }
                validate_server_ip(dns_resolver)?;
                Ok(())
            }
            Self::StartSystemProxy {
                listen_port,
                exceptions,
            } => {
                if *listen_port == 0 {
                    return Err(HelperValidationError::InvalidListenPort);
                }
                if exceptions.len() > MAX_PROXY_EXCEPTIONS {
                    return Err(HelperValidationError::TooManyExceptions {
                        count: exceptions.len(),
                    });
                }
                for entry in exceptions {
                    validate_exception_entry(entry)?;
                }
                Ok(())
            }
            Self::UpdateServerRoute { server_ips } => validate_server_ip_list(server_ips),
            Self::Stop | Self::Status => Ok(()),
        }
    }
}

/// Validates a server or DNS resolver IP address (rejects unspecified `0.0.0.0`/`::`, multicast,
/// and IPv4 limited broadcast `255.255.255.255`).
pub fn validate_server_ip(ip: &IpAddr) -> Result<(), HelperValidationError> {
    let valid = match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    };
    if !valid {
        return Err(HelperValidationError::InvalidServerIp(*ip));
    }
    Ok(())
}

fn validate_server_ip_list(server_ips: &[IpAddr]) -> Result<(), HelperValidationError> {
    if server_ips.is_empty() {
        return Err(HelperValidationError::EmptyServerIps);
    }
    if server_ips.len() > MAX_SERVER_IPS {
        return Err(HelperValidationError::TooManyServerIps {
            count: server_ips.len(),
        });
    }
    for ip in server_ips {
        validate_server_ip(ip)?;
    }
    Ok(())
}

/// Validates a BSD/macOS network interface identifier against
/// `^([a-z]{2,12}|pdp_ip)[0-9]{1,4}$` (max 16 ASCII bytes, e.g. `en0`, `utun4`, `bridge0`,
/// `pdp_ip0`).
pub fn validate_interface_name(name: &str) -> Result<(), HelperValidationError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 16 || !name.is_ascii() {
        return Err(HelperValidationError::InvalidInterfaceName(
            name.to_string(),
        ));
    }

    let digits = if let Some(rest) = bytes.strip_prefix(b"pdp_ip") {
        rest
    } else {
        let alpha_len = bytes.iter().take_while(|b| b.is_ascii_lowercase()).count();
        if !(2..=12).contains(&alpha_len) {
            return Err(HelperValidationError::InvalidInterfaceName(
                name.to_string(),
            ));
        }
        &bytes[alpha_len..]
    };

    if !(1..=4).contains(&digits.len()) || !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(HelperValidationError::InvalidInterfaceName(
            name.to_string(),
        ));
    }

    Ok(())
}

/// Validates a macOS network service name (`networksetup` / `SystemConfiguration`):
/// `1..=128` Unicode scalar values, printable UTF-8, no NUL or control characters (`\0`, `\r`, `\n`,
/// etc.), and must not start with `'-'` (to prevent CLI flag injection into `networksetup`).
pub fn validate_service_name(name: &str) -> Result<(), HelperValidationError> {
    let count = name.chars().count();
    if !(1..=128).contains(&count)
        || name.trim().is_empty()
        || name.starts_with('-')
        || name.chars().any(char::is_control)
    {
        return Err(HelperValidationError::InvalidServiceName(name.to_string()));
    }
    Ok(())
}

/// Validates a bypass CIDR block (`prefix >= 2` and non-unspecified network address).
pub fn validate_cidr(cidr: &IpNetwork) -> Result<(), HelperValidationError> {
    if cidr.prefix() < 2 {
        return Err(HelperValidationError::InvalidCidr {
            cidr: *cidr,
            reason: "prefix length must be >= 2",
        });
    }
    if cidr.network().is_unspecified() {
        return Err(HelperValidationError::InvalidCidr {
            cidr: *cidr,
            reason: "network address must not be unspecified",
        });
    }
    Ok(())
}

/// Validates a macOS system proxy exception entry (CIDR, IP literal, `*.local`, or domain pattern
/// without whitespace or control characters).
pub fn validate_exception_entry(entry: &str) -> Result<(), HelperValidationError> {
    if entry.is_empty() || entry.len() > 253 {
        return Err(HelperValidationError::InvalidExceptionEntry {
            entry: entry.to_string(),
            reason: "entry must be 1..=253 characters".to_string(),
        });
    }
    if entry.starts_with('-') || entry.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(HelperValidationError::InvalidExceptionEntry {
            entry: entry.to_string(),
            reason: "entry must not start with '-' or contain whitespace/control characters"
                .to_string(),
        });
    }

    if entry.contains('/') {
        let net = entry.parse::<IpNetwork>().map_err(|err| {
            HelperValidationError::InvalidExceptionEntry {
                entry: entry.to_string(),
                reason: err.to_string(),
            }
        })?;
        return validate_cidr(&net).map_err(|err| HelperValidationError::InvalidExceptionEntry {
            entry: entry.to_string(),
            reason: err.to_string(),
        });
    }

    if let Ok(ip) = entry.parse::<IpAddr>() {
        if ip.is_unspecified() {
            return Err(HelperValidationError::InvalidExceptionEntry {
                entry: entry.to_string(),
                reason: "unspecified IP address is not allowed".to_string(),
            });
        }
        return Ok(());
    }

    validate_and_normalize_domain_pattern(entry)
        .map(|_| ())
        .map_err(|err| HelperValidationError::InvalidExceptionEntry {
            entry: entry.to_string(),
            reason: err.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{BUILTIN_SYSTEM_PROXY_EXCEPTIONS, builtin_tun_bypass_cidrs};

    #[test]
    fn helper_command_validation_accepts_valid_and_rejects_malformed_inputs() {
        let valid_tun = HelperCommand::StartTun {
            server_ips: vec![
                "203.0.113.10".parse().unwrap(),
                "2001:db8::5".parse().unwrap(),
            ],
            bypass_cidrs: builtin_tun_bypass_cidrs(),
            dns_resolver: "1.1.1.1".parse().unwrap(),
        };
        assert!(valid_tun.validate().is_ok());

        let valid_proxy = HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: BUILTIN_SYSTEM_PROXY_EXCEPTIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        };
        assert!(valid_proxy.validate().is_ok());
        assert!(HelperCommand::Stop.validate().is_ok());
        assert!(HelperCommand::Status.validate().is_ok());

        // Empty server_ips
        assert_eq!(
            HelperCommand::StartTun {
                server_ips: vec![],
                bypass_cidrs: vec![],
                dns_resolver: "1.1.1.1".parse().unwrap(),
            }
            .validate(),
            Err(HelperValidationError::EmptyServerIps)
        );

        // Unspecified or multicast server IP / DNS resolver
        assert!(
            HelperCommand::UpdateServerRoute {
                server_ips: vec!["0.0.0.0".parse().unwrap()],
            }
            .validate()
            .is_err()
        );
        assert!(
            HelperCommand::UpdateServerRoute {
                server_ips: vec!["224.0.0.1".parse().unwrap()],
            }
            .validate()
            .is_err()
        );
        assert!(
            HelperCommand::StartTun {
                server_ips: vec!["1.2.3.4".parse().unwrap()],
                bypass_cidrs: vec![],
                dns_resolver: "::".parse().unwrap(),
            }
            .validate()
            .is_err()
        );

        // Port 0 & bad exception entry
        assert_eq!(
            HelperCommand::StartSystemProxy {
                listen_port: 0,
                exceptions: vec![],
            }
            .validate(),
            Err(HelperValidationError::InvalidListenPort)
        );
        assert!(
            HelperCommand::StartSystemProxy {
                listen_port: 2080,
                exceptions: vec!["bad\nentry.com".to_string()],
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn standalone_validators_reject_injection_and_malformed_values() {
        for ok_if in [
            "en0",
            "en12",
            "utun0",
            "utun4",
            "utun9999",
            "bridge0",
            "lo0",
            "pdp_ip0",
            "pdp_ip1",
            "pdp_ip9999",
        ] {
            assert!(
                validate_interface_name(ok_if).is_ok(),
                "expected {ok_if:?} to be valid"
            );
        }
        for bad_if in [
            "",
            "e0",
            "en",
            "en01234",
            "utun4;rm -rf /",
            "utun4/1",
            "EN0",
            "eth_0",
            "pdp_ip",
            "pdp_ip01234",
            "pdp_ip_0",
            "PDP_IP0",
            "utun 0",
            "abcdefghijklm0",
        ] {
            assert!(
                validate_interface_name(bad_if).is_err(),
                "expected {bad_if:?} to be rejected"
            );
        }

        for ok_svc in [
            "Wi-Fi",
            "USB 10/100/1000 LAN",
            "Thunderbolt Bridge",
            "iPhone USB",
        ] {
            assert!(validate_service_name(ok_svc).is_ok());
        }
        for bad_svc in [
            "",
            "   ",
            "-setwebproxy",
            "Wi-Fi\0injected",
            "Wi-Fi\ninjected",
            "Wi-Fi\rinjected",
            &"a".repeat(129),
        ] {
            assert!(
                validate_service_name(bad_svc).is_err(),
                "expected {bad_svc:?} to be rejected"
            );
        }
    }

    #[test]
    fn helper_messages_and_unknown_field_rejection_roundtrip() {
        // Unknown commands and unknown fields on struct commands must be rejected
        let rogue_cmd = r#"{"command":"exec_shell","cmd":"id"}"#;
        assert!(serde_json::from_str::<HelperCommand>(rogue_cmd).is_err());
        let rogue_fields =
            r#"{"command":"start_system_proxy","listen_port":2080,"exceptions":[],"extra":1}"#;
        assert!(serde_json::from_str::<HelperCommand>(rogue_fields).is_err());

        let messages = vec![
            HelperMessage::Response(HelperResponse::TunReady {
                utun_name: "utun7".to_string(),
                outbound_if_index: 6,
                outbound_if_name: "en0".to_string(),
                original_dns_servers: vec!["192.168.1.1".parse().unwrap()],
            }),
            HelperMessage::Response(HelperResponse::SystemProxyReady {
                services: vec!["Wi-Fi".to_string()],
            }),
            HelperMessage::Response(HelperResponse::ServerRouteUpdated {
                outbound_if_index: 11,
                outbound_if_name: "en1".to_string(),
                original_dns_servers: vec!["8.8.8.8".parse().unwrap()],
            }),
            HelperMessage::Response(HelperResponse::Stopped),
            HelperMessage::Response(HelperResponse::Status(HelperStatus {
                mode: HelperMode::Tun,
                utun_name: Some("utun7".to_string()),
                outbound_if_index: Some(6),
                outbound_if_name: Some("en0".to_string()),
                original_dns_servers: vec!["192.168.1.1".parse().unwrap()],
            })),
            HelperMessage::Response(HelperResponse::Error {
                message: "permission denied".to_string(),
            }),
            HelperMessage::NetworkChanged {
                outbound_if_index: 12,
                outbound_if_name: "en2".to_string(),
                original_dns_servers: vec!["10.0.0.1".parse().unwrap()],
            },
        ];

        for msg in &messages {
            let encoded = serde_json::to_vec(msg).expect("encode HelperMessage");
            let decoded: HelperMessage = serde_json::from_slice(&encoded).expect("decode");
            assert_eq!(&decoded, msg);
        }
    }
}
