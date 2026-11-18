//! Typed `EngineConfig` and minimal internal transport/limit types (`PLAN.md` §6).
//!
//! Replaces `shoes`'s multi-file YAML config hierarchy with a compact, strongly-typed Rust model
//! built directly from [`vless_ipc::Profile`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use vless_ipc::{
    DEFAULT_DNS_RESOLVER, Profile, ProfileError, ProfileSecurity, format_sha256_pin_hex,
};

use crate::address::{Address, NetLocation};
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::reality::CipherSuite;

pub mod tun {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(default, deny_unknown_fields)]
    pub struct TunResourceLimits {
        pub tcp_buffer_size: usize,
        pub tcp_memory_bytes: Option<usize>,
        pub max_tcp_connections: Option<usize>,
        pub max_udp_sessions: Option<usize>,
        pub max_udp_destinations: Option<usize>,
        pub max_udp_destinations_per_session: Option<usize>,
        /// Shared outbound payload allowance across session and destination queues.
        pub max_udp_queued_bytes: Option<usize>,
    }

    impl Default for TunResourceLimits {
        fn default() -> Self {
            Self {
                tcp_buffer_size: 128 * 1024,
                tcp_memory_bytes: None,
                max_tcp_connections: None,
                max_udp_sessions: None,
                max_udp_destinations: None,
                max_udp_destinations_per_session: None,
                max_udp_queued_bytes: None,
            }
        }
    }

    impl TunResourceLimits {
        pub fn validate(&self) -> std::io::Result<()> {
            if !(1024..=16 * 1024 * 1024).contains(&self.tcp_buffer_size)
                || self
                    .tcp_memory_bytes
                    .is_some_and(|bytes| bytes / 4 < self.tcp_buffer_size)
                || self.max_tcp_connections == Some(0)
                || self.max_udp_sessions == Some(0)
                || self.max_udp_destinations == Some(0)
                || self.max_udp_destinations_per_session == Some(0)
                || self.max_udp_queued_bytes.is_some_and(|bytes| bytes < 65535)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid TUN resource limits",
                ));
            }
            Ok(())
        }

        pub fn tcp_connection_limit(&self) -> Option<usize> {
            let memory_limit = self
                .tcp_memory_bytes
                .map(|bytes| bytes / 4 / self.tcp_buffer_size);
            match (self.max_tcp_connections, memory_limit) {
                (Some(count), Some(memory)) => Some(count.min(memory)),
                (count, None) => count,
                (None, memory) => memory,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tun_admission_defaults_and_limits_validate() {
            let mut limits = TunResourceLimits::default();
            limits.validate().unwrap();
            assert_eq!(limits.tcp_buffer_size, 128 * 1024);
            assert_eq!(limits.tcp_connection_limit(), None);

            limits.tcp_memory_bytes = Some(8 * limits.tcp_buffer_size);
            assert_eq!(limits.tcp_connection_limit(), Some(2));
            limits.validate().unwrap();

            limits.max_udp_queued_bytes = Some(65534);
            assert!(limits.validate().is_err());
        }
    }
}

/// Process-wide admission limits (`None` = unlimited).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalLimits {
    pub max_connections: Option<usize>,
    pub max_connections_per_ip: Option<usize>,
    pub max_streams: Option<usize>,
    pub max_streams_per_connection: Option<usize>,
    pub max_udp_destinations: Option<usize>,
    pub reload_grace_secs: u64,
}

impl Default for GlobalLimits {
    fn default() -> Self {
        Self {
            max_connections: None,
            max_connections_per_ip: None,
            max_streams: None,
            max_streams_per_connection: None,
            max_udp_destinations: None,
            reload_grace_secs: 5,
        }
    }
}

impl GlobalLimits {
    pub fn validate(&self) -> std::io::Result<()> {
        for (name, value, max) in [
            ("max_connections", self.max_connections, usize::MAX),
            (
                "max_connections_per_ip",
                self.max_connections_per_ip,
                usize::MAX,
            ),
            ("max_streams", self.max_streams, usize::MAX),
            (
                "max_streams_per_connection",
                self.max_streams_per_connection,
                65535,
            ),
            (
                "max_udp_destinations",
                self.max_udp_destinations,
                usize::MAX,
            ),
        ] {
            if value.is_some_and(|v| v == 0 || v > max) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{name} must be in 1..={max}; omit for unlimited"),
                ));
            }
        }
        if self.reload_grace_secs > 86400 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reload_grace_secs must be at most 86400",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum TlsKeyExchangeGroup {
    X25519MLKEM768,
    SecP256r1MLKEM768,
    X25519,
    SecP256r1,
    SecP384r1,
}

impl TlsKeyExchangeGroup {
    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::X25519MLKEM768 | Self::SecP256r1MLKEM768)
    }

    pub fn rustls_group(self) -> &'static dyn rustls::crypto::SupportedKxGroup {
        use rustls::crypto::aws_lc_rs::kx_group;
        match self {
            Self::X25519MLKEM768 => kx_group::X25519MLKEM768,
            Self::SecP256r1MLKEM768 => kx_group::SECP256R1MLKEM768,
            Self::X25519 => kx_group::X25519,
            Self::SecP256r1 => kx_group::SECP256R1,
            Self::SecP384r1 => kx_group::SECP384R1,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TlsKeyExchangeGroups(Option<Vec<TlsKeyExchangeGroup>>);

impl TlsKeyExchangeGroups {
    pub fn new(groups: Vec<TlsKeyExchangeGroup>) -> std::io::Result<Self> {
        if groups.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "key_exchange_groups must not be empty",
            ));
        }
        for (idx, group) in groups.iter().enumerate() {
            if groups[..idx].contains(group) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "duplicate key_exchange_groups entry",
                ));
            }
        }
        Ok(Self(Some(groups)))
    }

    pub fn is_default(&self) -> bool {
        self.0.is_none()
    }

    pub fn groups(&self) -> Option<&[TlsKeyExchangeGroup]> {
        self.0.as_deref()
    }

    pub fn requires_hybrid(&self) -> bool {
        self.groups()
            .is_some_and(|groups| groups.iter().all(|g| g.is_hybrid()))
    }

    pub fn validate_vision(&self, vision: bool) -> std::io::Result<()> {
        if vision && self.requires_hybrid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hybrid-only key_exchange_groups cannot be combined with Vision: direct copy bypasses TLS encryption",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    #[default]
    Tcp,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpConfig {
    pub no_delay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self { no_delay: true }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTlsClientConfig {
    pub key_exchange_groups: TlsKeyExchangeGroups,
    pub verify: bool,
    pub server_fingerprints: NoneOrSome<String>,
    pub sni_hostname: NoneOrOne<String>,
    pub alpn_protocols: NoneOrSome<String>,
    pub tls_buffer_size: Option<usize>,
    pub client_cert_and_key: Option<(Vec<u8>, Vec<u8>)>,
    pub vision: bool,
    pub protocol: Box<ResolvedClientProxyConfig>,
}

#[derive(Debug, Clone)]
pub enum ResolvedClientProxyConfig {
    Direct,
    Vless {
        user_id: String,
        vision: bool,
        udp_enabled: bool,
    },
    Reality {
        public_key: String,
        short_id: String,
        sni_hostname: Option<String>,
        cipher_suites: NoneOrSome<CipherSuite>,
        vision: bool,
        protocol: Box<ResolvedClientProxyConfig>,
    },
    Tls(ResolvedTlsClientConfig),
}

impl ResolvedClientProxyConfig {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Vless { .. } => "VLESS",
            Self::Reality { .. } => "Reality",
            Self::Tls(_) => "TLS",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedClientConfig {
    pub bind_interface: NoneOrOne<String>,
    pub address: NetLocation,
    pub protocol: ResolvedClientProxyConfig,
    pub transport: Transport,
    pub tcp_settings: Option<TcpConfig>,
}

impl Default for ResolvedClientConfig {
    fn default() -> Self {
        Self {
            bind_interface: NoneOrOne::None,
            address: NetLocation::new(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 0),
            protocol: ResolvedClientProxyConfig::Direct,
            transport: Transport::Tcp,
            tcp_settings: Some(TcpConfig::default()),
        }
    }
}

/// Local inbound mode for an [`EngineConfig`] instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineInbound {
    /// Local mixed HTTP/1.1 + SOCKS5 (+ SOCKS5 UDP ASSOCIATE) listener.
    MixedProxy { listen_addr: SocketAddr },
    /// TUN packet stack operating on a file descriptor (e.g. macOS `utun` via `SCM_RIGHTS` or a
    /// Linux `socketpair` / TUN fd).
    Tun {
        raw_fd: i32,
        close_fd_on_drop: bool,
        packet_information: bool,
        mtu: u16,
        outbound_if_index: Option<u32>,
    },
}

/// Complete typed configuration for running a `vless-engine` session (`PLAN.md` §6).
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub profile: Profile,
    pub inbound: EngineInbound,
    pub dns_resolver: IpAddr,
    pub bypass_cidrs: Vec<IpNetwork>,
    pub bypass_domains: Vec<String>,
    pub limits: GlobalLimits,
    pub tun_limits: tun::TunResourceLimits,
}

impl EngineConfig {
    /// Default MTU for macOS `utun` tunnels (matches `vless_tray_helper::backend::UTUN_MTU` = 1400
    /// so inner `smoltcp` MSS + TLS 1.3 record framing fits inside a single outer TCP segment).
    pub const DEFAULT_TUN_MTU: u16 = 1400;

    /// Constructs a local mixed HTTP+SOCKS5 proxy configuration from `profile`.
    pub fn new_mixed_proxy(profile: Profile, listen_addr: SocketAddr) -> Self {
        Self {
            profile,
            inbound: EngineInbound::MixedProxy { listen_addr },
            dns_resolver: DEFAULT_DNS_RESOLVER,
            bypass_cidrs: Vec::new(),
            bypass_domains: Vec::new(),
            limits: GlobalLimits::default(),
            tun_limits: tun::TunResourceLimits::default(),
        }
    }

    /// Constructs a TUN mode configuration from `profile` and an open TUN file descriptor.
    pub fn new_tun(
        profile: Profile,
        raw_fd: i32,
        close_fd_on_drop: bool,
        packet_information: bool,
        outbound_if_index: Option<u32>,
    ) -> Self {
        Self {
            profile,
            inbound: EngineInbound::Tun {
                raw_fd,
                close_fd_on_drop,
                packet_information,
                mtu: Self::DEFAULT_TUN_MTU,
                outbound_if_index,
            },
            dns_resolver: DEFAULT_DNS_RESOLVER,
            bypass_cidrs: Vec::new(),
            bypass_domains: Vec::new(),
            limits: GlobalLimits::default(),
            tun_limits: tun::TunResourceLimits::default(),
        }
    }

    /// Validates the profile and resource limits.
    pub fn validate(&self) -> Result<(), std::io::Error> {
        self.profile.validate().map_err(|err: ProfileError| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
        })?;
        self.limits.validate()?;
        self.tun_limits.validate()?;
        if let EngineInbound::Tun { raw_fd, mtu, .. } = self.inbound {
            if raw_fd < 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid negative TUN file descriptor {raw_fd}"),
                ));
            }
            if mtu < 576 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid TUN MTU {mtu}: must be >= 576"),
                ));
            }
        }
        Ok(())
    }

    /// Returns the server [`NetLocation`] (`server_host:server_port`) for outbound dialing.
    pub fn server_location(&self) -> std::io::Result<NetLocation> {
        let addr = Address::from(&self.profile.server_host)?;
        Ok(NetLocation::new(addr, self.profile.server_port))
    }

    /// Lowers [`Profile`] into the internal [`ResolvedClientConfig`] handler description:
    /// - `ProfileSecurity::Reality` -> `RealityClientHandler::new_vision_vless` (`Vision` + `XUDP`)
    /// - `ProfileSecurity::Ktls` -> `TlsClientHandler::new` + `VlessTcpClientHandler` (`XUDP` without `Vision`)
    pub fn to_resolved_client_config(&self) -> std::io::Result<ResolvedClientConfig> {
        let address = self.server_location()?;
        let user_id = self.profile.uuid.to_string();

        let protocol = match &self.profile.security {
            ProfileSecurity::Reality {
                public_key_b64,
                short_id_hex,
                sni,
                ..
            } => ResolvedClientProxyConfig::Reality {
                public_key: public_key_b64.clone(),
                short_id: short_id_hex.clone(),
                sni_hostname: Some(sni.clone()),
                cipher_suites: NoneOrSome::Unspecified,
                vision: true,
                protocol: Box::new(ResolvedClientProxyConfig::Vless {
                    user_id,
                    vision: true,
                    udp_enabled: true,
                }),
            },
            ProfileSecurity::Ktls {
                sni,
                alpn,
                cert_sha256_pin,
                ..
            } => {
                // When a SHA-256 leaf pin is configured, allow self-signed server certificates
                // whose SHA-256 matches the pin (`PLAN.md` §7: "with a self-signed certificate,
                // the connection fails unless it is set"). Otherwise verify against system roots.
                let (verify, server_fingerprints) = match cert_sha256_pin {
                    Some(pin) => (false, NoneOrSome::One(format_sha256_pin_hex(pin))),
                    None => (true, NoneOrSome::None),
                };

                ResolvedClientProxyConfig::Tls(ResolvedTlsClientConfig {
                    key_exchange_groups: TlsKeyExchangeGroups::default(),
                    verify,
                    server_fingerprints,
                    sni_hostname: NoneOrOne::One(sni.clone()),
                    alpn_protocols: NoneOrSome::Some(alpn.clone()),
                    tls_buffer_size: None,
                    client_cert_and_key: None,
                    vision: false,
                    protocol: Box::new(ResolvedClientProxyConfig::Vless {
                        user_id,
                        vision: false,
                        udp_enabled: true,
                    }),
                })
            }
        };

        // On macOS/iOS, outbound sockets bind dynamically via `socket_policy::apply` reading the
        // live `OUTBOUND_IF_INDEX` atomic (`IP_BOUND_IF` / `IPV6_BOUND_IF`), allowing seamless
        // interface transitions on `NetworkChanged` without recreating `ClientProxySelector`.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let bind_interface = NoneOrOne::None;
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let bind_interface = match self.outbound_interface_name() {
            Some(name) => NoneOrOne::One(name),
            None => NoneOrOne::None,
        };

        Ok(ResolvedClientConfig {
            bind_interface,
            address,
            protocol,
            transport: Transport::Tcp,
            tcp_settings: Some(TcpConfig { no_delay: true }),
        })
    }

    /// Resolves `outbound_if_index` (if running in TUN mode) to its OS interface name via
    /// `if_indextoname` so outbound sockets bind directly to the physical interface (`IP_BOUND_IF`).
    pub fn outbound_interface_name(&self) -> Option<String> {
        let EngineInbound::Tun {
            outbound_if_index: Some(if_index),
            ..
        } = self.inbound
        else {
            return None;
        };
        if_index_to_name(if_index)
    }
}

pub fn validate_resolved_client_vision_protocol(
    vision: bool,
    protocol: &ResolvedClientProxyConfig,
    transport_name: &str,
) -> std::io::Result<()> {
    if !vision {
        return Ok(());
    }
    match protocol {
        ResolvedClientProxyConfig::Vless { .. } => Ok(()),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{transport_name} with Vision only supports VLESS inner protocol, got {}",
                other.protocol_name()
            ),
        )),
    }
}

/// Converts a numeric interface index (e.g. from `vless-tray-helper`) into its kernel interface name.
pub fn if_index_to_name(if_index: u32) -> Option<String> {
    if if_index == 0 {
        return None;
    }
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE + 1];
    // SAFETY: `buf` is at least `IF_NAMESIZE` bytes and zero-terminated; `if_indextoname` writes at
    // most `IF_NAMESIZE` bytes including NUL on success or returns NULL on failure.
    let ptr = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` points into `buf`, which `if_indextoname` NUL-terminated.
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    cstr.to_str().ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};
    use vless_ipc::parse_vless_link;

    use super::*;

    #[test]
    fn reality_and_ktls_profiles_lower_to_expected_handler_configs() {
        let pbk = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        let reality_profile = parse_vless_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.10:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={pbk}&sid=01ab#Reality"
        ))
        .unwrap()
        .profile;

        let cfg = EngineConfig::new_mixed_proxy(reality_profile, "127.0.0.1:2080".parse().unwrap());
        cfg.validate().unwrap();
        let resolved = cfg.to_resolved_client_config().unwrap();
        match resolved.protocol {
            ResolvedClientProxyConfig::Reality {
                vision,
                sni_hostname,
                protocol,
                ..
            } => {
                assert!(vision);
                assert_eq!(sni_hostname.as_deref(), Some("www.apple.com"));
                assert!(matches!(
                    *protocol,
                    ResolvedClientProxyConfig::Vless {
                        vision: true,
                        udp_enabled: true,
                        ..
                    }
                ));
            }
            other => panic!("expected Reality, got {other:?}"),
        }

        let pin = "aa".repeat(32);
        let ktls_pinned = parse_vless_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:8443?security=tls&sni=example.com&pcs={pin}#kTLS"
        ))
        .unwrap()
        .profile;
        let cfg_ktls =
            EngineConfig::new_mixed_proxy(ktls_pinned, "127.0.0.1:2080".parse().unwrap());
        let resolved_ktls = cfg_ktls.to_resolved_client_config().unwrap();
        match resolved_ktls.protocol {
            ResolvedClientProxyConfig::Tls(tls) => {
                assert!(!tls.verify);
                assert!(!tls.vision);
                assert_eq!(tls.server_fingerprints.into_vec(), vec![pin]);
                assert_eq!(tls.alpn_protocols.into_vec(), vec!["http/1.1".to_string()]);
                assert!(matches!(
                    *tls.protocol,
                    ResolvedClientProxyConfig::Vless {
                        vision: false,
                        udp_enabled: true,
                        ..
                    }
                ));
            }
            other => panic!("expected Tls, got {other:?}"),
        }
    }
}
