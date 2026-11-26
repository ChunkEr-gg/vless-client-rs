//! `SystemBackend` trait and data models abstracting privileged macOS networking operations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vless_ipc::{
    HelperValidationError, validate_interface_name, validate_server_ip, validate_service_name,
};

use crate::error::HelperError;
use crate::parsers::{
    validate_ipv6_gateway_str, validate_proxy_bypass_token, validate_proxy_server_token,
    validate_service_uuid_or_id,
};

/// Local IPv4 address assigned to the `utun` interface (`PLAN.md` §5.2).
pub const UTUN_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

/// Point-to-point peer IPv4 address assigned to the `utun` interface (`198.18.0.1/30`).
pub const UTUN_IPV4_PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

/// Netmask for `198.18.0.0/30` on the `utun` interface.
pub const UTUN_IPV4_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);

/// CIDR string for the local `/30` subnet on `utun`.
pub const UTUN_IPV4_SUBNET_STR: &str = "198.18.0.0/30";

/// Local IPv6 ULA address (`fd00:198:18::1`, inside `fd00::/8`) assigned to the `utun` interface.
pub const UTUN_IPV6_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0198, 0x0018, 0, 0, 0, 0, 1);

/// Prefix length for `fd00:198:18::1/128` on the `IFF_POINTOPOINT` `utun` interface.
pub const UTUN_IPV6_PREFIXLEN: u8 = 128;

/// MTU configured on the `utun` interface (aligned with `vless-engine`'s 1400-byte `smoltcp` MTU).
pub const UTUN_MTU: u16 = 1400;

/// Half-default tunnel capture CIDRs (`PLAN.md` §5.2 items 3 & 6).
pub const TUN_CAPTURE_CIDR_STRS: &[&str] = &["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

/// Address and MTU parameters applied to a newly created `utun` interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtunConfig {
    pub ipv4_addr: Ipv4Addr,
    pub ipv4_peer: Ipv4Addr,
    pub ipv4_netmask: Ipv4Addr,
    pub ipv6_addr: Ipv6Addr,
    pub ipv6_prefixlen: u8,
    pub mtu: u16,
}

impl Default for UtunConfig {
    fn default() -> Self {
        Self {
            ipv4_addr: UTUN_IPV4_ADDR,
            ipv4_peer: UTUN_IPV4_PEER,
            ipv4_netmask: UTUN_IPV4_NETMASK,
            ipv6_addr: UTUN_IPV6_ADDR,
            ipv6_prefixlen: UTUN_IPV6_PREFIXLEN,
            mtu: UTUN_MTU,
        }
    }
}

/// Physical IPv4 default gateway and interface metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultGatewayV4 {
    pub gateway: Ipv4Addr,
    pub interface: String,
    pub if_index: u32,
}

impl DefaultGatewayV4 {
    /// Validates all fields before invoking system networking tools.
    pub fn validate(&self) -> Result<(), HelperError> {
        validate_server_ip(&IpAddr::V4(self.gateway))?;
        validate_interface_name(&self.interface)?;
        if self.if_index == 0 {
            return Err(HelperError::Backend(format!(
                "interface {} resolved to invalid index 0",
                self.interface
            )));
        }
        Ok(())
    }
}

/// Physical IPv6 default gateway (including `%<if>` scope for `fe80::/10` link-local routers) and
/// interface metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultGatewayV6 {
    pub gateway: String,
    pub interface: String,
    pub if_index: u32,
}

impl DefaultGatewayV6 {
    /// Validates all fields before invoking system networking tools.
    pub fn validate(&self) -> Result<(), HelperError> {
        validate_ipv6_gateway_str(&self.gateway)?;
        validate_interface_name(&self.interface)?;
        if self.if_index == 0 {
            return Err(HelperError::Backend(format!(
                "interface {} resolved to invalid index 0",
                self.interface
            )));
        }
        Ok(())
    }
}

/// Saved `SCDynamicStore` DNS configuration for `State:/Network/Service/<service_id>/DNS` and
/// `Setup:/Network/Service/<service_id>/DNS`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSnapshot {
    pub service_id: String,
    pub had_state_dns: bool,
    pub state_dns_plist_xml: Option<String>,
    #[serde(default)]
    pub had_setup_dns: bool,
    #[serde(default)]
    pub setup_dns_plist_xml: Option<String>,
    pub original_dns_servers: Vec<IpAddr>,
}

impl DnsSnapshot {
    /// Validates the service identifier and stored DNS metadata.
    pub fn validate(&self) -> Result<(), HelperError> {
        validate_service_uuid_or_id(&self.service_id)?;
        if self.had_state_dns && self.state_dns_plist_xml.is_none() {
            return Err(HelperError::Journal(format!(
                "DNS snapshot for service {} has had_state_dns=true without state_dns_plist_xml",
                self.service_id
            )));
        }
        if self.had_setup_dns && self.setup_dns_plist_xml.is_none() {
            return Err(HelperError::Journal(format!(
                "DNS snapshot for service {} has had_setup_dns=true without setup_dns_plist_xml",
                self.service_id
            )));
        }
        for ip in &self.original_dns_servers {
            validate_server_ip(ip)?;
        }
        Ok(())
    }
}

/// Point-in-time snapshot of the host's physical default routes, primary service, and DNS servers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub v4_gateway: Option<DefaultGatewayV4>,
    pub v6_gateway: Option<DefaultGatewayV6>,
    pub primary_service_id: Option<String>,
    pub dns_snapshot: Option<DnsSnapshot>,
}

impl NetworkSnapshot {
    /// Returns `(interface_name, if_index)` for the primary physical outbound interface,
    /// preferring IPv4 and falling back to IPv6 on IPv6-only networks.
    pub fn primary_outbound_interface(&self) -> Option<(String, u32)> {
        if let Some(v4) = &self.v4_gateway {
            return Some((v4.interface.clone(), v4.if_index));
        }
        if let Some(v6) = &self.v6_gateway {
            return Some((v6.interface.clone(), v6.if_index));
        }
        None
    }

    /// Returns the discovered pre-tunnel physical DNS servers, if any.
    pub fn original_dns_servers(&self) -> Vec<IpAddr> {
        self.dns_snapshot
            .as_ref()
            .map(|d| d.original_dns_servers.clone())
            .unwrap_or_default()
    }
}

/// Destination of a managed kernel routing table entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RouteDestination {
    Host(IpAddr),
    Cidr(IpNetwork),
}

impl RouteDestination {
    /// Returns `true` if this destination is IPv6.
    pub fn is_ipv6(&self) -> bool {
        match self {
            Self::Host(ip) => ip.is_ipv6(),
            Self::Cidr(net) => net.is_ipv6(),
        }
    }
}

/// Next-hop gateway or interface target for a managed kernel routing table entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "target_type", content = "target", rename_all = "snake_case")]
pub enum RouteTarget {
    GatewayV4(Ipv4Addr),
    GatewayV6(String),
    Interface(String),
}

/// Complete specification of a route managed by `vless-tray-helper`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteSpec {
    pub destination: RouteDestination,
    pub target: RouteTarget,
}

impl RouteSpec {
    /// Strictly validates destination and target invariants before passing arguments to
    /// `/sbin/route`.
    pub fn validate(&self) -> Result<(), HelperError> {
        match &self.destination {
            RouteDestination::Host(ip) => {
                validate_server_ip(ip)?;
            }
            RouteDestination::Cidr(cidr) => {
                if cidr.prefix() == 0 {
                    return Err(HelperError::Validation(
                        HelperValidationError::InvalidCidr {
                            cidr: *cidr,
                            reason: "prefix length 0 (default route) must never be modified",
                        },
                    ));
                }
                if cidr.network() != cidr.ip() {
                    return Err(HelperError::Validation(
                        HelperValidationError::InvalidCidr {
                            cidr: *cidr,
                            reason: "CIDR host bits must be zeroed to canonical network address",
                        },
                    ));
                }
            }
        }

        match (&self.destination, &self.target) {
            (dest, RouteTarget::GatewayV4(gw)) => {
                if dest.is_ipv6() {
                    return Err(HelperError::Backend(
                        "cannot route IPv6 destination via IPv4 gateway".into(),
                    ));
                }
                validate_server_ip(&IpAddr::V4(*gw))?;
            }
            (dest, RouteTarget::GatewayV6(gw)) => {
                if !dest.is_ipv6() {
                    return Err(HelperError::Backend(
                        "cannot route IPv4 destination via IPv6 gateway".into(),
                    ));
                }
                validate_ipv6_gateway_str(gw)?;
            }
            (_, RouteTarget::Interface(iface)) => {
                validate_interface_name(iface)?;
            }
        }

        Ok(())
    }
}

/// Outcome of `SystemBackend::add_route`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAddResult {
    /// Route was newly inserted into the kernel routing table by this call.
    Added,
    /// Identical route prefix was already present in the kernel routing table (`EEXIST`).
    AlreadyExisted,
}

/// Saved state of a single proxy protocol (HTTP, HTTPS, or SOCKS5) on a macOS network service.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEndpointConfig {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
}

impl ProxyEndpointConfig {
    /// Validates stored server token before passing back to `networksetup`.
    pub fn validate(&self) -> Result<(), HelperError> {
        if !self.server.is_empty() {
            validate_proxy_server_token(&self.server)?;
        }
        Ok(())
    }
}

/// Saved proxy state for a single enabled macOS network service (`networksetup`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProxySnapshot {
    pub service: String,
    pub web: ProxyEndpointConfig,
    pub secure_web: ProxyEndpointConfig,
    pub socks: ProxyEndpointConfig,
    pub bypass_domains: Vec<String>,
}

impl ServiceProxySnapshot {
    /// Validates service name, proxy server tokens, and saved bypass domain entries.
    pub fn validate(&self) -> Result<(), HelperError> {
        validate_service_name(&self.service)?;
        self.web.validate()?;
        self.secure_web.validate()?;
        self.socks.validate()?;
        for token in &self.bypass_domains {
            validate_proxy_bypass_token(token)?;
        }
        Ok(())
    }
}

/// Abstraction over all privileged OS networking, DNS, proxy, and `PF_ROUTE` operations.
pub trait SystemBackend: Send + Sync + 'static {
    /// Captures current physical default gateways, interfaces, `if_nametoindex`, primary
    /// `SystemConfiguration` service ID, and DNS settings (ignoring `exclude_utun` if active).
    fn snapshot_network(&self, exclude_utun: Option<&str>) -> Result<NetworkSnapshot, HelperError>;

    /// Opens a new `utun` interface and returns `(utun_fd, utun_name)`.
    fn create_utun(&self) -> Result<(OwnedFd, String), HelperError>;

    /// Configures IPv4 (`198.18.0.1` peer `198.18.0.2/30`), IPv6 (`fd00:198:18::1/128`), MTU
    /// (`1400`), and brings `<utun_name>` `up`.
    fn configure_utun(&self, utun_name: &str, config: &UtunConfig) -> Result<(), HelperError>;

    /// Installs a host, bypass CIDR, or half-default TUN route.
    fn add_route(&self, route: &RouteSpec) -> Result<RouteAddResult, HelperError>;

    /// Deletes a previously added route (idempotent if already absent).
    fn delete_route(&self, route: &RouteSpec) -> Result<(), HelperError>;

    /// Applies ephemeral `State:/Network/Service/<service_id>/DNS` and
    /// `Setup:/Network/Service/<service_id>/DNS` overrides in `SCDynamicStore`.
    fn set_dns_override(&self, service_id: &str, dns_resolver: IpAddr) -> Result<(), HelperError>;

    /// Restores `State:/Network/Service/<service_id>/DNS` and
    /// `Setup:/Network/Service/<service_id>/DNS` from `snapshot` (or removes keys that did not
    /// exist prior to TUN mode).
    fn restore_dns_override(&self, snapshot: &DnsSnapshot) -> Result<(), HelperError>;

    /// Lists enabled macOS network services (`networksetup -listallnetworkservices`).
    fn list_enabled_network_services(&self) -> Result<Vec<String>, HelperError>;

    /// Reads HTTP, HTTPS, SOCKS5, and `ExceptionsList` proxy settings for `service`.
    fn get_service_proxies(&self, service: &str) -> Result<ServiceProxySnapshot, HelperError>;

    /// Sets HTTP, HTTPS, and SOCKS5 proxies (`host:port`, enabled) and `exceptions` on `service`.
    fn set_service_proxies(
        &self,
        service: &str,
        host: &str,
        port: u16,
        exceptions: &[String],
    ) -> Result<(), HelperError>;

    /// Restores saved HTTP, HTTPS, SOCKS5, and `ExceptionsList` proxy settings for `snapshot`.
    fn restore_service_proxies(&self, snapshot: &ServiceProxySnapshot) -> Result<(), HelperError>;

    /// Subscribes to route/interface change notifications (`PF_ROUTE` on macOS).
    fn subscribe_route_changes(&self) -> Result<mpsc::Receiver<()>, HelperError>;
}
