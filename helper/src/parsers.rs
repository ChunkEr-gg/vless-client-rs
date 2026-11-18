//! Pure parsers, validators, and command-argv builders for macOS networking utilities
//! (`/sbin/route`, `/sbin/ifconfig`, `/usr/sbin/networksetup`, and `/etc/resolv.conf`).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

use ipnetwork::IpNetwork;
use vless_ipc::{
    HelperValidationError, validate_interface_name, validate_server_ip, validate_service_name,
};

use crate::backend::{ProxyEndpointConfig, RouteDestination, RouteSpec, RouteTarget, UtunConfig};
use crate::error::HelperError;

/// Route table mutation operation passed to `/sbin/route`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAction {
    Add,
    Delete,
}

impl RouteAction {
    pub const fn as_arg(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "delete",
        }
    }
}

/// Parsed fields from `/sbin/route -n get default` or `/sbin/route -n get -inet6 default`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDefaultRoute {
    pub gateway: Option<String>,
    pub interface: String,
}

/// Parses the stdout of `/sbin/route -n get default` or `/sbin/route -n get -inet6 default`.
///
/// Returns `None` if no route entry or valid BSD interface name was present (for example, on an
/// IPv4-only network where no IPv6 default route exists).
pub fn parse_route_get_output(stdout: &str) -> Option<ParsedDefaultRoute> {
    let mut gateway: Option<String> = None;
    let mut interface: Option<String> = None;

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            let gw = rest.trim();
            if !gw.is_empty() {
                gateway = Some(gw.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("interface:") {
            let iface = rest.trim();
            if !iface.is_empty() {
                interface = Some(iface.to_string());
            }
        }
    }

    let interface = interface?;
    validate_interface_name(&interface).ok()?;
    Some(ParsedDefaultRoute { gateway, interface })
}

/// Validates and canonicalizes an IPv6 gateway address reported by `/sbin/route` or
/// `SCDynamicStore`.
///
/// If the gateway is a link-local address (`fe80::/10`) without an explicit `%<iface>` zone
/// qualifier, `%<interface>` is appended so `/sbin/route -n add -inet6 ...` has a valid scope.
pub fn normalize_ipv6_gateway(raw_gw: &str, interface: &str) -> Result<String, HelperError> {
    validate_interface_name(interface)?;
    let trimmed = raw_gw.trim();
    if trimmed.is_empty() {
        return Err(HelperError::Backend("empty IPv6 gateway address".into()));
    }

    let (addr_part, explicit_scope) = match trimmed.split_once('%') {
        Some((addr, scope)) => (addr, Some(scope)),
        None => (trimmed, None),
    };

    let ipv6: Ipv6Addr = addr_part
        .parse()
        .map_err(|_| HelperError::Backend(format!("invalid IPv6 gateway address {trimmed:?}")))?;
    validate_server_ip(&IpAddr::V6(ipv6))?;

    if let Some(scope) = explicit_scope {
        validate_interface_name(scope)?;
        Ok(format!("{ipv6}%{scope}"))
    } else if ipv6.is_unicast_link_local() {
        Ok(format!("{ipv6}%{interface}"))
    } else {
        Ok(ipv6.to_string())
    }
}

/// Validates an already-normalized IPv6 gateway string (`2001:db8::1` or `fe80::1%en0`).
pub fn validate_ipv6_gateway_str(gw: &str) -> Result<(), HelperError> {
    if gw.is_empty()
        || gw.starts_with('-')
        || gw.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(HelperError::Backend(format!(
            "invalid IPv6 gateway string {gw:?}"
        )));
    }

    let (addr_part, scope_opt) = match gw.split_once('%') {
        Some((addr, scope)) => (addr, Some(scope)),
        None => (gw, None),
    };

    let ipv6: Ipv6Addr = addr_part
        .parse()
        .map_err(|_| HelperError::Backend(format!("invalid IPv6 gateway address {gw:?}")))?;
    validate_server_ip(&IpAddr::V6(ipv6))?;

    if let Some(scope) = scope_opt {
        validate_interface_name(scope)?;
    } else if ipv6.is_unicast_link_local() {
        return Err(HelperError::Backend(format!(
            "link-local IPv6 gateway {gw:?} requires %<if> scope suffix"
        )));
    }

    Ok(())
}

/// Validates a `SystemConfiguration` `PrimaryService` identifier before interpolating it into
/// `State:/Network/Service/<service_id>/DNS`.
pub fn validate_service_uuid_or_id(service_id: &str) -> Result<(), HelperError> {
    let bytes = service_id.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || bytes[0] == b'-'
        || bytes[0] == b'.'
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(HelperError::Backend(format!(
            "invalid SystemConfiguration service ID {service_id:?}"
        )));
    }
    Ok(())
}

/// Validates a saved proxy server hostname or IP token before passing it to `networksetup`.
pub fn validate_proxy_server_token(server: &str) -> Result<(), HelperError> {
    if server.is_empty()
        || server.len() > 253
        || server.starts_with('-')
        || server.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(HelperError::Backend(format!(
            "invalid proxy server token {server:?}"
        )));
    }
    Ok(())
}

/// Validates a saved proxy bypass domain/CIDR token read from `networksetup -getproxybypassdomains`
/// before passing it back as a standalone `argv` element to `networksetup -setproxybypassdomains`.
///
/// Allows ordinary ASCII space `' '` inside pre-existing user `ExceptionsList` entries (such as
/// `"*.local, 169.254/16"`) while rejecting empty/blank strings, `len > 253`, leading `'-'`,
/// control characters, or `\r` / `\n` / `\t`.
pub fn validate_proxy_bypass_token(token: &str) -> Result<(), HelperError> {
    if token.is_empty()
        || token.trim().is_empty()
        || token.len() > 253
        || token.starts_with('-')
        || token
            .chars()
            .any(|c| c.is_control() || (c.is_whitespace() && c != ' '))
    {
        return Err(HelperError::Validation(
            HelperValidationError::InvalidExceptionEntry {
                entry: token.to_string(),
                reason: "bypass token must be 1..=253 printable characters without control/tab/newline chars and not start with '-'".into(),
            },
        ));
    }
    Ok(())
}

/// Parses `/usr/sbin/networksetup -listallnetworkservices` output, returning all **enabled**
/// network services validated via [`validate_service_name`].
pub fn parse_network_services_output(stdout: &str) -> Result<Vec<String>, HelperError> {
    let mut services = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip the standard banner line on line 1:
        // "An asterisk (*) denotes that a network service is disabled."
        if line
            .get(..13)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("an asterisk ("))
        {
            continue;
        }
        // Disabled network services are prefixed with '*'.
        if line.starts_with('*') {
            continue;
        }

        validate_service_name(line)?;
        if !services.iter().any(|existing| existing == line) {
            services.push(line.to_string());
        }
    }
    Ok(services)
}

/// Parses `/usr/sbin/networksetup -listnetworkserviceorder` output, returning the set of network
/// service names backed by a non-empty hardware `Device:` (excluding virtual `NEVPNManager` /
/// IPSec / WireGuard services where `Device:` is empty).
pub fn parse_hardware_backed_services_from_service_order(stdout: &str) -> HashSet<String> {
    let mut backed = HashSet::new();
    let mut current_service: Option<String> = None;

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            current_service = None;
            continue;
        }

        if line.starts_with("(Hardware Port:") && line.ends_with(')') {
            let Some(svc_name) = current_service.take() else {
                continue;
            };
            let inner = &line[1..line.len() - 1];
            if let Some((_, dev_part)) = inner.rsplit_once("Device:") {
                let device = dev_part.trim();
                if !device.is_empty() {
                    backed.insert(svc_name);
                }
            }
            continue;
        }

        if line.starts_with('(')
            && let Some(close_idx) = line.find(')')
        {
            let tag = line[1..close_idx].trim();
            if !tag.is_empty() && tag.bytes().all(|b| b.is_ascii_digit() || b == b'*') {
                let svc_raw = line[close_idx + 1..].trim();
                let svc = svc_raw.strip_prefix('*').map(str::trim).unwrap_or(svc_raw);
                current_service = (!svc.is_empty()).then(|| svc.to_string());
                continue;
            }
        }
    }

    backed
}

/// Parses `/usr/sbin/networksetup -getwebproxy` / `-getsecurewebproxy` /
/// `-getsocksfirewallproxy` output.
pub fn parse_proxy_info_output(stdout: &str) -> Result<ProxyEndpointConfig, HelperError> {
    let mut enabled: Option<bool> = None;
    let mut server: Option<String> = None;
    let mut port: Option<u16> = None;

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Note: check "Authenticated Proxy Enabled:" before generic suffix matching; strip_prefix
        // is anchored at line start so "Enabled:" only matches the top-level proxy state line.
        if let Some(val) = line.strip_prefix("Enabled:") {
            let token = val.trim();
            enabled = Some(match token.to_ascii_lowercase().as_str() {
                "yes" | "1" | "true" | "on" => true,
                "no" | "0" | "false" | "off" => false,
                other => {
                    return Err(HelperError::Backend(format!(
                        "unrecognized networksetup Enabled value {other:?}"
                    )));
                }
            });
        } else if let Some(val) = line.strip_prefix("Server:") {
            let srv = val.trim().to_string();
            if !srv.is_empty() {
                validate_proxy_server_token(&srv)?;
            }
            server = Some(srv);
        } else if let Some(val) = line.strip_prefix("Port:") {
            let parsed_port: u16 = val.trim().parse().map_err(|_| {
                HelperError::Backend(format!("invalid networksetup Port value {:?}", val.trim()))
            })?;
            port = Some(parsed_port);
        }
    }

    let enabled = enabled.ok_or_else(|| {
        HelperError::Backend("missing `Enabled:` line in networksetup proxy output".into())
    })?;
    let port = port.ok_or_else(|| {
        HelperError::Backend("missing `Port:` line in networksetup proxy output".into())
    })?;

    Ok(ProxyEndpointConfig {
        enabled,
        server: server.unwrap_or_default(),
        port,
    })
}

/// Parses `/usr/sbin/networksetup -getproxybypassdomains <service>` output.
///
/// When no bypass domains are configured, `networksetup` prints:
/// `"There aren't any Bypass Domains set on <service>."` — which maps cleanly to `Vec::new()`.
pub fn parse_proxy_bypass_output(stdout: &str) -> Result<Vec<String>, HelperError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("there aren't any bypass domains set on")
        || lower.starts_with("there aren\u{2019}t any bypass domains set on")
    {
        return Ok(Vec::new());
    }

    let mut domains = Vec::new();
    for raw_line in stdout.lines() {
        let entry = raw_line.trim();
        if entry.is_empty() {
            continue;
        }
        validate_proxy_bypass_token(entry)?;
        domains.push(entry.to_string());
    }
    Ok(domains)
}

/// Extracts valid non-loopback unicast DNS server IPs from `/etc/resolv.conf` content as a
/// read-only fallback when neither `State:` nor `Setup:` `SCDynamicStore` keys list servers.
pub fn parse_resolv_conf_nameservers(contents: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.split(['#', ';']).next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let addr_token = rest.trim().split('%').next().unwrap_or("");
        if let Ok(ip) = addr_token.parse::<IpAddr>()
            && !ip.is_loopback()
            && validate_server_ip(&ip).is_ok()
            && !servers.contains(&ip)
        {
            servers.push(ip);
        }
    }
    servers
}

/// Builds the two `/sbin/ifconfig` argv lists required to configure a point-to-point macOS `utun`
/// interface (`198.18.0.1` -> `198.18.0.2` `/30` MTU `1400` `up`, and `fd00:198:18::1/128`).
pub fn build_ifconfig_utun_args(
    utun_name: &str,
    config: &UtunConfig,
) -> Result<[Vec<String>; 2], HelperError> {
    validate_interface_name(utun_name)?;
    let v4_args = vec![
        utun_name.to_string(),
        "inet".to_string(),
        config.ipv4_addr.to_string(),
        config.ipv4_peer.to_string(),
        "netmask".to_string(),
        config.ipv4_netmask.to_string(),
        "mtu".to_string(),
        config.mtu.to_string(),
        "up".to_string(),
    ];
    let v6_args = vec![
        utun_name.to_string(),
        "inet6".to_string(),
        config.ipv6_addr.to_string(),
        "prefixlen".to_string(),
        config.ipv6_prefixlen.to_string(),
    ];
    Ok([v4_args, v6_args])
}

/// Builds the exact `/sbin/route` argv list (without shell) for adding or deleting `route`.
pub fn build_route_command_args(
    action: RouteAction,
    route: &RouteSpec,
) -> Result<Vec<String>, HelperError> {
    route.validate()?;

    let mut args = Vec::with_capacity(8);
    args.push("-n".to_string());
    args.push(action.as_arg().to_string());

    if route.destination.is_ipv6() {
        args.push("-inet6".to_string());
    }

    match &route.destination {
        RouteDestination::Host(ip) => {
            args.push("-host".to_string());
            args.push(ip.to_string());
        }
        RouteDestination::Cidr(IpNetwork::V4(v4)) if v4.prefix() == 32 => {
            args.push("-host".to_string());
            args.push(v4.ip().to_string());
        }
        RouteDestination::Cidr(IpNetwork::V6(v6)) if v6.prefix() == 128 => {
            args.push("-host".to_string());
            args.push(v6.ip().to_string());
        }
        RouteDestination::Cidr(cidr) => {
            args.push("-net".to_string());
            args.push(cidr.to_string());
        }
    }

    match &route.target {
        RouteTarget::GatewayV4(gw) => {
            args.push(gw.to_string());
        }
        RouteTarget::GatewayV6(gw) => {
            args.push(gw.clone());
        }
        RouteTarget::Interface(iface) => {
            args.push("-interface".to_string());
            args.push(iface.clone());
        }
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::UtunConfig;

    #[test]
    fn parse_route_get_ipv4_ipv6_link_local_and_missing_ipv6() {
        let ipv4_sample = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";
        let parsed_v4 = parse_route_get_output(ipv4_sample).expect("parse v4 route");
        assert_eq!(parsed_v4.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(parsed_v4.interface, "en0");

        let ipv6_scoped_sample = "\
   route to: ::
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,CLONING>
";
        let parsed_v6_scoped = parse_route_get_output(ipv6_scoped_sample).expect("parse v6 route");
        assert_eq!(parsed_v6_scoped.gateway.as_deref(), Some("fe80::1%en0"));
        assert_eq!(parsed_v6_scoped.interface, "en0");
        assert_eq!(
            normalize_ipv6_gateway(
                parsed_v6_scoped.gateway.as_deref().unwrap(),
                &parsed_v6_scoped.interface
            )
            .unwrap(),
            "fe80::1%en0"
        );

        // Link-local gateway without %if automatically gets %en0 appended
        assert_eq!(
            normalize_ipv6_gateway("fe80::a2b1:ccff:fe11:2233", "en0").unwrap(),
            "fe80::a2b1:ccff:fe11:2233%en0"
        );
        // Global unicast gateway keeps clean address without %if
        assert_eq!(
            normalize_ipv6_gateway("2001:db8:1::1", "en0").unwrap(),
            "2001:db8:1::1"
        );

        // IPv4-only host where `route -n get -inet6 default` prints error / no route
        let no_ipv6_route = "route: writing to routing socket: not in table\n";
        assert!(parse_route_get_output(no_ipv6_route).is_none());

        // Malformed / injected interface name is rejected
        let injected = "gateway: 192.168.1.1\ninterface: en0;id\n";
        assert!(parse_route_get_output(injected).is_none());
    }

    #[test]
    fn parse_networksetup_services_proxies_and_bypass_domains() {
        let services_sample = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Thunderbolt Bridge
USB 10/100/1000 LAN
*iPhone USB
";
        let services = parse_network_services_output(services_sample).unwrap();
        assert_eq!(services, vec!["Wi-Fi", "USB 10/100/1000 LAN"]);

        let enabled_proxy = "\
Enabled: Yes
Server: corp-proxy.internal
Port: 8443
Authenticated Proxy Enabled: 0
";
        assert_eq!(
            parse_proxy_info_output(enabled_proxy).unwrap(),
            ProxyEndpointConfig {
                enabled: true,
                server: "corp-proxy.internal".to_string(),
                port: 8443,
            }
        );

        let disabled_empty_proxy = "\
Enabled: No
Server: 
Port: 0
Authenticated Proxy Enabled: 0
";
        assert_eq!(
            parse_proxy_info_output(disabled_empty_proxy).unwrap(),
            ProxyEndpointConfig {
                enabled: false,
                server: String::new(),
                port: 0,
            }
        );

        let empty_bypass = "There aren't any Bypass Domains set on Wi-Fi.\n";
        assert!(parse_proxy_bypass_output(empty_bypass).unwrap().is_empty());

        let populated_bypass = "*.local\n169.254/16\n*.local, 169.254/16\ninternal.corp\n";
        assert_eq!(
            parse_proxy_bypass_output(populated_bypass).unwrap(),
            vec![
                "*.local",
                "169.254/16",
                "*.local, 169.254/16",
                "internal.corp",
            ]
        );

        // Space-containing pre-existing bypass tokens are accepted, while leading '-', tabs,
        // newlines, control chars, or blank strings are rejected.
        assert!(validate_proxy_bypass_token("*.local, 169.254/16").is_ok());
        assert!(validate_proxy_bypass_token("my internal host").is_ok());
        for bad_token in [
            "",
            "   ",
            "-setwebproxy",
            "bad\ttoken",
            "bad\ntoken",
            "bad\0token",
        ] {
            assert!(
                validate_proxy_bypass_token(bad_token).is_err(),
                "expected {bad_token:?} to be rejected"
            );
        }

        let service_order_sample = "\
An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Corp WireGuard VPN
(Hardware Port: io.wireguard.macos, Device: )

(3) IPSec Tunnel
(Hardware Port: IPSec, Device:)

(*) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(4) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN (2), Device: en7)

(5) iPhone USB
(Hardware Port: iPhone USB, Device: pdp_ip0)
";
        let hw_backed = parse_hardware_backed_services_from_service_order(service_order_sample);
        assert_eq!(
            hw_backed,
            HashSet::from([
                "Wi-Fi".to_string(),
                "Thunderbolt Bridge".to_string(),
                "USB 10/100/1000 LAN".to_string(),
                "iPhone USB".to_string(),
            ])
        );
        assert!(!hw_backed.contains("Corp WireGuard VPN"));
        assert!(!hw_backed.contains("IPSec Tunnel"));
    }

    #[test]
    fn ifconfig_and_route_argv_builders_match_macos_pointopoint_syntax() {
        let cfg = UtunConfig::default();
        assert_eq!(cfg.ipv6_prefixlen, 128);
        assert_eq!(cfg.mtu, 1400);

        let [v4_args, v6_args] = build_ifconfig_utun_args("utun7", &cfg).unwrap();
        assert_eq!(
            v4_args,
            vec![
                "utun7",
                "inet",
                "198.18.0.1",
                "198.18.0.2",
                "netmask",
                "255.255.255.252",
                "mtu",
                "1400",
                "up",
            ]
        );
        assert_eq!(
            v6_args,
            vec!["utun7", "inet6", "fd00:198:18::1", "prefixlen", "128"]
        );

        let v4_host = RouteSpec {
            destination: RouteDestination::Host("203.0.113.10".parse().unwrap()),
            target: RouteTarget::GatewayV4("192.168.1.1".parse().unwrap()),
        };
        assert_eq!(
            build_route_command_args(RouteAction::Add, &v4_host).unwrap(),
            vec!["-n", "add", "-host", "203.0.113.10", "192.168.1.1"]
        );

        let v6_capture = RouteSpec {
            destination: RouteDestination::Cidr("::/1".parse().unwrap()),
            target: RouteTarget::Interface("utun7".to_string()),
        };
        assert_eq!(
            build_route_command_args(RouteAction::Add, &v6_capture).unwrap(),
            vec!["-n", "add", "-inet6", "-net", "::/1", "-interface", "utun7"]
        );
        assert_eq!(
            build_route_command_args(RouteAction::Delete, &v6_capture).unwrap(),
            vec![
                "-n",
                "delete",
                "-inet6",
                "-net",
                "::/1",
                "-interface",
                "utun7"
            ]
        );
    }

    #[test]
    fn resolv_conf_fallback_parser_ignores_comments_and_loopback() {
        let sample = "\
# macOS Notice
nameserver 127.0.0.1
nameserver 192.168.1.1 # router
nameserver 2606:4700:4700::1111
nameserver 0.0.0.0
";
        assert_eq!(
            parse_resolv_conf_nameservers(sample),
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
