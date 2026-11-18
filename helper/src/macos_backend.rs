//! Production macOS implementation of [`SystemBackend`] (`PLAN.md` §4, §5.2–§5.5).
//!
//! Security invariants:
//! - Executes ONLY fixed system binaries (`/sbin/route`, `/sbin/ifconfig`,
//!   `/usr/sbin/networksetup`) via direct `argv` arrays with no shell (`sh -c` is never used) and
//!   sanitized environment (`env_clear()`, `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LC_ALL=C`).
//! - Validates every interface name, service name, service ID, IP address, CIDR, and exception
//!   token before invoking OS APIs or binaries.
//! - Overrides DNS strictly via ephemeral `SCDynamicStore` `State:/Network/Service/<id>/DNS` and
//!   `Setup:/Network/Service/<id>/DNS` keys in `configd` RAM without touching persistent
//!   `/Library/Preferences/SystemConfiguration/preferences.plist` on disk.

use std::ffi::CString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Output, Stdio};

use system_configuration::core_foundation::{
    array::CFArray,
    base::{CFType, TCFType, ToVoid},
    data::CFData,
    dictionary::CFDictionary,
    propertylist::{
        CFPropertyList, create_data, create_with_data, kCFPropertyListImmutable,
        kCFPropertyListXMLFormat_v1_0,
    },
    string::{CFString, CFStringRef},
};
use system_configuration::{
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder},
    sys::schema_definitions::{
        kSCDynamicStorePropNetPrimaryInterface, kSCDynamicStorePropNetPrimaryService,
        kSCPropNetDNSServerAddresses, kSCPropNetIPv4Router,
    },
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use vless_ipc::{
    HelperValidationError, validate_exception_entry, validate_interface_name, validate_server_ip,
    validate_service_name,
};

use crate::backend::{
    DefaultGatewayV4, DefaultGatewayV6, DnsSnapshot, NetworkSnapshot, ProxyEndpointConfig,
    RouteAddResult, RouteSpec, RouteTarget, ServiceProxySnapshot, SystemBackend, UtunConfig,
};
use crate::error::HelperError;
use crate::launchd::{set_cloexec, set_nonblocking};
use crate::parsers::{
    RouteAction, build_ifconfig_utun_args, build_route_command_args, normalize_ipv6_gateway,
    parse_hardware_backed_services_from_service_order, parse_network_services_output,
    parse_proxy_bypass_output, parse_proxy_info_output, parse_resolv_conf_nameservers,
    parse_route_get_output, validate_proxy_server_token, validate_service_uuid_or_id,
};

/// Kernel control name for macOS `utun` virtual point-to-point interfaces.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/// Closed allowlist of system binaries `MacosSystemBackend` is permitted to execute (`PLAN.md` §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedBinary {
    Route,
    Ifconfig,
    Networksetup,
}

impl FixedBinary {
    const fn path(self) -> &'static str {
        match self {
            Self::Route => "/sbin/route",
            Self::Ifconfig => "/sbin/ifconfig",
            Self::Networksetup => "/usr/sbin/networksetup",
        }
    }
}

/// Production macOS [`SystemBackend`] using XNU `utun` control sockets, `/sbin/ifconfig`,
/// `/sbin/route`, `SCDynamicStore`, `/usr/sbin/networksetup`, and `PF_ROUTE`.
#[derive(Debug, Default)]
pub struct MacosSystemBackend;

impl MacosSystemBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SystemBackend for MacosSystemBackend {
    fn snapshot_network(&self, exclude_utun: Option<&str>) -> Result<NetworkSnapshot, HelperError> {
        let store = open_dynamic_store()?;
        let sc_v4 = query_sc_global_ipv4(&store);
        let sc_v6 = query_sc_global_ipv6(&store);

        let v4_gateway = query_default_gateway_v4(exclude_utun, sc_v4.as_ref())?;
        let v6_gateway = query_default_gateway_v6(exclude_utun, sc_v6.as_ref())?;

        let primary_service_id = sc_v4
            .and_then(|g| g.primary_service)
            .or_else(|| sc_v6.and_then(|g| g.primary_service));

        let dns_snapshot = match &primary_service_id {
            Some(service_id) => Some(snapshot_service_dns(&store, service_id)?),
            None => None,
        };

        Ok(NetworkSnapshot {
            v4_gateway,
            v6_gateway,
            primary_service_id,
            dns_snapshot,
        })
    }

    fn create_utun(&self) -> Result<(OwnedFd, String), HelperError> {
        // SAFETY: Opening a kernel control datagram socket (`PF_SYSTEM`, `SYSPROTO_CONTROL`) has no
        // memory preconditions and returns a fresh descriptor or `-1` on error.
        let raw_fd =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw_fd < 0 {
            return Err(HelperError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `raw_fd >= 0` is a newly created owned socket descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        set_cloexec(fd.as_raw_fd())?;

        let mut info = libc::ctl_info {
            ctl_id: 0,
            ctl_name: [0; libc::MAX_KCTL_NAME],
        };
        for (dst, &src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.iter()) {
            *dst = src as libc::c_char;
        }

        // SAFETY: `fd` is a valid `PF_SYSTEM` control socket and `info` is an initialized
        // `libc::ctl_info` containing the NUL-terminated `"com.apple.net.utun_control"` name.
        let ioctl_rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &raw mut info) };
        if ioctl_rc < 0 {
            return Err(HelperError::Io(io::Error::last_os_error()));
        }

        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0, // 0 instructs XNU to allocate the lowest unused utunN unit
            sc_reserved: [0; 5],
        };

        // SAFETY: `fd` is an open `PF_SYSTEM` socket, `addr` is a properly aligned and sized
        // `sockaddr_ctl`, and `socklen_t` matches `size_of::<sockaddr_ctl>()`.
        let connect_rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if connect_rc < 0 {
            return Err(HelperError::Io(io::Error::last_os_error()));
        }

        let mut ifname_buf = [0u8; 64];
        let mut ifname_len = ifname_buf.len() as libc::socklen_t;

        // SAFETY: `fd` is a connected `utun` control socket, `ifname_buf` is a 64-byte mutable
        // stack buffer, and `ifname_len` holds its byte capacity.
        let opt_rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut ifname_len,
            )
        };
        if opt_rc < 0 {
            return Err(HelperError::Io(io::Error::last_os_error()));
        }

        let valid_len = usize::try_from(ifname_len)
            .unwrap_or(0)
            .min(ifname_buf.len());
        let slice = &ifname_buf[..valid_len];
        let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        let utun_name = std::str::from_utf8(&slice[..nul_pos])
            .map_err(|_| HelperError::Backend("kernel returned non-UTF8 utun name".into()))?
            .to_string();

        validate_interface_name(&utun_name)?;
        Ok((fd, utun_name))
    }

    fn configure_utun(&self, utun_name: &str, config: &UtunConfig) -> Result<(), HelperError> {
        let [v4_args, v6_args] = build_ifconfig_utun_args(utun_name, config)?;
        run_checked_binary(FixedBinary::Ifconfig, &v4_args)?;
        run_checked_binary(FixedBinary::Ifconfig, &v6_args)?;
        Ok(())
    }

    fn add_route(&self, route: &RouteSpec) -> Result<RouteAddResult, HelperError> {
        let args = build_route_command_args(RouteAction::Add, route)?;
        let out = run_raw_binary(FixedBinary::Route, &args)?;
        if out.status.success() {
            return Ok(RouteAddResult::Added);
        }

        let combined = combined_output_text(&out);
        if combined.to_ascii_lowercase().contains("file exists") {
            log::debug!("route already present in kernel table ({route:?}): {combined}");
            return Ok(RouteAddResult::AlreadyExisted);
        }

        Err(command_failed_err(FixedBinary::Route, &out))
    }

    fn delete_route(&self, route: &RouteSpec) -> Result<(), HelperError> {
        let args = build_route_command_args(RouteAction::Delete, route)?;

        let target_iface = match &route.target {
            RouteTarget::Interface(iface) => Some(iface.as_str()),
            RouteTarget::GatewayV6(gw) => gw.split_once('%').map(|(_, scope)| scope),
            RouteTarget::GatewayV4(_) => None,
        };
        if let Some(iface) = target_iface
            && interface_index(iface).is_err()
        {
            log::debug!(
                "skipping route delete on vanished interface {iface:?} ({route:?}); kernel already purged it"
            );
            return Ok(());
        }

        let out = run_raw_binary(FixedBinary::Route, &args)?;
        if out.status.success() {
            return Ok(());
        }

        let lower = combined_output_text(&out).to_ascii_lowercase();
        let vanished_after_check =
            target_iface.is_some_and(|iface| interface_index(iface).is_err());
        if lower.contains("not in table")
            || lower.contains("no such process")
            || lower.contains("bad interface name")
            || lower.contains("network is unreachable")
            || (lower.contains("bad address") && (target_iface.is_some() || vanished_after_check))
        {
            log::debug!("route already absent during delete ({route:?}): {lower}");
            return Ok(());
        }

        Err(command_failed_err(FixedBinary::Route, &out))
    }

    fn set_dns_override(&self, service_id: &str, dns_resolver: IpAddr) -> Result<(), HelperError> {
        validate_service_uuid_or_id(service_id)?;
        validate_server_ip(&dns_resolver)?;

        let store = open_dynamic_store()?;
        let state_key = format!("State:/Network/Service/{service_id}/DNS");
        let setup_key = format!("Setup:/Network/Service/{service_id}/DNS");
        let prev_state_plist = store.get(state_key.as_str());

        // SAFETY: `kSCPropNetDNSServerAddresses` is a valid static `CFStringRef` constant exported
        // by Apple's `SystemConfiguration.framework`.
        let addr_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
        let addr_val = CFArray::from_CFTypes(&[CFString::new(&dns_resolver.to_string())]);

        // Build `{ ServerAddresses: [dns_resolver] }` WITHOUT `SupplementalMatchDomains` so Apple
        // registers it as the unscoped primary global resolver, and write to BOTH `State:` and
        // `Setup:` inside `configd`'s ephemeral `SCDynamicStore` RAM.
        let typed_dict = CFDictionary::from_CFType_pairs(&[(addr_key, addr_val)]);
        let untyped_dict = typed_dict.into_untyped();

        if !store.set(state_key.as_str(), untyped_dict.clone()) {
            return Err(HelperError::Backend(format!(
                "SCDynamicStoreSetValue failed for {state_key}"
            )));
        }
        if !store.set(setup_key.as_str(), untyped_dict) {
            match prev_state_plist {
                Some(prev) => {
                    let _ = store.set_raw(state_key.as_str(), &prev);
                }
                None => {
                    let _ = store.remove(state_key.as_str());
                }
            }
            return Err(HelperError::Backend(format!(
                "SCDynamicStoreSetValue failed for {setup_key}"
            )));
        }
        Ok(())
    }

    fn restore_dns_override(&self, snapshot: &DnsSnapshot) -> Result<(), HelperError> {
        snapshot.validate()?;
        let store = open_dynamic_store()?;
        let state_key = format!("State:/Network/Service/{}/DNS", snapshot.service_id);
        let setup_key = format!("Setup:/Network/Service/{}/DNS", snapshot.service_id);

        let state_res = restore_or_remove_sc_dns_key(
            &store,
            &state_key,
            snapshot.had_state_dns,
            snapshot.state_dns_plist_xml.as_deref(),
            &snapshot.service_id,
        );
        let setup_res = restore_or_remove_sc_dns_key(
            &store,
            &setup_key,
            snapshot.had_setup_dns,
            snapshot.setup_dns_plist_xml.as_deref(),
            &snapshot.service_id,
        );
        state_res.and(setup_res)
    }

    fn list_enabled_network_services(&self) -> Result<Vec<String>, HelperError> {
        let stdout = run_checked_binary(
            FixedBinary::Networksetup,
            &["-listallnetworkservices".to_string()],
        )?;
        let mut services = parse_network_services_output(&stdout)?;

        if let Ok(order_out) = run_raw_binary(
            FixedBinary::Networksetup,
            &["-listnetworkserviceorder".to_string()],
        ) && order_out.status.success()
        {
            let order_stdout = String::from_utf8_lossy(&order_out.stdout);
            let hw_backed = parse_hardware_backed_services_from_service_order(&order_stdout);
            if !hw_backed.is_empty() {
                services.retain(|svc| hw_backed.contains(svc));
            }
        }

        Ok(services)
    }

    fn get_service_proxies(&self, service: &str) -> Result<ServiceProxySnapshot, HelperError> {
        validate_service_name(service)?;

        let web_out = run_checked_binary(
            FixedBinary::Networksetup,
            &["-getwebproxy".to_string(), service.to_string()],
        )?;
        let secure_out = run_checked_binary(
            FixedBinary::Networksetup,
            &["-getsecurewebproxy".to_string(), service.to_string()],
        )?;
        let socks_out = run_checked_binary(
            FixedBinary::Networksetup,
            &["-getsocksfirewallproxy".to_string(), service.to_string()],
        )?;
        let bypass_out = run_checked_binary(
            FixedBinary::Networksetup,
            &["-getproxybypassdomains".to_string(), service.to_string()],
        )?;

        Ok(ServiceProxySnapshot {
            service: service.to_string(),
            web: parse_proxy_info_output(&web_out)?,
            secure_web: parse_proxy_info_output(&secure_out)?,
            socks: parse_proxy_info_output(&socks_out)?,
            bypass_domains: parse_proxy_bypass_output(&bypass_out)?,
        })
    }

    fn set_service_proxies(
        &self,
        service: &str,
        host: &str,
        port: u16,
        exceptions: &[String],
    ) -> Result<(), HelperError> {
        validate_service_name(service)?;
        validate_proxy_server_token(host)?;
        if port == 0 {
            return Err(HelperError::Validation(
                HelperValidationError::InvalidListenPort,
            ));
        }
        for entry in exceptions {
            validate_exception_entry(entry)?;
        }

        let port_str = port.to_string();
        for (set_flag, state_flag) in [
            ("-setwebproxy", "-setwebproxystate"),
            ("-setsecurewebproxy", "-setsecurewebproxystate"),
            ("-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
        ] {
            run_checked_binary(
                FixedBinary::Networksetup,
                &[
                    set_flag.to_string(),
                    service.to_string(),
                    host.to_string(),
                    port_str.clone(),
                ],
            )?;
            run_checked_binary(
                FixedBinary::Networksetup,
                &[
                    state_flag.to_string(),
                    service.to_string(),
                    "on".to_string(),
                ],
            )?;
        }

        let mut bypass_args = Vec::with_capacity(2 + exceptions.len().max(1));
        bypass_args.push("-setproxybypassdomains".to_string());
        bypass_args.push(service.to_string());
        if exceptions.is_empty() {
            bypass_args.push("Empty".to_string());
        } else {
            bypass_args.extend(exceptions.iter().cloned());
        }
        run_checked_binary(FixedBinary::Networksetup, &bypass_args)?;

        Ok(())
    }

    fn restore_service_proxies(&self, snapshot: &ServiceProxySnapshot) -> Result<(), HelperError> {
        snapshot.validate()?;
        let svc = &snapshot.service;

        restore_single_proxy_protocol(svc, "-setwebproxy", "-setwebproxystate", &snapshot.web)?;
        restore_single_proxy_protocol(
            svc,
            "-setsecurewebproxy",
            "-setsecurewebproxystate",
            &snapshot.secure_web,
        )?;
        restore_single_proxy_protocol(
            svc,
            "-setsocksfirewallproxy",
            "-setsocksfirewallproxystate",
            &snapshot.socks,
        )?;

        let mut bypass_args = Vec::with_capacity(2 + snapshot.bypass_domains.len().max(1));
        bypass_args.push("-setproxybypassdomains".to_string());
        bypass_args.push(svc.clone());
        if snapshot.bypass_domains.is_empty() {
            bypass_args.push("Empty".to_string());
        } else {
            bypass_args.extend(snapshot.bypass_domains.iter().cloned());
        }
        run_networksetup_ignoring_missing_service(&bypass_args)?;

        Ok(())
    }

    fn subscribe_route_changes(&self) -> Result<mpsc::Receiver<()>, HelperError> {
        // SAFETY: Opening a kernel routing raw socket (`PF_ROUTE`, `SOCK_RAW`, `AF_UNSPEC`) has no
        // memory preconditions and returns a new owned descriptor or `-1` on failure.
        let raw_fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw_fd < 0 {
            return Err(HelperError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `raw_fd >= 0` is a newly created owned socket descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        set_cloexec(fd.as_raw_fd())?;
        set_nonblocking(fd.as_raw_fd())?;

        // SAFETY: `fd` is a valid, open `OwnedFd` for the `PF_ROUTE` socket whose raw descriptor
        // remains open and unchanged for the entire lifetime of `AsyncFd`.
        let async_fd =
            unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE) }
                .map_err(io::Error::from)?;
        // Bounded capacity 1 coalesces bursts of PF_ROUTE messages during Wi-Fi / DHCP handovers.
        let (tx, rx) = mpsc::channel(1);

        tokio::spawn(async move {
            #[repr(C, align(8))]
            struct AlignedRouteBuf([u8; 4096]);

            let mut buf = AlignedRouteBuf([0u8; 4096]);
            loop {
                let mut guard = tokio::select! {
                    () = tx.closed() => break,
                    res = async_fd.readable() => match res {
                        Ok(g) => g,
                        Err(err) => {
                            log::warn!("PF_ROUTE AsyncFd readable failed: {err}");
                            break;
                        }
                    },
                };

                let mut saw_relevant_change = false;
                let mut closed_or_fatal = false;

                let _ = guard.try_io(|inner| {
                    let raw = inner.get_ref().as_raw_fd();
                    loop {
                        // SAFETY: `raw` is a live non-blocking `PF_ROUTE` socket and `buf.0` is a
                        // 4096-byte mutable stack buffer.
                        let n = unsafe {
                            libc::read(raw, buf.0.as_mut_ptr().cast::<libc::c_void>(), buf.0.len())
                        };
                        if n > 0 {
                            let bytes_read = n as usize;
                            if bytes_read >= std::mem::size_of::<libc::rt_msghdr>() {
                                // SAFETY: `AlignedRouteBuf` is 8-byte aligned (>= alignment of
                                // `libc::rt_msghdr`) and `bytes_read >= size_of::<rt_msghdr>()`.
                                let hdr = unsafe { &*buf.0.as_ptr().cast::<libc::rt_msghdr>() };
                                if is_relevant_route_message(hdr) {
                                    saw_relevant_change = true;
                                }
                            }
                            continue;
                        }
                        if n == 0 {
                            closed_or_fatal = true;
                            return Ok(());
                        }
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        if err.raw_os_error() == Some(libc::ENOBUFS) {
                            log::debug!(
                                "PF_ROUTE socket buffer overflow (ENOBUFS); forcing route reconciliation and continuing drain"
                            );
                            saw_relevant_change = true;
                            continue;
                        }
                        if err.kind() == io::ErrorKind::WouldBlock {
                            return Err(err);
                        }
                        log::warn!("PF_ROUTE socket read error: {err}");
                        closed_or_fatal = true;
                        return Ok(());
                    }
                });

                if saw_relevant_change {
                    match tx.try_send(()) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
                        Err(mpsc::error::TrySendError::Closed(())) => break,
                    }
                }

                if closed_or_fatal || tx.is_closed() {
                    break;
                }
            }
        });

        Ok(rx)
    }
}

fn is_relevant_route_message(hdr: &libc::rt_msghdr) -> bool {
    if libc::c_int::from(hdr.rtm_version) != libc::RTM_VERSION {
        return false;
    }
    if hdr.rtm_errno != 0 {
        return false;
    }
    matches!(
        libc::c_int::from(hdr.rtm_type),
        libc::RTM_ADD
            | libc::RTM_DELETE
            | libc::RTM_CHANGE
            | libc::RTM_NEWADDR
            | libc::RTM_DELADDR
            | libc::RTM_IFINFO
            | libc::RTM_IFINFO2
    )
}

fn restore_single_proxy_protocol(
    service: &str,
    set_flag: &str,
    state_flag: &str,
    endpoint: &ProxyEndpointConfig,
) -> Result<(), HelperError> {
    let state_token = if endpoint.enabled { "on" } else { "off" };

    if !endpoint.server.is_empty() && endpoint.port > 0 {
        run_networksetup_ignoring_missing_service(&[
            set_flag.to_string(),
            service.to_string(),
            endpoint.server.clone(),
            endpoint.port.to_string(),
        ])?;
    }

    run_networksetup_ignoring_missing_service(&[
        state_flag.to_string(),
        service.to_string(),
        state_token.to_string(),
    ])
}

fn run_networksetup_ignoring_missing_service(args: &[String]) -> Result<(), HelperError> {
    let out = run_raw_binary(FixedBinary::Networksetup, args)?;
    if out.status.success() {
        return Ok(());
    }
    let combined = combined_output_text(&out);
    if combined
        .to_ascii_lowercase()
        .contains("is not a recognized network service")
    {
        log::warn!("skipping proxy restore on removed network service ({args:?}): {combined}");
        return Ok(());
    }
    Err(command_failed_err(FixedBinary::Networksetup, &out))
}

#[derive(Debug, Default)]
struct ScGlobalNetInfo {
    primary_service: Option<String>,
    primary_interface: Option<String>,
    router: Option<String>,
}

fn open_dynamic_store() -> Result<SCDynamicStore, HelperError> {
    SCDynamicStoreBuilder::new("io.vless-tray.helper")
        .build()
        .ok_or_else(|| HelperError::Backend("failed to create SCDynamicStore session".into()))
}

fn query_sc_global_ipv4(store: &SCDynamicStore) -> Option<ScGlobalNetInfo> {
    let dict = store
        .get("State:/Network/Global/IPv4")
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)?;

    // SAFETY: All three `CFStringRef` statics are exported by `SystemConfiguration.framework`.
    let primary_service =
        unsafe { dict_find_cfstring(&dict, kSCDynamicStorePropNetPrimaryService) }
            .filter(|s| validate_service_uuid_or_id(s).is_ok());
    let primary_interface =
        unsafe { dict_find_cfstring(&dict, kSCDynamicStorePropNetPrimaryInterface) }
            .filter(|s| validate_interface_name(s).is_ok());
    let router = unsafe { dict_find_cfstring(&dict, kSCPropNetIPv4Router) };

    Some(ScGlobalNetInfo {
        primary_service,
        primary_interface,
        router,
    })
}

fn query_sc_global_ipv6(store: &SCDynamicStore) -> Option<ScGlobalNetInfo> {
    let dict = store
        .get("State:/Network/Global/IPv6")
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)?;

    // SAFETY: Exported static `SystemConfiguration.framework` `CFStringRef` keys.
    let primary_service =
        unsafe { dict_find_cfstring(&dict, kSCDynamicStorePropNetPrimaryService) }
            .filter(|s| validate_service_uuid_or_id(s).is_ok());
    let primary_interface =
        unsafe { dict_find_cfstring(&dict, kSCDynamicStorePropNetPrimaryInterface) }
            .filter(|s| validate_interface_name(s).is_ok());
    let router_key = CFString::from_static_string("Router");
    let router = unsafe { dict_find_cfstring(&dict, router_key.as_concrete_TypeRef()) };

    Some(ScGlobalNetInfo {
        primary_service,
        primary_interface,
        router,
    })
}

/// # Safety
/// `key` must be a valid non-null `CFStringRef`.
unsafe fn dict_find_cfstring(dict: &CFDictionary, key: CFStringRef) -> Option<String> {
    let val_ptr = dict.find(key.to_void())?;
    if (*val_ptr).is_null() {
        return None;
    }
    // SAFETY: `*val_ptr` is a non-null `CFTypeRef` owned by `dict`; wrapping under the Get rule
    // retains it safely before runtime type-checking via `downcast_into::<CFString>()`.
    let cf_type = unsafe { CFType::wrap_under_get_rule(*val_ptr) };
    cf_type.downcast_into::<CFString>().map(|s| s.to_string())
}

fn query_default_gateway_v4(
    exclude_utun: Option<&str>,
    sc_v4: Option<&ScGlobalNetInfo>,
) -> Result<Option<DefaultGatewayV4>, HelperError> {
    let out = run_raw_binary(
        FixedBinary::Route,
        &["-n".to_string(), "get".to_string(), "default".to_string()],
    )?;
    if out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(parsed) = parse_route_get_output(&stdout)
            && exclude_utun != Some(parsed.interface.as_str())
            && !parsed.interface.starts_with("utun")
            && let Some(gw_str) = parsed.gateway
            && let Ok(gw_ip) = gw_str.parse::<Ipv4Addr>()
            && validate_server_ip(&IpAddr::V4(gw_ip)).is_ok()
        {
            let if_index = interface_index(&parsed.interface)?;
            return Ok(Some(DefaultGatewayV4 {
                gateway: gw_ip,
                interface: parsed.interface,
                if_index,
            }));
        }
    }

    // Fallback to SCDynamicStore `State:/Network/Global/IPv4` if `route -n get default` was empty
    // or pointed at a `utun` interface.
    if let Some(info) = sc_v4
        && let (Some(iface), Some(router_str)) = (&info.primary_interface, &info.router)
        && exclude_utun != Some(iface.as_str())
        && !iface.starts_with("utun")
        && let Ok(gw_ip) = router_str.parse::<Ipv4Addr>()
        && validate_server_ip(&IpAddr::V4(gw_ip)).is_ok()
    {
        let if_index = interface_index(iface)?;
        return Ok(Some(DefaultGatewayV4 {
            gateway: gw_ip,
            interface: iface.clone(),
            if_index,
        }));
    }

    Ok(None)
}

fn query_default_gateway_v6(
    exclude_utun: Option<&str>,
    sc_v6: Option<&ScGlobalNetInfo>,
) -> Result<Option<DefaultGatewayV6>, HelperError> {
    let out = run_raw_binary(
        FixedBinary::Route,
        &[
            "-n".to_string(),
            "get".to_string(),
            "-inet6".to_string(),
            "default".to_string(),
        ],
    )?;
    if out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(parsed) = parse_route_get_output(&stdout)
            && exclude_utun != Some(parsed.interface.as_str())
            && !parsed.interface.starts_with("utun")
            && let Some(gw_str) = parsed.gateway
            && let Ok(normalized_gw) = normalize_ipv6_gateway(&gw_str, &parsed.interface)
        {
            let if_index = interface_index(&parsed.interface)?;
            return Ok(Some(DefaultGatewayV6 {
                gateway: normalized_gw,
                interface: parsed.interface,
                if_index,
            }));
        }
    }

    if let Some(info) = sc_v6
        && let (Some(iface), Some(router_str)) = (&info.primary_interface, &info.router)
        && exclude_utun != Some(iface.as_str())
        && !iface.starts_with("utun")
        && let Ok(normalized_gw) = normalize_ipv6_gateway(router_str, iface)
    {
        let if_index = interface_index(iface)?;
        return Ok(Some(DefaultGatewayV6 {
            gateway: normalized_gw,
            interface: iface.clone(),
            if_index,
        }));
    }

    Ok(None)
}

fn restore_or_remove_sc_dns_key(
    store: &SCDynamicStore,
    key: &str,
    had_key: bool,
    plist_xml: Option<&str>,
    service_id: &str,
) -> Result<(), HelperError> {
    if had_key {
        let xml = plist_xml.ok_or_else(|| {
            HelperError::Journal(format!(
                "missing DNS plist XML for {key} (service {service_id})"
            ))
        })?;
        let cf_data = CFData::from_buffer(xml.as_bytes());
        let (plist_ptr, _fmt) =
            create_with_data(cf_data, kCFPropertyListImmutable).map_err(|err| {
                HelperError::Backend(format!(
                    "failed to deserialize saved DNS plist for {key}: {err}"
                ))
            })?;
        // SAFETY: `create_with_data` follows CoreFoundation's Create rule and returns a
        // non-null owned `CFPropertyListRef` on `Ok`.
        let plist = unsafe { CFPropertyList::wrap_under_create_rule(plist_ptr) };
        if !store.set_raw(key, &plist) {
            return Err(HelperError::Backend(format!(
                "SCDynamicStoreSetValue failed while restoring {key}"
            )));
        }
    } else if !store.remove(key) && store.get(key).is_some() {
        return Err(HelperError::Backend(format!(
            "SCDynamicStoreRemoveValue failed for {key}"
        )));
    }
    Ok(())
}

fn serialize_plist_to_xml(key_label: &str, plist: &CFPropertyList) -> Result<String, HelperError> {
    let cf_data =
        create_data(plist.as_CFTypeRef(), kCFPropertyListXMLFormat_v1_0).map_err(|err| {
            HelperError::Backend(format!(
                "failed to serialize existing {key_label} plist: {err}"
            ))
        })?;
    String::from_utf8(cf_data.bytes().to_vec()).map_err(|_| {
        HelperError::Backend(format!("serialized {key_label} XML plist was not UTF-8"))
    })
}

fn snapshot_service_dns(
    store: &SCDynamicStore,
    service_id: &str,
) -> Result<DnsSnapshot, HelperError> {
    validate_service_uuid_or_id(service_id)?;
    let state_key = format!("State:/Network/Service/{service_id}/DNS");
    let setup_key = format!("Setup:/Network/Service/{service_id}/DNS");

    let mut had_setup_dns = false;
    let mut setup_dns_plist_xml = None;
    let mut setup_servers = Vec::new();

    if let Some(setup_plist) = store.get(setup_key.as_str()) {
        had_setup_dns = true;
        setup_dns_plist_xml = Some(serialize_plist_to_xml(&setup_key, &setup_plist)?);
        setup_servers = extract_dns_servers_from_plist(&setup_plist);
    }

    let mut had_state_dns = false;
    let mut state_dns_plist_xml = None;
    let mut state_servers = Vec::new();

    if let Some(state_plist) = store.get(state_key.as_str()) {
        had_state_dns = true;
        state_dns_plist_xml = Some(serialize_plist_to_xml(&state_key, &state_plist)?);
        state_servers = extract_dns_servers_from_plist(&state_plist);
    }

    // Prioritize manual DNS (`Setup:`) first, then DHCP DNS (`State:`), then `/etc/resolv.conf`.
    let mut original_dns_servers = if !setup_servers.is_empty() {
        setup_servers
    } else {
        state_servers
    };

    if original_dns_servers.is_empty()
        && let Ok(resolv_conf) = fs::read_to_string("/etc/resolv.conf")
    {
        original_dns_servers = parse_resolv_conf_nameservers(&resolv_conf);
    }

    Ok(DnsSnapshot {
        service_id: service_id.to_string(),
        had_state_dns,
        state_dns_plist_xml,
        had_setup_dns,
        setup_dns_plist_xml,
        original_dns_servers,
    })
}

fn extract_dns_servers_from_plist(plist: &CFPropertyList) -> Vec<IpAddr> {
    let Some(dict) = plist.downcast::<CFDictionary>() else {
        return Vec::new();
    };
    // SAFETY: `kSCPropNetDNSServerAddresses` is a valid static `SystemConfiguration` `CFStringRef`.
    let Some(arr_ptr) = (unsafe { dict.find(kSCPropNetDNSServerAddresses.to_void()) }) else {
        return Vec::new();
    };
    if (*arr_ptr).is_null() {
        return Vec::new();
    }
    // SAFETY: `*arr_ptr` is a non-null `CFTypeRef` borrowed from `dict`.
    let Some(cf_arr) =
        (unsafe { CFType::wrap_under_get_rule(*arr_ptr) }).downcast_into::<CFArray>()
    else {
        return Vec::new();
    };

    let mut servers = Vec::new();
    for item_ptr in &cf_arr {
        if (*item_ptr).is_null() {
            continue;
        }
        // SAFETY: Each element in `cf_arr` is a non-null `CFTypeRef` retained via Get rule before
        // downcasting to `CFString`.
        let Some(cf_str) =
            (unsafe { CFType::wrap_under_get_rule(*item_ptr) }).downcast_into::<CFString>()
        else {
            continue;
        };
        let addr_token = cf_str.to_string();
        let clean = addr_token.split('%').next().unwrap_or("");
        if let Ok(ip) = clean.parse::<IpAddr>()
            && validate_server_ip(&ip).is_ok()
            && !servers.contains(&ip)
        {
            servers.push(ip);
        }
    }
    servers
}

fn interface_index(name: &str) -> Result<u32, HelperError> {
    validate_interface_name(name)?;
    let c_name = CString::new(name).map_err(|_| {
        HelperError::Validation(HelperValidationError::InvalidInterfaceName(
            name.to_string(),
        ))
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated ASCII interface identifier.
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(HelperError::Io(io::Error::last_os_error()));
    }
    Ok(idx)
}

fn run_raw_binary(bin: FixedBinary, args: &[String]) -> Result<Output, HelperError> {
    Command::new(bin.path())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .map_err(HelperError::Io)
}

fn run_checked_binary(bin: FixedBinary, args: &[String]) -> Result<String, HelperError> {
    let out = run_raw_binary(bin, args)?;
    if !out.status.success() {
        return Err(command_failed_err(bin, &out));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn combined_output_text(out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    match (stderr.trim().is_empty(), stdout.trim().is_empty()) {
        (false, true) => stderr.trim().to_string(),
        (true, false) => stdout.trim().to_string(),
        (false, false) => format!("{} | {}", stderr.trim(), stdout.trim()),
        (true, true) => String::new(),
    }
}

fn command_failed_err(bin: FixedBinary, out: &Output) -> HelperError {
    HelperError::CommandFailed {
        program: bin.path().to_string(),
        status: out.status.to_string(),
        stderr: combined_output_text(out),
    }
}
