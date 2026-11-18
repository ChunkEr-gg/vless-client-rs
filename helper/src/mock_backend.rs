//! Deterministic in-memory macOS [`SystemBackend`] simulator for unit and integration testing on
//! Linux and macOS (`PLAN.md` §8 Phases 3, 4, and 6).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Mutex;

use tokio::sync::mpsc;
use vless_ipc::{
    HelperValidationError, validate_exception_entry, validate_interface_name, validate_server_ip,
    validate_service_name,
};

use crate::backend::{
    DefaultGatewayV4, DefaultGatewayV6, DnsSnapshot, NetworkSnapshot, ProxyEndpointConfig,
    RouteAddResult, RouteSpec, ServiceProxySnapshot, SystemBackend, UtunConfig,
};
use crate::error::HelperError;
use crate::launchd::set_cloexec;
use crate::parsers::{validate_proxy_server_token, validate_service_uuid_or_id};

/// Configurable fault-injection hook for testing partial-failure rollback (`PLAN.md` §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockFailPoint {
    SnapshotNetwork,
    CreateUtun,
    ConfigureUtun,
    /// Fail on the Nth (1-indexed) call to `add_route`.
    AddRouteNth(usize),
    SetDnsOverride,
    ListNetworkServices,
    GetServiceProxies(String),
    SetServiceProxies(String),
}

/// Simulated `SCDynamicStore` DNS state for a single `SystemConfiguration` service ID.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockServiceDnsState {
    /// Current `State:/Network/Service/<id>/DNS` `ServerAddresses` (`None` if key is absent).
    pub state_dns_servers: Option<Vec<IpAddr>>,
    /// Current `State:/Network/Service/<id>/DNS` `SupplementalMatchDomains`.
    pub state_supplemental_match_domains: Option<Vec<String>>,
    /// Serialized mock XML plist representing the exact `State:/Network/Service/<id>/DNS` dict.
    pub state_raw_xml: Option<String>,
    /// Persistent `Setup:/Network/Service/<id>/DNS` `ServerAddresses` fallback.
    pub setup_dns_servers: Vec<IpAddr>,
}

/// Simulated `networksetup` state for a single macOS network service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockNetworkService {
    pub enabled: bool,
    pub web: ProxyEndpointConfig,
    pub secure_web: ProxyEndpointConfig,
    pub socks: ProxyEndpointConfig,
    pub bypass_domains: Vec<String>,
}

/// Simulated `utun` interface configuration applied via `configure_utun`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockUtunDevice {
    pub name: String,
    pub config: Option<UtunConfig>,
}

/// Recorded operation log entry for white-box assertions on ordering and rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockOperation {
    SnapshotNetwork {
        exclude_utun: Option<String>,
    },
    CreateUtun {
        name: String,
    },
    ConfigureUtun {
        name: String,
        config: UtunConfig,
    },
    AddRoute(RouteSpec),
    DeleteRoute(RouteSpec),
    SetDnsOverride {
        service_id: String,
        resolver: IpAddr,
    },
    RestoreDnsOverride {
        service_id: String,
        had_state_dns: bool,
    },
    SetServiceProxies {
        service: String,
        host: String,
        port: u16,
        exceptions: Vec<String>,
    },
    RestoreServiceProxies {
        service: String,
    },
}

#[derive(Debug)]
struct MockInner {
    next_utun_unit: u32,
    v4_gateway: Option<DefaultGatewayV4>,
    v6_gateway: Option<DefaultGatewayV6>,
    primary_service_id: Option<String>,
    dns_services: HashMap<String, MockServiceDnsState>,
    network_services: BTreeMap<String, MockNetworkService>,
    service_order: Vec<String>,
    utun_devices: HashMap<String, MockUtunDevice>,
    utun_peers: HashMap<String, StdUnixStream>,
    routes: Vec<RouteSpec>,
    preexisting_routes: HashSet<RouteSpec>,
    add_route_calls: usize,
    fail_point: Option<MockFailPoint>,
    operations: Vec<MockOperation>,
    route_watchers: Vec<mpsc::Sender<()>>,
}

/// Thread-safe, deterministic in-memory [`SystemBackend`] modelling macOS networking APIs.
#[derive(Debug)]
pub struct MockSystemBackend {
    inner: Mutex<MockInner>,
}

impl Default for MockSystemBackend {
    fn default() -> Self {
        Self::new_dual_stack_default()
    }
}

impl MockSystemBackend {
    /// Constructs a realistic default dual-stack macOS environment (`en0` Wi-Fi + disabled
    /// `Thunderbolt Bridge` + enabled `USB 10/100/1000 LAN`).
    pub fn new_dual_stack_default() -> Self {
        let primary_service = "E621E1F8-C36C-495A-93FC-0C247A3E6E5F".to_string();
        let router_dns: IpAddr = "192.168.1.1".parse().unwrap();

        let mut dns_services = HashMap::new();
        dns_services.insert(
            primary_service.clone(),
            MockServiceDnsState {
                state_dns_servers: Some(vec![router_dns]),
                state_supplemental_match_domains: None,
                state_raw_xml: Some(encode_mock_dns_xml(&[router_dns], None)),
                setup_dns_servers: Vec::new(),
            },
        );

        let mut network_services = BTreeMap::new();
        network_services.insert(
            "Wi-Fi".to_string(),
            MockNetworkService {
                enabled: true,
                web: ProxyEndpointConfig {
                    enabled: false,
                    server: String::new(),
                    port: 0,
                },
                secure_web: ProxyEndpointConfig {
                    enabled: false,
                    server: String::new(),
                    port: 0,
                },
                socks: ProxyEndpointConfig {
                    enabled: false,
                    server: String::new(),
                    port: 0,
                },
                bypass_domains: vec!["*.local".to_string(), "169.254/16".to_string()],
            },
        );
        network_services.insert(
            "Thunderbolt Bridge".to_string(),
            MockNetworkService {
                enabled: false,
                web: ProxyEndpointConfig::default(),
                secure_web: ProxyEndpointConfig::default(),
                socks: ProxyEndpointConfig::default(),
                bypass_domains: Vec::new(),
            },
        );
        network_services.insert(
            "USB 10/100/1000 LAN".to_string(),
            MockNetworkService {
                enabled: true,
                web: ProxyEndpointConfig {
                    enabled: true,
                    server: "corp-proxy.internal".to_string(),
                    port: 8080,
                },
                secure_web: ProxyEndpointConfig {
                    enabled: false,
                    server: "corp-proxy.internal".to_string(),
                    port: 8443,
                },
                socks: ProxyEndpointConfig::default(),
                // Explicitly empty bypass list ("There aren't any Bypass Domains set on...")
                bypass_domains: Vec::new(),
            },
        );

        let service_order = vec![
            "Wi-Fi".to_string(),
            "Thunderbolt Bridge".to_string(),
            "USB 10/100/1000 LAN".to_string(),
        ];

        Self {
            inner: Mutex::new(MockInner {
                next_utun_unit: 7,
                v4_gateway: Some(DefaultGatewayV4 {
                    gateway: "192.168.1.1".parse().unwrap(),
                    interface: "en0".to_string(),
                    if_index: 6,
                }),
                v6_gateway: Some(DefaultGatewayV6 {
                    gateway: "fe80::1%en0".to_string(),
                    interface: "en0".to_string(),
                    if_index: 6,
                }),
                primary_service_id: Some(primary_service),
                dns_services,
                network_services,
                service_order,
                utun_devices: HashMap::new(),
                utun_peers: HashMap::new(),
                routes: Vec::new(),
                preexisting_routes: HashSet::new(),
                add_route_calls: 0,
                fail_point: None,
                operations: Vec::new(),
                route_watchers: Vec::new(),
            }),
        }
    }

    /// Configures an IPv4-only physical network (`v6_gateway = None`).
    pub fn set_ipv6_gateway(&self, v6_gateway: Option<DefaultGatewayV6>) {
        let mut guard = self.inner.lock().unwrap();
        guard.v6_gateway = v6_gateway;
    }

    /// Configures the IPv4 default gateway (`None` simulates an IPv6-only or disconnected host).
    pub fn set_ipv4_gateway(&self, v4_gateway: Option<DefaultGatewayV4>) {
        let mut guard = self.inner.lock().unwrap();
        guard.v4_gateway = v4_gateway;
    }

    /// Sets or clears a deterministic fault-injection point (`MockFailPoint`) and resets the
    /// `add_route` call counter.
    pub fn set_fail_point(&self, fail_point: Option<MockFailPoint>) {
        let mut guard = self.inner.lock().unwrap();
        guard.fail_point = fail_point;
        guard.add_route_calls = 0;
    }

    /// Inserts a pre-existing OS route (`EEXIST` / `AlreadyExisted` on `add_route`).
    pub fn insert_preexisting_route(&self, route: RouteSpec) {
        let mut guard = self.inner.lock().unwrap();
        if !guard.routes.contains(&route) {
            guard.routes.push(route.clone());
        }
        guard.preexisting_routes.insert(route);
    }

    /// Configures DNS state for a `SystemConfiguration` service ID.
    pub fn set_service_dns_state(&self, service_id: &str, state: MockServiceDnsState) {
        let mut guard = self.inner.lock().unwrap();
        guard.dns_services.insert(service_id.to_string(), state);
    }

    /// Configures a network service entry (`networksetup`).
    pub fn set_network_service(&self, name: &str, svc: MockNetworkService) {
        let mut guard = self.inner.lock().unwrap();
        if !guard.service_order.iter().any(|s| s == name) {
            guard.service_order.push(name.to_string());
        }
        guard.network_services.insert(name.to_string(), svc);
    }

    /// Removes a network service (simulating unplugging a USB Ethernet adapter while active).
    pub fn remove_network_service(&self, name: &str) {
        let mut guard = self.inner.lock().unwrap();
        guard.network_services.remove(name);
        guard.service_order.retain(|s| s != name);
    }

    /// Extracts the simulated "kernel" peer half of the `UnixStream::pair()` backing `utun_name`.
    ///
    /// Once extracted, the ONLY other open file descriptor for that socketpair is the `OwnedFd`
    /// returned by `create_utun` (and passed to the client via `SCM_RIGHTS`). Closing the client's
    /// `OwnedFd` will immediately produce `Ok(0)` EOF on this peer stream if and only if the
    /// helper retained zero copies of `utun_fd`.
    pub fn take_utun_peer(&self, utun_name: &str) -> Option<StdUnixStream> {
        let mut guard = self.inner.lock().unwrap();
        guard.utun_peers.remove(utun_name)
    }

    /// Returns a snapshot of all currently installed routes in order.
    pub fn routes(&self) -> Vec<RouteSpec> {
        let guard = self.inner.lock().unwrap();
        guard.routes.clone()
    }

    /// Replaces the current routing table directly (useful for seeding crash-recovery tests).
    pub fn seed_routes(&self, routes: Vec<RouteSpec>) {
        let mut guard = self.inner.lock().unwrap();
        guard.routes = routes;
    }

    /// Returns the simulated `SCDynamicStore` DNS state for `service_id`.
    pub fn dns_state(&self, service_id: &str) -> Option<MockServiceDnsState> {
        let guard = self.inner.lock().unwrap();
        guard.dns_services.get(service_id).cloned()
    }

    /// Returns the simulated `networksetup` proxy state for `service`.
    pub fn service_state(&self, service: &str) -> Option<MockNetworkService> {
        let guard = self.inner.lock().unwrap();
        guard.network_services.get(service).cloned()
    }

    /// Returns the configured `MockUtunDevice` for `utun_name`.
    pub fn utun_device(&self, utun_name: &str) -> Option<MockUtunDevice> {
        let guard = self.inner.lock().unwrap();
        guard.utun_devices.get(utun_name).cloned()
    }

    /// Returns the chronological log of operations executed against this backend.
    pub fn operations(&self) -> Vec<MockOperation> {
        let guard = self.inner.lock().unwrap();
        guard.operations.clone()
    }

    /// Updates the simulated physical network gateways/service/DNS and fires a `PF_ROUTE` event to
    /// all subscribed watchers.
    pub fn simulate_network_transition(
        &self,
        v4_gateway: Option<DefaultGatewayV4>,
        v6_gateway: Option<DefaultGatewayV6>,
        primary_service_id: Option<String>,
        new_service_dns: Option<(String, MockServiceDnsState)>,
    ) {
        let watchers = {
            let mut guard = self.inner.lock().unwrap();
            guard.v4_gateway = v4_gateway;
            guard.v6_gateway = v6_gateway;
            guard.primary_service_id = primary_service_id;
            if let Some((svc_id, dns_state)) = new_service_dns {
                guard.dns_services.insert(svc_id, dns_state);
            }
            guard.route_watchers.retain(|tx| !tx.is_closed());
            guard.route_watchers.clone()
        };

        for tx in watchers {
            let _ = tx.try_send(());
        }
    }

    /// Emits a raw `PF_ROUTE` wakeup without changing physical gateways (tests self-event filtering).
    pub fn emit_spurious_route_event(&self) {
        let watchers = {
            let mut guard = self.inner.lock().unwrap();
            guard.route_watchers.retain(|tx| !tx.is_closed());
            guard.route_watchers.clone()
        };
        for tx in watchers {
            let _ = tx.try_send(());
        }
    }
}

impl SystemBackend for MockSystemBackend {
    fn snapshot_network(&self, exclude_utun: Option<&str>) -> Result<NetworkSnapshot, HelperError> {
        let mut guard = self.inner.lock().unwrap();
        guard.operations.push(MockOperation::SnapshotNetwork {
            exclude_utun: exclude_utun.map(str::to_string),
        });

        if guard.fail_point == Some(MockFailPoint::SnapshotNetwork) {
            return Err(HelperError::Backend(
                "injected fault: SnapshotNetwork".into(),
            ));
        }

        let v4_gateway = guard
            .v4_gateway
            .clone()
            .filter(|gw| exclude_utun != Some(gw.interface.as_str()));
        let v6_gateway = guard
            .v6_gateway
            .clone()
            .filter(|gw| exclude_utun != Some(gw.interface.as_str()));
        let primary_service_id = guard.primary_service_id.clone();

        let dns_snapshot = if let Some(ref svc_id) = primary_service_id {
            validate_service_uuid_or_id(svc_id)?;
            let dns_entry = guard.dns_services.get(svc_id).cloned().unwrap_or_default();
            let had_setup_dns = !dns_entry.setup_dns_servers.is_empty();
            let setup_dns_plist_xml =
                had_setup_dns.then(|| encode_mock_dns_xml(&dns_entry.setup_dns_servers, None));

            let had_state_dns = dns_entry.state_dns_servers.is_some();
            let state_dns_plist_xml = if had_state_dns {
                Some(dns_entry.state_raw_xml.unwrap_or_else(|| {
                    encode_mock_dns_xml(
                        dns_entry.state_dns_servers.as_deref().unwrap_or(&[]),
                        dns_entry.state_supplemental_match_domains.as_deref(),
                    )
                }))
            } else {
                None
            };
            let original_dns_servers = if !dns_entry.setup_dns_servers.is_empty() {
                dns_entry.setup_dns_servers
            } else {
                dns_entry.state_dns_servers.unwrap_or_default()
            };
            Some(DnsSnapshot {
                service_id: svc_id.clone(),
                had_state_dns,
                state_dns_plist_xml,
                had_setup_dns,
                setup_dns_plist_xml,
                original_dns_servers,
            })
        } else {
            None
        };

        Ok(NetworkSnapshot {
            v4_gateway,
            v6_gateway,
            primary_service_id,
            dns_snapshot,
        })
    }

    fn create_utun(&self) -> Result<(OwnedFd, String), HelperError> {
        let mut guard = self.inner.lock().unwrap();
        if guard.fail_point == Some(MockFailPoint::CreateUtun) {
            return Err(HelperError::Backend("injected fault: CreateUtun".into()));
        }

        let unit = guard.next_utun_unit;
        guard.next_utun_unit += 1;
        let utun_name = format!("utun{unit}");
        validate_interface_name(&utun_name)?;

        let (kernel_side, client_side) = StdUnixStream::pair()?;
        set_cloexec(kernel_side.as_raw_fd())?;
        set_cloexec(client_side.as_raw_fd())?;

        guard.utun_devices.insert(
            utun_name.clone(),
            MockUtunDevice {
                name: utun_name.clone(),
                config: None,
            },
        );
        guard.utun_peers.insert(utun_name.clone(), kernel_side);
        guard.operations.push(MockOperation::CreateUtun {
            name: utun_name.clone(),
        });

        Ok((OwnedFd::from(client_side), utun_name))
    }

    fn configure_utun(&self, utun_name: &str, config: &UtunConfig) -> Result<(), HelperError> {
        validate_interface_name(utun_name)?;
        let mut guard = self.inner.lock().unwrap();
        guard.operations.push(MockOperation::ConfigureUtun {
            name: utun_name.to_string(),
            config: config.clone(),
        });

        if guard.fail_point == Some(MockFailPoint::ConfigureUtun) {
            return Err(HelperError::Backend("injected fault: ConfigureUtun".into()));
        }

        let dev = guard.utun_devices.get_mut(utun_name).ok_or_else(|| {
            HelperError::Backend(format!("unknown mock utun interface {utun_name}"))
        })?;
        dev.config = Some(config.clone());
        Ok(())
    }

    fn add_route(&self, route: &RouteSpec) -> Result<RouteAddResult, HelperError> {
        route.validate()?;
        let mut guard = self.inner.lock().unwrap();
        guard.add_route_calls += 1;
        let call_num = guard.add_route_calls;
        guard
            .operations
            .push(MockOperation::AddRoute(route.clone()));

        if guard.fail_point == Some(MockFailPoint::AddRouteNth(call_num)) {
            return Err(HelperError::Backend(format!(
                "injected fault: AddRouteNth({call_num})"
            )));
        }

        if guard.routes.contains(route)
            || guard
                .routes
                .iter()
                .any(|r| r.destination == route.destination)
        {
            return Ok(RouteAddResult::AlreadyExisted);
        }

        guard.routes.push(route.clone());
        Ok(RouteAddResult::Added)
    }

    fn delete_route(&self, route: &RouteSpec) -> Result<(), HelperError> {
        route.validate()?;
        let mut guard = self.inner.lock().unwrap();
        guard
            .operations
            .push(MockOperation::DeleteRoute(route.clone()));
        guard.routes.retain(|existing| existing != route);
        Ok(())
    }

    fn set_dns_override(&self, service_id: &str, dns_resolver: IpAddr) -> Result<(), HelperError> {
        validate_service_uuid_or_id(service_id)?;
        validate_server_ip(&dns_resolver)?;

        let mut guard = self.inner.lock().unwrap();
        guard.operations.push(MockOperation::SetDnsOverride {
            service_id: service_id.to_string(),
            resolver: dns_resolver,
        });

        if guard.fail_point == Some(MockFailPoint::SetDnsOverride) {
            return Err(HelperError::Backend(
                "injected fault: SetDnsOverride".into(),
            ));
        }

        let entry = guard
            .dns_services
            .entry(service_id.to_string())
            .or_default();
        entry.state_dns_servers = Some(vec![dns_resolver]);
        entry.state_supplemental_match_domains = None;
        entry.state_raw_xml = Some(encode_mock_dns_xml(&[dns_resolver], None));
        entry.setup_dns_servers = vec![dns_resolver];
        Ok(())
    }

    fn restore_dns_override(&self, snapshot: &DnsSnapshot) -> Result<(), HelperError> {
        snapshot.validate()?;
        let mut guard = self.inner.lock().unwrap();
        guard.operations.push(MockOperation::RestoreDnsOverride {
            service_id: snapshot.service_id.clone(),
            had_state_dns: snapshot.had_state_dns,
        });

        let entry = guard
            .dns_services
            .entry(snapshot.service_id.clone())
            .or_default();

        if snapshot.had_state_dns {
            let xml = snapshot.state_dns_plist_xml.clone().ok_or_else(|| {
                HelperError::Journal("missing state_dns_plist_xml in DnsSnapshot".into())
            })?;
            let (servers, match_domains) =
                decode_mock_dns_xml(&xml, &snapshot.original_dns_servers);
            entry.state_dns_servers = Some(servers);
            entry.state_supplemental_match_domains = match_domains;
            entry.state_raw_xml = Some(xml);
        } else {
            entry.state_dns_servers = None;
            entry.state_supplemental_match_domains = None;
            entry.state_raw_xml = None;
        }

        if snapshot.had_setup_dns {
            let xml = snapshot.setup_dns_plist_xml.clone().ok_or_else(|| {
                HelperError::Journal("missing setup_dns_plist_xml in DnsSnapshot".into())
            })?;
            let (servers, _) = decode_mock_dns_xml(&xml, &snapshot.original_dns_servers);
            entry.setup_dns_servers = servers;
        } else {
            entry.setup_dns_servers.clear();
        }
        Ok(())
    }

    fn list_enabled_network_services(&self) -> Result<Vec<String>, HelperError> {
        let guard = self.inner.lock().unwrap();
        if guard.fail_point == Some(MockFailPoint::ListNetworkServices) {
            return Err(HelperError::Backend(
                "injected fault: ListNetworkServices".into(),
            ));
        }

        let mut out = Vec::new();
        for name in &guard.service_order {
            if let Some(svc) = guard.network_services.get(name)
                && svc.enabled
            {
                validate_service_name(name)?;
                out.push(name.clone());
            }
        }
        Ok(out)
    }

    fn get_service_proxies(&self, service: &str) -> Result<ServiceProxySnapshot, HelperError> {
        validate_service_name(service)?;
        let guard = self.inner.lock().unwrap();
        if guard.fail_point == Some(MockFailPoint::GetServiceProxies(service.to_string())) {
            return Err(HelperError::Backend(format!(
                "injected fault: GetServiceProxies({service})"
            )));
        }

        let svc = guard.network_services.get(service).ok_or_else(|| {
            HelperError::Backend(format!("{service} is not a recognized network service"))
        })?;

        Ok(ServiceProxySnapshot {
            service: service.to_string(),
            web: svc.web.clone(),
            secure_web: svc.secure_web.clone(),
            socks: svc.socks.clone(),
            bypass_domains: svc.bypass_domains.clone(),
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

        let mut guard = self.inner.lock().unwrap();
        guard.operations.push(MockOperation::SetServiceProxies {
            service: service.to_string(),
            host: host.to_string(),
            port,
            exceptions: exceptions.to_vec(),
        });

        if guard.fail_point == Some(MockFailPoint::SetServiceProxies(service.to_string())) {
            return Err(HelperError::Backend(format!(
                "injected fault: SetServiceProxies({service})"
            )));
        }

        let svc = guard.network_services.get_mut(service).ok_or_else(|| {
            HelperError::Backend(format!("{service} is not a recognized network service"))
        })?;

        let ep = ProxyEndpointConfig {
            enabled: true,
            server: host.to_string(),
            port,
        };
        svc.web = ep.clone();
        svc.secure_web = ep.clone();
        svc.socks = ep;
        svc.bypass_domains = exceptions.to_vec();
        Ok(())
    }

    fn restore_service_proxies(&self, snapshot: &ServiceProxySnapshot) -> Result<(), HelperError> {
        snapshot.validate()?;
        let mut guard = self.inner.lock().unwrap();
        guard.operations.push(MockOperation::RestoreServiceProxies {
            service: snapshot.service.clone(),
        });

        // Mirrors macOS restore behavior when a removable USB adapter disappeared mid-session.
        let Some(svc) = guard.network_services.get_mut(&snapshot.service) else {
            return Ok(());
        };

        svc.web = snapshot.web.clone();
        svc.secure_web = snapshot.secure_web.clone();
        svc.socks = snapshot.socks.clone();
        svc.bypass_domains = snapshot.bypass_domains.clone();
        Ok(())
    }

    fn subscribe_route_changes(&self) -> Result<mpsc::Receiver<()>, HelperError> {
        let (tx, rx) = mpsc::channel(4);
        let mut guard = self.inner.lock().unwrap();
        guard.route_watchers.push(tx);
        Ok(rx)
    }
}

/// Encodes a deterministic XML plist string representing a `State:/Network/Service/<id>/DNS` dict.
pub fn encode_mock_dns_xml(
    servers: &[IpAddr],
    supplemental_match_domains: Option<&[String]>,
) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>ServerAddresses</key><array>",
    );
    for ip in servers {
        xml.push_str("<string>");
        xml.push_str(&ip.to_string());
        xml.push_str("</string>");
    }
    xml.push_str("</array>");
    if let Some(domains) = supplemental_match_domains {
        xml.push_str("<key>SupplementalMatchDomains</key><array>");
        for d in domains {
            xml.push_str("<string>");
            xml.push_str(d);
            xml.push_str("</string>");
        }
        xml.push_str("</array>");
    }
    xml.push_str("</dict></plist>\n");
    xml
}

fn decode_mock_dns_xml(
    xml: &str,
    fallback_servers: &[IpAddr],
) -> (Vec<IpAddr>, Option<Vec<String>>) {
    let mut servers = Vec::new();
    if let Some((_, after_sa)) = xml.split_once("<key>ServerAddresses</key><array>")
        && let Some((arr_body, _)) = after_sa.split_once("</array>")
    {
        let mut rem = arr_body;
        while let Some((_, after_open)) = rem.split_once("<string>") {
            let Some((val, rest)) = after_open.split_once("</string>") else {
                break;
            };
            if let Ok(ip) = val.parse::<IpAddr>() {
                servers.push(ip);
            }
            rem = rest;
        }
    }
    if servers.is_empty() {
        servers = fallback_servers.to_vec();
    }

    let mut match_domains = None;
    if let Some((_, after_md)) = xml.split_once("<key>SupplementalMatchDomains</key><array>")
        && let Some((arr_body, _)) = after_md.split_once("</array>")
    {
        let mut domains = Vec::new();
        let mut rem = arr_body;
        while let Some((_, after_open)) = rem.split_once("<string>") {
            let Some((val, rest)) = after_open.split_once("</string>") else {
                break;
            };
            domains.push(val.to_string());
            rem = rest;
        }
        match_domains = Some(domains);
    }

    (servers, match_domains)
}
