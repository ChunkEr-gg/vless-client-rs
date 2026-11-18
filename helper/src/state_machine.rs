//! Core `vless-tray-helper` state machine (`StartTun`, `StartSystemProxy`, `UpdateServerRoute`,
//! `Stop`, `Status`, `PF_ROUTE` network migrations, partial-failure rollback, and EOF teardown).

use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipnetwork::IpNetwork;
use vless_ipc::{
    HelperCommand, HelperMessage, HelperMode, HelperResponse, HelperStatus,
    builtin_system_proxy_exceptions, builtin_tun_bypass_cidrs, validate_cidr,
    validate_exception_entry,
};

use crate::backend::{
    DefaultGatewayV4, DefaultGatewayV6, DnsSnapshot, RouteAddResult, RouteDestination, RouteSpec,
    RouteTarget, ServiceProxySnapshot, SystemBackend, TUN_CAPTURE_CIDR_STRS, UTUN_IPV4_SUBNET_STR,
    UtunConfig,
};
use crate::error::HelperError;
use crate::journal::{
    HelperJournal, JOURNAL_SCHEMA_VERSION, delete_journal, recover_if_present,
    restore_from_journal, save_journal,
};

/// Result of executing a single [`HelperCommand`] against [`HelperStateMachine`].
#[derive(Debug)]
pub struct CommandOutcome {
    pub response: HelperResponse,
    /// Sole `OwnedFd` for the newly created `utun` device (set **only** when `response` is
    /// [`HelperResponse::TunReady`]). The caller must transmit it via `SCM_RIGHTS` and drop it
    /// immediately (`PLAN.md` §4).
    pub utun_fd: Option<OwnedFd>,
}

#[derive(Debug)]
struct ActiveTunState {
    utun_name: String,
    v4_gateway: Option<DefaultGatewayV4>,
    v6_gateway: Option<DefaultGatewayV6>,
    outbound_if_name: String,
    outbound_if_index: u32,
    dns_snapshot: DnsSnapshot,
    dns_resolver: IpAddr,
    server_ips: Vec<IpAddr>,
    bypass_cidrs: Vec<IpNetwork>,
    installed_routes: Vec<RouteSpec>,
}

impl ActiveTunState {
    fn to_journal(&self) -> HelperJournal {
        HelperJournal::Tun {
            version: JOURNAL_SCHEMA_VERSION,
            utun_name: self.utun_name.clone(),
            v4_gateway: self.v4_gateway.clone(),
            v6_gateway: self.v6_gateway.clone(),
            dns_snapshots: vec![self.dns_snapshot.clone()],
            dns_resolver: self.dns_resolver,
            server_ips: self.server_ips.clone(),
            bypass_cidrs: self.bypass_cidrs.clone(),
            routes: self.installed_routes.clone(),
        }
    }
}

#[derive(Debug)]
struct ActiveProxyState {
    listen_port: u16,
    exceptions: Vec<String>,
    services: Vec<ServiceProxySnapshot>,
}

impl ActiveProxyState {
    fn to_journal(&self) -> HelperJournal {
        HelperJournal::SystemProxy {
            version: JOURNAL_SCHEMA_VERSION,
            listen_port: self.listen_port,
            exceptions: self.exceptions.clone(),
            services: self.services.clone(),
        }
    }
}

#[derive(Debug, Default)]
enum ActiveSessionState {
    #[default]
    Idle,
    Tun(Box<ActiveTunState>),
    SystemProxy(ActiveProxyState),
}

/// Stateful controller owning the active VPN/proxy mode and `helper-state.json` lifecycle.
#[derive(Debug)]
pub struct HelperStateMachine<B: SystemBackend> {
    backend: Arc<B>,
    state_path: PathBuf,
    active: ActiveSessionState,
}

impl<B: SystemBackend> HelperStateMachine<B> {
    /// Creates a new idle state machine backed by `backend` and journal file `state_path`.
    pub fn new(backend: Arc<B>, state_path: PathBuf) -> Self {
        Self {
            backend,
            state_path,
            active: ActiveSessionState::Idle,
        }
    }

    /// Returns a reference to the underlying [`SystemBackend`].
    pub fn backend(&self) -> &Arc<B> {
        &self.backend
    }

    /// Returns the path to `helper-state.json`.
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Returns the current [`HelperMode`].
    pub fn mode(&self) -> HelperMode {
        match &self.active {
            ActiveSessionState::Idle => HelperMode::Idle,
            ActiveSessionState::Tun(_) => HelperMode::Tun,
            ActiveSessionState::SystemProxy(_) => HelperMode::SystemProxy,
        }
    }

    /// Returns the current [`HelperStatus`] snapshot.
    pub fn status(&self) -> HelperStatus {
        match &self.active {
            ActiveSessionState::Idle => HelperStatus {
                mode: HelperMode::Idle,
                utun_name: None,
                outbound_if_index: None,
                outbound_if_name: None,
                original_dns_servers: Vec::new(),
            },
            ActiveSessionState::Tun(tun) => HelperStatus {
                mode: HelperMode::Tun,
                utun_name: Some(tun.utun_name.clone()),
                outbound_if_index: Some(tun.outbound_if_index),
                outbound_if_name: Some(tun.outbound_if_name.clone()),
                original_dns_servers: tun.dns_snapshot.original_dns_servers.clone(),
            },
            ActiveSessionState::SystemProxy(_) => HelperStatus {
                mode: HelperMode::SystemProxy,
                utun_name: None,
                outbound_if_index: None,
                outbound_if_name: None,
                original_dns_servers: Vec::new(),
            },
        }
    }

    /// Recovers and deletes any leftover `helper-state.json` from an earlier unclean shutdown.
    pub fn recover_leftover_journal(&mut self) -> Result<bool, HelperError> {
        recover_if_present(&*self.backend, &self.state_path)
    }

    /// Validates and executes a [`HelperCommand`], converting any operational or validation error
    /// into [`HelperResponse::Error`] (after rolling back any partial mutations).
    pub fn handle_command(&mut self, cmd: HelperCommand) -> CommandOutcome {
        if let Err(err) = cmd.validate() {
            return CommandOutcome {
                response: HelperResponse::Error {
                    message: err.to_string(),
                },
                utun_fd: None,
            };
        }

        let res = match cmd {
            HelperCommand::StartTun {
                server_ips,
                bypass_cidrs,
                dns_resolver,
            } => self.start_tun(server_ips, bypass_cidrs, dns_resolver),
            HelperCommand::StartSystemProxy {
                listen_port,
                exceptions,
            } => self
                .start_system_proxy(listen_port, exceptions)
                .map(|response| CommandOutcome {
                    response,
                    utun_fd: None,
                }),
            HelperCommand::UpdateServerRoute { server_ips } => self
                .update_server_route(server_ips)
                .map(|response| CommandOutcome {
                    response,
                    utun_fd: None,
                }),
            HelperCommand::Stop => self.stop().map(|()| CommandOutcome {
                response: HelperResponse::Stopped,
                utun_fd: None,
            }),
            HelperCommand::Status => Ok(CommandOutcome {
                response: HelperResponse::Status(self.status()),
                utun_fd: None,
            }),
        };

        match res {
            Ok(outcome) => outcome,
            Err(err) => {
                log::warn!("helper command failed: {err}");
                CommandOutcome {
                    response: HelperResponse::Error {
                        message: err.to_string(),
                    },
                    utun_fd: None,
                }
            }
        }
    }

    /// Tears down any active TUN or System Proxy session, restores system state from the journal,
    /// and deletes `helper-state.json`. Safe and idempotent when already `Idle`.
    pub fn stop(&mut self) -> Result<(), HelperError> {
        let prev = std::mem::replace(&mut self.active, ActiveSessionState::Idle);
        let journal = match prev {
            ActiveSessionState::Idle => {
                delete_journal(&self.state_path)?;
                return Ok(());
            }
            ActiveSessionState::Tun(tun) => tun.to_journal(),
            ActiveSessionState::SystemProxy(proxy) => proxy.to_journal(),
        };

        if let Err(err) = restore_from_journal(&*self.backend, &journal) {
            log::warn!("teardown completed with non-fatal backend warning: {err}");
        }
        delete_journal(&self.state_path)?;
        Ok(())
    }

    /// Handles an asynchronous kernel routing/interface change notification (`PF_ROUTE`,
    /// `PLAN.md` §5.5).
    ///
    /// When in `HelperMode::Tun` and the physical gateway, outbound interface, or primary
    /// `SystemConfiguration` service has changed, moves server host routes, bypass CIDR routes,
    /// and DNS overrides to the new network and returns `Some(HelperMessage::NetworkChanged { .. })`.
    pub fn handle_route_change(&mut self) -> Result<Option<HelperMessage>, HelperError> {
        let ActiveSessionState::Tun(ref mut tun) = self.active else {
            return Ok(None);
        };

        let snap = self.backend.snapshot_network(Some(&tun.utun_name))?;
        let Some((outbound_if_name, outbound_if_index)) = snap.primary_outbound_interface() else {
            log::debug!(
                "ignoring transient PF_ROUTE event while physical default route is unavailable"
            );
            return Ok(None);
        };

        let new_service_id = snap
            .primary_service_id
            .as_deref()
            .unwrap_or(&tun.dns_snapshot.service_id);
        let same_service = new_service_id == tun.dns_snapshot.service_id;

        if snap.v4_gateway == tun.v4_gateway && snap.v6_gateway == tun.v6_gateway && same_service {
            return Ok(None);
        }

        let server_ips = tun.server_ips.clone();
        reconcile_tun_routes_and_dns(
            &*self.backend,
            &self.state_path,
            tun,
            &snap,
            outbound_if_name,
            outbound_if_index,
            server_ips,
        )?;

        Ok(Some(HelperMessage::NetworkChanged {
            outbound_if_index: tun.outbound_if_index,
            outbound_if_name: tun.outbound_if_name.clone(),
            original_dns_servers: tun.dns_snapshot.original_dns_servers.clone(),
        }))
    }

    fn start_tun(
        &mut self,
        raw_server_ips: Vec<IpAddr>,
        raw_bypass_cidrs: Vec<IpNetwork>,
        dns_resolver: IpAddr,
    ) -> Result<CommandOutcome, HelperError> {
        if !matches!(self.active, ActiveSessionState::Idle) {
            return Err(HelperError::InvalidState(format!(
                "cannot start TUN while helper is already in {:?} mode; send stop first",
                self.mode()
            )));
        }

        let server_ips = dedup_ips(&raw_server_ips);
        let bypass_cidrs = merge_tun_bypass_cidrs(&raw_bypass_cidrs)?;

        let snap = self.backend.snapshot_network(None)?;
        let Some((outbound_if_name, outbound_if_index)) = snap.primary_outbound_interface() else {
            return Err(HelperError::Backend(
                "no active physical default gateway/interface found".into(),
            ));
        };
        let Some(dns_snapshot) = snap.dns_snapshot.clone() else {
            return Err(HelperError::Backend(
                "no primary SystemConfiguration network service found for leak-free DNS override"
                    .into(),
            ));
        };

        ensure_routable_server_ips(
            &server_ips,
            snap.v4_gateway.as_ref(),
            snap.v6_gateway.as_ref(),
        )?;

        let (utun_fd, utun_name) = self.backend.create_utun()?;
        let (utun_subnet_route, utun_capture_routes) = build_utun_interface_routes(&utun_name)?;
        let gw_routes = build_gateway_routes(
            snap.v4_gateway.as_ref(),
            snap.v6_gateway.as_ref(),
            &server_ips,
            &bypass_cidrs,
        );

        let mut planned_routes =
            Vec::with_capacity(1 + gw_routes.len() + utun_capture_routes.len());
        planned_routes.push(utun_subnet_route);
        planned_routes.extend(gw_routes);
        planned_routes.extend(utun_capture_routes);

        let planned_journal = HelperJournal::Tun {
            version: JOURNAL_SCHEMA_VERSION,
            utun_name: utun_name.clone(),
            v4_gateway: snap.v4_gateway.clone(),
            v6_gateway: snap.v6_gateway.clone(),
            dns_snapshots: vec![dns_snapshot.clone()],
            dns_resolver,
            server_ips: server_ips.clone(),
            bypass_cidrs: bypass_cidrs.clone(),
            routes: planned_routes.clone(),
        };

        // CRITICAL (`PLAN.md` §5.1): Persist the full planned journal with mode 0600 BEFORE
        // executing a single mutating OS command.
        save_journal(&self.state_path, &planned_journal)?;

        let mut installed_routes = Vec::with_capacity(planned_routes.len());
        let mut dns_overridden = false;

        let setup_res = (|| -> Result<(), HelperError> {
            self.backend
                .configure_utun(&utun_name, &UtunConfig::default())?;

            for route in &planned_routes {
                match self.backend.add_route(route)? {
                    RouteAddResult::Added => installed_routes.push(route.clone()),
                    RouteAddResult::AlreadyExisted => {
                        log::debug!(
                            "skipping journal deletion ownership for preexisting route {route:?}"
                        );
                    }
                }
            }

            self.backend
                .set_dns_override(&dns_snapshot.service_id, dns_resolver)?;
            dns_overridden = true;
            Ok(())
        })();

        if let Err(err) = setup_res {
            drop(utun_fd);
            rollback_partial_tun(
                &*self.backend,
                &self.state_path,
                &installed_routes,
                dns_overridden.then_some(&dns_snapshot),
            );
            return Err(err);
        }

        let active_tun = ActiveTunState {
            utun_name: utun_name.clone(),
            v4_gateway: snap.v4_gateway,
            v6_gateway: snap.v6_gateway,
            outbound_if_name: outbound_if_name.clone(),
            outbound_if_index,
            dns_snapshot: dns_snapshot.clone(),
            dns_resolver,
            server_ips,
            bypass_cidrs,
            installed_routes,
        };

        if let Err(err) = save_journal(&self.state_path, &active_tun.to_journal()) {
            drop(utun_fd);
            rollback_partial_tun(
                &*self.backend,
                &self.state_path,
                &active_tun.installed_routes,
                Some(&active_tun.dns_snapshot),
            );
            return Err(err);
        }

        let original_dns_servers = active_tun.dns_snapshot.original_dns_servers.clone();
        self.active = ActiveSessionState::Tun(Box::new(active_tun));

        Ok(CommandOutcome {
            response: HelperResponse::TunReady {
                utun_name,
                outbound_if_index,
                outbound_if_name,
                original_dns_servers,
            },
            utun_fd: Some(utun_fd),
        })
    }

    fn update_server_route(
        &mut self,
        raw_server_ips: Vec<IpAddr>,
    ) -> Result<HelperResponse, HelperError> {
        let ActiveSessionState::Tun(ref mut tun) = self.active else {
            return Err(HelperError::InvalidState(
                "update_server_route is only valid while TUN mode is active".into(),
            ));
        };

        let new_server_ips = dedup_ips(&raw_server_ips);
        let snap = self.backend.snapshot_network(Some(&tun.utun_name))?;
        let Some((outbound_if_name, outbound_if_index)) = snap.primary_outbound_interface() else {
            return Err(HelperError::Backend(
                "no active physical default gateway/interface available for server route update"
                    .into(),
            ));
        };

        ensure_routable_server_ips(
            &new_server_ips,
            snap.v4_gateway.as_ref(),
            snap.v6_gateway.as_ref(),
        )?;

        reconcile_tun_routes_and_dns(
            &*self.backend,
            &self.state_path,
            tun,
            &snap,
            outbound_if_name,
            outbound_if_index,
            new_server_ips,
        )?;

        Ok(HelperResponse::ServerRouteUpdated {
            outbound_if_index: tun.outbound_if_index,
            outbound_if_name: tun.outbound_if_name.clone(),
            original_dns_servers: tun.dns_snapshot.original_dns_servers.clone(),
        })
    }

    fn start_system_proxy(
        &mut self,
        listen_port: u16,
        raw_exceptions: Vec<String>,
    ) -> Result<HelperResponse, HelperError> {
        if !matches!(self.active, ActiveSessionState::Idle) {
            return Err(HelperError::InvalidState(format!(
                "cannot start SystemProxy while helper is already in {:?} mode; send stop first",
                self.mode()
            )));
        }

        let merged_exceptions = merge_proxy_exceptions(&raw_exceptions)?;
        let service_names = self.backend.list_enabled_network_services()?;
        if service_names.is_empty() {
            return Err(HelperError::Backend(
                "no enabled macOS network services found to configure system proxy".into(),
            ));
        }

        let mut snapshots = Vec::with_capacity(service_names.len());
        for svc in &service_names {
            snapshots.push(self.backend.get_service_proxies(svc)?);
        }

        let journal = HelperJournal::SystemProxy {
            version: JOURNAL_SCHEMA_VERSION,
            listen_port,
            exceptions: merged_exceptions.clone(),
            services: snapshots.clone(),
        };

        // CRITICAL (`PLAN.md` §5.1): Persist saved proxy snapshots BEFORE running `networksetup`.
        save_journal(&self.state_path, &journal)?;

        for (mutated_count, svc) in service_names.iter().enumerate() {
            if let Err(err) =
                self.backend
                    .set_service_proxies(svc, "127.0.0.1", listen_port, &merged_exceptions)
            {
                for snap in &snapshots[..mutated_count] {
                    if let Err(restore_err) = self.backend.restore_service_proxies(snap) {
                        log::warn!(
                            "rollback failed to restore proxy settings on service {:?}: {restore_err}",
                            snap.service
                        );
                    }
                }
                let _ = delete_journal(&self.state_path);
                return Err(err);
            }
        }

        self.active = ActiveSessionState::SystemProxy(ActiveProxyState {
            listen_port,
            exceptions: merged_exceptions,
            services: snapshots,
        });

        Ok(HelperResponse::SystemProxyReady {
            services: service_names,
        })
    }
}

fn reconcile_tun_routes_and_dns<B: SystemBackend>(
    backend: &B,
    state_path: &Path,
    tun: &mut ActiveTunState,
    snap: &crate::backend::NetworkSnapshot,
    outbound_if_name: String,
    outbound_if_index: u32,
    new_server_ips: Vec<IpAddr>,
) -> Result<(), HelperError> {
    let mut old_utun_head = Vec::new();
    let mut old_gw_routes = Vec::new();
    let mut old_utun_tail = Vec::new();
    let mut seen_gw = false;

    for route in &tun.installed_routes {
        if matches!(&route.target, RouteTarget::Interface(iface) if iface == &tun.utun_name) {
            if !seen_gw
                && route.destination
                    == RouteDestination::Cidr(UTUN_IPV4_SUBNET_STR.parse().unwrap())
            {
                old_utun_head.push(route.clone());
            } else {
                old_utun_tail.push(route.clone());
            }
        } else {
            seen_gw = true;
            old_gw_routes.push(route.clone());
        }
    }

    let desired_gw_routes = build_gateway_routes(
        snap.v4_gateway.as_ref(),
        snap.v6_gateway.as_ref(),
        &new_server_ips,
        &tun.bypass_cidrs,
    );

    let same_service = snap
        .primary_service_id
        .as_deref()
        .is_none_or(|svc| svc == tun.dns_snapshot.service_id);

    let (transitional_dns_snapshots, target_dns_snapshot) =
        if !same_service && let Some(new_dns_snap) = snap.dns_snapshot.clone() {
            (
                vec![tun.dns_snapshot.clone(), new_dns_snap.clone()],
                new_dns_snap,
            )
        } else {
            // IMPORTANT: When the primary service ID is unchanged, `State:/Network/Service/<id>/DNS`
            // currently holds our own `dns_resolver` override — preserve `tun.dns_snapshot` so we never
            // overwrite the genuine pre-TUN DNS servers!
            (vec![tun.dns_snapshot.clone()], tun.dns_snapshot.clone())
        };

    // Write a transitional union journal BEFORE mutating routes/DNS so a crash mid-migration can
    // reverse both old and new routes and restore both services' DNS.
    let mut union_routes = Vec::new();
    union_routes.extend(old_utun_head.iter().cloned());
    union_routes.extend(old_gw_routes.iter().cloned());
    for route in &desired_gw_routes {
        if !union_routes.contains(route) {
            union_routes.push(route.clone());
        }
    }
    union_routes.extend(old_utun_tail.iter().cloned());

    let mut union_server_ips = tun.server_ips.clone();
    for ip in &new_server_ips {
        if !union_server_ips.contains(ip) {
            union_server_ips.push(*ip);
        }
    }
    // Keep within MAX_SERVER_IPS cap for journal validation
    union_server_ips.truncate(vless_ipc::MAX_SERVER_IPS);

    let transitional_journal = HelperJournal::Tun {
        version: JOURNAL_SCHEMA_VERSION,
        utun_name: tun.utun_name.clone(),
        v4_gateway: snap.v4_gateway.clone().or_else(|| tun.v4_gateway.clone()),
        v6_gateway: snap.v6_gateway.clone().or_else(|| tun.v6_gateway.clone()),
        dns_snapshots: transitional_dns_snapshots,
        dns_resolver: tun.dns_resolver,
        server_ips: new_server_ips.clone(),
        bypass_cidrs: tun.bypass_cidrs.clone(),
        routes: union_routes,
    };
    save_journal(state_path, &transitional_journal)?;

    // 1. Remove obsolete physical-gateway routes (non-fatal if kernel already purged a vanished
    //    adapter's routes).
    for old_route in &old_gw_routes {
        if !desired_gw_routes.contains(old_route)
            && let Err(err) = backend.delete_route(old_route)
        {
            log::warn!(
                "non-fatal error deleting obsolete gateway route {old_route:?} during network handover: {err}"
            );
        }
    }

    // 2. Add new physical-gateway routes.
    let mut active_gw_routes = Vec::with_capacity(desired_gw_routes.len());
    for route in &desired_gw_routes {
        if old_gw_routes.contains(route) || backend.add_route(route)? == RouteAddResult::Added {
            active_gw_routes.push(route.clone());
        }
    }

    // 3. Migrate or re-assert ephemeral dynamic-store DNS override.
    if !same_service {
        if let Err(err) = backend.restore_dns_override(&tun.dns_snapshot) {
            log::warn!(
                "non-fatal error restoring DNS on previous service {}: {err}",
                tun.dns_snapshot.service_id
            );
        }
        backend.set_dns_override(&target_dns_snapshot.service_id, tun.dns_resolver)?;
    } else {
        backend.set_dns_override(&target_dns_snapshot.service_id, tun.dns_resolver)?;
    }

    let mut final_routes =
        Vec::with_capacity(old_utun_head.len() + active_gw_routes.len() + old_utun_tail.len());
    final_routes.extend(old_utun_head);
    final_routes.extend(active_gw_routes);
    final_routes.extend(old_utun_tail);

    tun.v4_gateway = snap.v4_gateway.clone();
    tun.v6_gateway = snap.v6_gateway.clone();
    tun.outbound_if_name = outbound_if_name;
    tun.outbound_if_index = outbound_if_index;
    tun.dns_snapshot = target_dns_snapshot;
    tun.server_ips = new_server_ips;
    tun.installed_routes = final_routes;

    save_journal(state_path, &tun.to_journal())?;
    Ok(())
}

fn ensure_routable_server_ips(
    server_ips: &[IpAddr],
    v4_gw: Option<&DefaultGatewayV4>,
    v6_gw: Option<&DefaultGatewayV6>,
) -> Result<(), HelperError> {
    let any_routable = server_ips
        .iter()
        .any(|ip| (ip.is_ipv4() && v4_gw.is_some()) || (ip.is_ipv6() && v6_gw.is_some()));
    if !any_routable {
        return Err(HelperError::Backend(
            "none of the resolved server_ips match an available physical IPv4/IPv6 default gateway"
                .into(),
        ));
    }
    Ok(())
}

fn dedup_ips(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut out = Vec::with_capacity(ips.len());
    for &ip in ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn merge_tun_bypass_cidrs(caller_cidrs: &[IpNetwork]) -> Result<Vec<IpNetwork>, HelperError> {
    let mut merged = builtin_tun_bypass_cidrs();
    for raw in caller_cidrs {
        validate_cidr(raw)?;
        let normalized = IpNetwork::new(raw.network(), raw.prefix())
            .map_err(|_| HelperError::Backend(format!("failed to normalize bypass CIDR {raw}")))?;
        if !merged.contains(&normalized) {
            merged.push(normalized);
        }
    }
    Ok(merged)
}

fn merge_proxy_exceptions(caller_exceptions: &[String]) -> Result<Vec<String>, HelperError> {
    let mut merged = builtin_system_proxy_exceptions();
    for entry in caller_exceptions {
        validate_exception_entry(entry)?;
        if !merged.iter().any(|existing| existing == entry) {
            merged.push(entry.clone());
        }
    }
    Ok(merged)
}

fn build_utun_interface_routes(
    utun_name: &str,
) -> Result<(RouteSpec, Vec<RouteSpec>), HelperError> {
    let subnet_cidr: IpNetwork = UTUN_IPV4_SUBNET_STR
        .parse()
        .expect("valid UTUN_IPV4_SUBNET_STR constant");
    let subnet_route = RouteSpec {
        destination: RouteDestination::Cidr(subnet_cidr),
        target: RouteTarget::Interface(utun_name.to_string()),
    };
    subnet_route.validate()?;

    let mut capture_routes = Vec::with_capacity(TUN_CAPTURE_CIDR_STRS.len());
    for cidr_str in TUN_CAPTURE_CIDR_STRS {
        let cidr: IpNetwork = cidr_str.parse().expect("valid TUN_CAPTURE_CIDR_STRS");
        let spec = RouteSpec {
            destination: RouteDestination::Cidr(cidr),
            target: RouteTarget::Interface(utun_name.to_string()),
        };
        spec.validate()?;
        capture_routes.push(spec);
    }

    Ok((subnet_route, capture_routes))
}

fn build_gateway_routes(
    v4_gateway: Option<&DefaultGatewayV4>,
    v6_gateway: Option<&DefaultGatewayV6>,
    server_ips: &[IpAddr],
    bypass_cidrs: &[IpNetwork],
) -> Vec<RouteSpec> {
    let mut routes = Vec::with_capacity(server_ips.len() + bypass_cidrs.len());

    // 1. Explicit `/32` and `/128` host routes for resolved VLESS server IPs.
    for &ip in server_ips {
        match ip {
            IpAddr::V4(v4) => {
                if let Some(gw4) = v4_gateway {
                    routes.push(RouteSpec {
                        destination: RouteDestination::Host(IpAddr::V4(v4)),
                        target: RouteTarget::GatewayV4(gw4.gateway),
                    });
                }
            }
            IpAddr::V6(v6) => {
                // Skip IPv6 server host routes cleanly when the host has no IPv6 default gateway
                // (`PLAN.md` §5.2 item 6).
                if let Some(gw6) = v6_gateway {
                    routes.push(RouteSpec {
                        destination: RouteDestination::Host(IpAddr::V6(v6)),
                        target: RouteTarget::GatewayV6(gw6.gateway.clone()),
                    });
                }
            }
        }
    }

    // 2. Private, link-local, multicast, ULA, and user-specified bypass CIDRs.
    for &cidr in bypass_cidrs {
        // Avoid duplicate route entries if a single-host CIDR matches a server host route above.
        let overlaps_server_host = match cidr {
            IpNetwork::V4(v4) if v4.prefix() == 32 => server_ips.contains(&IpAddr::V4(v4.ip())),
            IpNetwork::V6(v6) if v6.prefix() == 128 => server_ips.contains(&IpAddr::V6(v6.ip())),
            _ => false,
        };
        if overlaps_server_host {
            continue;
        }

        match cidr {
            IpNetwork::V4(net4) => {
                if let Some(gw4) = v4_gateway {
                    // Route IPv4 link-local (`169.254.0.0/16`) and multicast (`224.0.0.0/4`)
                    // directly onto the physical interface (`-interface <enX>`) so on-link
                    // Bonjour/mDNS works without forwarding to a unicast router.
                    let target = if net4.ip().is_link_local() || net4.ip().is_multicast() {
                        RouteTarget::Interface(gw4.interface.clone())
                    } else {
                        RouteTarget::GatewayV4(gw4.gateway)
                    };
                    routes.push(RouteSpec {
                        destination: RouteDestination::Cidr(IpNetwork::V4(net4)),
                        target,
                    });
                }
            }
            IpNetwork::V6(net6) => {
                // Skip `fe80::/10` (and any link-local IPv6 prefix): on XNU
                // (`net.inet6.ip6.use_defzone=0`), unscoped `fe80::/10` route insertion fails
                // with `EINVAL`, and `fe80::%<if>` traffic is already interface-scoped by XNU.
                if (net6.ip() == Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0) && net6.prefix() == 10)
                    || net6.ip().is_unicast_link_local()
                {
                    continue;
                }
                if let Some(gw6) = v6_gateway {
                    routes.push(RouteSpec {
                        destination: RouteDestination::Cidr(IpNetwork::V6(net6)),
                        target: RouteTarget::GatewayV6(gw6.gateway.clone()),
                    });
                }
            }
        }
    }

    routes
}

fn rollback_partial_tun<B: SystemBackend>(
    backend: &B,
    state_path: &Path,
    installed_routes: &[RouteSpec],
    dns_to_restore: Option<&DnsSnapshot>,
) {
    if let Some(dns_snap) = dns_to_restore
        && let Err(err) = backend.restore_dns_override(dns_snap)
    {
        log::warn!(
            "rollback failed to restore DNS override for service {}: {err}",
            dns_snap.service_id
        );
    }
    for route in installed_routes.iter().rev() {
        if let Err(err) = backend.delete_route(route) {
            log::warn!("rollback failed to delete route {route:?}: {err}");
        }
    }
    let _ = delete_journal(state_path);
}
