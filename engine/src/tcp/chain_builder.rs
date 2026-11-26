//! Builder functions for [`ClientProxyChain`], [`ClientChainGroup`], and [`ClientProxySelector`].

use std::sync::Arc;

use vless_ipc::builtin_tun_bypass_cidrs;

use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{EngineConfig, EngineInbound, ResolvedClientConfig};
use crate::dns_proxy::DnsForwarder;
use crate::resolver::Resolver;
use crate::rules::Predicate;
use crate::tcp::proxy_connector_impl::create_proxy_connector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;

pub fn try_build_single_chain(
    config: ResolvedClientConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientProxyChain> {
    let socket: Arc<dyn SocketConnector> = Arc::new(SocketConnectorImpl::from_config(&config));
    let initial = if config.protocol.is_direct() {
        InitialHopEntry::Direct(socket)
    } else {
        let proxy = create_proxy_connector(config, resolver)?.ok_or_else(|| {
            std::io::Error::other("Missing proxy connector for non-direct configuration")
        })?;
        InitialHopEntry::Proxy { socket, proxy }
    };
    Ok(ClientProxyChain::new_single(initial))
}

pub fn build_direct_chain_group(_resolver: Arc<dyn Resolver>) -> ClientChainGroup {
    build_direct_chain_group_with_interface(None)
}

pub fn build_direct_chain_group_with_interface(bind_interface: Option<String>) -> ClientChainGroup {
    let socket: Arc<dyn SocketConnector> =
        Arc::new(SocketConnectorImpl::new_tcp(bind_interface, true));
    ClientChainGroup::single(ClientProxyChain::new_single(InitialHopEntry::Direct(
        socket,
    )))
}

/// Builds the [`ClientProxySelector`] (and optional port-53 [`DnsForwarder`] in TUN mode) from a
/// validated [`EngineConfig`].
pub fn build_selector_from_engine_config(
    config: &EngineConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<ClientProxySelector>> {
    config.validate()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let direct_bind_if = None;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let direct_bind_if = config.outbound_interface_name();
    let direct_group = Arc::new(build_direct_chain_group_with_interface(direct_bind_if));
    let outbound_cfg = config.to_resolved_client_config()?;
    let vless_chain = try_build_single_chain(outbound_cfg, resolver.clone())?;
    let vless_group = Arc::new(ClientChainGroup::single(vless_chain));

    // Combine built-in private/link-local/multicast/ULA CIDRs with user bypass CIDRs so neither
    // TUN nor local MixedProxy accidentally sends RFC1918 / link-local traffic to the remote VPS.
    let mut cidrs = builtin_tun_bypass_cidrs();
    for cidr in &config.bypass_cidrs {
        if !cidrs.contains(cidr) {
            cidrs.push(*cidr);
        }
    }

    let mut connect_rules = Vec::new();
    if !cidrs.is_empty() {
        connect_rules.push(ConnectRule::compiled(
            Predicate::from_cidrs(&cidrs, true)?,
            true,
            ConnectAction::new_allow(None, direct_group.clone()),
        ));
    }
    if !config.bypass_domains.is_empty() {
        connect_rules.push(ConnectRule::compiled(
            Predicate::from_domain_patterns(&config.bypass_domains)?,
            true,
            ConnectAction::new_allow(None, direct_group),
        ));
    }
    // Catch-all: forward through VLESS
    connect_rules.push(ConnectRule::compiled(
        Predicate::match_all(),
        false,
        ConnectAction::new_allow(None, vless_group.clone()),
    ));

    let intercept_dns_port_53 = matches!(config.inbound, EngineInbound::Tun { .. });
    let dns_forwarder = intercept_dns_port_53.then(|| {
        Arc::new(DnsForwarder::new(
            vless_group,
            resolver,
            config.dns_resolver,
        ))
    });

    Ok(Arc::new(
        ClientProxySelector::new(connect_rules)
            .with_sniff(true)
            .with_dns_forwarder(dns_forwarder),
    ))
}
