//! Destination routing selector with LRU decision cache and port-53 DNS interception (`PLAN.md` §6).

use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;

use log::debug;
use lru::LruCache;
use parking_lot::RwLock;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns_proxy::DnsForwarder;
use crate::resolver::{Resolver, resolve_location};
use crate::rules::{Outcome, Predicate, Traffic, domain};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RoutingCacheKey {
    Hostname { hostname: String, port: u16 },
    Ipv4 { addr: Ipv4Addr, port: u16 },
    Ipv6 { addr: Ipv6Addr, port: u16 },
}

impl RoutingCacheKey {
    fn from_location(location: &NetLocation) -> Self {
        match location.address() {
            Address::Hostname(hostname) => RoutingCacheKey::Hostname {
                hostname: domain::normalize(hostname)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| hostname.clone()),
                port: location.port(),
            },
            Address::Ipv4(addr) => RoutingCacheKey::Ipv4 {
                addr: *addr,
                port: location.port(),
            },
            Address::Ipv6(addr) => match addr.to_ipv4_mapped() {
                Some(addr) => RoutingCacheKey::Ipv4 {
                    addr,
                    port: location.port(),
                },
                None => RoutingCacheKey::Ipv6 {
                    addr: *addr,
                    port: location.port(),
                },
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CachedDecision {
    Allow(usize),
    Block,
}

pub struct RoutingCache {
    inner: RwLock<LruCache<RoutingCacheKey, CachedDecision>>,
}

impl std::fmt::Debug for RoutingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache = self.inner.read();
        f.debug_struct("RoutingCache")
            .field("len", &cache.len())
            .field("cap", &cache.cap())
            .finish()
    }
}

impl RoutingCache {
    pub const DEFAULT_CAPACITY: usize = 4_096;

    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            inner: RwLock::new(LruCache::new(cap)),
        }
    }

    #[inline]
    pub(crate) fn get(&self, location: &NetLocation) -> Option<CachedDecision> {
        let key = RoutingCacheKey::from_location(location);
        self.inner.read().peek(&key).copied()
    }

    #[inline]
    pub(crate) fn insert(&self, location: &NetLocation, decision: CachedDecision) {
        let key = RoutingCacheKey::from_location(location);
        self.inner.write().put(key, decision);
    }
}

#[derive(Debug)]
pub struct ConnectRule {
    pub predicate: Arc<Predicate>,
    pub no_resolve: bool,
    pub action: ConnectAction,
}

impl ConnectRule {
    pub fn compiled(predicate: Arc<Predicate>, no_resolve: bool, action: ConnectAction) -> Self {
        Self {
            predicate,
            no_resolve,
            action,
        }
    }
}

#[derive(Debug)]
pub enum ConnectAction {
    Allow {
        override_address: Option<NetLocation>,
        chain_group: Arc<ClientChainGroup>,
    },
    Block,
}

impl ConnectAction {
    pub fn new_allow(
        override_address: Option<NetLocation>,
        chain_group: Arc<ClientChainGroup>,
    ) -> Self {
        ConnectAction::Allow {
            override_address,
            chain_group,
        }
    }

    pub fn new_block() -> Self {
        ConnectAction::Block
    }

    pub fn to_decision(&self, location: ResolvedLocation) -> ConnectDecision<'_> {
        match self {
            ConnectAction::Allow {
                override_address,
                chain_group,
            } => {
                let remote_location = match override_address {
                    Some(l) => {
                        let new_loc = if l.port() > 0 {
                            l.clone()
                        } else {
                            NetLocation::new(l.address().clone(), location.location().port())
                        };
                        new_loc.into()
                    }
                    None => location,
                };
                ConnectDecision::Allow {
                    chain_group: chain_group.as_ref(),
                    remote_location,
                }
            }
            ConnectAction::Block => ConnectDecision::Block,
        }
    }
}

#[derive(Debug)]
pub struct ClientProxySelector {
    rules: Vec<ConnectRule>,
    cache: Option<RoutingCache>,
    has_ip_rules: bool,
    has_hostname_rules: bool,
    has_protocol_rules: bool,
    sniff_enabled: bool,
    dns_interception: Option<Arc<DnsForwarder>>,
}

#[derive(Debug)]
pub(crate) enum IngressTarget {
    LocalDns {
        wire_destination: NetLocation,
        forwarder: Arc<DnsForwarder>,
    },
    Forward(PreparedDestination),
}

#[derive(Debug, PartialEq, Eq)]
enum DestinationSource {
    SuppliedHostname,
    LiteralIp,
}

#[derive(Debug)]
pub(crate) struct PreparedDestination {
    wire_destination: NetLocation,
    connection_target: ResolvedLocation,
    source: DestinationSource,
    pub(crate) traffic: Traffic,
}

impl PreparedDestination {
    fn is_sniffable(&self) -> bool {
        self.source != DestinationSource::SuppliedHostname
    }
}

#[derive(Debug)]
pub(crate) struct RoutedDestination<'a> {
    pub wire_destination: NetLocation,
    pub decision: ConnectDecision<'a>,
}

#[derive(Debug)]
pub enum ConnectDecision<'a> {
    Allow {
        chain_group: &'a ClientChainGroup,
        remote_location: ResolvedLocation,
    },
    Block,
}

impl ClientProxySelector {
    pub fn new(rules: Vec<ConnectRule>) -> Self {
        let has_protocol_rules = rules
            .iter()
            .any(|rule| rule.predicate.dependencies.protocol);
        let traffic_dependent =
            has_protocol_rules || rules.iter().any(|rule| rule.predicate.dependencies.network);
        let cache = (!traffic_dependent && rules.len() > 4)
            .then(|| RoutingCache::new(RoutingCache::DEFAULT_CAPACITY));
        let has_ip_rules = rules.iter().any(|rule| rule.predicate.dependencies.ip);
        let has_hostname_rules = rules
            .iter()
            .any(|rule| rule.predicate.dependencies.hostname);

        Self {
            rules,
            cache,
            has_ip_rules,
            has_hostname_rules,
            has_protocol_rules,
            sniff_enabled: false,
            dns_interception: None,
        }
    }

    pub(crate) fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    pub(crate) fn with_dns_forwarder(mut self, forwarder: Option<Arc<DnsForwarder>>) -> Self {
        self.dns_interception = forwarder;
        self
    }

    pub(crate) fn set_dns_error_callback(
        &self,
        cb: Option<crate::tcp::tcp_server::StreamErrorCallback>,
    ) {
        if let Some(ref forwarder) = self.dns_interception {
            forwarder.set_error_callback(cb);
        }
    }

    pub fn notify_network_changed(&self) {
        if let Some(ref forwarder) = self.dns_interception {
            forwarder.notify_network_changed();
        }
    }

    pub(crate) fn prepare(&self, mut location: ResolvedLocation) -> std::io::Result<IngressTarget> {
        let wire_destination = location.location().clone();
        if let Some(hostname) = wire_destination.address().hostname() {
            if let Ok(ip) = hostname.parse() {
                location = NetLocation::from_ip_addr(ip, wire_destination.port()).into();
            } else {
                domain::normalize(hostname)?;
            }
        }
        if let Some(forwarder) = &self.dns_interception
            && forwarder.should_intercept(location.location())
        {
            return Ok(IngressTarget::LocalDns {
                wire_destination,
                forwarder: forwarder.clone(),
            });
        }
        let source = if location.address().hostname().is_some() {
            DestinationSource::SuppliedHostname
        } else {
            DestinationSource::LiteralIp
        };
        Ok(IngressTarget::Forward(PreparedDestination {
            wire_destination,
            connection_target: location,
            source,
            traffic: Traffic::TCP,
        }))
    }

    pub(crate) fn should_sniff(&self, target: &PreparedDestination) -> bool {
        self.sniff_enabled && self.has_hostname_rules && target.is_sniffable()
    }

    pub(crate) fn has_protocol_rules(&self) -> bool {
        self.has_protocol_rules
    }

    pub(crate) async fn judge_prepared<'a>(
        &'a self,
        target: PreparedDestination,
        hostname: Option<&str>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<RoutedDestination<'a>> {
        let decision = if let Some(name) = hostname.filter(|name| domain::normalize(name).is_ok()) {
            self.judge_uncached(
                target.connection_target,
                resolver,
                Some(name),
                target.traffic,
            )
            .await?
        } else {
            self.judge_ordinary(target.connection_target, resolver, target.traffic)
                .await?
        };
        Ok(RoutedDestination {
            wire_destination: target.wire_destination,
            decision,
        })
    }

    pub async fn judge<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        self.judge_ordinary(location, resolver, Traffic::TCP).await
    }

    async fn judge_ordinary<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        traffic: Traffic,
    ) -> std::io::Result<ConnectDecision<'a>> {
        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(location.location())
        {
            return Ok(match cached {
                CachedDecision::Allow(idx) => self.rules[idx].action.to_decision(location),
                CachedDecision::Block => ConnectDecision::Block,
            });
        }

        let original_loc = location.location().clone();
        let was_unresolved_hostname = location.address().hostname().is_some()
            && location.resolved_addr().is_none()
            && self.has_ip_rules;

        let (rule_idx, resolved_loc) = self
            .evaluate_rules(location, resolver, None, traffic)
            .await?;

        let can_cache = !(was_unresolved_hostname && resolved_loc.resolved_addr().is_some());
        match rule_idx {
            Some(idx) => {
                let rule = &self.rules[idx];
                if can_cache && let Some(ref cache) = self.cache {
                    let cached = match &rule.action {
                        ConnectAction::Allow { .. } => CachedDecision::Allow(idx),
                        ConnectAction::Block => CachedDecision::Block,
                    };
                    cache.insert(&original_loc, cached);
                }
                Ok(rule.action.to_decision(resolved_loc))
            }
            None => {
                if can_cache && let Some(ref cache) = self.cache {
                    cache.insert(&original_loc, CachedDecision::Block);
                }
                Ok(ConnectDecision::Block)
            }
        }
    }

    async fn judge_uncached<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        sniffed_hostname: Option<&str>,
        traffic: Traffic,
    ) -> std::io::Result<ConnectDecision<'a>> {
        let (rule_idx, resolved_loc) = self
            .evaluate_rules(location, resolver, sniffed_hostname, traffic)
            .await?;
        Ok(match rule_idx {
            Some(idx) => self.rules[idx].action.to_decision(resolved_loc),
            None => ConnectDecision::Block,
        })
    }

    async fn evaluate_rules(
        &self,
        mut location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        sniffed_hostname: Option<&str>,
        traffic: Traffic,
    ) -> std::io::Result<(Option<usize>, ResolvedLocation)> {
        let port = location.location().port();
        let hostname_owned = location.address().hostname().map(str::to_owned);
        let hostname = sniffed_hostname.or(hostname_owned.as_deref());

        let mut known_ip = location
            .resolved_addr()
            .or_else(|| location.location().to_socket_addr_nonblocking())
            .map(|sa| sa.ip());
        let mut resolution_failed = false;

        for (idx, rule) in self.rules.iter().enumerate() {
            loop {
                let outcome =
                    rule.predicate
                        .evaluate(hostname, known_ip, port, traffic, rule.no_resolve);
                match outcome {
                    Outcome::Match => {
                        debug!("Routing matched rule #{idx} for {}", location.location());
                        return Ok((Some(idx), location));
                    }
                    Outcome::Miss => break,
                    Outcome::Unknown { may_resolve } => {
                        if !may_resolve || resolution_failed {
                            break;
                        }
                        match resolve_location(&mut location, resolver).await {
                            Ok(addr) => {
                                known_ip = Some(addr.ip());
                            }
                            Err(err) => {
                                debug!(
                                    "Rule #{idx} IP lookup for {} failed ({err}); continuing",
                                    location.location()
                                );
                                resolution_failed = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok((None, location))
    }
}
