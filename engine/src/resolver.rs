use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use log::debug;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{Semaphore, broadcast};

use crate::address::{Address, NetLocation, ResolvedLocation};

pub type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

const CACHING_NATIVE_RESOLVER_CACHE_CAPACITY: usize = 10_000;
const CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS: usize = 1_024;
const RESOLVER_CACHE_CAPACITY: usize = 1_024;

fn bounded_lru<K: Hash + Eq, V>(capacity: usize) -> LruCache<K, V> {
    let mut cache = LruCache::unbounded();
    cache.resize(NonZeroUsize::new(capacity).unwrap());
    cache
}

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;
}

/// Resolver wrapper that enforces a timeout on DNS resolution.
pub struct TimeoutResolver<T> {
    inner: T,
    timeout: Duration,
}

impl<T: Resolver> TimeoutResolver<T> {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn new(inner: T) -> Self {
        Self {
            inner,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(inner: T, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<T: Resolver> Debug for TimeoutResolver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeoutResolver")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<T: Resolver> Resolver for TimeoutResolver<T> {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![addr]) });
        }

        let inner_future = self.inner.resolve_location(location);
        let timeout_duration = self.timeout;
        let location_str = location.to_string();

        Box::pin(async move {
            match tokio::time::timeout(timeout_duration, inner_future).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "DNS resolution for {location_str} timed out after {timeout_duration:?}"
                    ),
                )),
            }
        })
    }
}

#[derive(Debug, Default)]
pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![addr]) });
        }
        let address = location.address().clone();
        let port = location.port();
        Box::pin(
            tokio::net::lookup_host((address.to_string(), port)).map(move |result| {
                let ret = result.map(|r| {
                    r.filter(|addr| !addr.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!("NativeResolver resolved {address}:{port} -> {ret:?}");
                ret
            }),
        )
    }
}

/// Resolver that pins the VLESS server's own hostname to pre-resolved IP addresses (`PLAN.md` §5.2,
/// §5.4) so outbound connections to the VLESS server never trigger system DNS lookups inside the
/// TUN tunnel, while delegating any other hostnames (e.g. direct domain-bypass targets) to `inner`.
#[derive(Debug)]
pub struct ServerEndpointResolver {
    server_host_lower: String,
    pinned_ips: RwLock<Vec<IpAddr>>,
    inner: Arc<dyn Resolver>,
}

impl ServerEndpointResolver {
    pub fn new(server_host: &str, initial_ips: Vec<IpAddr>, inner: Arc<dyn Resolver>) -> Self {
        Self {
            server_host_lower: server_host.trim_end_matches('.').to_ascii_lowercase(),
            pinned_ips: RwLock::new(initial_ips),
            inner,
        }
    }

    /// Atomically replaces the pinned server IPs (called after physical-interface DNS refresh on
    /// network change or wake).
    pub fn update_server_ips(&self, ips: Vec<IpAddr>) {
        if !ips.is_empty() {
            *self.pinned_ips.write() = ips;
        }
    }

    pub fn current_server_ips(&self) -> Vec<IpAddr> {
        self.pinned_ips.read().clone()
    }
}

impl Resolver for ServerEndpointResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![addr]) });
        }

        if let Address::Hostname(host) = location.address()
            && host
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&self.server_host_lower)
        {
            let ips = self.pinned_ips.read().clone();
            if !ips.is_empty() {
                let port = location.port();
                let addrs: Vec<SocketAddr> = ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect();
                return Box::pin(async move { Ok(addrs) });
            }
        }

        self.inner.resolve_location(location)
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(socket_addr);
    }
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(resolve_results[0])
}

pub async fn resolve_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(vec![socket_addr]);
    }

    let addrs = resolver.resolve_location(location).await?;
    if addrs.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(addrs)
}

pub async fn resolve_location(
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = location.resolved_addr() {
        return Ok(addr);
    }
    let addr = resolve_single_address(resolver, location.location()).await?;
    location.set_resolved(addr);
    Ok(addr)
}

pub struct CachingNativeResolver {
    state: Arc<Mutex<NativeResolverState>>,
    participants: Arc<Semaphore>,
    lookup: Arc<dyn Resolver>,
    result_timeout_secs: u64,
}

impl CachingNativeResolver {
    pub fn clear_cache(&self) {
        self.state.lock().cache.clear();
    }
}

type NativeLookupResult = Result<Arc<[SocketAddr]>, Arc<std::io::Error>>;

struct NativeResolverState {
    cache: LruCache<Address, CachedResolveResult>,
    inflight: HashMap<Address, broadcast::Sender<NativeLookupResult>>,
}

struct CachedResolveResult {
    completed_at: tokio::time::Instant,
    addrs: Arc<[SocketAddr]>,
}

impl NativeResolverState {
    fn cached(&mut self, address: &Address, max_age: Duration) -> Option<Arc<[SocketAddr]>> {
        if max_age.is_zero() {
            return None;
        }
        if let Some(cached) = self.cache.get(address)
            && cached.completed_at.elapsed() < max_age
        {
            return Some(cached.addrs.clone());
        }
        self.cache.pop(address);
        None
    }
}

struct NativeLookupOwner {
    state: Arc<Mutex<NativeResolverState>>,
    address: Address,
    registered: bool,
}

enum NativeLookupRole {
    Owner(NativeLookupOwner),
    Subscriber(broadcast::Receiver<NativeLookupResult>),
}

impl NativeLookupOwner {
    fn publish(mut self, result: &NativeLookupResult, cache_enabled: bool) {
        let mut state = self.state.lock();
        if cache_enabled && let Ok(addrs) = result {
            state.cache.put(
                self.address.clone(),
                CachedResolveResult {
                    completed_at: tokio::time::Instant::now(),
                    addrs: addrs.clone(),
                },
            );
        }
        if self.registered {
            let sender = state.inflight.remove(&self.address).unwrap();
            self.registered = false;
            drop(state);
            let _ = sender.send(result.clone());
        }
    }
}

impl Drop for NativeLookupOwner {
    fn drop(&mut self) {
        if self.registered {
            let sender = self.state.lock().inflight.remove(&self.address);
            drop(sender);
        }
    }
}

fn native_addrs_with_port(addrs: &[SocketAddr], port: u16) -> Vec<SocketAddr> {
    addrs
        .iter()
        .map(|addr| {
            let mut addr = *addr;
            addr.set_port(port);
            addr
        })
        .collect()
}

fn native_lookup_error(error: Arc<std::io::Error>) -> std::io::Error {
    match error.raw_os_error() {
        Some(errno) => std::io::Error::from_raw_os_error(errno),
        None => std::io::Error::new(error.kind(), error),
    }
}

impl std::fmt::Debug for CachingNativeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingNativeResolver")
            .field("result_timeout_secs", &self.result_timeout_secs)
            .finish()
    }
}

impl CachingNativeResolver {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60;

    pub fn new() -> Self {
        Self::with_timeout(Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn with_timeout(result_timeout_secs: u64) -> Self {
        Self::with_lookup(Arc::new(NativeResolver::new()), result_timeout_secs)
    }

    pub(crate) fn with_lookup(lookup: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(NativeResolverState {
                cache: bounded_lru(CACHING_NATIVE_RESOLVER_CACHE_CAPACITY),
                inflight: HashMap::new(),
            })),
            participants: Arc::new(Semaphore::new(CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS)),
            lookup,
            result_timeout_secs,
        }
    }
}

impl Default for CachingNativeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for CachingNativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let max_age = Duration::from_secs(self.result_timeout_secs);
        let cache_enabled = self.result_timeout_secs > 0;
        let caller_port = location.port();
        if let Some(addrs) = self.state.lock().cached(location.address(), max_age) {
            let addrs = native_addrs_with_port(&addrs, caller_port);
            return Box::pin(async move { Ok(addrs) });
        }

        let query_location = NetLocation::new(location.address().clone(), 0);
        let state = self.state.clone();
        let participants = self.participants.clone();
        let lookup = self.lookup.clone();

        Box::pin(async move {
            let permit = participants.try_acquire().ok();
            loop {
                let role = {
                    let mut locked = state.lock();
                    if let Some(addrs) = locked.cached(query_location.address(), max_age) {
                        return Ok(native_addrs_with_port(&addrs, caller_port));
                    }
                    if let Some(sender) = locked.inflight.get(query_location.address())
                        && permit.is_some()
                    {
                        NativeLookupRole::Subscriber(sender.subscribe())
                    } else {
                        let registered = permit.is_some();
                        if registered {
                            let (sender, _) = broadcast::channel(1);
                            locked
                                .inflight
                                .insert(query_location.address().clone(), sender);
                        }
                        NativeLookupRole::Owner(NativeLookupOwner {
                            state: state.clone(),
                            address: query_location.address().clone(),
                            registered,
                        })
                    }
                };

                let result = match role {
                    NativeLookupRole::Subscriber(mut subscriber) => match subscriber.recv().await {
                        Ok(result) => result,
                        Err(_) => continue,
                    },
                    NativeLookupRole::Owner(owner) => {
                        let result = lookup
                            .resolve_location(&query_location)
                            .await
                            .and_then(|mut addrs| {
                                addrs.retain(|addr| !addr.ip().is_unspecified());
                                if addrs.is_empty() {
                                    Err(std::io::Error::other(format!(
                                        "DNS lookup returned no addresses for {}",
                                        query_location.address()
                                    )))
                                } else {
                                    Ok(Arc::from(addrs))
                                }
                            })
                            .map_err(Arc::new);
                        owner.publish(&result, cache_enabled);
                        result
                    }
                };
                let addrs = result.map_err(native_lookup_error)?;
                let addrs = native_addrs_with_port(&addrs, caller_port);
                debug!(
                    "CachingNativeResolver resolved {}:{caller_port} -> {addrs:?}",
                    query_location.address()
                );
                return Ok(addrs);
            }
        })
    }
}

pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    cache: LruCache<NetLocation, (Instant, SocketAddr)>,
    pending: Option<(NetLocation, ResolveFuture)>,
    result_timeout_secs: u64,
}

impl ResolverCache {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60;

    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::new_with_timeout(resolver, Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(resolver: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            resolver,
            cache: bounded_lru(RESOLVER_CACHE_CAPACITY),
            pending: None,
            result_timeout_secs,
        }
    }

    pub async fn resolve_location(&mut self, target: &NetLocation) -> std::io::Result<SocketAddr> {
        self.pending = None;

        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Ok(socket_addr);
        }

        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Ok(*addr);
            }
            self.cache.pop(target);
        }

        let addrs = self.resolver.resolve_location(target).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "DNS lookup returned no addresses for {target}"
            )));
        }
        let addr = addrs[0];
        self.cache.put(target.clone(), (Instant::now(), addr));
        Ok(addr)
    }

    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending_target, _)| pending_target != target)
        {
            self.pending = None;
        }

        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(socket_addr));
        }

        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Poll::Ready(Ok(*addr));
            }
            self.cache.pop(target);
        }

        if self.pending.is_none() {
            self.pending = Some((target.clone(), self.resolver.resolve_location(target)));
        }

        let result = self.pending.as_mut().unwrap().1.as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => {
                self.pending = None;
                if addrs.is_empty() {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "DNS lookup returned no addresses for {target}"
                    ))));
                }
                let addr = addrs[0];
                self.cache.put(target.clone(), (Instant::now(), addr));
                Poll::Ready(Ok(addr))
            }
            Poll::Ready(Err(e)) => {
                self.pending = None;
                Poll::Ready(Err(e))
            }
        }
    }
}

const DNS_RECORD_A: u16 = 1;
const DNS_RECORD_CNAME: u16 = 5;
const DNS_RECORD_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;
const MAX_DNS_POINTER_HOPS: usize = 32;
const DIRECT_DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves `host` by sending direct RFC 1035 `A` and `AAAA` UDP DNS queries to `dns_servers`
/// (port 53) over outbound UDP sockets governed by [`crate::socket_policy`] (`IP_BOUND_IF` on
/// macOS) so the VLESS server's own hostname is never resolved through the tunnel (`PLAN.md` §5.4).
pub async fn resolve_host_via_udp_dns(
    host: &str,
    dns_servers: &[IpAddr],
    bind_interface: Option<String>,
) -> std::io::Result<Vec<IpAddr>> {
    let endpoints: Vec<SocketAddr> = dns_servers
        .iter()
        .map(|&ip| SocketAddr::new(ip, 53))
        .collect();
    resolve_host_via_udp_dns_addrs(host, &endpoints, bind_interface).await
}

/// Resolves `host` via direct RFC 1035 `A` + `AAAA` UDP DNS queries to explicit `SocketAddr`
/// endpoints (used by [`resolve_host_via_udp_dns`] and unprivileged ephemeral-port unit tests).
pub async fn resolve_host_via_udp_dns_addrs(
    host: &str,
    dns_endpoints: &[SocketAddr],
    bind_interface: Option<String>,
) -> std::io::Result<Vec<IpAddr>> {
    match Address::from(host)? {
        Address::Ipv4(v4) => return Ok(vec![IpAddr::V4(v4)]),
        Address::Ipv6(v6) => return Ok(vec![IpAddr::V6(v6)]),
        Address::Hostname(_) => {}
    }

    if dns_endpoints.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no upstream DNS servers provided for direct server resolution",
        ));
    }

    let mut last_err: Option<std::io::Error> = None;
    for &endpoint in dns_endpoints {
        let (res_a, res_aaaa) = tokio::join!(
            query_udp_dns_record(host, DNS_RECORD_A, endpoint, bind_interface.clone()),
            query_udp_dns_record(host, DNS_RECORD_AAAA, endpoint, bind_interface.clone()),
        );

        let mut ips = Vec::new();
        for res in [res_a, res_aaaa] {
            match res {
                Ok(found) => {
                    for ip in found {
                        if !ip.is_unspecified() && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        if !ips.is_empty() {
            return Ok(ips);
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other(format!(
            "direct UDP DNS lookup returned no A/AAAA records for {host}"
        ))
    }))
}

async fn query_udp_dns_record(
    host: &str,
    qtype: u16,
    dns_endpoint: SocketAddr,
    bind_interface: Option<String>,
) -> std::io::Result<Vec<IpAddr>> {
    let tx_id: u16 = rand::random();
    let query_bytes = build_rfc1035_query(host, qtype, tx_id)?;
    let socket = crate::socket_util::new_udp_socket_for_peer(dns_endpoint, bind_interface)?;
    socket.send_to(&query_bytes, dns_endpoint).await?;

    let deadline = tokio::time::Instant::now() + DIRECT_DNS_TIMEOUT;
    let mut recv_buf = [0u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((n, peer))) => {
                if peer != dns_endpoint {
                    continue;
                }
                if let Some(parsed) = parse_rfc1035_ip_response(&recv_buf[..n], tx_id, host, qtype)
                {
                    return parsed;
                }
            }
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("direct UDP DNS query to {dns_endpoint} for {host} timed out"),
                ));
            }
        }
    }
}

pub(crate) fn build_rfc1035_query(host: &str, qtype: u16, tx_id: u16) -> std::io::Result<Vec<u8>> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid DNS hostname {host:?}"),
        ));
    }

    let mut pkt = Vec::with_capacity(18 + trimmed.len());
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid DNS label {label:?} in {host:?}"),
            ));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // Root terminator
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(pkt)
}

/// Parses an RFC 1035 UDP DNS response.
///
/// Returns `None` if the packet is not a response matching `expected_tx_id` (allowing the caller
/// to ignore stray/unrelated UDP packets until timeout), or `Some(io::Result<Vec<IpAddr>>)` once
/// the matching transaction response is decoded.
pub(crate) fn parse_rfc1035_ip_response(
    msg: &[u8],
    expected_tx_id: u16,
    expected_host: &str,
    expected_qtype: u16,
) -> Option<std::io::Result<Vec<IpAddr>>> {
    if msg.len() < 12 {
        return None;
    }
    let rx_id = u16::from_be_bytes([msg[0], msg[1]]);
    if rx_id != expected_tx_id {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if (flags & 0x8000) == 0 {
        // QR == 0 (query, not response)
        return None;
    }

    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Some(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("DNS server returned RCODE {rcode} for {expected_host}"),
        )));
    }

    let qdcount = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let ancount = usize::from(u16::from_be_bytes([msg[6], msg[7]]));
    let expected_lower = expected_host.trim_end_matches('.').to_ascii_lowercase();

    let mut offset = 12usize;
    for q_idx in 0..qdcount {
        let (qname, next) = match decode_dns_name(msg, offset) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        if next + 4 > msg.len() {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated DNS question section",
            )));
        }
        let qtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
        let qclass = u16::from_be_bytes([msg[next + 2], msg[next + 3]]);
        if q_idx == 0
            && (!qname.eq_ignore_ascii_case(&expected_lower)
                || qtype != expected_qtype
                || qclass != DNS_CLASS_IN)
        {
            return None;
        }
        offset = next + 4;
    }

    struct ParsedRr {
        name: String,
        rtype: u16,
        rclass: u16,
        rdata_offset: usize,
        rdlength: usize,
    }

    let mut records = Vec::with_capacity(ancount.min(64));
    for _ in 0..ancount {
        let (name, next) = match decode_dns_name(msg, offset) {
            Ok(v) => v,
            Err(e) => {
                if (flags & 0x0200) != 0 && !records.is_empty() {
                    break;
                }
                return Some(Err(e));
            }
        };
        if next + 10 > msg.len() {
            if (flags & 0x0200) != 0 && !records.is_empty() {
                break;
            }
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated DNS resource record header",
            )));
        }
        let rtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
        let rclass = u16::from_be_bytes([msg[next + 2], msg[next + 3]]);
        // TTL at next+4..next+8
        let rdlength = usize::from(u16::from_be_bytes([msg[next + 8], msg[next + 9]]));
        let rdata_offset = next + 10;
        let rdata_end = match rdata_offset.checked_add(rdlength) {
            Some(end) if end <= msg.len() => end,
            _ => {
                if (flags & 0x0200) != 0 && !records.is_empty() {
                    break;
                }
                return Some(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated DNS resource record RDATA",
                )));
            }
        };
        records.push(ParsedRr {
            name,
            rtype,
            rclass,
            rdata_offset,
            rdlength,
        });
        offset = rdata_end;
    }

    // Expand CNAME aliases (bounded to 16 hops) starting from `expected_lower`.
    let mut accepted_names = vec![expected_lower];
    for _ in 0..records.len().min(16) {
        let mut added = false;
        for rr in &records {
            if rr.rtype == DNS_RECORD_CNAME
                && rr.rclass == DNS_CLASS_IN
                && accepted_names.iter().any(|n| n == &rr.name)
                && let Ok((cname_target, cname_end)) = decode_dns_name(msg, rr.rdata_offset)
                && cname_end <= rr.rdata_offset + rr.rdlength
                && !accepted_names.contains(&cname_target)
            {
                accepted_names.push(cname_target);
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    let mut ips = Vec::new();
    for rr in &records {
        if rr.rclass != DNS_CLASS_IN || !accepted_names.iter().any(|n| n == &rr.name) {
            continue;
        }
        let rdata = &msg[rr.rdata_offset..rr.rdata_offset + rr.rdlength];
        match (expected_qtype, rr.rtype, rdata.len()) {
            (DNS_RECORD_A, DNS_RECORD_A, 4) => {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ));
                if !ip.is_unspecified() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            (DNS_RECORD_AAAA, DNS_RECORD_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                if !ip.is_unspecified() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            _ => {}
        }
    }

    Some(Ok(ips))
}

/// Decodes a domain name from `msg` starting at `start_offset` per RFC 1035 §4.1.4, enforcing a
/// strict compression pointer hop limit (`MAX_DNS_POINTER_HOPS`) to prevent pointer loops.
fn decode_dns_name(msg: &[u8], start_offset: usize) -> std::io::Result<(String, usize)> {
    let mut pos = start_offset;
    let mut end_after_first_jump: Option<usize> = None;
    let mut hops = 0usize;
    let mut out = String::new();
    let mut wire_len = 0usize;

    loop {
        if pos >= msg.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "DNS name extends past end of packet",
            ));
        }
        let tag = msg[pos];
        if tag == 0 {
            let consumed_end = end_after_first_jump.unwrap_or(pos + 1);
            return Ok((out, consumed_end));
        }
        match tag & 0xC0 {
            0xC0 => {
                if pos + 1 >= msg.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated DNS compression pointer",
                    ));
                }
                hops += 1;
                if hops > MAX_DNS_POINTER_HOPS {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "DNS name compression pointer loop detected",
                    ));
                }
                if end_after_first_jump.is_none() {
                    end_after_first_jump = Some(pos + 2);
                }
                let target = ((usize::from(tag & 0x3F)) << 8) | usize::from(msg[pos + 1]);
                if target >= msg.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "DNS compression pointer out of bounds",
                    ));
                }
                pos = target;
            }
            0x00 => {
                let len = usize::from(tag);
                let label_start = pos + 1;
                let label_end = label_start + len;
                if label_end > msg.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "DNS label extends past end of packet",
                    ));
                }
                wire_len += len + 1;
                if wire_len > 255 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decoded DNS name exceeds 255 bytes",
                    ));
                }
                let label = std::str::from_utf8(&msg[label_start..label_end]).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "non-UTF8 bytes in DNS label",
                    )
                })?;
                if !out.is_empty() {
                    out.push('.');
                }
                for ch in label.chars() {
                    out.push(ch.to_ascii_lowercase());
                }
                pos = label_end;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported reserved DNS label type",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FailingResolver;
    impl Resolver for FailingResolver {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            Box::pin(async { Err(std::io::Error::other("should not hit fallback")) })
        }
    }

    #[tokio::test]
    async fn server_endpoint_resolver_returns_pinned_ips_and_updates_atomically() {
        let resolver = ServerEndpointResolver::new(
            "Edge.Example.COM",
            vec!["198.51.100.10".parse().unwrap()],
            Arc::new(FailingResolver),
        );
        let loc = NetLocation::from_str("edge.example.com:443", None).unwrap();
        let addrs = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(addrs, vec!["198.51.100.10:443".parse().unwrap()]);

        resolver.update_server_ips(vec!["203.0.113.99".parse().unwrap()]);
        let addrs2 = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(addrs2, vec!["203.0.113.99:443".parse().unwrap()]);
    }

    #[test]
    fn rfc1035_parser_handles_cname_compression_pointers_and_rejects_pointer_loops() {
        // Build query for `edge.example.com` (offset 12 = `\x04edge\x07example\x03com\x00`, ends at 30)
        let mut msg = build_rfc1035_query("edge.example.com", DNS_RECORD_A, 0x4242).unwrap();
        // Turn header into response with ANCOUNT = 2
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[6] = 0x00;
        msg[7] = 0x02;

        // Answer 1: `0xC00C` (pointer to `edge.example.com`) -> CNAME `node1` + `0xC011` (`example.com`)
        let cname_rdata_start_name = b"\x05node1\xc0\x11"; // 8 bytes -> `node1.example.com`
        msg.extend_from_slice(&[0xc0, 0x0c]); // NAME = ptr(12)
        msg.extend_from_slice(&DNS_RECORD_CNAME.to_be_bytes());
        msg.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        let cname_pos = msg.len() + 2;
        msg.extend_from_slice(&(cname_rdata_start_name.len() as u16).to_be_bytes());
        msg.extend_from_slice(cname_rdata_start_name);

        // Answer 2: pointer to `node1.example.com` (`cname_pos`) -> A `203.0.113.77`
        msg.extend_from_slice(&[0xc0, cname_pos as u8]);
        msg.extend_from_slice(&DNS_RECORD_A.to_be_bytes());
        msg.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[203, 0, 113, 77]);

        // Mismatched TXID is ignored (`None`)
        assert!(
            parse_rfc1035_ip_response(&msg, 0x9999, "edge.example.com", DNS_RECORD_A).is_none()
        );

        // Matching TXID decodes compressed CNAME + A record
        let ips = parse_rfc1035_ip_response(&msg, 0x4242, "Edge.Example.COM.", DNS_RECORD_A)
            .unwrap()
            .unwrap();
        assert_eq!(ips, vec![IpAddr::from([203, 0, 113, 77])]);

        // Craft self-referential compression loop at offset 12 (`0xC0 0x0C`)
        let mut loop_pkt = vec![
            0x11, 0x22, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
        ];
        let err = parse_rfc1035_ip_response(&loop_pkt, 0x1122, "edge.example.com", DNS_RECORD_A)
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // Mutual 2-node loop (`12 -> 18 -> 12`)
        loop_pkt[13] = 0x12;
        loop_pkt.extend_from_slice(&[0xc0, 0x0c]);
        let err2 = parse_rfc1035_ip_response(&loop_pkt, 0x1122, "edge.example.com", DNS_RECORD_A)
            .unwrap()
            .unwrap_err();
        assert_eq!(err2.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn resolve_host_via_udp_dns_resolves_a_and_aaaa_and_handles_ip_literals() {
        // IP literal fast-path requires zero network I/O even with empty DNS server list
        let literal = resolve_host_via_udp_dns("198.51.100.42", &[], None)
            .await
            .unwrap();
        assert_eq!(literal, vec!["198.51.100.42".parse::<IpAddr>().unwrap()]);

        let mock_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = mock_dns.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = mock_dns.recv_from(&mut buf).await.unwrap();
                let q = &buf[..n];
                let qtype = u16::from_be_bytes([q[n - 4], q[n - 3]]);

                // Send a stray spoofed-TXID packet first to ensure client ignores it
                let mut stray = q.to_vec();
                stray[0] ^= 0xff;
                stray[2] = 0x81;
                stray[3] = 0x80;
                let _ = mock_dns.send_to(&stray, peer).await;

                let mut resp = q.to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[6] = 0x00;
                resp[7] = 0x01; // ANCOUNT = 1
                resp.extend_from_slice(&[0xc0, 0x0c]); // NAME -> offset 12
                resp.extend_from_slice(&qtype.to_be_bytes());
                resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&120u32.to_be_bytes());
                if qtype == DNS_RECORD_A {
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&[198, 51, 100, 88]);
                } else {
                    resp.extend_from_slice(&16u16.to_be_bytes());
                    resp.extend_from_slice(
                        &"2001:db8::88"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                }
                mock_dns.send_to(&resp, peer).await.unwrap();
            }
        });

        let resolved = resolve_host_via_udp_dns_addrs("vless.example.org", &[dns_addr], None)
            .await
            .unwrap();
        responder.await.unwrap();
        assert_eq!(
            resolved,
            vec![
                "198.51.100.88".parse::<IpAddr>().unwrap(),
                "2001:db8::88".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
