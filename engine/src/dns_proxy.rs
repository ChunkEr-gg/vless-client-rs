//! Port-53 DNS-over-XUDP shared multiplexer (`PLAN.md` §5.4, §6).
//!
//! In TUN mode, the helper sets the system DNS resolver to `dns_resolver` (default `1.1.1.1`),
//! which routes into `utun`. [`ClientProxySelector`] intercepts UDP and TCP port 53 destined to
//! `dns_resolver` (as well as `198.18.0.2`).
//!
//! Instead of opening a new REALITY/TLS + XUDP connection per UDP source port, [`DnsForwarder`]
//! multiplexes all UDP and RFC-1035-framed TCP DNS queries onto **one long-lived XUDP association**
//! (`COMMAND_MUX` to `resolver:53`):
//! - Rewrites 16-bit DNS transaction IDs on the wire so concurrent queries never collide, restoring
//!   each caller's original transaction ID when the matching response arrives.
//! - Lazily dials on first query, reconnects on demand if the XUDP stream closes or errors (with
//!   one automatic retry if a previously-used idle stream went stale), and uses zero timers while
//!   no queries are in flight. TCP queries too large for XUDP and truncated replies
//!   on a TCP request use a real VLESS TCP connection to the resolver.

use std::collections::{HashMap, VecDeque};
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use std::num::NonZeroU32;

use futures::stream::{FuturesUnordered, Stream};
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncShutdownMessageExt, AsyncStream, AsyncWriteMessage,
};
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;

const DNS_PORT: u16 = 53;
const DNS_HEADER_LEN: usize = 12;
/// Maximum XUDP payload size (`8192 - 666`, matching `XudpClientStream`).
const MAX_XUDP_DNS_PAYLOAD: usize = 8192 - 666;
const DNS_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const DNS_MUX_CHANNEL_CAPACITY: usize = 256;
const DNS_STREAM_INFLIGHT_CAP: usize = 64;

/// Legacy stub `utun` peer address accepted alongside `dns_resolver` on port 53.
pub const TUN_STUB_DNS_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));

type DialXudpFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn AsyncMessageStream>>> + Send + 'a>>;

#[async_trait::async_trait]
trait DnsXudpDialer: Send + Sync {
    async fn query_tcp(&self, _query: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn dial_xudp(&self) -> DialXudpFuture<'_>;
}

struct ChainXudpDialer {
    vless_chain: Arc<ClientChainGroup>,
    resolver: Arc<dyn Resolver>,
    upstream_dns: NetLocation,
}

#[async_trait::async_trait]
impl DnsXudpDialer for ChainXudpDialer {
    async fn query_tcp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let setup = self
            .vless_chain
            .connect_tcp(self.upstream_dns.clone().into(), &self.resolver)
            .await?;
        let mut stream = crate::prepend_stream::PrependStream::new(
            setup.client_stream,
            setup.early_data.map(Vec::into_boxed_slice),
        );
        stream
            .write_u16(u16::try_from(query.len()).map_err(io::Error::other)?)
            .await?;
        stream.write_all(query).await?;
        stream.flush().await?;
        let length = usize::from(stream.read_u16().await?);
        if length < DNS_HEADER_LEN {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut reply = vec![0; length];
        stream.read_exact(&mut reply).await?;
        if reply[..2] != query[..2] || reply[2] & 0x80 == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(reply)
    }

    fn dial_xudp(&self) -> DialXudpFuture<'_> {
        let target = self.upstream_dns.clone().into();
        Box::pin(async move {
            self.vless_chain
                .connect_udp_bidirectional(&self.resolver, target)
                .await
        })
    }
}

struct MuxRequest {
    query: Vec<u8>,
    reply_tx: oneshot::Sender<io::Result<Vec<u8>>>,
}

struct PendingQuery {
    orig_id: u16,
    reply_tx: oneshot::Sender<io::Result<Vec<u8>>>,
    sent_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
    /// Original query bytes retained so in-flight queries can be re-sent once if an idle cached
    /// stream went stale or if a live physical network interface transition resets the carrier.
    orig_query: Vec<u8>,
    allow_stale_retry: bool,
}

/// Multiplexes TUN port-53 DNS queries (both UDP datagrams and RFC 1035 TCP frames) onto one
/// shared, on-demand reconnecting XUDP association to `dns_resolver:53`.
pub struct DnsForwarder {
    dialer: Arc<dyn DnsXudpDialer>,
    dns_ip: IpAddr,
    upstream_dns: NetLocation,
    cancel: CancellationToken,
    reset_notify: Arc<Notify>,
    error_cb: Arc<RwLock<Option<crate::tcp::tcp_server::StreamErrorCallback>>>,
    mux_tx: Mutex<Option<mpsc::Sender<MuxRequest>>>,
}

impl std::fmt::Debug for DnsForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsForwarder")
            .field("upstream_dns", &self.upstream_dns)
            .finish()
    }
}

impl DnsForwarder {
    pub fn new(
        vless_chain: Arc<ClientChainGroup>,
        resolver: Arc<dyn Resolver>,
        dns_ip: IpAddr,
    ) -> Self {
        let upstream_dns = NetLocation::from_ip_addr(dns_ip, DNS_PORT);
        let dialer = Arc::new(ChainXudpDialer {
            vless_chain,
            resolver,
            upstream_dns: upstream_dns.clone(),
        });
        Self::with_dialer(dialer, dns_ip, upstream_dns)
    }

    fn with_dialer(
        dialer: Arc<dyn DnsXudpDialer>,
        dns_ip: IpAddr,
        upstream_dns: NetLocation,
    ) -> Self {
        Self {
            dialer,
            dns_ip,
            upstream_dns,
            cancel: CancellationToken::new(),
            reset_notify: Arc::new(Notify::new()),
            error_cb: Arc::new(RwLock::new(None)),
            mux_tx: Mutex::new(None),
        }
    }

    pub(crate) fn set_error_callback(
        &self,
        cb: Option<crate::tcp::tcp_server::StreamErrorCallback>,
    ) {
        *self.error_cb.write() = cb;
    }

    /// Signals that the active physical network interface changed (or the system woke from sleep),
    /// causing the XUDP DNS multiplexer to drop its cached carrier and migrate in-flight queries
    /// onto a freshly dialed carrier on the new interface.
    pub fn notify_network_changed(&self) {
        self.reset_notify.notify_one();
    }

    pub fn dns_ip(&self) -> IpAddr {
        self.dns_ip
    }

    pub fn upstream_location(&self) -> &NetLocation {
        &self.upstream_dns
    }

    /// Returns `true` when `location` targets port 53 at `dns_resolver` or `198.18.0.2`.
    pub fn should_intercept(&self, location: &NetLocation) -> bool {
        if location.port() != DNS_PORT {
            return false;
        }
        let Some(sa) = location.to_socket_addr_nonblocking() else {
            return false;
        };
        let ip = sa.ip().to_canonical();
        ip == self.dns_ip.to_canonical() || ip == TUN_STUB_DNS_IPV4
    }

    fn ensure_mux_sender(&self) -> mpsc::Sender<MuxRequest> {
        let mut guard = self.mux_tx.lock();
        if let Some(existing) = guard.as_ref()
            && !existing.is_closed()
        {
            return existing.clone();
        }
        let (tx, rx) = mpsc::channel(DNS_MUX_CHANNEL_CAPACITY);
        let dialer = self.dialer.clone();
        let cancel = self.cancel.clone();
        let reset_notify = self.reset_notify.clone();
        let error_cb = self.error_cb.clone();
        crate::network_tasks::spawn(run_xudp_dns_mux(dialer, rx, cancel, reset_notify, error_cb));
        *guard = Some(tx.clone());
        tx
    }

    /// Creates a TCP stream speaking RFC 1035 §4.2.2 2-byte big-endian length-prefixed DNS frames,
    /// Large queries and truncated replies use the upstream TCP stream.
    pub fn tcp_stream(&self) -> Box<dyn AsyncStream> {
        let (local, mut peer) = tokio::io::duplex(65536);
        let dialer = self.dialer.clone();
        let mux_tx = self.ensure_mux_sender();
        let cancel = self.cancel.clone();

        crate::network_tasks::spawn(async move {
            loop {
                let mut first_byte = [0u8; 1];
                let read_first = tokio::select! {
                    () = cancel.cancelled() => break,
                    res = peer.read(&mut first_byte) => res,
                };
                match read_first {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }

                let mut second_byte = [0u8; 1];
                if !matches!(
                    tokio::time::timeout(DNS_QUERY_TIMEOUT, peer.read_exact(&mut second_byte))
                        .await,
                    Ok(Ok(_))
                ) {
                    break;
                }
                let qlen = usize::from(u16::from_be_bytes([first_byte[0], second_byte[0]]));
                if qlen < DNS_HEADER_LEN {
                    log::debug!("Dropping invalid TCP DNS frame of length {qlen}");
                    break;
                }

                let mut query = vec![0u8; qlen];
                match tokio::time::timeout(DNS_QUERY_TIMEOUT, peer.read_exact(&mut query)).await {
                    Ok(Ok(_)) => {}
                    _ => break,
                }

                let exchange = async {
                    if query.len() <= MAX_XUDP_DNS_PAYLOAD {
                        let (reply_tx, reply_rx) = oneshot::channel();
                        mux_tx
                            .send(MuxRequest {
                                query: query.clone(),
                                reply_tx,
                            })
                            .await
                            .map_err(|_| io::ErrorKind::BrokenPipe)?;
                        let reply = reply_rx.await.map_err(|_| io::ErrorKind::BrokenPipe)??;
                        if reply.len() >= DNS_HEADER_LEN && reply[2] & 0x02 == 0 {
                            return Ok(reply);
                        }
                    }
                    dialer.query_tcp(&query).await
                };
                let resp = tokio::select! {
                    () = cancel.cancelled() => break,
                    result = tokio::time::timeout(DNS_QUERY_TIMEOUT, exchange) => match result {
                        Ok(Ok(reply)) => reply,
                        _ => break,
                    },
                };
                let Ok(rlen) = u16::try_from(resp.len()) else {
                    break;
                };
                let mut framed = Vec::with_capacity(2 + resp.len());
                framed.extend_from_slice(&rlen.to_be_bytes());
                framed.extend_from_slice(&resp);
                if peer.write_all(&framed).await.is_err() || peer.flush().await.is_err() {
                    break;
                }
            }
            let _ = peer.shutdown().await;
        });

        Box::new(DuplexAsyncStream(local))
    }

    /// Creates a message stream that forwards raw UDP DNS datagrams through the single shared XUDP
    /// association.
    pub fn udp_stream(&self) -> Box<dyn AsyncMessageStream> {
        let mux_tx = self.ensure_mux_sender();
        Box::new(DnsUdpMessageStream {
            mux_tx: Some(mux_tx),
            inflight: FuturesUnordered::new(),
            read_waker: None,
        })
    }
}

impl Drop for DnsForwarder {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

enum StreamStep {
    Received(Vec<u8>),
    Closed(io::Result<()>),
}

async fn poll_xudp_stream_step(
    stream: &mut Box<dyn AsyncMessageStream>,
    outbound_queue: &mut VecDeque<Vec<u8>>,
    needs_flush: &mut bool,
) -> StreamStep {
    poll_fn(|cx| {
        while let Some(front) = outbound_queue.front() {
            match Pin::new(&mut **stream).poll_write_message(cx, front) {
                Poll::Ready(Ok(())) => {
                    outbound_queue.pop_front();
                    *needs_flush = true;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(StreamStep::Closed(Err(err))),
                Poll::Pending => break,
            }
        }

        if *needs_flush && outbound_queue.is_empty() {
            match Pin::new(&mut **stream).poll_flush_message(cx) {
                Poll::Ready(Ok(())) => {
                    *needs_flush = false;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(StreamStep::Closed(Err(err))),
                Poll::Pending => {}
            }
        }

        loop {
            let mut storage = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut storage);
            match Pin::new(&mut **stream).poll_read_message(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        if stream.read_message_eof_on_empty() {
                            return Poll::Ready(StreamStep::Closed(Ok(())));
                        }
                        continue;
                    }
                    return Poll::Ready(StreamStep::Received(filled.to_vec()));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(StreamStep::Closed(Err(err))),
                Poll::Pending => break,
            }
        }

        Poll::Pending
    })
    .await
}

fn allocate_wire_id(next_id: &mut u16, pending: &HashMap<u16, PendingQuery>) -> Option<u16> {
    if pending.len() >= usize::from(u16::MAX) {
        return None;
    }
    for _ in 0..=usize::from(u16::MAX) {
        let candidate = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn enqueue_query(
    query: Vec<u8>,
    reply_tx: oneshot::Sender<io::Result<Vec<u8>>>,
    sent_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
    allow_stale_retry: bool,
    next_wire_id: &mut u16,
    pending: &mut HashMap<u16, PendingQuery>,
    outbound_queue: &mut VecDeque<Vec<u8>>,
) {
    if !(DNS_HEADER_LEN..=MAX_XUDP_DNS_PAYLOAD).contains(&query.len()) {
        let _ = reply_tx.send(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "DNS query length {} outside valid XUDP bounds ({DNS_HEADER_LEN}..={MAX_XUDP_DNS_PAYLOAD})",
                query.len()
            ),
        )));
        return;
    }

    let Some(wire_id) = allocate_wire_id(next_wire_id, pending) else {
        let _ = reply_tx.send(Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "all 65535 DNS wire IDs are currently in flight",
        )));
        return;
    };

    let orig_id = u16::from_be_bytes([query[0], query[1]]);
    let orig_query = query.clone();
    let mut wire_pkt = query;
    let wire_bytes = wire_id.to_be_bytes();
    wire_pkt[0] = wire_bytes[0];
    wire_pkt[1] = wire_bytes[1];

    pending.insert(
        wire_id,
        PendingQuery {
            orig_id,
            reply_tx,
            sent_at,
            deadline,
            orig_query,
            allow_stale_retry,
        },
    );
    outbound_queue.push_back(wire_pkt);
}

async fn dial_xudp_cancellable(
    dialer: &Arc<dyn DnsXudpDialer>,
    cancel: &CancellationToken,
) -> Option<io::Result<Box<dyn AsyncMessageStream>>> {
    tokio::select! {
        () = cancel.cancelled() => None,
        res = tokio::time::timeout(DNS_DIAL_TIMEOUT, dialer.dial_xudp()) => Some(match res {
            Ok(inner) => inner,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS-over-XUDP dial timed out",
            )),
        }),
    }
}

fn report_dns_error(
    error_cb: &RwLock<Option<crate::tcp::tcp_server::StreamErrorCallback>>,
    err: &io::Error,
) {
    if let Some(ref cb) = *error_cb.read() {
        cb(err);
    }
}

/// Sweeps expired in-flight queries and returns `true` if any query timed out while the active
/// XUDP carrier produced zero responses since that query was dispatched (indicating a half-open /
/// blackholed TCP carrier that must be dropped so subsequent queries reconnect cleanly).
fn sweep_expired_pending(
    pending: &mut HashMap<u16, PendingQuery>,
    last_rx_at: Option<tokio::time::Instant>,
) -> bool {
    let now = tokio::time::Instant::now();
    let expired_ids: Vec<u16> = pending
        .iter()
        .filter_map(|(&id, entry)| (now > entry.deadline).then_some(id))
        .collect();
    let mut carrier_unresponsive = false;
    for id in expired_ids {
        if let Some(entry) = pending.remove(&id) {
            if last_rx_at.is_none_or(|rx_t| rx_t < entry.sent_at) {
                carrier_unresponsive = true;
            }
            let _ = entry.reply_tx.send(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS-over-XUDP query timed out",
            )));
        }
    }
    carrier_unresponsive
}

async fn run_xudp_dns_mux(
    dialer: Arc<dyn DnsXudpDialer>,
    mut req_rx: mpsc::Receiver<MuxRequest>,
    cancel: CancellationToken,
    reset_notify: Arc<Notify>,
    error_cb: Arc<RwLock<Option<crate::tcp::tcp_server::StreamErrorCallback>>>,
) {
    let mut stream: Option<Box<dyn AsyncMessageStream>> = None;
    let mut stream_has_succeeded = false;
    let mut last_rx_at: Option<tokio::time::Instant> = None;
    let mut dialed_if_index: Option<NonZeroU32> = None;
    let mut outbound_queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut needs_flush = false;
    let mut pending: HashMap<u16, PendingQuery> = HashMap::new();
    let mut next_wire_id: u16 = rand::random();
    let mut sweep_interval = tokio::time::interval(DNS_SWEEP_INTERVAL);
    sweep_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let has_pending = !pending.is_empty();
        tokio::select! {
            () = cancel.cancelled() => {
                break;
            }
            () = reset_notify.notified() => {
                stream = None;
                stream_has_succeeded = false;
                last_rx_at = None;
                dialed_if_index = None;
                outbound_queue.clear();
                needs_flush = false;

                let now = tokio::time::Instant::now();
                let mut retry_batch = Vec::new();
                for (_, entry) in pending.drain() {
                    if now <= entry.deadline {
                        retry_batch.push((entry.orig_query, entry.reply_tx, entry.deadline));
                    } else {
                        let _ = entry.reply_tx.send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DNS-over-XUDP query timed out",
                        )));
                    }
                }

                if !retry_batch.is_empty() {
                    let cur_if = crate::socket_policy::outbound_interface_index();
                    let Some(dial_res) = dial_xudp_cancellable(&dialer, &cancel).await else {
                        for (_, reply_tx, _) in retry_batch {
                            let _ = reply_tx.send(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "DNS forwarder shut down",
                            )));
                        }
                        break;
                    };
                    match dial_res {
                        Ok(new_stream) => {
                            stream = Some(new_stream);
                            dialed_if_index = cur_if;
                            let sent_at = tokio::time::Instant::now();
                            for (orig_query, reply_tx, deadline) in retry_batch {
                                enqueue_query(
                                    orig_query,
                                    reply_tx,
                                    sent_at,
                                    deadline,
                                    false,
                                    &mut next_wire_id,
                                    &mut pending,
                                    &mut outbound_queue,
                                );
                            }
                        }
                        Err(dial_err) => {
                            report_dns_error(&error_cb, &dial_err);
                            for (_, reply_tx, _) in retry_batch {
                                let _ = reply_tx.send(Err(io::Error::new(
                                    dial_err.kind(),
                                    dial_err.to_string(),
                                )));
                            }
                        }
                    }
                }
            }
            _ = sweep_interval.tick(), if has_pending => {
                if sweep_expired_pending(&mut pending, last_rx_at) && stream.is_some() {
                    log::debug!("Resetting unresponsive DNS-over-XUDP carrier after query timeout");
                    stream = None;
                    stream_has_succeeded = false;
                    last_rx_at = None;
                    dialed_if_index = None;
                    outbound_queue.clear();
                    needs_flush = false;
                }
            }
            step = async {
                let s = stream.as_mut().expect("guarded by stream.is_some()");
                poll_xudp_stream_step(s, &mut outbound_queue, &mut needs_flush).await
            }, if stream.is_some() => {
                match step {
                    StreamStep::Received(mut resp) => {
                        let now = tokio::time::Instant::now();
                        last_rx_at = Some(now);
                        stream_has_succeeded = true;
                        if resp.len() >= DNS_HEADER_LEN {
                            let wire_id = u16::from_be_bytes([resp[0], resp[1]]);
                            if let Some(entry) = pending.remove(&wire_id)
                                && now <= entry.deadline
                            {
                                let orig = entry.orig_id.to_be_bytes();
                                resp[0] = orig[0];
                                resp[1] = orig[1];
                                let _ = entry.reply_tx.send(Ok(resp));
                            }
                        }
                    }
                    StreamStep::Closed(close_res) => {
                        if let Err(ref err) = close_res {
                            report_dns_error(&error_cb, err);
                        }
                        stream = None;
                        stream_has_succeeded = false;
                        last_rx_at = None;
                        dialed_if_index = None;
                        outbound_queue.clear();
                        needs_flush = false;

                        let now = tokio::time::Instant::now();
                        let mut retry_batch = Vec::new();
                        for (_, entry) in pending.drain() {
                            if now <= entry.deadline && entry.allow_stale_retry {
                                retry_batch.push((entry.orig_query, entry.reply_tx, entry.deadline));
                            } else {
                                let err = match &close_res {
                                    Ok(()) => io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "DNS XUDP stream closed by peer",
                                    ),
                                    Err(e) => io::Error::new(e.kind(), e.to_string()),
                                };
                                let _ = entry.reply_tx.send(Err(err));
                            }
                        }

                        if !retry_batch.is_empty() {
                            let cur_if = crate::socket_policy::outbound_interface_index();
                            let Some(dial_res) = dial_xudp_cancellable(&dialer, &cancel).await else {
                                for (_, reply_tx, _) in retry_batch {
                                    let _ = reply_tx.send(Err(io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "DNS forwarder shut down",
                                    )));
                                }
                                break;
                            };
                            match dial_res {
                                Ok(new_stream) => {
                                    stream = Some(new_stream);
                                    dialed_if_index = cur_if;
                                    let sent_at = tokio::time::Instant::now();
                                    for (orig_query, reply_tx, deadline) in retry_batch {
                                        enqueue_query(
                                            orig_query,
                                            reply_tx,
                                            sent_at,
                                            deadline,
                                            false,
                                            &mut next_wire_id,
                                            &mut pending,
                                            &mut outbound_queue,
                                        );
                                    }
                                }
                                Err(dial_err) => {
                                    report_dns_error(&error_cb, &dial_err);
                                    for (_, reply_tx, _) in retry_batch {
                                        let _ = reply_tx.send(Err(io::Error::new(
                                            dial_err.kind(),
                                            dial_err.to_string(),
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            req_opt = req_rx.recv() => {
                let Some(req) = req_opt else {
                    break;
                };
                if !(DNS_HEADER_LEN..=MAX_XUDP_DNS_PAYLOAD).contains(&req.query.len()) {
                    let _ = req.reply_tx.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid DNS query length",
                    )));
                    continue;
                }

                let cur_if = crate::socket_policy::outbound_interface_index();
                if stream.is_some() && pending.is_empty() && cur_if != dialed_if_index {
                    stream = None;
                    stream_has_succeeded = false;
                    last_rx_at = None;
                    dialed_if_index = None;
                    outbound_queue.clear();
                    needs_flush = false;
                }

                let sent_at = tokio::time::Instant::now();
                let deadline = sent_at + DNS_QUERY_TIMEOUT;
                if stream.is_none() {
                    let Some(dial_res) = dial_xudp_cancellable(&dialer, &cancel).await else {
                        let _ = req.reply_tx.send(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "DNS forwarder shut down",
                        )));
                        break;
                    };
                    match dial_res {
                        Ok(new_stream) => {
                            stream = Some(new_stream);
                            dialed_if_index = cur_if;
                            enqueue_query(
                                req.query,
                                req.reply_tx,
                                sent_at,
                                deadline,
                                false,
                                &mut next_wire_id,
                                &mut pending,
                                &mut outbound_queue,
                            );
                        }
                        Err(err) => {
                            log::debug!("DNS-over-XUDP connect failed: {err}");
                            report_dns_error(&error_cb, &err);
                            let _ = req.reply_tx.send(Err(err));
                        }
                    }
                } else {
                    enqueue_query(
                        req.query,
                        req.reply_tx,
                        sent_at,
                        deadline,
                        stream_has_succeeded,
                        &mut next_wire_id,
                        &mut pending,
                        &mut outbound_queue,
                    );
                }
            }
        }
    }

    for (_, entry) in pending.drain() {
        let _ = entry.reply_tx.send(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "DNS forwarder shut down",
        )));
    }
    if let Some(mut active_stream) = stream {
        let _ =
            tokio::time::timeout(Duration::from_secs(1), active_stream.shutdown_message()).await;
    }
}

struct DuplexAsyncStream(tokio::io::DuplexStream);

impl AsyncRead for DuplexAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexAsyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncPing for DuplexAsyncStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for DuplexAsyncStream {}

struct DnsUdpMessageStream {
    mux_tx: Option<mpsc::Sender<MuxRequest>>,
    inflight: FuturesUnordered<oneshot::Receiver<io::Result<Vec<u8>>>>,
    read_waker: Option<Waker>,
}

impl AsyncReadMessage for DnsUdpMessageStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match Pin::new(&mut self.inflight).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(Ok(bytes)))) => {
                    let copy_len = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..copy_len]);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Err(err)))) => {
                    log::debug!("UDP DNS query via shared XUDP failed: {err}");
                }
                Poll::Ready(Some(Err(_))) => {}
                Poll::Ready(None) => {
                    if self.mux_tx.is_none() {
                        return Poll::Ready(Ok(()));
                    }
                    self.read_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWriteMessage for DnsUdpMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        let Some(ref tx) = self.mux_tx else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DNS forwarder UDP stream is shut down",
            )));
        };
        if !(DNS_HEADER_LEN..=MAX_XUDP_DNS_PAYLOAD).contains(&buf.len()) {
            return Poll::Ready(Ok(()));
        }
        if self.inflight.len() >= DNS_STREAM_INFLIGHT_CAP {
            log::debug!("Dropping excess in-flight UDP DNS query on single flow");
            return Poll::Ready(Ok(()));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        match tx.try_send(MuxRequest {
            query: buf.to_vec(),
            reply_tx,
        }) {
            Ok(()) => {
                self.inflight.push(reply_rx);
                if let Some(waker) = self.read_waker.take() {
                    waker.wake();
                }
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::debug!("Shared XUDP DNS mux queue full; dropping excess DNS query");
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DNS forwarder shared XUDP worker exited",
            ))),
        }
    }
}

impl AsyncFlushMessage for DnsUdpMessageStream {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for DnsUdpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.mux_tx = None;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for DnsUdpMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for DnsUdpMessageStream {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct MockPacketStream {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl AsyncReadMessage for MockPacketStream {
        fn poll_read_message(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(pkt)) => {
                    buf.put_slice(&pkt);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            }
        }
    }

    impl AsyncWriteMessage for MockPacketStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<()>> {
            self.tx
                .send(buf.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock server closed"))?;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for MockPacketStream {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for MockPacketStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for MockPacketStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for MockPacketStream {}

    type MockConnPair = (
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedSender<Vec<u8>>,
    );

    struct MockXudpDialer {
        dial_count: Arc<AtomicUsize>,
        conn_tx: mpsc::UnboundedSender<MockConnPair>,
    }

    impl DnsXudpDialer for MockXudpDialer {
        fn dial_xudp(&self) -> DialXudpFuture<'_> {
            self.dial_count.fetch_add(1, Ordering::SeqCst);
            let (c2s_tx, c2s_rx) = mpsc::unbounded_channel();
            let (s2c_tx, s2c_rx) = mpsc::unbounded_channel();
            let _ = self.conn_tx.send((c2s_rx, s2c_tx));
            Box::pin(async move {
                Ok(Box::new(MockPacketStream {
                    tx: c2s_tx,
                    rx: s2c_rx,
                }) as Box<dyn AsyncMessageStream>)
            })
        }
    }

    fn make_dns_packet(tx_id: u16, marker: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 16];
        pkt[0..2].copy_from_slice(&tx_id.to_be_bytes());
        pkt[2] = 0x01;
        pkt[5] = 0x01;
        pkt[12] = marker;
        pkt
    }

    #[tokio::test]
    async fn maximum_length_dns_query_reaches_tcp_resolver_intact() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = NetLocation::from_ip_addr(addr.ip(), addr.port());
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_direct_chain_group(resolver.clone());
        let dialer = ChainXudpDialer {
            resolver,
            vless_chain: Arc::new(chain),
            upstream_dns: target.clone(),
        };
        let forwarder = DnsForwarder::with_dialer(Arc::new(dialer), addr.ip(), target);
        let mut local = forwarder.tcp_stream();
        let mut query = make_dns_packet(0x1234, 0xab);
        query.extend((query.len()..usize::from(u16::MAX)).map(|i| (i % 251) as u8));
        let mut reply = make_dns_packet(0x1234, 0xcd);
        reply[2] |= 0x80;
        let upstream = async {
            let (mut tcp, _) = listener.accept().await.unwrap();
            assert_eq!(tcp.read_u16().await.unwrap(), u16::MAX);
            let mut received = vec![0; query.len()];
            tcp.read_exact(&mut received).await.unwrap();
            assert_eq!(received, query);
            tcp.write_u16(reply.len() as u16).await.unwrap();
            tcp.write_all(&reply).await.unwrap();
        };
        let client = async {
            local.write_u16(u16::MAX).await.unwrap();
            local.write_all(&query).await.unwrap();
            assert_eq!(usize::from(local.read_u16().await.unwrap()), reply.len());
            let mut received = vec![0; reply.len()];
            local.read_exact(&mut received).await.unwrap();
            assert_eq!(received, reply);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(upstream, client);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shared_xudp_mux_rewrites_colliding_ids_handles_tcp_and_udp_and_reconnects_on_stale() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        let dialer = Arc::new(MockXudpDialer {
            dial_count: dial_count.clone(),
            conn_tx,
        });
        let dns_ip: IpAddr = "1.1.1.1".parse().unwrap();
        let forwarder =
            DnsForwarder::with_dialer(dialer, dns_ip, NetLocation::from_ip_addr(dns_ip, DNS_PORT));

        let mut udp_a = forwarder.udp_stream();
        let mut udp_b = forwarder.udp_stream();
        let mut tcp_c = forwarder.tcp_stream();

        // Both UDP clients use the EXACT SAME transaction ID `0xCAFE` concurrently!
        let q_a = make_dns_packet(0xcafe, 0xaa);
        let q_b = make_dns_packet(0xcafe, 0xbb);
        let q_c = make_dns_packet(0xbeef, 0xcc);

        poll_fn(|cx| Pin::new(&mut *udp_a).poll_write_message(cx, &q_a))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *udp_b).poll_write_message(cx, &q_b))
            .await
            .unwrap();

        let mut tcp_frame = Vec::new();
        tcp_frame.extend_from_slice(&(q_c.len() as u16).to_be_bytes());
        tcp_frame.extend_from_slice(&q_c);
        tcp_c.write_all(&tcp_frame).await.unwrap();
        tcp_c.flush().await.unwrap();

        // Accept the SINGLE shared XUDP stream on the mock server
        let (mut server_rx, server_tx) = conn_rx.recv().await.unwrap();
        let rx1 = server_rx.recv().await.unwrap();
        let rx2 = server_rx.recv().await.unwrap();
        let rx3 = server_rx.recv().await.unwrap();
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            1,
            "all UDP + TCP DNS flows must share ONE XUDP connection"
        );

        let id1 = u16::from_be_bytes([rx1[0], rx1[1]]);
        let id2 = u16::from_be_bytes([rx2[0], rx2[1]]);
        let id3 = u16::from_be_bytes([rx3[0], rx3[1]]);
        assert_ne!(id1, id2, "colliding client IDs must get distinct wire IDs");
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Reply OUT OF ORDER (`rx3`, `rx2`, `rx1`) with distinct answer markers
        for mut pkt in [rx3, rx2, rx1] {
            pkt[2] = 0x81;
            pkt[3] = 0x80;
            let marker = pkt[12];
            pkt.extend_from_slice(&[marker, marker, marker, marker]);
            server_tx.send(pkt).unwrap();
        }

        let mut buf_a = [0u8; 64];
        let mut rbuf_a = ReadBuf::new(&mut buf_a);
        poll_fn(|cx| Pin::new(&mut *udp_a).poll_read_message(cx, &mut rbuf_a))
            .await
            .unwrap();
        assert_eq!(&rbuf_a.filled()[0..2], &0xcafeu16.to_be_bytes());
        assert_eq!(&rbuf_a.filled()[16..20], &[0xaa; 4]);

        let mut buf_b = [0u8; 64];
        let mut rbuf_b = ReadBuf::new(&mut buf_b);
        poll_fn(|cx| Pin::new(&mut *udp_b).poll_read_message(cx, &mut rbuf_b))
            .await
            .unwrap();
        assert_eq!(&rbuf_b.filled()[0..2], &0xcafeu16.to_be_bytes());
        assert_eq!(&rbuf_b.filled()[16..20], &[0xbb; 4]);

        let mut len_c = [0u8; 2];
        tcp_c.read_exact(&mut len_c).await.unwrap();
        let mut resp_c = vec![0u8; usize::from(u16::from_be_bytes(len_c))];
        tcp_c.read_exact(&mut resp_c).await.unwrap();
        assert_eq!(&resp_c[0..2], &0xbeefu16.to_be_bytes());
        assert_eq!(&resp_c[16..20], &[0xcc; 4]);

        // Drop `server_rx` & `server_tx` to simulate idle XUDP association closure, then verify
        // on-demand reconnect (`dial_count` increments to 2) on the next query!
        drop(server_rx);
        drop(server_tx);

        let q_after = make_dns_packet(0x1234, 0xdd);
        poll_fn(|cx| Pin::new(&mut *udp_a).poll_write_message(cx, &q_after))
            .await
            .unwrap();

        let (mut server_rx2, server_tx2) = conn_rx.recv().await.unwrap();
        let mut rx_after = server_rx2.recv().await.unwrap();
        assert_eq!(dial_count.load(Ordering::SeqCst), 2);
        rx_after[2] = 0x81;
        rx_after[3] = 0x80;
        rx_after.extend_from_slice(&[0xdd; 4]);
        server_tx2.send(rx_after).unwrap();

        let mut buf_after = [0u8; 64];
        let mut rbuf_after = ReadBuf::new(&mut buf_after);
        poll_fn(|cx| Pin::new(&mut *udp_a).poll_read_message(cx, &mut rbuf_after))
            .await
            .unwrap();
        assert_eq!(&rbuf_after.filled()[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&rbuf_after.filled()[16..20], &[0xdd; 4]);
    }

    struct DelayedMockXudpDialer {
        dial_count: Arc<AtomicUsize>,
        delay: Duration,
        conn_tx: mpsc::UnboundedSender<MockConnPair>,
    }

    impl DnsXudpDialer for DelayedMockXudpDialer {
        fn dial_xudp(&self) -> DialXudpFuture<'_> {
            self.dial_count.fetch_add(1, Ordering::SeqCst);
            let delay = self.delay;
            let (c2s_tx, c2s_rx) = mpsc::unbounded_channel();
            let (s2c_tx, s2c_rx) = mpsc::unbounded_channel();
            let _ = self.conn_tx.send((c2s_rx, s2c_tx));
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(Box::new(MockPacketStream {
                    tx: c2s_tx,
                    rx: s2c_rx,
                }) as Box<dyn AsyncMessageStream>)
            })
        }
    }

    #[tokio::test]
    async fn cold_start_burst_dials_once_and_network_change_migrates_inflight_queries() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        let dialer = Arc::new(DelayedMockXudpDialer {
            dial_count: dial_count.clone(),
            delay: Duration::from_millis(20),
            conn_tx,
        });
        let dns_ip: IpAddr = "1.1.1.1".parse().unwrap();
        let forwarder = Arc::new(DnsForwarder::with_dialer(
            dialer,
            dns_ip,
            NetLocation::from_ip_addr(dns_ip, DNS_PORT),
        ));

        // 1. Cold-start burst: 36 concurrent queries arrive BEFORE the first XUDP handshake completes.
        const BURST: usize = 36;
        let mut readers = Vec::with_capacity(BURST);
        for idx in 0..BURST {
            let mut s = forwarder.udp_stream();
            let q = make_dns_packet(0x4000, idx as u8);
            poll_fn(|cx| Pin::new(&mut *s).poll_write_message(cx, &q))
                .await
                .unwrap();
            readers.push((idx as u8, s));
        }

        let (mut server_rx1, server_tx1) = conn_rx.recv().await.unwrap();
        let mut wire_ids = std::collections::HashSet::new();
        let mut wire_packets = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            let pkt = tokio::time::timeout(Duration::from_secs(2), server_rx1.recv())
                .await
                .unwrap()
                .unwrap();
            let wid = u16::from_be_bytes([pkt[0], pkt[1]]);
            assert!(wire_ids.insert(wid), "duplicate wire ID {wid} in burst");
            wire_packets.push(pkt);
        }
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            1,
            "36 cold-start DNS queries must share a single initial XUDP dial"
        );

        for mut pkt in wire_packets.into_iter().rev() {
            pkt[2] = 0x81;
            pkt[3] = 0x80;
            let marker = pkt[12];
            pkt.extend_from_slice(&[marker; 4]);
            server_tx1.send(pkt).unwrap();
        }

        for (expected_marker, mut s) in readers {
            let mut buf = [0u8; 64];
            let mut rbuf = ReadBuf::new(&mut buf);
            poll_fn(|cx| Pin::new(&mut *s).poll_read_message(cx, &mut rbuf))
                .await
                .unwrap();
            assert_eq!(&rbuf.filled()[0..2], &0x4000u16.to_be_bytes());
            assert_eq!(&rbuf.filled()[16..20], &[expected_marker; 4]);
        }

        // 2. Simulate live Wi-Fi -> Hotspot transition: two queries are in flight on blackholed
        // `server_rx1` (which stays open without replying), then `notify_network_changed()` fires!
        let mut mig_a = forwarder.udp_stream();
        let mut mig_b = forwarder.udp_stream();
        poll_fn(|cx| Pin::new(&mut *mig_a).poll_write_message(cx, &make_dns_packet(0x7001, 0xe1)))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *mig_b).poll_write_message(cx, &make_dns_packet(0x7002, 0xe2)))
            .await
            .unwrap();
        // Wait until both queries have reached the old stalled carrier
        let _ = server_rx1.recv().await.unwrap();
        let _ = server_rx1.recv().await.unwrap();

        forwarder.notify_network_changed();

        let (mut server_rx2, server_tx2) =
            tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(dial_count.load(Ordering::SeqCst), 2);

        for _ in 0..2 {
            let mut pkt = tokio::time::timeout(Duration::from_secs(2), server_rx2.recv())
                .await
                .unwrap()
                .unwrap();
            pkt[2] = 0x81;
            pkt[3] = 0x80;
            let marker = pkt[12];
            pkt.extend_from_slice(&[marker; 4]);
            server_tx2.send(pkt).unwrap();
        }

        for (expected_id, expected_marker, s) in [
            (0x7001u16, 0xe1u8, &mut mig_a),
            (0x7002u16, 0xe2u8, &mut mig_b),
        ] {
            let mut buf = [0u8; 64];
            let mut rbuf = ReadBuf::new(&mut buf);
            poll_fn(|cx| Pin::new(&mut **s).poll_read_message(cx, &mut rbuf))
                .await
                .unwrap();
            assert_eq!(&rbuf.filled()[0..2], &expected_id.to_be_bytes());
            assert_eq!(&rbuf.filled()[16..20], &[expected_marker; 4]);
        }
    }

    struct FailingDialer;
    impl DnsXudpDialer for FailingDialer {
        fn dial_xudp(&self) -> DialXudpFuture<'_> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    vless_ipc::REALITY_AUTH_OR_CLOCK_ERROR,
                ))
            })
        }
    }

    #[tokio::test]
    async fn tcp_dns_truncated_length_exits_cleanly_and_sweep_detects_unresponsive_carrier() {
        let dns_ip: IpAddr = "1.1.1.1".parse().unwrap();
        let forwarder = DnsForwarder::with_dialer(
            Arc::new(FailingDialer),
            dns_ip,
            NetLocation::from_ip_addr(dns_ip, DNS_PORT),
        );
        let seen_errors = Arc::new(AtomicUsize::new(0));
        let seen_clone = seen_errors.clone();
        forwarder.set_error_callback(Some(Arc::new(move |err| {
            if err
                .to_string()
                .contains(vless_ipc::REALITY_AUTH_OR_CLOCK_ERROR)
            {
                seen_clone.fetch_add(1, Ordering::SeqCst);
            }
        })));

        // 1-byte truncated TCP DNS prefix (`[0x01]` followed by EOF) must exit immediately without
        // dialing or hanging.
        let mut tcp_trunc = forwarder.tcp_stream();
        tcp_trunc.write_all(&[0x01]).await.unwrap();
        tcp_trunc.shutdown().await.unwrap();
        let mut eof_buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(1), tcp_trunc.read(&mut eof_buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(seen_errors.load(Ordering::SeqCst), 0);

        // Full UDP DNS query against FailingDialer must invoke error callback with REALITY error.
        let mut udp = forwarder.udp_stream();
        let q = make_dns_packet(0x1111, 0x22);
        poll_fn(|cx| Pin::new(&mut *udp).poll_write_message(cx, &q))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while seen_errors.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("FailingDialer must fire error callback with REALITY_AUTH_OR_CLOCK_ERROR");
        assert_eq!(seen_errors.load(Ordering::SeqCst), 1);

        // Verify `sweep_expired_pending` distinguishes dead carrier vs healthy carrier.
        let now = tokio::time::Instant::now();
        let mut pending = HashMap::new();
        let (tx1, _rx1) = oneshot::channel();
        pending.insert(
            1,
            PendingQuery {
                orig_id: 1,
                reply_tx: tx1,
                sent_at: now - Duration::from_secs(6),
                deadline: now - Duration::from_secs(1),
                orig_query: q.clone(),
                allow_stale_retry: false,
            },
        );
        // Another query received a reply 2s ago (after `sent_at`) -> carrier is healthy (`false`).
        assert!(!sweep_expired_pending(
            &mut pending,
            Some(now - Duration::from_secs(2))
        ));

        let (tx2, _rx2) = oneshot::channel();
        pending.insert(
            2,
            PendingQuery {
                orig_id: 2,
                reply_tx: tx2,
                sent_at: now - Duration::from_secs(6),
                deadline: now - Duration::from_secs(1),
                orig_query: q,
                allow_stale_retry: false,
            },
        );
        // Last RX was 10s ago (before `sent_at`) -> carrier is unresponsive (`true`).
        assert!(sweep_expired_pending(
            &mut pending,
            Some(now - Duration::from_secs(10))
        ));
    }
}
