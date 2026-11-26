use std::io;
use std::sync::Arc;

use tokio::io::AsyncRead;

use crate::address::NetLocation;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, IngressTarget};
use crate::dns_proxy::DnsForwarder;
use crate::resolver::Resolver;
use crate::sniff::{SNIFF_TIMEOUT, StreamProbe};

use super::tcp_handler::TcpClientSetupResult;

pub(crate) struct PreparedTcp {
    target: IngressTarget,
    prefix: Vec<u8>,
    probe: Option<StreamProbe>,
    source: Option<std::net::SocketAddr>,
}

pub(crate) struct RoutedTcp {
    pub wire_destination: NetLocation,
    pub is_local_dns: bool,
    pub setup: Option<TcpClientSetupResult>,
    pub prefix: Vec<u8>,
}

pub(crate) struct TcpRoute<'a> {
    wire_destination: NetLocation,
    prefix: Vec<u8>,
    target: TcpRouteTarget<'a>,
}

enum TcpRouteTarget<'a> {
    LocalDns(Arc<DnsForwarder>),
    Forward(ConnectDecision<'a>),
}

impl TcpRoute<'_> {
    pub(crate) async fn connect(self, resolver: &Arc<dyn Resolver>) -> io::Result<RoutedTcp> {
        let is_local_dns = matches!(&self.target, TcpRouteTarget::LocalDns(_));
        let setup = match self.target {
            TcpRouteTarget::LocalDns(forwarder) => Some(TcpClientSetupResult {
                client_stream: forwarder.tcp_stream(),
                early_data: None,
            }),
            TcpRouteTarget::Forward(ConnectDecision::Allow {
                chain_group,
                remote_location,
            }) => Some(chain_group.connect_tcp(remote_location, resolver).await?),
            TcpRouteTarget::Forward(ConnectDecision::Block) => None,
        };
        Ok(RoutedTcp {
            wire_destination: self.wire_destination,
            is_local_dns,
            setup,
            prefix: self.prefix,
        })
    }
}

impl PreparedTcp {
    pub(crate) fn new(
        selector: &ClientProxySelector,
        target: NetLocation,
        mut prefix: Vec<u8>,
    ) -> io::Result<Self> {
        let target = selector.prepare(target.into())?;
        let probe = match &target {
            IngressTarget::Forward(target) if selector.should_sniff(target) => {
                Some(StreamProbe::from_prefix(std::mem::take(&mut prefix)))
            }
            _ => None,
        };
        Ok(Self {
            target,
            prefix,
            probe,
            source: None,
        })
    }

    pub(crate) fn with_source(mut self, source: Option<std::net::SocketAddr>) -> Self {
        self.source = source;
        self
    }

    pub(crate) fn needs_sniff_read(&self) -> bool {
        self.probe.as_ref().is_some_and(StreamProbe::needs_more)
    }

    pub(crate) async fn route<'a, R: AsyncRead + Unpin + ?Sized>(
        self,
        inbound: &mut R,
        selector: &'a ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<TcpRoute<'a>> {
        let (hostname, prefix) = if let Some(probe) = self.probe {
            let result = probe.finish(inbound, SNIFF_TIMEOUT).await?;
            (result.hostname, result.prefix)
        } else {
            (None, self.prefix)
        };
        let (wire_destination, target) = match self.target {
            IngressTarget::LocalDns {
                wire_destination,
                forwarder,
            } => (wire_destination, TcpRouteTarget::LocalDns(forwarder)),
            IngressTarget::Forward(target) => {
                let routed = selector
                    .judge_prepared(target, hostname.as_deref(), resolver)
                    .await?;
                (
                    routed.wire_destination,
                    TcpRouteTarget::Forward(routed.decision),
                )
            }
        };
        Ok(TcpRoute {
            wire_destination,
            target,
            prefix,
        })
    }
}
