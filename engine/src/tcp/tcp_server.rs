//! Local TCP listener & bidirectional TCP/UDP stream processor (`PLAN.md` §6).

use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::async_stream::{AsyncFlushMessage, AsyncMessageStream, AsyncStream};
use crate::config::TcpConfig;
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socket_util::set_tcp_keepalive;
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;

/// Error callback invoked on outbound dial failure so `vless-engine` can surface REALITY/auth/clock
/// or transport diagnostics in [`EngineStatus`].
pub type StreamErrorCallback = Arc<dyn Fn(&std::io::Error) + Send + Sync>;

async fn send_connect_failure(
    stream: &mut Box<dyn AsyncStream>,
    response: Option<fn(std::io::ErrorKind) -> Vec<u8>>,
    kind: std::io::ErrorKind,
) {
    let _ = timeout(crate::util::SHUTDOWN_TIMEOUT, async {
        if let Some(response) = response
            && stream.write_all(&response(kind)).await.is_ok()
        {
            let _ = stream.flush().await;
        }
        stream.shutdown().await
    })
    .await;
}

pub async fn run_tcp_listener(
    listener: Arc<tokio::net::TcpListener>,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    cancel: CancellationToken,
    on_error: Option<StreamErrorCallback>,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;
    let mut tasks = crate::listener_tasks::ListenerTasks::new();

    loop {
        let accepted = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("TCP listener shutting down");
                drop(tasks);
                return Ok(());
            }
            () = tasks.join_next(), if !tasks.is_empty() => continue,
            result = listener.accept() => result,
        };
        let (stream, addr) = match accepted {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(permit) = crate::resources::try_connection(Some(addr.ip())) else {
            continue;
        };

        if let Err(e) =
            set_tcp_keepalive(&stream, Duration::from_secs(300), Duration::from_secs(60))
        {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {e}");
        }

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        let error_cb = on_error.clone();
        let conn_cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let res = tokio::select! {
                () = conn_cancel.cancelled() => Ok(()),
                r = process_stream(stream, cloned_handler, cloned_resolver) => r,
            };
            if let Err(e) = res {
                if let Some(cb) = error_cb {
                    cb(&e);
                }
                debug!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    server_handler.setup_server_stream(Box::new(stream)).await
}

pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
    process_stream_with_permit(
        stream,
        server_handler,
        resolver,
        permit,
        Duration::from_secs(60),
    )
    .await
}

pub(crate) async fn process_stream_with_permit<AS: AsyncStream + 'static>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    _permit: crate::resources::BudgetPermit,
    setup_timeout: Duration,
) -> std::io::Result<()> {
    let source = stream.peer_addr();
    let setup_result =
        match timeout(setup_timeout, setup_server_stream(stream, server_handler)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to setup server stream: {e}"),
                ));
            }
            Err(elapsed) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("server setup timed out: {elapsed}"),
                ));
            }
        };

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            mut connection_success_response,
            mut connection_failure_response,
            initial_remote_data,
        } => {
            let setup_client_stream_future = async {
                let route = timeout(setup_timeout, async {
                    let prepared = super::ingress::PreparedTcp::new(
                        &proxy_selector,
                        remote_location.clone(),
                        initial_remote_data.map_or_else(Vec::new, |data| data.into_vec()),
                    )?
                    .with_source(source);
                    if prepared.needs_sniff_read() {
                        crate::util::timeout_stream_setup(async {
                            let response = connection_success_response.take();
                            connection_failure_response = None;
                            let flush = response.is_some() || server_need_initial_flush;
                            if let Some(data) = response {
                                write_all(&mut server_stream, &data).await?;
                            }
                            if flush {
                                server_stream.flush().await?;
                            }
                            Ok(())
                        })
                        .await?;
                    }
                    prepared
                        .route(&mut server_stream, &proxy_selector, &resolver)
                        .await
                })
                .await?;
                match route {
                    Ok(route) => timeout(setup_timeout, route.connect(&resolver)).await,
                    Err(error) => Ok(Err(error)),
                }
            };

            let routed = match setup_client_stream_future.await {
                Ok(Ok(routed)) => routed,
                Ok(Err(e)) => {
                    send_connect_failure(&mut server_stream, connection_failure_response, e.kind())
                        .await;
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to setup client stream to {remote_location}: {e}"),
                    ));
                }
                Err(elapsed) => {
                    send_connect_failure(
                        &mut server_stream,
                        connection_failure_response,
                        std::io::ErrorKind::TimedOut,
                    )
                    .await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("client setup to {remote_location} timed out: {elapsed}"),
                    ));
                }
            };
            drop(proxy_selector);
            drop(resolver);
            let Some(TcpClientSetupResult {
                mut client_stream,
                early_data,
            }) = routed.setup
            else {
                send_connect_failure(
                    &mut server_stream,
                    connection_failure_response,
                    std::io::ErrorKind::PermissionDenied,
                )
                .await;
                return Ok(());
            };
            debug!("TCP setup completed for {}", routed.wire_destination);

            crate::util::timeout_stream_setup(async {
                let flush_server = server_need_initial_flush || early_data.is_some();
                if let Some(data) = connection_success_response {
                    write_all(&mut server_stream, &data).await?;
                }
                if let Some(data) = early_data {
                    write_all(&mut server_stream, &data).await?;
                }
                if flush_server {
                    server_stream.flush().await?;
                }
                if !routed.is_local_dns && !routed.prefix.is_empty() {
                    write_all(&mut client_stream, &routed.prefix).await?;
                    client_stream.flush().await?;
                }
                Ok(())
            })
            .await?;

            if routed.is_local_dns {
                server_stream = Box::new(crate::prepend_stream::PrependStream::new(
                    server_stream,
                    Some(routed.prefix.into_boxed_slice()),
                ));
            } else {
                drop(routed.prefix);
            }

            let copy_result =
                copy_bidirectional(&mut server_stream, &mut client_stream, false, false).await;
            crate::util::shutdown_stream_pair(&mut server_stream, &mut client_stream).await;
            copy_result?;
            Ok(())
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: mut server_need_initial_flush,
            proxy_selector,
        } => {
            let mut server_stream = crate::routing::ingress::PeekMessageStream::new(server_stream);
            let setup = crate::util::timeout_stream_setup(async {
                let prepared =
                    crate::routing::ingress::PreparedUdp::new(&proxy_selector, remote_location)?;
                if prepared.needs_sniff(&proxy_selector) && server_need_initial_flush {
                    futures::future::poll_fn(|cx| {
                        std::pin::Pin::new(&mut server_stream).poll_flush_message(cx)
                    })
                    .await?;
                    server_need_initial_flush = false;
                }
                prepared
                    .route(&mut server_stream, &proxy_selector, &resolver)
                    .await?
                    .with_source(source)
                    .connect(&resolver)
                    .await
                    .map(|setup| setup.stream)
            })
            .await
            .map_err(|error| {
                if crate::routing::ingress::is_policy_block(&error) {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "Blocked bidirectional udp forward",
                    )
                } else {
                    error
                }
            });
            let client_stream = match setup {
                Ok(stream) => stream,
                Err(error) => {
                    crate::util::shutdown_message_stream(&mut server_stream).await;
                    return Err(error);
                }
            };
            run_udp_copy(
                server_stream,
                client_stream,
                server_need_initial_flush,
                false,
            )
            .await
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            run_udp_routing(
                ServerStream::Session(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::Session(session) => {
            drop(resolver);
            session.await;
            Ok(())
        }
    }
}

#[inline]
pub async fn run_udp_copy<S: AsyncMessageStream, C: AsyncMessageStream>(
    mut server_stream: S,
    mut client_stream: C,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    futures::join!(
        crate::util::shutdown_message_stream(&mut server_stream),
        crate::util::shutdown_message_stream(&mut client_stream),
    );

    copy_result
}
