//! Inbound HTTP/1.x CONNECT & absolute-form proxy handler (`PLAN.md` §6).

use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const PROXY_AUTH_HEADER_PREFIX: &str = "proxy-authorization: basic ";
const CONNECTION_HEADER_PREFIX: &str = "connection: ";
const PROXY_CONNECTION_HEADER_PREFIX: &str = "proxy-connection: ";

async fn authentication_challenge(
    stream: &mut Box<dyn AsyncStream>,
    version: &str,
) -> std::io::Result<()> {
    let response = format!(
        concat!(
            "{} 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"proxy\"\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n\r\n",
        ),
        version,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

fn create_http_auth_token(username: &str, password: &str) -> String {
    BASE64.encode(format!("{username}:{password}"))
}

#[derive(Debug)]
pub struct HttpTcpServerHandler {
    auth_token: Option<String>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl HttpTcpServerHandler {
    pub fn new(
        auth_credentials: Option<(String, String)>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let auth_token = auth_credentials
            .map(|(username, password)| create_http_auth_token(&username, &password));
        Self {
            auth_token,
            proxy_selector,
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_reader = StreamReader::new();
        setup_http_server_stream_inner(
            self.auth_token.as_deref(),
            server_stream,
            stream_reader,
            self.proxy_selector.clone(),
            self.resolver.clone(),
        )
        .await
    }
}

pub async fn setup_http_server_stream_inner(
    auth_token: Option<&str>,
    mut server_stream: Box<dyn AsyncStream>,
    mut stream_reader: StreamReader,
    proxy_selector: Arc<ClientProxySelector>,
    _resolver: Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    let line = stream_reader.read_line(&mut server_stream).await?;
    if !line.ends_with(" HTTP/1.0") && !line.ends_with(" HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unrecognized http request: {line}"),
        ));
    }

    if line.len() < 19 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid http request: {line}"),
        ));
    }

    let http_version = line[line.len() - 8..].to_string();
    let (remote_location, connection_success_response, initial_remote_data, need_initial_flush) =
        if line.starts_with("CONNECT ") {
            let address = &line[8..line.len() - 9];
            let remote_location = NetLocation::from_authority(address, None)?;

            let mut need_auth = auth_token.is_some();
            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }
                if need_auth
                    && line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
                    && line.as_bytes()[0..PROXY_AUTH_HEADER_PREFIX.len()]
                        .eq_ignore_ascii_case(PROXY_AUTH_HEADER_PREFIX.as_bytes())
                {
                    if !bool::from(
                        line.as_bytes()[PROXY_AUTH_HEADER_PREFIX.len()..]
                            .ct_eq(auth_token.unwrap().as_bytes()),
                    ) {
                        debug!("Received incorrect HTTP CONNECT authentication");
                        authentication_challenge(&mut server_stream, &http_version).await?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Incorrect HTTP CONNECT authentication",
                        ));
                    }
                    need_auth = false;
                    continue;
                }
            }

            if need_auth {
                authentication_challenge(&mut server_stream, &http_version).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing HTTP CONNECT authentication",
                ));
            }

            let connection_success_response = Some(
                format!("{http_version} 200 Connection established\r\n\r\n")
                    .into_bytes()
                    .into_boxed_slice(),
            );

            (
                remote_location,
                connection_success_response,
                stream_reader.unparsed_data_owned(),
                true,
            )
        } else {
            let line = &line[0..line.len() - 9];
            let space_index = line.find(' ').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unrecognized http request: {line} {http_version}"),
                )
            })?;

            let directive = &line[0..space_index];
            let url = &line[space_index + 1..];

            if !url.starts_with("http://") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unsupported http forward url: {url}"),
                ));
            }

            let url = &url[7..];
            let (address, location) = match url.find('/') {
                Some(i) => (&url[0..i], &url[i..]),
                None => (url, "/"),
            };

            let remote_location = NetLocation::from_authority(address, Some(80))?;
            let mut request = format!("{directive} {location} {http_version}\r\n");
            let mut need_auth = auth_token.is_some();

            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }
                let lowercase_line = line.to_ascii_lowercase();
                if line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
                    && lowercase_line.starts_with(PROXY_AUTH_HEADER_PREFIX)
                {
                    if need_auth {
                        if !bool::from(
                            line.as_bytes()[PROXY_AUTH_HEADER_PREFIX.len()..]
                                .ct_eq(auth_token.unwrap().as_bytes()),
                        ) {
                            authentication_challenge(&mut server_stream, &http_version).await?;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "Incorrect HTTP GET authentication",
                            ));
                        }
                        need_auth = false;
                    }
                    continue;
                } else if lowercase_line.starts_with(CONNECTION_HEADER_PREFIX)
                    || lowercase_line.starts_with(PROXY_CONNECTION_HEADER_PREFIX)
                {
                    continue;
                }

                request.push_str(line);
                request.push_str("\r\n");

                if request.len() > 16384 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP GET request is too long",
                    ));
                }
            }

            if need_auth {
                authentication_challenge(&mut server_stream, &http_version).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing HTTP GET authentication",
                ));
            }

            request.push_str("Connection: close\r\n\r\n");
            let request_bytes = request.into_bytes();
            let unparsed_data = stream_reader.unparsed_data();
            let mut initial_remote_data =
                Vec::with_capacity(request_bytes.len() + unparsed_data.len());
            initial_remote_data.extend_from_slice(&request_bytes);
            initial_remote_data.extend_from_slice(unparsed_data);

            (
                remote_location,
                None,
                Some(initial_remote_data.into_boxed_slice()),
                false,
            )
        };

    Ok(TcpServerSetupResult::TcpForward {
        remote_location,
        stream: server_stream,
        need_initial_flush,
        connection_success_response,
        initial_remote_data,
        connection_failure_response: None,
        proxy_selector,
    })
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn server_request(
        request: &[u8],
    ) -> (
        std::io::Result<TcpServerSetupResult>,
        tokio::io::DuplexStream,
    ) {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let handler = HttpTcpServerHandler::new(
            Some(("user".into(), "password".into())),
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(crate::resolver::NativeResolver::new()),
        );
        (
            handler
                .setup_server_stream(Box::new(
                    crate::async_stream::test_streams::FlushGatedStream::new(server),
                ))
                .await,
            client,
        )
    }

    #[tokio::test]
    async fn authenticated_connect_preserves_coalesced_payload() {
        let token = create_http_auth_token("user", "password");
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\npRoXy-AuThOrIzAtIoN: bAsIc {token}\r\n\r\npayload"
        );
        let (result, _) = server_request(request.as_bytes()).await;
        let TcpServerSetupResult::TcpForward {
            remote_location,
            need_initial_flush,
            connection_success_response,
            initial_remote_data,
            ..
        } = result.unwrap()
        else {
            panic!("expected TCP forwarding");
        };
        assert_eq!(
            remote_location,
            NetLocation::from_str("example.com:443", None).unwrap()
        );
        assert!(need_initial_flush);
        assert_eq!(
            connection_success_response.as_deref(),
            Some(&b"HTTP/1.1 200 Connection established\r\n\r\n"[..])
        );
        assert_eq!(initial_remote_data.as_deref(), Some(&b"payload"[..]));
    }

    #[tokio::test]
    async fn missing_or_wrong_credentials_return_proxy_authentication_challenge() {
        for request in ["CONNECT example.com:443", "GET http://example.com/"] {
            for auth in ["", "Proxy-Authorization: Basic wrong\r\n"] {
                let (result, mut client) =
                    server_request(format!("{request} HTTP/1.1\r\n{auth}\r\n").as_bytes()).await;
                assert_eq!(
                    result.err().unwrap().kind(),
                    std::io::ErrorKind::InvalidInput
                );
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(
                    response,
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        }
    }
}
