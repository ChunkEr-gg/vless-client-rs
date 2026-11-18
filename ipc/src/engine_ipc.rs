//! JSON-lines IPC protocol between `vless-tray` (app) and `vless-engine` (child process).
//!
//! Messages are exchanged as one UTF-8 JSON object per `\n`-terminated line over child `stdin`
//! (App -> Engine) and child `stdout` (Engine -> App), keeping user UUIDs out of CLI `argv` / `ps`.

use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::profile::Profile;

/// Maximum permitted length of a single JSON-lines frame (including trailing `\n`), 256 KiB.
pub const MAX_ENGINE_IPC_LINE_BYTES: usize = 256 * 1024;

/// User-facing diagnostic reported when a REALITY handshake falls through to the cover site
/// (`PLAN.md` §5.6).
pub const REALITY_AUTH_OR_CLOCK_ERROR: &str = "The server did not accept this client. Check pbk, sid and sni, and that the Mac's clock is correct (within the server's maxTimeDiffMs).";

/// How the engine should establish its local inbound and (optionally) talk to the root helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineLaunchMode {
    /// Listen on `listen_addr` (mixed HTTP + SOCKS5) and ask `vless-tray-helper` to configure
    /// macOS system proxies.
    SystemProxy {
        listen_addr: SocketAddr,
        helper_socket: PathBuf,
    },
    /// Request a `utun` interface and routes from `vless-tray-helper` via `SCM_RIGHTS`.
    Tun { helper_socket: PathBuf },
    /// Listen on `listen_addr` directly without contacting the root helper (CLI / testing).
    StandaloneProxy { listen_addr: SocketAddr },
    /// Operate on an already-opened raw TUN descriptor without contacting the root helper.
    DirectTunFd {
        tun_fd: i32,
        outbound_if_index: Option<u32>,
    },
}

/// Control messages sent from `vless-tray` to `vless-engine` over child `stdin`.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppToEngine {
    /// Initial launch configuration containing the active profile, mode, DNS, and bypass rules.
    Start {
        profile: Profile,
        mode: EngineLaunchMode,
        dns_resolver: IpAddr,
        bypass_cidrs: Vec<IpNetwork>,
        bypass_domains: Vec<String>,
    },
    /// Triggered on macOS wake notifications (`PLAN.md` §5.5) to re-resolve and verify reachability.
    RecheckServer,
    /// Graceful shutdown request.
    Stop,
}

/// High-level lifecycle status reported by `vless-engine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineStatus {
    Starting,
    Connected,
    Reconnecting,
    Disconnecting,
    Stopped,
    Error,
}

/// Severity level for structured engine log events forwarded to the UI log viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Events and telemetry sent from `vless-engine` to `vless-tray` over child `stdout`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineToApp {
    /// Engine state transition notification.
    State {
        status: EngineStatus,
        detail: Option<String>,
        listen_addr: Option<SocketAddr>,
        utun_name: Option<String>,
    },
    /// Structured log record for the Settings log tail view.
    Log {
        timestamp_ms: u64,
        level: LogLevel,
        target: String,
        message: String,
    },
    /// Result of a `RecheckServer` probe.
    ServerCheck {
        reachable: bool,
        rtt_ms: Option<u64>,
        error: Option<String>,
    },
}

/// Errors returned when encoding or decoding JSON-lines messages.
#[derive(Debug, Error)]
pub enum EngineIpcError {
    #[error("IPC I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("IPC JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IPC JSON line exceeds maximum size of {max_bytes} bytes")]
    LineTooLong { max_bytes: usize },

    #[error("IPC JSON line is empty")]
    EmptyLine,

    #[error("IPC JSON line is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// Encodes `msg` as a single `\n`-terminated JSON line, enforcing [`MAX_ENGINE_IPC_LINE_BYTES`].
pub fn encode_json_line<T: Serialize>(msg: &T) -> Result<String, EngineIpcError> {
    let mut json = serde_json::to_string(msg)?;
    if json.len() + 1 > MAX_ENGINE_IPC_LINE_BYTES {
        return Err(EngineIpcError::LineTooLong {
            max_bytes: MAX_ENGINE_IPC_LINE_BYTES,
        });
    }
    json.push('\n');
    Ok(json)
}

/// Decodes a single JSON line (with or without trailing `\r\n` / `\n`), enforcing
/// [`MAX_ENGINE_IPC_LINE_BYTES`].
pub fn decode_json_line<T: DeserializeOwned>(line: &str) -> Result<T, EngineIpcError> {
    if line.len() > MAX_ENGINE_IPC_LINE_BYTES {
        return Err(EngineIpcError::LineTooLong {
            max_bytes: MAX_ENGINE_IPC_LINE_BYTES,
        });
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(EngineIpcError::EmptyLine);
    }
    Ok(serde_json::from_str(trimmed)?)
}

/// Synchronously writes a JSON-line message and flushes `writer`.
pub fn write_json_line_sync<W: Write, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), EngineIpcError> {
    let line = encode_json_line(msg)?;
    writer.write_all(line.as_bytes())?;
    writer.flush()?;
    Ok(())
}

/// Synchronously reads up to [`MAX_ENGINE_IPC_LINE_BYTES`] until `\n` and decodes a message.
/// Returns `Ok(None)` on clean EOF (`0` bytes read).
pub fn read_json_line_sync<R: BufRead, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<Option<T>, EngineIpcError> {
    let mut buf = Vec::new();
    let bytes_read = reader
        .take((MAX_ENGINE_IPC_LINE_BYTES + 1) as u64)
        .read_until(b'\n', &mut buf)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_ENGINE_IPC_LINE_BYTES {
        return Err(EngineIpcError::LineTooLong {
            max_bytes: MAX_ENGINE_IPC_LINE_BYTES,
        });
    }
    let line = String::from_utf8(buf)?;
    decode_json_line(&line).map(Some)
}

/// Asynchronously writes a JSON-line message and flushes `writer`.
pub async fn write_json_line_async<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), EngineIpcError> {
    let line = encode_json_line(msg)?;
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Asynchronously reads up to [`MAX_ENGINE_IPC_LINE_BYTES`] until `\n` and decodes a message.
/// Returns `Ok(None)` on clean EOF (`0` bytes read).
pub async fn read_json_line_async<R: AsyncBufRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<Option<T>, EngineIpcError> {
    let mut buf = Vec::new();
    let bytes_read = tokio::io::AsyncBufReadExt::read_until(
        &mut reader.take((MAX_ENGINE_IPC_LINE_BYTES + 1) as u64),
        b'\n',
        &mut buf,
    )
    .await?;
    if bytes_read == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_ENGINE_IPC_LINE_BYTES {
        return Err(EngineIpcError::LineTooLong {
            max_bytes: MAX_ENGINE_IPC_LINE_BYTES,
        });
    }
    let line = String::from_utf8(buf)?;
    decode_json_line(&line).map(Some)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

    use super::*;
    use crate::profile::parse_vless_link;

    #[test]
    fn app_to_engine_and_engine_to_app_roundtrip() {
        let pbk = URL_SAFE_NO_PAD.encode([0x33u8; 32]);
        let profile = parse_vless_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.10:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={pbk}#Office"
        ))
        .unwrap()
        .profile;

        let app_messages = vec![
            AppToEngine::Start {
                profile: profile.clone(),
                mode: EngineLaunchMode::Tun {
                    helper_socket: PathBuf::from("/var/run/vless-tray.sock"),
                },
                dns_resolver: "1.1.1.1".parse().unwrap(),
                bypass_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
                bypass_domains: vec!["*.local".to_string()],
            },
            AppToEngine::Start {
                profile,
                mode: EngineLaunchMode::SystemProxy {
                    listen_addr: "127.0.0.1:2080".parse().unwrap(),
                    helper_socket: PathBuf::from("/var/run/vless-tray.sock"),
                },
                dns_resolver: "1.1.1.1".parse().unwrap(),
                bypass_cidrs: vec![],
                bypass_domains: vec![],
            },
            AppToEngine::RecheckServer,
            AppToEngine::Stop,
        ];

        let mut stream_buf = Vec::new();
        for msg in &app_messages {
            write_json_line_sync(&mut stream_buf, msg).expect("encode AppToEngine");
        }

        let mut cursor = Cursor::new(stream_buf);
        let mut decoded_app = Vec::new();
        while let Some(msg) = read_json_line_sync::<_, AppToEngine>(&mut cursor).unwrap() {
            decoded_app.push(msg);
        }
        assert_eq!(decoded_app, app_messages);

        let engine_messages = vec![
            EngineToApp::State {
                status: EngineStatus::Connected,
                detail: None,
                listen_addr: Some("127.0.0.1:2080".parse().unwrap()),
                utun_name: Some("utun4".to_string()),
            },
            EngineToApp::State {
                status: EngineStatus::Error,
                detail: Some(REALITY_AUTH_OR_CLOCK_ERROR.to_string()),
                listen_addr: None,
                utun_name: None,
            },
            EngineToApp::Log {
                timestamp_ms: 1_700_000_000_123,
                level: LogLevel::Info,
                target: "vless_engine::reality".to_string(),
                message: "handshake succeeded\nwith escaped newline".to_string(),
            },
            EngineToApp::ServerCheck {
                reachable: true,
                rtt_ms: Some(24),
                error: None,
            },
        ];

        for msg in &engine_messages {
            let line = encode_json_line(msg).expect("encode EngineToApp");
            assert!(line.ends_with('\n'));
            assert_eq!(line.matches('\n').count(), 1);
            let parsed: EngineToApp = decode_json_line(&line).expect("decode EngineToApp");
            assert_eq!(&parsed, msg);
        }
    }

    #[tokio::test]
    async fn async_json_line_enforces_max_length_and_handles_eof() {
        let msg = AppToEngine::RecheckServer;
        let mut wire = Vec::new();
        write_json_line_async(&mut wire, &msg).await.unwrap();

        let mut reader = tokio::io::BufReader::new(wire.as_slice());
        let first: Option<AppToEngine> = read_json_line_async(&mut reader).await.unwrap();
        assert_eq!(first, Some(AppToEngine::RecheckServer));
        let eof: Option<AppToEngine> = read_json_line_async(&mut reader).await.unwrap();
        assert_eq!(eof, None);

        // Oversized line rejected without unbounded allocation
        let oversized = "x".repeat(MAX_ENGINE_IPC_LINE_BYTES + 16);
        assert!(matches!(
            decode_json_line::<AppToEngine>(&oversized),
            Err(EngineIpcError::LineTooLong { .. })
        ));

        let mut oversized_reader = tokio::io::BufReader::new(oversized.as_bytes());
        assert!(matches!(
            read_json_line_async::<_, AppToEngine>(&mut oversized_reader).await,
            Err(EngineIpcError::LineTooLong { .. })
        ));
    }
}
