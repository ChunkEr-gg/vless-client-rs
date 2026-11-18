//! Child `vless-engine` process supervisor (`PLAN.md` §3, §4, §5.5).
//!
//! Security & reliability invariants:
//! - `vless-engine` is **always** spawned as an unprivileged child OS process (`vless-engine ipc`),
//!   never linked into `vless-tray`.
//! - User UUIDs and profile credentials **never** appear in `argv` or environment variables (`ps`);
//!   the active [`Profile`] is transmitted over child `stdin` via `AppToEngine::Start`.
//! - Structured `EngineToApp` telemetry is consumed from child `stdout`, `stderr` is captured for
//!   crash diagnostics, and logs are persisted to `<config_dir>/engine.log` with mode `0600` and
//!   bounded size (`MAX_ENGINE_LOG_BYTES`, 512 KiB).
//! - If `vless-engine` exits unexpectedly while active, `SupervisorState` transitions to
//!   `EngineStatus::Error` so the menu-bar UI survives and surfaces the failure.

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{Mutex as AsyncMutex, watch};
use uuid::Uuid;
use vless_ipc::{
    AppConfig, AppToEngine, BypassValidationError, ConnectionMode, DEFAULT_HELPER_SOCKET_PATH,
    EngineIpcError, EngineLaunchMode, EngineStatus, EngineToApp, HelperValidationError, LogLevel,
    ProfileError, effective_tun_bypass, read_json_line_async, validate_server_ip,
    write_atomic_0600, write_json_line_async,
};

/// File name inside `<config_dir>` used for live engine log tailing by `vless-tray --settings`.
pub const ENGINE_LOG_FILE_NAME: &str = "engine.log";

/// Maximum size of `engine.log` before bounded tail rotation (512 KiB).
pub const DEFAULT_MAX_ENGINE_LOG_BYTES: u64 = 512 * 1024;

/// Default timeout waiting for `vless-engine` to exit after `AppToEngine::Stop` before `SIGKILL`
/// (5s gives `vless-tray-helper` headroom to restore `networksetup` proxies across multiple macOS adapters).
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum bytes read from a single `stderr` line to avoid unbounded allocation.
const MAX_STDERR_LINE_BYTES: usize = 8 * 1024;

/// Maximum number of recent `stderr` lines retained in memory for crash diagnostics.
const MAX_RECENT_STDERR_LINES: usize = 8;

/// Callback invoked whenever [`SupervisorState`] transitions.
pub type StateChangeCallback = Arc<dyn Fn(&SupervisorState) + Send + Sync>;

/// Result summary of the most recent `RecheckServer` probe (`PLAN.md` §5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerCheckSummary {
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
    pub error: Option<String>,
}

/// Observable snapshot of the supervised `vless-engine` child process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisorState {
    pub status: EngineStatus,
    pub active_mode: ConnectionMode,
    pub active_profile_id: Option<Uuid>,
    pub active_profile_name: Option<String>,
    pub detail: Option<String>,
    pub listen_addr: Option<SocketAddr>,
    pub utun_name: Option<String>,
    pub last_server_check: Option<ServerCheckSummary>,
}

impl Default for SupervisorState {
    fn default() -> Self {
        Self {
            status: EngineStatus::Stopped,
            active_mode: ConnectionMode::Off,
            active_profile_id: None,
            active_profile_name: None,
            detail: None,
            listen_addr: None,
            utun_name: None,
            last_server_check: None,
        }
    }
}

impl SupervisorState {
    /// Returns `true` when an engine session is starting, connected, or reconnecting.
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            EngineStatus::Starting | EngineStatus::Connected | EngineStatus::Reconnecting
        )
    }
}

/// Configuration for [`EngineSupervisor`].
#[derive(Clone)]
pub struct SupervisorConfig {
    pub config_dir: PathBuf,
    pub helper_socket: PathBuf,
    pub engine_bin_override: Option<PathBuf>,
    pub stop_timeout: Duration,
    pub max_log_bytes: u64,
    pub on_state_change: Option<StateChangeCallback>,
}

impl fmt::Debug for SupervisorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisorConfig")
            .field("config_dir", &self.config_dir)
            .field("helper_socket", &self.helper_socket)
            .field("engine_bin_override", &self.engine_bin_override)
            .field("stop_timeout", &self.stop_timeout)
            .field("max_log_bytes", &self.max_log_bytes)
            .field(
                "on_state_change",
                &self.on_state_change.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl SupervisorConfig {
    /// Creates a [`SupervisorConfig`] writing `engine.log` inside `config_dir`.
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            config_dir,
            helper_socket: PathBuf::from(DEFAULT_HELPER_SOCKET_PATH),
            engine_bin_override: None,
            stop_timeout: DEFAULT_STOP_TIMEOUT,
            max_log_bytes: DEFAULT_MAX_ENGINE_LOG_BYTES,
            on_state_change: None,
        }
    }

    /// Returns the full path to `<config_dir>/engine.log`.
    pub fn engine_log_path(&self) -> PathBuf {
        self.config_dir.join(ENGINE_LOG_FILE_NAME)
    }
}

/// Errors returned by [`EngineSupervisor`] control operations.
#[derive(Debug)]
pub enum SupervisorError {
    ModeIsOff,
    NoProfileSelected,
    InvalidProxyPort,
    InvalidDnsResolver(IpAddr),
    Profile(ProfileError),
    Bypass(BypassValidationError),
    SpawnFailed { binary: PathBuf, source: io::Error },
    Ipc(EngineIpcError),
    MissingChildPipes,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModeIsOff => write!(
                f,
                "connection mode is Off — choose System Proxy or TUN before connecting"
            ),
            Self::NoProfileSelected => {
                write!(
                    f,
                    "no profile selected — open Settings… to add or select a profile"
                )
            }
            Self::InvalidProxyPort => write!(f, "system proxy port must be between 1 and 65535"),
            Self::InvalidDnsResolver(ip) => write!(
                f,
                "invalid TUN DNS resolver {ip}: must be a routable unicast IP address"
            ),
            Self::Profile(err) => write!(f, "invalid profile: {err}"),
            Self::Bypass(err) => write!(f, "invalid bypass entry: {err}"),
            Self::SpawnFailed { binary, source } => write!(
                f,
                "failed to launch engine binary {}: {source}",
                binary.display()
            ),
            Self::Ipc(err) => write!(f, "engine IPC error: {err}"),
            Self::MissingChildPipes => {
                write!(f, "child vless-engine process did not expose stdio pipes")
            }
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<ProfileError> for SupervisorError {
    fn from(value: ProfileError) -> Self {
        Self::Profile(value)
    }
}

impl From<BypassValidationError> for SupervisorError {
    fn from(value: BypassValidationError) -> Self {
        Self::Bypass(value)
    }
}

impl From<EngineIpcError> for SupervisorError {
    fn from(value: EngineIpcError) -> Self {
        Self::Ipc(value)
    }
}

impl From<HelperValidationError> for SupervisorError {
    fn from(value: HelperValidationError) -> Self {
        match value {
            HelperValidationError::InvalidServerIp(ip) => Self::InvalidDnsResolver(ip),
            _ => Self::InvalidProxyPort,
        }
    }
}

/// Resolves the `vless-engine` binary path:
/// 1. Explicit `override_bin` (if configured).
/// 2. Sibling `vless-engine` next to `current_exe` (`Contents/MacOS/vless-engine` or
///    `target/{release,debug}/vless-engine`).
/// 3. Parent directory `../vless-engine` when `current_exe` is inside Cargo's `deps/` directory.
/// 4. Fallback `"vless-engine"` resolved via `PATH`.
pub fn resolve_engine_binary(override_bin: Option<&Path>) -> PathBuf {
    let current_exe = std::env::current_exe().ok();
    resolve_engine_binary_from(current_exe.as_deref(), override_bin)
}

/// Pure, deterministic `vless-engine` path resolver for unit tests and runtime use.
pub fn resolve_engine_binary_from(
    current_exe: Option<&Path>,
    override_bin: Option<&Path>,
) -> PathBuf {
    if let Some(explicit) = override_bin {
        return explicit.to_path_buf();
    }

    if let Some(exe) = current_exe
        && let Some(exe_dir) = exe.parent()
    {
        let sibling = exe_dir.join("vless-engine");
        if sibling.is_file() {
            return sibling;
        }

        if exe_dir.file_name().and_then(|n| n.to_str()) == Some("deps")
            && let Some(parent) = exe_dir.parent()
        {
            let parent_bin = parent.join("vless-engine");
            if parent_bin.is_file() {
                return parent_bin;
            }
        }
    }

    PathBuf::from("vless-engine")
}

/// Parsed single-line representation of an `engine.log` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedLogLine {
    pub level: LogLevel,
    pub raw_line: String,
}

/// Formats a structured engine log event as a single sanitized `\n`-terminated UTF-8 line.
///
/// Control characters (`\r`, `\n`, `\0`) inside `target` and `message` are escaped so untrusted
/// network strings can never forge synthetic `[INFO]`/`[ERROR]` log lines.
pub fn format_engine_log_line(
    timestamp_ms: u64,
    level: LogLevel,
    target: &str,
    message: &str,
) -> String {
    let ts = format_utc_timestamp_ms(timestamp_ms);
    let lvl = match level {
        LogLevel::Trace => "TRACE",
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
    };
    let clean_target = sanitize_log_component(target);
    let clean_msg = sanitize_log_component(message);
    if clean_target.is_empty() {
        format!("{ts} [{lvl}] {clean_msg}\n")
    } else {
        format!("{ts} [{lvl}] {clean_target}: {clean_msg}\n")
    }
}

/// Parses the [`LogLevel`] tag (`[TRACE]`, `[DEBUG]`, `[INFO]`, `[WARN]`, `[ERROR]`) from a line in
/// `engine.log`, defaulting to [`LogLevel::Info`] for unstructured lines.
pub fn parse_engine_log_line(line: &str) -> ParsedLogLine {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let level = if trimmed.contains(" [ERROR] ") || trimmed.starts_with("[ERROR]") {
        LogLevel::Error
    } else if trimmed.contains(" [WARN] ") || trimmed.starts_with("[WARN]") {
        LogLevel::Warn
    } else if trimmed.contains(" [DEBUG] ") || trimmed.starts_with("[DEBUG]") {
        LogLevel::Debug
    } else if trimmed.contains(" [TRACE] ") || trimmed.starts_with("[TRACE]") {
        LogLevel::Trace
    } else {
        LogLevel::Info
    };

    ParsedLogLine {
        level,
        raw_line: trimmed.to_string(),
    }
}

fn sanitize_log_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() && c != '\t' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            other => out.push(other),
        }
    }
    out
}

/// Formats `timestamp_ms` since `UNIX_EPOCH` as `YYYY-MM-DD HH:MM:SS.mmm` UTC using Howard
/// Hinnant's civil-from-days algorithm (zero external date/time dependencies).
pub fn format_utc_timestamp_ms(timestamp_ms: u64) -> String {
    let total_secs = (timestamp_ms / 1000) as i64;
    let millis = timestamp_ms % 1000;

    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02}:{second:02}.{millis:03}")
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Appends a formatted line to `<config_dir>/engine.log`, creating the parent directory (`0700`)
/// and file (`0600`) if missing, and rotating/truncating atomically (`0600`) whenever the file
/// exceeds `max_bytes`.
pub fn append_engine_log_entry(
    log_path: &Path,
    line: &str,
    max_bytes: u64,
    write_lock: &Mutex<()>,
) -> io::Result<()> {
    let _guard = write_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(parent) = log_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    let max_bytes = max_bytes.max(4096);
    let line_bytes = line.as_bytes();

    // Check existing size first; if appending would exceed `max_bytes`, keep the newest half
    // aligned on a newline boundary plus the new line, written atomically with mode `0600`.
    let current_len = fs::metadata(log_path).map(|m| m.len()).unwrap_or(0);
    if current_len.saturating_add(line_bytes.len() as u64) > max_bytes {
        let keep_budget = (max_bytes / 2) as usize;
        let existing = fs::read(log_path).unwrap_or_default();
        let tail_slice = if existing.len() > keep_budget {
            let start = existing.len() - keep_budget;
            match existing[start..].iter().position(|&b| b == b'\n') {
                Some(nl_pos) if start + nl_pos + 1 < existing.len() => {
                    &existing[start + nl_pos + 1..]
                }
                _ => &existing[start..],
            }
        } else {
            existing.as_slice()
        };

        let mut rotated = Vec::with_capacity(tail_slice.len() + line_bytes.len());
        rotated.extend_from_slice(tail_slice);
        rotated.extend_from_slice(line_bytes);
        if rotated.len() as u64 > max_bytes {
            let trim_from = rotated.len() - (max_bytes as usize);
            let aligned = rotated[trim_from..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| trim_from + p + 1)
                .unwrap_or(trim_from);
            rotated.drain(..aligned);
        }
        return write_atomic_0600(log_path, &rotated);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log_path)?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(line_bytes)?;
    file.flush()?;
    Ok(())
}

struct ActiveSession {
    session_id: u64,
    stdin: Option<ChildStdin>,
    stopping: Arc<AtomicBool>,
    kill_tx: watch::Sender<bool>,
    exited_rx: watch::Receiver<bool>,
}

struct SharedInner {
    config: SupervisorConfig,
    next_session_id: AtomicU64,
    current_session_id: Mutex<u64>,
    state_tx: watch::Sender<SupervisorState>,
    log_write_lock: Mutex<()>,
    session: AsyncMutex<Option<ActiveSession>>,
    control_lock: AsyncMutex<()>,
}

impl SharedInner {
    fn update_state(&self, mutate: impl FnOnce(&mut SupervisorState)) {
        let mut snapshot = None;
        self.state_tx.send_if_modified(|state| {
            let before = state.clone();
            mutate(state);
            let changed = *state != before;
            if changed {
                snapshot = Some(state.clone());
            }
            changed
        });

        if let Some(updated) = snapshot
            && let Some(cb) = &self.config.on_state_change
        {
            cb(&updated);
        }
    }

    fn write_log(&self, timestamp_ms: u64, level: LogLevel, target: &str, message: &str) {
        let formatted = format_engine_log_line(timestamp_ms, level, target, message);
        let _ = append_engine_log_entry(
            &self.config.engine_log_path(),
            &formatted,
            self.config.max_log_bytes,
            &self.log_write_lock,
        );
    }
}

/// Asynchronous supervisor managing the `vless-engine` child process.
#[derive(Clone)]
pub struct EngineSupervisor {
    inner: Arc<SharedInner>,
    state_rx: watch::Receiver<SupervisorState>,
}

impl EngineSupervisor {
    /// Creates a new idle [`EngineSupervisor`].
    pub fn new(config: SupervisorConfig) -> Self {
        let (state_tx, state_rx) = watch::channel(SupervisorState::default());
        let inner = Arc::new(SharedInner {
            config,
            next_session_id: AtomicU64::new(1),
            current_session_id: Mutex::new(0),
            state_tx,
            log_write_lock: Mutex::new(()),
            session: AsyncMutex::new(None),
            control_lock: AsyncMutex::new(()),
        });
        Self { inner, state_rx }
    }

    /// Returns the current [`SupervisorState`] snapshot without blocking.
    pub fn state(&self) -> SupervisorState {
        self.state_rx.borrow().clone()
    }

    /// Subscribes to [`SupervisorState`] changes via a `tokio::sync::watch::Receiver`.
    pub fn subscribe(&self) -> watch::Receiver<SupervisorState> {
        self.state_rx.clone()
    }

    /// Returns the configured path to `engine.log`.
    pub fn engine_log_path(&self) -> PathBuf {
        self.inner.config.engine_log_path()
    }

    /// Records a user-visible error message into `SupervisorState` (`EngineStatus::Error`).
    pub fn record_error(&self, message: impl Into<String>) {
        let msg = message.into();
        self.inner.write_log(
            now_epoch_ms(),
            LogLevel::Error,
            "vless_tray::supervisor",
            &msg,
        );
        self.inner.update_state(|st| {
            st.status = EngineStatus::Error;
            st.detail = Some(msg);
            st.listen_addr = None;
            st.utun_name = None;
        });
    }

    /// Validates `app_config`, cleanly stops any prior `vless-engine` child, spawns a fresh
    /// `vless-engine ipc` child process, and sends `AppToEngine::Start` over `stdin`.
    pub async fn connect(&self, app_config: &AppConfig) -> Result<(), SupervisorError> {
        let _ctrl = self.inner.control_lock.lock().await;

        if app_config.mode == ConnectionMode::Off {
            return Err(SupervisorError::ModeIsOff);
        }

        let profile = app_config
            .selected_profile()
            .ok_or(SupervisorError::NoProfileSelected)?
            .clone();
        profile.validate()?;

        if app_config.system_proxy_port == 0 {
            return Err(SupervisorError::InvalidProxyPort);
        }

        validate_server_ip(&app_config.dns_resolver)?;
        if app_config.dns_resolver.is_loopback() {
            return Err(SupervisorError::InvalidDnsResolver(app_config.dns_resolver));
        }

        let (bypass_cidrs, bypass_domains) = effective_tun_bypass(&app_config.bypass_list)?;

        let launch_mode = match app_config.mode {
            ConnectionMode::Off => unreachable!("checked above"),
            ConnectionMode::SystemProxy => EngineLaunchMode::SystemProxy {
                listen_addr: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    app_config.system_proxy_port,
                ),
                helper_socket: self.inner.config.helper_socket.clone(),
            },
            ConnectionMode::Tun => EngineLaunchMode::Tun {
                helper_socket: self.inner.config.helper_socket.clone(),
            },
        };

        // Tear down any previously running engine child first so the root helper cleanly restores
        // previous routes/proxies before the new session connects.
        self.stop_existing_locked(false).await;

        let session_id = self.inner.next_session_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut cur = self
                .inner
                .current_session_id
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *cur = session_id;
        }

        let profile_id = profile.id;
        let profile_name = profile.name.clone();
        let active_mode = app_config.mode;

        self.inner.update_state(|st| {
            st.status = EngineStatus::Starting;
            st.active_mode = active_mode;
            st.active_profile_id = Some(profile_id);
            st.active_profile_name = Some(profile_name.clone());
            st.detail = Some("Starting engine…".to_string());
            st.listen_addr = None;
            st.utun_name = None;
            st.last_server_check = None;
        });

        let engine_bin = resolve_engine_binary(self.inner.config.engine_bin_override.as_deref());

        // Zero-UUID-in-`ps` guarantee (`PLAN.md` §4): ONLY `"ipc"` is passed in `argv`, and no
        // profile credentials are placed in environment variables.
        let mut cmd = Command::new(&engine_bin);
        cmd.arg("ipc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(source) => {
                let err = SupervisorError::SpawnFailed {
                    binary: engine_bin,
                    source,
                };
                let msg = err.to_string();
                self.inner.write_log(
                    now_epoch_ms(),
                    LogLevel::Error,
                    "vless_tray::supervisor",
                    &msg,
                );
                self.inner.update_state(|st| {
                    st.status = EngineStatus::Error;
                    st.detail = Some(msg);
                    st.listen_addr = None;
                    st.utun_name = None;
                });
                return Err(err);
            }
        };

        let mut stdin = child
            .stdin
            .take()
            .ok_or(SupervisorError::MissingChildPipes)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(SupervisorError::MissingChildPipes)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(SupervisorError::MissingChildPipes)?;

        let start_msg = AppToEngine::Start {
            profile,
            mode: launch_mode,
            dns_resolver: app_config.dns_resolver,
            bypass_cidrs,
            bypass_domains,
        };

        if let Err(ipc_err) = write_json_line_async(&mut stdin, &start_msg).await {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let err = SupervisorError::Ipc(ipc_err);
            let msg = err.to_string();
            self.inner.write_log(
                now_epoch_ms(),
                LogLevel::Error,
                "vless_tray::supervisor",
                &msg,
            );
            self.inner.update_state(|st| {
                st.status = EngineStatus::Error;
                st.detail = Some(msg);
                st.listen_addr = None;
                st.utun_name = None;
            });
            return Err(err);
        }

        self.inner.write_log(
            now_epoch_ms(),
            LogLevel::Info,
            "vless_tray::supervisor",
            &format!("spawned vless-engine session #{session_id} for profile '{profile_name}'"),
        );

        let stopping = Arc::new(AtomicBool::new(false));
        let (kill_tx, mut kill_rx) = watch::channel(false);
        let (exited_tx, exited_rx) = watch::channel(false);

        let recent_stderr: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_STDERR_LINES)));
        let last_error_log: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        // Spawn stdout reader (`EngineToApp` JSON lines).
        let stdout_inner = Arc::clone(&self.inner);
        let stdout_stopping = Arc::clone(&stopping);
        let stdout_last_err = Arc::clone(&last_error_log);
        let stdout_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_json_line_async::<_, EngineToApp>(&mut reader).await {
                    Ok(Some(event)) => {
                        handle_engine_event(
                            &stdout_inner,
                            session_id,
                            &stdout_stopping,
                            &stdout_last_err,
                            event,
                        );
                    }
                    Ok(None) => break,
                    Err(err) => {
                        let diag = format!("malformed EngineToApp frame on stdout: {err}");
                        stdout_inner.write_log(
                            now_epoch_ms(),
                            LogLevel::Warn,
                            "vless_tray::supervisor",
                            &diag,
                        );
                        *stdout_last_err.lock().unwrap_or_else(|p| p.into_inner()) = Some(diag);
                        if matches!(
                            err,
                            EngineIpcError::Io(_) | EngineIpcError::LineTooLong { .. }
                        ) {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn stderr reader (diagnostic / crash output).
        let stderr_inner = Arc::clone(&self.inner);
        let stderr_buf = Arc::clone(&recent_stderr);
        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            loop {
                let mut buf = Vec::new();
                let read_res =
                    tokio::io::AsyncReadExt::take(&mut reader, (MAX_STDERR_LINE_BYTES + 1) as u64)
                        .read_until(b'\n', &mut buf)
                        .await;

                match read_res {
                    Ok(0) => break,
                    Ok(_) => {
                        let line = String::from_utf8_lossy(&buf)
                            .trim_end_matches(['\r', '\n'])
                            .trim()
                            .to_string();
                        if !line.is_empty() {
                            stderr_inner.write_log(
                                now_epoch_ms(),
                                LogLevel::Warn,
                                "vless_engine::stderr",
                                &line,
                            );
                            let mut q = stderr_buf.lock().unwrap_or_else(|p| p.into_inner());
                            if q.len() >= MAX_RECENT_STDERR_LINES {
                                q.pop_front();
                            }
                            q.push_back(line);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Spawn child exit + kill monitor task.
        let wait_inner = Arc::clone(&self.inner);
        let wait_stopping = Arc::clone(&stopping);
        tokio::spawn(async move {
            let exit_status = tokio::select! {
                status = child.wait() => status,
                () = wait_watch_true(&mut kill_rx) => {
                    let _ = child.kill().await;
                    child.wait().await
                }
            };

            // Drain stdout & stderr tasks briefly so any final Error state or panic message emitted
            // immediately prior to process exit is recorded before we finalize SupervisorState.
            let _ = tokio::time::timeout(Duration::from_millis(250), async {
                let _ = tokio::join!(stdout_task, stderr_task);
            })
            .await;

            // Clear active session slot if it still belongs to this `session_id`.
            {
                let mut slot = wait_inner.session.lock().await;
                if slot.as_ref().is_some_and(|s| s.session_id == session_id) {
                    *slot = None;
                }
            }

            let is_current = {
                let cur = wait_inner
                    .current_session_id
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                *cur == session_id
            };

            if is_current {
                let intentional_stop = wait_stopping.load(Ordering::Acquire);
                if intentional_stop {
                    wait_inner.write_log(
                        now_epoch_ms(),
                        LogLevel::Info,
                        "vless_tray::supervisor",
                        &format!("vless-engine session #{session_id} stopped cleanly"),
                    );
                    wait_inner.update_state(|st| {
                        st.status = EngineStatus::Stopped;
                        st.active_mode = ConnectionMode::Off;
                        st.detail = None;
                        st.listen_addr = None;
                        st.utun_name = None;
                    });
                } else {
                    let crash_detail = build_unexpected_exit_detail(
                        exit_status.as_ref().ok(),
                        &recent_stderr,
                        &last_error_log,
                    );
                    wait_inner.write_log(
                        now_epoch_ms(),
                        LogLevel::Error,
                        "vless_tray::supervisor",
                        &format!(
                            "vless-engine session #{session_id} exited unexpectedly: {crash_detail}"
                        ),
                    );
                    wait_inner.update_state(|st| {
                        let existing_error_detail = if st.status == EngineStatus::Error {
                            st.detail.clone().filter(|d| !d.trim().is_empty())
                        } else {
                            None
                        };
                        st.status = EngineStatus::Error;
                        st.detail = Some(existing_error_detail.unwrap_or(crash_detail));
                        st.listen_addr = None;
                        st.utun_name = None;
                    });
                }
            }

            let _ = exited_tx.send(true);
        });

        {
            let mut slot = self.inner.session.lock().await;
            *slot = Some(ActiveSession {
                session_id,
                stdin: Some(stdin),
                stopping,
                kill_tx,
                exited_rx,
            });
        }

        Ok(())
    }

    /// Sends `AppToEngine::Stop`, closes child `stdin`, waits up to `stop_timeout` (`3s`) for
    /// graceful teardown, and force-kills the child if stuck.
    pub async fn disconnect(&self) -> Result<(), SupervisorError> {
        let _ctrl = self.inner.control_lock.lock().await;
        self.stop_existing_locked(true).await;
        Ok(())
    }

    /// Sends `AppToEngine::RecheckServer` on macOS wake (`PLAN.md` §5.5).
    ///
    /// Returns `Ok(true)` if an active engine session received the request, or `Ok(false)` if idle.
    pub async fn recheck_server(&self) -> Result<bool, SupervisorError> {
        let mut slot = self.inner.session.lock().await;
        let Some(active) = slot.as_mut() else {
            return Ok(false);
        };
        if active.stopping.load(Ordering::Acquire) {
            return Ok(false);
        }
        let Some(stdin) = active.stdin.as_mut() else {
            return Ok(false);
        };

        write_json_line_async(stdin, &AppToEngine::RecheckServer).await?;
        self.inner.write_log(
            now_epoch_ms(),
            LogLevel::Info,
            "vless_tray::supervisor",
            "sent RecheckServer to vless-engine",
        );
        Ok(true)
    }

    /// Awaits [`Self::disconnect`] during application quit so `vless-tray-helper` restores system
    /// routes, DNS, and proxies cleanly before `vless-tray` exits.
    pub async fn shutdown(&self) -> Result<(), SupervisorError> {
        self.disconnect().await
    }

    async fn stop_existing_locked(&self, mark_stopped_when_idle: bool) {
        let taken = {
            let mut slot = self.inner.session.lock().await;
            slot.take()
        };

        let Some(mut session) = taken else {
            if mark_stopped_when_idle {
                self.inner.update_state(|st| {
                    st.status = EngineStatus::Stopped;
                    st.active_mode = ConnectionMode::Off;
                    st.detail = None;
                    st.listen_addr = None;
                    st.utun_name = None;
                });
            }
            return;
        };

        session.stopping.store(true, Ordering::Release);
        self.inner.update_state(|st| {
            st.status = EngineStatus::Disconnecting;
            st.detail = Some("Disconnecting…".to_string());
        });

        // Send `AppToEngine::Stop` and drop `stdin` so child observes both the stop command and EOF.
        if let Some(mut stdin) = session.stdin.take() {
            let _ = write_json_line_async(&mut stdin, &AppToEngine::Stop).await;
            drop(stdin);
        }

        let timeout = self.inner.config.stop_timeout;
        let mut exited_rx = session.exited_rx.clone();
        if tokio::time::timeout(timeout, wait_watch_true(&mut exited_rx))
            .await
            .is_err()
        {
            self.inner.write_log(
                now_epoch_ms(),
                LogLevel::Warn,
                "vless_tray::supervisor",
                &format!(
                    "vless-engine session #{} did not exit within {:?}; sending SIGKILL",
                    session.session_id, timeout
                ),
            );
            let _ = session.kill_tx.send(true);
            wait_watch_true(&mut exited_rx).await;
        }

        if mark_stopped_when_idle {
            self.inner.update_state(|st| {
                st.status = EngineStatus::Stopped;
                st.active_mode = ConnectionMode::Off;
                st.detail = None;
                st.listen_addr = None;
                st.utun_name = None;
            });
        }
    }
}

async fn wait_watch_true(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

fn handle_engine_event(
    inner: &SharedInner,
    session_id: u64,
    stopping: &AtomicBool,
    last_error_log: &Mutex<Option<String>>,
    event: EngineToApp,
) {
    match event {
        EngineToApp::State {
            status,
            detail,
            listen_addr,
            utun_name,
        } => {
            let is_current = {
                let cur = inner
                    .current_session_id
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                *cur == session_id
            };
            if !is_current {
                return;
            }
            // Once an intentional stop/reconnect has begun, `stop_existing_locked` owns the
            // `Disconnecting -> Stopped` transition; ignore all late `State` frames (including
            // shutdown `Stopped` or aborted-connection `Error` frames) from the dying child.
            if stopping.load(Ordering::Acquire) {
                return;
            }
            inner.update_state(|st| {
                st.status = status;
                st.detail = detail;
                st.listen_addr = listen_addr;
                st.utun_name = utun_name;
            });
        }
        EngineToApp::Log {
            timestamp_ms,
            level,
            target,
            message,
        } => {
            let ts = if timestamp_ms == 0 {
                now_epoch_ms()
            } else {
                timestamp_ms
            };
            if level == LogLevel::Error {
                *last_error_log.lock().unwrap_or_else(|p| p.into_inner()) = Some(message.clone());
            }
            inner.write_log(ts, level, &target, &message);
        }
        EngineToApp::ServerCheck {
            reachable,
            rtt_ms,
            error,
        } => {
            let is_current = {
                let cur = inner
                    .current_session_id
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                *cur == session_id
            };
            if !is_current {
                return;
            }
            let summary = ServerCheckSummary {
                reachable,
                rtt_ms,
                error: error.clone(),
            };
            let log_msg = if reachable {
                match rtt_ms {
                    Some(ms) => format!("server check succeeded (RTT {ms} ms)"),
                    None => "server check succeeded".to_string(),
                }
            } else {
                format!(
                    "server check failed: {}",
                    error.as_deref().unwrap_or("unreachable")
                )
            };
            inner.write_log(
                now_epoch_ms(),
                if reachable {
                    LogLevel::Info
                } else {
                    LogLevel::Warn
                },
                "vless_engine::health",
                &log_msg,
            );
            inner.update_state(|st| {
                st.last_server_check = Some(summary);
                if !reachable
                    && let Some(err_text) = error
                    && st.status == EngineStatus::Connected
                {
                    st.detail = Some(format!("Server check failed: {err_text}"));
                } else if reachable
                    && st.status == EngineStatus::Connected
                    && let Some(ms) = rtt_ms
                {
                    st.detail = Some(format!("RTT {ms} ms"));
                }
            });
        }
    }
}

fn build_unexpected_exit_detail(
    status: Option<&ExitStatus>,
    recent_stderr: &Mutex<VecDeque<String>>,
    last_error_log: &Mutex<Option<String>>,
) -> String {
    let status_desc = match status {
        Some(st) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(code) = st.code() {
                    format!("engine exited with code {code}")
                } else if let Some(sig) = st.signal() {
                    format!("engine killed by signal {sig}")
                } else {
                    "engine exited unexpectedly".to_string()
                }
            }
            #[cfg(not(unix))]
            {
                match st.code() {
                    Some(code) => format!("engine exited with code {code}"),
                    None => "engine exited unexpectedly".to_string(),
                }
            }
        }
        None => "engine exited unexpectedly".to_string(),
    };

    if let Some(last_stderr) = recent_stderr
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .back()
        .cloned()
    {
        return format!("{status_desc}: {last_stderr}");
    }

    if let Some(last_err) = last_error_log
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
    {
        return format!("{status_desc}: {last_err}");
    }

    status_desc
}

/// Synchronous wrapper owning a dedicated background Tokio runtime for GUI event loops (`winit`
/// on macOS), keeping UI callbacks non-blocking during connect/reconnect while blocking cleanly on
/// [`Self::shutdown`] when quitting.
pub struct RuntimeSupervisor {
    runtime: tokio::runtime::Runtime,
    supervisor: EngineSupervisor,
}

impl RuntimeSupervisor {
    /// Creates a [`RuntimeSupervisor`] backed by a lightweight 2-worker Tokio runtime that sleeps
    /// completely when idle.
    pub fn new(config: SupervisorConfig) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vless-tray-sup")
            .enable_all()
            .build()?;
        let supervisor = EngineSupervisor::new(config);
        Ok(Self {
            runtime,
            supervisor,
        })
    }

    /// Returns the latest [`SupervisorState`] snapshot.
    pub fn state(&self) -> SupervisorState {
        self.supervisor.state()
    }

    /// Records a user-visible error message into `SupervisorState`.
    pub fn record_error(&self, message: impl Into<String>) {
        self.supervisor.record_error(message);
    }

    /// Asynchronously connects (or reconnects) using `config`, surfacing any preflight or launch
    /// error into [`SupervisorState`].
    pub fn spawn_connect(&self, config: AppConfig) {
        let sup = self.supervisor.clone();
        self.runtime.spawn(async move {
            if let Err(err) = sup.connect(&config).await {
                sup.record_error(err.to_string());
            }
        });
    }

    /// Asynchronously disconnects any active `vless-engine` child process.
    pub fn spawn_disconnect(&self) {
        let sup = self.supervisor.clone();
        self.runtime.spawn(async move {
            let _ = sup.disconnect().await;
        });
    }

    /// Asynchronously triggers `AppToEngine::RecheckServer`.
    pub fn spawn_recheck_server(&self) {
        let sup = self.supervisor.clone();
        self.runtime.spawn(async move {
            let _ = sup.recheck_server().await;
        });
    }

    /// Triggered on macOS `NSWorkspaceDidWakeNotification` (`PLAN.md` §5.5): probes the server
    /// immediately and, if Wi-Fi/DHCP has not finished re-associating yet (`reachable == false`),
    /// performs one single delayed follow-up check after `retry_delay` before returning to `0%`
    /// idle sleep.
    pub fn spawn_wake_recheck(&self, retry_delay: Duration) {
        let sup = self.supervisor.clone();
        self.runtime.spawn(async move {
            let sent = sup.recheck_server().await.unwrap_or(false);
            if !sent {
                return;
            }
            tokio::time::sleep(retry_delay).await;
            let st = sup.state();
            if st.is_active()
                && st
                    .last_server_check
                    .as_ref()
                    .is_none_or(|chk| !chk.reachable)
            {
                let _ = sup.recheck_server().await;
            }
        });
    }

    /// Registers a background watcher on the supervisor's Tokio runtime that invokes `on_signal`
    /// once when `SIGINT` or `SIGTERM` arrives so the GUI event loop can run graceful teardown.
    #[cfg(unix)]
    pub fn spawn_termination_watcher(&self, on_signal: impl FnOnce() + Send + 'static) {
        self.runtime.spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut sigint = signal(SignalKind::interrupt()).ok();
            tokio::select! {
                _ = async {
                    match sigterm.as_mut() {
                        Some(s) => { let _ = s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
                _ = async {
                    match sigint.as_mut() {
                        Some(s) => { let _ = s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
            }
            on_signal();
        });
    }

    /// Returns the configured path to `<config_dir>/engine.log`.
    pub fn engine_log_path(&self) -> PathBuf {
        self.supervisor.engine_log_path()
    }

    /// Returns the configured helper Unix domain socket path.
    pub fn helper_socket_path(&self) -> &Path {
        &self.supervisor.inner.config.helper_socket
    }

    /// Synchronously awaits graceful `vless-engine` teardown so `vless-tray-helper` restores
    /// system routes, DNS, and proxies before the process exits.
    pub fn shutdown(&self) {
        let _ = self.runtime.block_on(self.supervisor.shutdown());
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use vless_ipc::parse_vless_link;

    use super::*;

    const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    // 32 bytes of 0x42 in base64url (unpadded)
    const TEST_PBK: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

    fn sample_app_config(mode: ConnectionMode) -> AppConfig {
        let link = format!(
            "vless://{TEST_UUID}@198.51.100.42:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={TEST_PBK}&sid=0123456789abcdef#Tokyo"
        );
        let profile = parse_vless_link(&link).expect("valid link").profile;
        let id = profile.id;
        AppConfig {
            profiles: vec![profile],
            selected_profile_id: Some(id),
            mode,
            system_proxy_port: 2080,
            dns_resolver: "1.1.1.1".parse().unwrap(),
            bypass_list: vec!["*.corp.example".to_string(), "100.64.0.0/10".to_string()],
        }
    }

    fn write_executable_script(path: &Path, content: &str) {
        fs::write(path, content).expect("write mock engine script");
        fs::set_permissions(path, Permissions::from_mode(0o755)).expect("chmod +x");
    }

    #[test]
    fn engine_binary_resolution_prefers_override_then_sibling_then_path() {
        let dir = tempfile::tempdir().unwrap();
        let macos_dir = dir.path().join("VLESS Tray.app/Contents/MacOS");
        fs::create_dir_all(&macos_dir).unwrap();
        let tray_bin = macos_dir.join("vless-tray");
        let engine_bin = macos_dir.join("vless-engine");
        fs::write(&tray_bin, b"tray").unwrap();

        // Before sibling exists -> falls back to PATH ("vless-engine")
        assert_eq!(
            resolve_engine_binary_from(Some(&tray_bin), None),
            PathBuf::from("vless-engine")
        );

        // Once sibling exists -> resolves sibling
        fs::write(&engine_bin, b"engine").unwrap();
        assert_eq!(
            resolve_engine_binary_from(Some(&tray_bin), None),
            engine_bin
        );

        // Cargo test binary in target/debug/deps/ -> resolves target/debug/vless-engine
        let deps_dir = dir.path().join("target/debug/deps");
        fs::create_dir_all(&deps_dir).unwrap();
        let test_exe = deps_dir.join("vless_tray-1234");
        let target_engine = dir.path().join("target/debug/vless-engine");
        fs::write(&test_exe, b"test").unwrap();
        fs::write(&target_engine, b"engine").unwrap();
        assert_eq!(
            resolve_engine_binary_from(Some(&test_exe), None),
            target_engine
        );

        // Explicit override wins unconditionally
        let custom = PathBuf::from("/custom/vless-engine");
        assert_eq!(
            resolve_engine_binary_from(Some(&tray_bin), Some(&custom)),
            custom
        );
    }

    #[tokio::test]
    async fn supervisor_lifecycle_zero_uuid_in_argv_logs_0600_recheck_and_disconnect() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join("cfg");
        let argv_dump = temp.path().join("argv.txt");
        let env_dump = temp.path().join("env.txt");
        let stdin_dump = temp.path().join("stdin.jsonl");
        let mock_engine = temp.path().join("mock-vless-engine.sh");

        // Mock engine script:
        // 1. Dumps "$@" to argv.txt and `env` to env.txt so we can prove ZERO UUID in ps/env!
        // 2. Reads JSON lines on stdin:
        //    - On `start`: emits Log + State(Connected)
        //    - On `recheck_server`: emits ServerCheck(reachable=true, rtt_ms=19)
        //    - On `stop`: emits State(Disconnecting) and exits 0 cleanly.
        let script = format!(
            r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "{argv}"
env > "{env}"
while IFS= read -r line; do
    printf '%s\n' "$line" >> "{stdin}"
    case "$line" in
        *'"type":"start"'*)
            printf '%s\n' '{{"type":"log","timestamp_ms":1700000000500,"level":"info","target":"vless_engine::tun","message":"utun7 ready"}}'
            printf '%s\n' '{{"type":"state","status":"connected","detail":"TUN active","listen_addr":null,"utun_name":"utun7"}}'
            ;;
        *'"type":"recheck_server"'*)
            printf '%s\n' '{{"type":"server_check","reachable":true,"rtt_ms":19,"error":null}}'
            ;;
        *'"type":"stop"'*)
            exit 0
            ;;
    esac
done
"#,
            argv = argv_dump.display(),
            env = env_dump.display(),
            stdin = stdin_dump.display(),
        );
        write_executable_script(&mock_engine, &script);

        let notify_count = Arc::new(AtomicU64::new(0));
        let notify_clone = Arc::clone(&notify_count);

        let mut sup_cfg = SupervisorConfig::new(config_dir.clone());
        sup_cfg.engine_bin_override = Some(mock_engine);
        sup_cfg.helper_socket = PathBuf::from("/tmp/mock-helper.sock");
        sup_cfg.on_state_change = Some(Arc::new(move |_st| {
            notify_clone.fetch_add(1, Ordering::Relaxed);
        }));

        let supervisor = EngineSupervisor::new(sup_cfg);
        let mut rx = supervisor.subscribe();

        let app_cfg = sample_app_config(ConnectionMode::Tun);
        supervisor.connect(&app_cfg).await.expect("connect TUN");

        // Wait until status transitions to Connected
        tokio::time::timeout(
            Duration::from_secs(3),
            rx.wait_for(|s| s.status == EngineStatus::Connected),
        )
        .await
        .expect("timed out waiting for Connected")
        .expect("watch channel open");

        let connected_state = supervisor.state();
        assert_eq!(connected_state.utun_name.as_deref(), Some("utun7"));
        assert_eq!(connected_state.active_mode, ConnectionMode::Tun);
        assert_eq!(
            connected_state.active_profile_name.as_deref(),
            Some("Tokyo")
        );

        // Verify Zero-UUID-in-ps & env guarantee!
        let argv_text = fs::read_to_string(&argv_dump).expect("read argv.txt");
        assert_eq!(argv_text.trim(), "ipc");
        assert!(!argv_text.contains(TEST_UUID));
        assert!(!argv_text.contains(TEST_PBK));

        let env_text = fs::read_to_string(&env_dump).expect("read env.txt");
        assert!(!env_text.contains(TEST_UUID));
        assert!(!env_text.contains(TEST_PBK));

        // Verify AppToEngine::Start received over stdin with effective TUN bypass CIDRs + domains
        let stdin_lines = fs::read_to_string(&stdin_dump).expect("read stdin.jsonl");
        let first_line = stdin_lines.lines().next().expect("Start line");
        let decoded_start: AppToEngine =
            vless_ipc::decode_json_line(first_line).expect("decode AppToEngine::Start");
        match decoded_start {
            AppToEngine::Start {
                profile,
                mode,
                dns_resolver,
                bypass_cidrs,
                bypass_domains,
            } => {
                assert_eq!(profile.uuid.to_string(), TEST_UUID);
                assert_eq!(
                    mode,
                    EngineLaunchMode::Tun {
                        helper_socket: PathBuf::from("/tmp/mock-helper.sock")
                    }
                );
                assert_eq!(dns_resolver, "1.1.1.1".parse::<IpAddr>().unwrap());
                assert!(bypass_cidrs.contains(&"10.0.0.0/8".parse().unwrap()));
                assert!(bypass_cidrs.contains(&"100.64.0.0/10".parse().unwrap()));
                assert_eq!(bypass_domains, vec!["*.corp.example".to_string()]);
            }
            other => panic!("expected Start, got {other:?}"),
        }

        // Verify engine.log exists with strict 0600 permissions and contains the structured log
        let log_path = supervisor.engine_log_path();
        let log_meta = fs::metadata(&log_path).expect("engine.log metadata");
        assert_eq!(log_meta.mode() & 0o777, 0o600);
        let log_contents = fs::read_to_string(&log_path).expect("read engine.log");
        assert!(log_contents.contains("[INFO] vless_engine::tun: utun7 ready"));

        // Trigger macOS wake RecheckServer
        let sent = supervisor.recheck_server().await.expect("recheck_server");
        assert!(sent);

        tokio::time::timeout(
            Duration::from_secs(3),
            rx.wait_for(|s| s.last_server_check.is_some()),
        )
        .await
        .expect("timed out waiting for ServerCheck")
        .expect("watch channel open");

        assert_eq!(
            supervisor.state().last_server_check,
            Some(ServerCheckSummary {
                reachable: true,
                rtt_ms: Some(19),
                error: None,
            })
        );

        // Disconnect cleanly
        supervisor.disconnect().await.expect("disconnect");
        assert_eq!(supervisor.state().status, EngineStatus::Stopped);
        assert_eq!(supervisor.state().active_mode, ConnectionMode::Off);
        assert!(notify_count.load(Ordering::Relaxed) >= 3);

        // RecheckServer when disconnected is a clean no-op
        assert!(!supervisor.recheck_server().await.unwrap());
    }

    #[tokio::test]
    async fn unexpected_child_crash_transitions_to_error_with_stderr_diagnostics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mock_engine = temp.path().join("crash-engine.sh");

        let script = r#"#!/bin/sh
IFS= read -r _start_line
printf 'fatal: helper socket /var/run/vless-tray.sock permission denied\n' >&2
exit 42
"#;
        write_executable_script(&mock_engine, script);

        let mut sup_cfg = SupervisorConfig::new(temp.path().join("cfg"));
        sup_cfg.engine_bin_override = Some(mock_engine);

        let supervisor = EngineSupervisor::new(sup_cfg);
        let mut rx = supervisor.subscribe();

        let app_cfg = sample_app_config(ConnectionMode::SystemProxy);
        supervisor
            .connect(&app_cfg)
            .await
            .expect("initial spawn succeeds");

        tokio::time::timeout(
            Duration::from_secs(3),
            rx.wait_for(|s| s.status == EngineStatus::Error),
        )
        .await
        .expect("timed out waiting for crash -> Error")
        .expect("watch channel open");

        let err_state = supervisor.state();
        assert_eq!(err_state.status, EngineStatus::Error);
        let detail = err_state.detail.expect("error detail populated");
        assert!(
            detail.contains("code 42") && detail.contains("permission denied"),
            "unexpected detail: {detail}"
        );
    }

    #[tokio::test]
    async fn hung_engine_is_force_killed_after_stop_timeout_and_log_rotates_cleanly() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mock_engine = temp.path().join("hung-engine.sh");

        // Ignores stdin Stop/EOF and sleeps until killed
        let script = r#"#!/bin/sh
IFS= read -r _line || true
printf '%s\n' '{"type":"state","status":"connected","detail":null,"listen_addr":"127.0.0.1:2080","utun_name":null}'
sleep 30
"#;
        write_executable_script(&mock_engine, script);

        let mut sup_cfg = SupervisorConfig::new(temp.path().join("cfg"));
        sup_cfg.engine_bin_override = Some(mock_engine);
        sup_cfg.stop_timeout = Duration::from_millis(150);
        sup_cfg.max_log_bytes = 4096;

        let supervisor = EngineSupervisor::new(sup_cfg);
        let mut rx = supervisor.subscribe();

        let app_cfg = sample_app_config(ConnectionMode::SystemProxy);
        supervisor.connect(&app_cfg).await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(3),
            rx.wait_for(|s| s.status == EngineStatus::Connected),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            supervisor.state().listen_addr,
            Some("127.0.0.1:2080".parse().unwrap())
        );

        // Disconnect triggers SIGKILL fallback after 150ms and transitions cleanly to Stopped (NOT Error!)
        supervisor
            .shutdown()
            .await
            .expect("shutdown kills hung child");
        assert_eq!(supervisor.state().status, EngineStatus::Stopped);

        // Test bounded log rotation under 0600 permissions
        let lock = Mutex::new(());
        let log_path = supervisor.engine_log_path();
        for idx in 0..200 {
            let line = format_engine_log_line(
                1_700_000_000_000 + idx,
                LogLevel::Info,
                "test::rotator",
                &format!("entry-{idx:04}-padding-0123456789abcdef"),
            );
            append_engine_log_entry(&log_path, &line, 4096, &lock).unwrap();
        }
        let meta = fs::metadata(&log_path).unwrap();
        assert!(
            meta.len() <= 4096,
            "expected <= 4096 bytes, got {}",
            meta.len()
        );
        assert_eq!(meta.mode() & 0o777, 0o600);
        let rotated_text = fs::read_to_string(&log_path).unwrap();
        assert!(rotated_text.contains("entry-0199-padding"));
    }

    #[test]
    fn intentional_disconnect_suppresses_dying_child_error_and_wake_recheck_retries_once() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mock_engine = temp.path().join("wake-and-stop-engine.sh");
        let counter_file = temp.path().join("recheck-count");

        // First recheck_server simulates pre-Wi-Fi wake failure (reachable=false);
        // second recheck_server succeeds (reachable=true, rtt_ms=14).
        // On stop, child emits a spurious State(Error) frame right before exiting 0 — supervisor
        // MUST suppress it because stop was intentional!
        let script = format!(
            r#"#!/bin/sh
set -eu
count=0
while IFS= read -r line; do
    case "$line" in
        *'"type":"start"'*)
            printf '%s\n' '{{"type":"state","status":"connected","detail":null,"listen_addr":null,"utun_name":"utun5"}}'
            ;;
        *'"type":"recheck_server"'*)
            count=$((count + 1))
            printf '%s\n' "$count" > "{counter}"
            if [ "$count" -eq 1 ]; then
                printf '%s\n' '{{"type":"server_check","reachable":false,"rtt_ms":null,"error":"Network is unreachable"}}'
            else
                printf '%s\n' '{{"type":"server_check","reachable":true,"rtt_ms":14,"error":null}}'
            fi
            ;;
        *'"type":"stop"'*)
            printf '%s\n' '{{"type":"state","status":"error","detail":"aborted in-flight socket on shutdown","listen_addr":null,"utun_name":null}}'
            exit 0
            ;;
    esac
done
"#,
            counter = counter_file.display()
        );
        write_executable_script(&mock_engine, &script);

        let saw_error = Arc::new(AtomicBool::new(false));
        let saw_error_cb = Arc::clone(&saw_error);

        let mut sup_cfg = SupervisorConfig::new(temp.path().join("cfg"));
        sup_cfg.engine_bin_override = Some(mock_engine);
        sup_cfg.on_state_change = Some(Arc::new(move |st| {
            if st.status == EngineStatus::Error {
                saw_error_cb.store(true, Ordering::Release);
            }
        }));

        let rt_sup = RuntimeSupervisor::new(sup_cfg).expect("RuntimeSupervisor");
        let app_cfg = sample_app_config(ConnectionMode::Tun);
        rt_sup.spawn_connect(app_cfg);

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while rt_sup.state().status != EngineStatus::Connected {
            assert!(std::time::Instant::now() < deadline, "wait Connected");
            std::thread::sleep(Duration::from_millis(15));
        }

        // Trigger wake recheck with short 60ms retry delay: first probe fails, retry succeeds!
        rt_sup.spawn_wake_recheck(Duration::from_millis(60));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(chk) = rt_sup.state().last_server_check
                && chk.reachable
                && chk.rtt_ms == Some(14)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for wake retry ServerCheck recovery"
            );
            std::thread::sleep(Duration::from_millis(15));
        }
        assert_eq!(fs::read_to_string(&counter_file).unwrap().trim(), "2");

        // Graceful shutdown must NOT flash EngineStatus::Error even though child emitted error on stop
        rt_sup.shutdown();
        assert_eq!(rt_sup.state().status, EngineStatus::Stopped);
        assert!(
            !saw_error.load(Ordering::Acquire),
            "intentional stop must never transition through EngineStatus::Error"
        );
    }
}
