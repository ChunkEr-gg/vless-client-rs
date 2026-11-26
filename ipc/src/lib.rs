//! Shared IPC types, `vless://` link parser, `0600` atomic profile/config store, and `SCM_RIGHTS`
//! Unix domain socket framing for `vless-tray`.

pub mod engine_ipc;
pub mod helper_ipc;
pub use vless_profile as profile;
pub mod scm_rights;
pub mod store;

pub use engine_ipc::{
    AppToEngine, EngineIpcError, EngineLaunchMode, EngineStatus, EngineToApp, LogLevel,
    MAX_ENGINE_IPC_LINE_BYTES, REALITY_AUTH_OR_CLOCK_ERROR, decode_json_line, encode_json_line,
    read_json_line_async, read_json_line_sync, write_json_line_async, write_json_line_sync,
};
pub use helper_ipc::{
    DEFAULT_HELPER_OWNER_UID_PATH, DEFAULT_HELPER_SOCKET_PATH, DEFAULT_HELPER_STATE_PATH,
    DEFAULT_HELPER_SUPPORT_DIR, HelperCommand, HelperMessage, HelperMode, HelperResponse,
    HelperStatus, HelperValidationError, MAX_BYPASS_CIDRS, MAX_HELPER_FRAME_BYTES,
    MAX_PROXY_EXCEPTIONS, MAX_SERVER_IPS, validate_cidr, validate_exception_entry,
    validate_interface_name, validate_server_ip, validate_service_name,
};
pub use profile::{
    DEFAULT_KTLS_ALPN, ImportOutcome, Profile, ProfileError, ProfileSecurity,
    TLS_VISION_PROBE_WARNING, VISION_FLOW, decode_public_key, decode_short_id,
    format_sha256_pin_hex, parse_profile_list, parse_sha256_pin, parse_vless_link,
    validate_dns_name, validate_server_host,
};
pub use scm_rights::{
    async_recv_frame_with_fd, async_recv_helper_message, async_send_frame_with_fd,
    async_send_helper_command, async_send_helper_message, async_try_recv_frame_with_fd,
    async_try_recv_helper_command, peer_uid, peer_uid_from_fd, recv_frame_with_fd,
    recv_helper_command, recv_helper_message, send_frame_with_fd, send_helper_command,
    send_helper_message, tokio_peer_uid, try_recv_frame_with_fd, try_recv_helper_command,
};
pub use store::{
    AppConfig, BUILTIN_SYSTEM_PROXY_EXCEPTIONS, BUILTIN_TUN_BYPASS_CIDR_STRS, BypassEntry,
    BypassValidationError, CONFIG_FILE_NAME, ConfigError, ConfigStore, ConnectionMode,
    DEFAULT_DNS_RESOLVER, DEFAULT_SYSTEM_PROXY_PORT, builtin_system_proxy_exceptions,
    builtin_tun_bypass_cidrs, default_config_dir, effective_system_proxy_exceptions,
    effective_tun_bypass, parse_bypass_entry, parse_bypass_list, write_atomic_0600,
};
