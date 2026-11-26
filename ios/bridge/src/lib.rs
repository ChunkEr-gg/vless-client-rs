//! In-process engine ownership for the Swift client.
use std::ffi::{CStr, c_char};
use std::sync::Mutex;
use tokio::runtime::Runtime;
use vless_engine::{EngineConfig, EngineHandle, parse_vless_link};

static SESSION: Mutex<Option<(Runtime, EngineHandle)>> = Mutex::new(None);

/// Starts the local mixed proxy. Returns zero on success or a VLESS_START error.
///
/// # Safety
/// The caller must provide a valid, NUL-terminated UTF-8 C string for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vless_proxy_start(link: *const c_char, port: u16) -> i32 {
    if link.is_null() || port == 0 {
        return 1;
    }
    // SAFETY: the caller retains the string until this function returns.
    let link = unsafe { CStr::from_ptr(link) };
    let Some(imported) = link.to_str().ok().and_then(|s| parse_vless_link(s).ok()) else {
        return 1;
    };
    start_engine(EngineConfig::new_mixed_proxy(
        imported.profile,
        ([127, 0, 0, 1], port).into(),
    ))
}

/// Starts the packet engine on a borrowed datagram socket. EngineHandle duplicates the descriptor.
///
/// # Safety
/// The caller must retain a valid C string and an open socket until this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vless_packet_start(link: *const c_char, fd: i32) -> i32 {
    if link.is_null() || fd < 0 {
        return 1;
    }
    let link = unsafe { CStr::from_ptr(link) };
    let Some(imported) = link.to_str().ok().and_then(|s| parse_vless_link(s).ok()) else {
        return 1;
    };
    start_engine(EngineConfig::new_tun(
        imported.profile,
        fd,
        false,
        false,
        None,
    ))
}

fn start_engine(config: EngineConfig) -> i32 {
    let Ok(mut session) = SESSION.lock() else {
        return 3;
    };
    if session.is_some() {
        return 2;
    }
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        return 3;
    };
    let Ok((handle, _)) = runtime.block_on(EngineHandle::start(config)) else {
        return 3;
    };
    *session = Some((runtime, handle));
    0
}

/// Stops the listener and joins its engine tasks before returning.
#[unsafe(no_mangle)]
pub extern "C" fn vless_proxy_stop() {
    if let Ok(mut session) = SESSION.lock()
        && let Some((runtime, handle)) = session.take()
    {
        let _ = runtime.block_on(handle.stop());
    }
}

/// Imports a subscription and returns owned JSON or null on invalid input.
///
/// # Safety
/// `input` must remain a valid C string for the duration of this call.
/// Release the returned string with `vless_profiles_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vless_profiles_import(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let input = unsafe { CStr::from_ptr(input) };
    if input.to_bytes().len() > 1024 * 1024 {
        return std::ptr::null_mut();
    }
    let Some(entries) = input
        .to_str()
        .ok()
        .and_then(|s| vless_profile::parse_profile_list(s).ok())
    else {
        return std::ptr::null_mut();
    };
    if entries.len() > 128 {
        return std::ptr::null_mut();
    }
    let rows: Vec<_> = entries.into_iter().map(|entry| {
        let p = entry.profile;
        serde_json::json!({"name":p.name, "link":p.to_vless_link(), "endpoint":p.server_addr_display(),
            "security":if p.security.is_reality() {"REALITY + Vision"} else {"TLS"}, "warnings":entry.warnings})
    }).collect();
    std::ffi::CString::new(serde_json::Value::Array(rows).to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}

/// # Safety
/// `json` must be null or a live pointer returned by `vless_profiles_import`, released exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vless_profiles_free(json: *mut c_char) {
    if !json.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(json) });
    }
}
