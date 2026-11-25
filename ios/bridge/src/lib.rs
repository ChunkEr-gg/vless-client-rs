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
    let config = EngineConfig::new_mixed_proxy(imported.profile, ([127, 0, 0, 1], port).into());
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
