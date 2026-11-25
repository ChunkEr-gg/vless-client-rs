#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::time::{Duration, Instant};
use vless_tray_helper::{MacosSystemBackend, SystemBackend};

#[test]
#[ignore = "requires permission to open the macOS utun kernel control"]
fn kernel_releases_utun_after_last_descriptor_closes() {
    let (fd, name) = MacosSystemBackend::new().create_utun().unwrap();
    assert!(name.strip_prefix("utun").unwrap().parse::<u32>().is_ok());
    let name = CString::new(name).unwrap();
    // SAFETY: name is a live NUL-terminated interface name.
    let index = || unsafe { libc::if_nametoindex(name.as_ptr()) };
    let original = index();
    assert_ne!(original, 0);

    let retained = fd.try_clone().unwrap();
    drop(fd);
    assert_eq!(index(), original);
    drop(retained);

    let deadline = Instant::now() + Duration::from_secs(5);
    while index() == original {
        assert!(
            Instant::now() < deadline,
            "kernel retained the utun interface"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
