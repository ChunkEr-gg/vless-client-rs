#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
mod desktop;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

const DEFAULT_LISTEN: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080));
const MAX_LINK_SIZE: u64 = 16384;

fn parse_listen(value: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .ok()
        .filter(|addr| addr.ip().is_loopback())
        .ok_or_else(|| "Enter a loopback address and port.".into())
}

fn main() -> Result<(), String> {
    desktop::run()
}
