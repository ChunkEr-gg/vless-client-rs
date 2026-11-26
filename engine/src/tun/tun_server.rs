//! TUN server configuration (`PLAN.md` §5.3, §6).

use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct TunServerConfig {
    pub segmentation_offload: Option<bool>,
    pub resource_limits: crate::config::tun::TunResourceLimits,
    pub mtu: u16,
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
    pub icmp_enabled: bool,
    pub tun_name: Option<String>,
    pub address: Option<IpAddr>,
    pub netmask: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub raw_fd: Option<i32>,
    pub close_fd_on_drop: bool,
    /// Enable 4-byte `AF_INET`/`AF_INET6` packet information header (required for macOS `utun`).
    pub packet_information: bool,
}

impl Default for TunServerConfig {
    fn default() -> Self {
        Self {
            segmentation_offload: Some(false),
            resource_limits: Default::default(),
            mtu: 1500,
            tcp_enabled: true,
            udp_enabled: true,
            icmp_enabled: true,
            tun_name: None,
            address: None,
            netmask: None,
            destination: None,
            raw_fd: None,
            close_fd_on_drop: true,
            packet_information: false,
        }
    }
}

impl TunServerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resource_limits(mut self, limits: crate::config::tun::TunResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn raw_fd(mut self, fd: i32) -> Self {
        self.raw_fd = Some(fd);
        self
    }

    pub fn close_fd_on_drop(mut self, close: bool) -> Self {
        self.close_fd_on_drop = close;
        self
    }

    pub fn packet_information(mut self, pi: bool) -> Self {
        self.packet_information = pi;
        self
    }

    pub fn tcp_enabled(mut self, enabled: bool) -> Self {
        self.tcp_enabled = enabled;
        self
    }

    pub fn udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    pub fn icmp_enabled(mut self, enabled: bool) -> Self {
        self.icmp_enabled = enabled;
        self
    }
}
