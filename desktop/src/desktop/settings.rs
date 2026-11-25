use eframe::egui::{self, Ui};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Settings {
    pub auto_start: bool,
    pub tun: bool,
    pub log_connections: bool,
    pub timeout: u16,
    pub bypass_lan: bool,
    pub direct_domains: String,
    pub dns: IpAddr,
    pub resolve_domains: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_start: false,
            tun: false,
            log_connections: true,
            timeout: 10,
            bypass_lan: false,
            direct_domains: String::new(),
            dns: IpAddr::from([1, 1, 1, 1]),
            resolve_domains: false,
        }
    }
}

#[derive(PartialEq)]
pub(super) enum Tab {
    Service,
    Connection,
    Routing,
    Dns,
}

pub(super) struct Form {
    pub settings: Settings,
    pub listen: String,
    dns: String,
    tab: Tab,
    pub error: String,
}

impl Form {
    pub fn new(book: &super::store::Book) -> Self {
        Self {
            settings: book.settings.clone(),
            listen: book.listen.to_string(),
            dns: book.settings.dns.to_string(),
            tab: Tab::Connection,
            error: String::new(),
        }
    }

    pub fn apply(&mut self, book: &mut super::store::Book) -> Result<(), String> {
        book.listen = super::parse_listen(self.listen.trim())?;
        self.settings.dns = self
            .dns
            .trim()
            .parse()
            .map_err(|_| "DNS server must be an IP address.")?;
        for domain in self.settings.direct_domains.split_whitespace() {
            if !matches!(
                rustls_pki_types::ServerName::try_from(domain),
                Ok(rustls_pki_types::ServerName::DnsName(_))
            ) {
                return Err(format!("Invalid direct domain: {domain}"));
            }
        }
        book.settings = self.settings.clone();
        Ok(())
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            for (tab, name) in [
                (Tab::Service, "Service"),
                (Tab::Connection, "Connection"),
                (Tab::Routing, "Routing"),
                (Tab::Dns, "DNS"),
            ] {
                ui.selectable_value(&mut self.tab, tab, name);
            }
        });
        ui.add_space(6.0);
        match self.tab {
            Tab::Service => {
                ui.checkbox(
                    &mut self.settings.auto_start,
                    "Connect the first profile on app launch",
                );
                ui.checkbox(
                    &mut self.settings.log_connections,
                    "Include connection destinations in activity logs",
                );
            }
            Tab::Connection => {
                ui.label("SOCKS5 listener");
                ui.text_edit_singleline(&mut self.listen);
                ui.horizontal(|ui| {
                    ui.label("Connection timeout");
                    ui.add(
                        egui::DragValue::new(&mut self.settings.timeout)
                            .range(1..=120)
                            .suffix(" s"),
                    );
                });
            }
            Tab::Routing => {
                ui.checkbox(&mut self.settings.tun, "Route system traffic through TUN");
                ui.checkbox(
                    &mut self.settings.bypass_lan,
                    "Connect directly to private IP addresses",
                );
                ui.label("Direct domain suffixes · one per line");
                ui.text_edit_multiline(&mut self.settings.direct_domains);
            }
            Tab::Dns => {
                ui.label("DNS server IP");
                ui.text_edit_singleline(&mut self.dns);
                ui.label("DNS queries from TUN use this resolver through the proxy.");
                ui.checkbox(
                    &mut self.settings.resolve_domains,
                    "Use this resolver for SOCKS domain requests",
                );
            }
        }
    }
}
