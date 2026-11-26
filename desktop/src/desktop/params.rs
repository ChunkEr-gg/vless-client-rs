use super::store::SavedProfile;
use eframe::egui::{self, Ui};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Params {
    pub host: String,
    pub port: String,
    pub uuid: String,
    pub query: BTreeMap<String, String>,
    pub pin: String,
    fragment: String,
}

impl Params {
    pub fn from_profile(profile: &SavedProfile) -> Self {
        // Canonicalize URI spelling, pin aliases and escaped credentials before editing.
        let canonical = vless_profile::parse_vless_link(&profile.link)
            .expect("validated profile")
            .profile
            .to_vless_link();
        let (link, fragment) = canonical.split_once('#').unwrap_or((&canonical, ""));
        let (authority, query) = link.trim_start_matches("vless://").split_once('?').unwrap();
        let (uuid, address) = authority.split_once('@').unwrap();
        let (host, port) = address.rsplit_once(':').expect("validated endpoint");
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let mut query: BTreeMap<_, _> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let pin = profile
            .pin
            .as_deref()
            .and_then(|pin| vless_profile::parse_sha256_pin(pin).ok())
            .map(|pin| vless_profile::format_sha256_pin_hex(&pin))
            .or_else(|| query.get("pcs").cloned())
            .unwrap_or_default();
        query.remove("pcs");
        Self {
            host: host.into(),
            port: port.to_string(),
            uuid: uuid.into(),
            query,
            pin,
            fragment: fragment.into(),
        }
    }

    pub fn link(&self) -> Result<String, String> {
        let host = self.host.trim();
        if rustls_pki_types::ServerName::try_from(host).is_err() {
            return Err("Enter a valid server host or IP address.".into());
        }
        if uuid::Uuid::parse_str(self.uuid.trim()).is_err() {
            return Err("Invalid VLESS UUID.".into());
        }
        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| "Invalid server port.")?;
        let authority = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let reality = self.query.get("security").is_some_and(|s| s == "reality");
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (k, v) in &self.query {
            if v.is_empty() || (!reality && matches!(k.as_str(), "pbk" | "sid" | "flow" | "fp")) {
                continue;
            }
            query.append_pair(k, v);
        }
        Ok(format!(
            "vless://{}@{authority}:{port}?{}#{}",
            self.uuid.trim(),
            query.finish(),
            self.fragment
        ))
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        field(ui, "Server host", &mut self.host, false);
        field(ui, "Port", &mut self.port, false);
        field(ui, "User UUID", &mut self.uuid, true);
        let security = self.query.entry("security".into()).or_default();
        ui.horizontal(|ui| {
            ui.label("Security");
            for mode in ["reality", "tls"] {
                ui.selectable_value(security, mode.into(), mode.to_uppercase());
            }
        });
        let reality = security == "reality";
        field(
            ui,
            "Server name (SNI)",
            self.query.entry("sni".into()).or_default(),
            false,
        );
        if reality {
            field(
                ui,
                "Public key",
                self.query.entry("pbk".into()).or_default(),
                false,
            );
            field(
                ui,
                "Short ID",
                self.query.entry("sid".into()).or_default(),
                false,
            );
            let flow = self.query.entry("flow".into()).or_default();
            let mut vision = !flow.is_empty();
            if ui.checkbox(&mut vision, "Vision flow").changed() {
                *flow = if vision {
                    "xtls-rprx-vision".into()
                } else {
                    String::new()
                };
            }
        } else {
            field(
                ui,
                "ALPN (comma separated)",
                self.query.entry("alpn".into()).or_default(),
                false,
            );
            field(ui, "TLS certificate pin", &mut self.pin, false);
        }
    }
}

fn field(ui: &mut Ui, name: &str, value: &mut String, secret: bool) {
    let label = ui.label(name);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(secret)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(label.id);
}
