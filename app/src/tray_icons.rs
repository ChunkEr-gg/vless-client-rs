//! Programmatic 36x36 (`@2x` Retina) RGBA template icons and pure menu-bar formatting helpers.
//!
//! Kept cross-platform so icon geometry, alpha masks, `muda` mnemonic escaping, and status-line
//! formatting are unit-tested natively on Linux while `#[cfg(target_os = "macos")]` wraps the
//! RGBA buffers into `tray_icon::Icon` templates (`with_icon_as_template(true)`).

use vless_ipc::{AppConfig, ConnectionMode, EngineStatus, Profile, ProfileSecurity};

use crate::supervisor::SupervisorState;

/// Width and height in pixels (`18pt @2x` Retina) for macOS menu-bar template icons.
pub const TRAY_ICON_SIZE: u32 = 36;

/// Visual icon variant rendered in the macOS menu bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrayVisualState {
    /// Outline shield (hollow interior).
    Disconnected,
    /// Dashed shield outline with center progress dots.
    Connecting,
    /// Solid filled shield with negative-space checkmark cutout.
    Connected,
    /// Outline shield with bold exclamation mark (`!`).
    Error,
}

impl TrayVisualState {
    /// Maps an [`EngineStatus`] to its corresponding [`TrayVisualState`].
    pub fn from_engine_status(status: EngineStatus) -> Self {
        match status {
            EngineStatus::Stopped => Self::Disconnected,
            EngineStatus::Starting | EngineStatus::Reconnecting | EngineStatus::Disconnecting => {
                Self::Connecting
            }
            EngineStatus::Connected => Self::Connected,
            EngineStatus::Error => Self::Error,
        }
    }
}

/// Renders a crisp anti-aliased `36x36` RGBA template icon (`RGB = 0,0,0`, alpha mask `0..=255`).
pub fn render_tray_icon_rgba(visual: TrayVisualState) -> Vec<u8> {
    let size = TRAY_ICON_SIZE as usize;
    let mut rgba = vec![0u8; size * size * 4];

    for py in 0..size {
        for px in 0..size {
            let x = (px as f32) + 0.5;
            let y = (py as f32) + 0.5;

            let shield_sd = shield_signed_distance(x, y);
            let alpha = match visual {
                TrayVisualState::Disconnected => {
                    // Clean 2.5px outline stroke around the shield perimeter (`-2.5 <= sd <= 0.0`).
                    stroke_alpha(shield_sd, -1.25, 1.25)
                }
                TrayVisualState::Connecting => {
                    // Dashed shield perimeter + three subtle progress dots inside.
                    let outline = stroke_alpha(shield_sd, -1.25, 1.25);
                    let angle = (y - 17.5).atan2(x - 18.0);
                    // 10 evenly spaced radial dashes around the perimeter
                    let wave = (angle * 10.0).cos();
                    let dash_mask = clamp01((wave + 0.15) * 3.0);
                    let dashed_outline = outline * dash_mask;

                    let dot_left = circle_fill_alpha(x, y, 13.5, 18.0, 1.5);
                    let dot_mid = circle_fill_alpha(x, y, 18.0, 18.0, 1.5);
                    let dot_right = circle_fill_alpha(x, y, 22.5, 18.0, 1.5);
                    dashed_outline.max(dot_left).max(dot_mid).max(dot_right)
                }
                TrayVisualState::Connected => {
                    // Solid filled shield with a crisp negative-space checkmark cutout.
                    let fill = fill_alpha(shield_sd);
                    let check_left = capsule_alpha(x, y, 12.2, 18.4, 16.3, 22.5, 1.55);
                    let check_right = capsule_alpha(x, y, 16.3, 22.5, 24.2, 13.8, 1.55);
                    let cutout = check_left.max(check_right);
                    clamp01(fill * (1.0 - cutout))
                }
                TrayVisualState::Error => {
                    // Shield outline + bold exclamation mark ('!') inside.
                    let outline = stroke_alpha(shield_sd, -1.25, 1.25);
                    let stem = capsule_alpha(x, y, 18.0, 11.2, 18.0, 19.6, 1.55);
                    let dot = circle_fill_alpha(x, y, 18.0, 24.2, 1.65);
                    outline.max(stem).max(dot)
                }
            };

            let a_byte = (clamp01(alpha) * 255.0).round() as u8;
            let idx = (py * size + px) * 4;
            // Template image convention on macOS: black RGB (0, 0, 0) + alpha channel.
            rgba[idx] = 0;
            rgba[idx + 1] = 0;
            rgba[idx + 2] = 0;
            rgba[idx + 3] = a_byte;
        }
    }

    rgba
}

/// Builds a `tray_icon::Icon` from [`render_tray_icon_rgba`] on macOS.
#[cfg(target_os = "macos")]
pub fn build_macos_icon(visual: TrayVisualState) -> Result<tray_icon::Icon, tray_icon::BadIcon> {
    let rgba = render_tray_icon_rgba(visual);
    tray_icon::Icon::from_rgba(rgba, TRAY_ICON_SIZE, TRAY_ICON_SIZE)
}

/// Signed distance (< 0 inside, > 0 outside) to a classic symmetric macOS menu-bar shield centered
/// in a `36x36` canvas (`y` in `4.0..=32.0`, half-width `~12.5px` at top tapering smoothly to a
/// rounded tip at `(18.0, 32.0)`).
fn shield_signed_distance(x: f32, y: f32) -> f32 {
    let top = 4.5_f32;
    let bottom = 31.5_f32;
    let height = bottom - top;
    let dx = (x - 18.0).abs();

    if y < top {
        // Above top edge (slight upward arch toward center)
        let arch_top = top - 0.8 * (1.0 - (dx / 12.2).min(1.0).powi(2));
        if dx <= 12.2 {
            arch_top - y
        } else {
            ((dx - 12.2).powi(2) + (y - top).powi(2)).sqrt()
        }
    } else if y > bottom {
        (dx.powi(2) + (y - bottom).powi(2)).sqrt()
    } else {
        let t = (y - top) / height; // 0.0 at top -> 1.0 at tip
        // Gently curved sides in upper half, tapering smoothly to a point at t = 1.0
        let half_width = if t < 0.42 {
            12.2 - 0.8 * (t / 0.42).powi(2)
        } else {
            let u = (t - 0.42) / 0.58;
            11.4 * (1.0 - u.powf(1.45))
        };

        // Approximate perpendicular distance to the side curve + top/bottom caps
        let side_dist = (dx - half_width) * 0.86;
        let top_dist = (top - 0.8 * (1.0 - (dx / 12.2).min(1.0).powi(2))) - y;
        let bottom_dist = y - bottom;
        side_dist.max(top_dist).max(bottom_dist)
    }
}

fn fill_alpha(sd: f32) -> f32 {
    clamp01(0.5 - sd)
}

fn stroke_alpha(sd: f32, center_sd: f32, half_width: f32) -> f32 {
    let d = (sd - center_sd).abs() - half_width;
    clamp01(0.5 - d)
}

fn circle_fill_alpha(x: f32, y: f32, cx: f32, cy: f32, radius: f32) -> f32 {
    let d = ((x - cx).powi(2) + (y - cy).powi(2)).sqrt() - radius;
    clamp01(0.5 - d)
}

fn capsule_alpha(x: f32, y: f32, ax: f32, ay: f32, bx: f32, by: f32, radius: f32) -> f32 {
    let pax = x - ax;
    let pay = y - ay;
    let bax = bx - ax;
    let bay = by - ay;
    let denom = (bax * bax + bay * bay).max(1e-6);
    let h = ((pax * bax + pay * bay) / denom).clamp(0.0, 1.0);
    let dist = ((pax - bax * h).powi(2) + (pay - bay * h).powi(2)).sqrt() - radius;
    clamp01(0.5 - dist)
}

fn clamp01(v: f32) -> f32 {
    v.clamp(0.0, 1.0)
}

/// Escapes `&` as `&&` so `muda`'s mnemonic parser on macOS preserves literal ampersands in
/// profile names, hostnames, and error descriptions.
pub fn escape_muda_text(text: &str) -> String {
    text.replace('&', "&&")
}

/// Human-readable label for a [`ConnectionMode`].
pub fn format_mode_label(mode: ConnectionMode) -> &'static str {
    match mode {
        ConnectionMode::Off => "Off",
        ConnectionMode::SystemProxy => "System Proxy",
        ConnectionMode::Tun => "TUN",
    }
}

/// Formats the primary disabled status `MenuItem` text at the top of the menu bar menu.
pub fn format_tray_status_line(
    state: &SupervisorState,
    config: &AppConfig,
    transient_notice: Option<&str>,
) -> String {
    if let Some(notice) = transient_notice
        && !notice.trim().is_empty()
    {
        return escape_muda_text(&truncate_chars(notice.trim(), 78));
    }

    let profile_label = state
        .active_profile_name
        .as_deref()
        .or_else(|| config.selected_profile().map(|p| p.name.as_str()))
        .unwrap_or("No Profile");

    let raw = match state.status {
        EngineStatus::Stopped => {
            if config.profiles.is_empty() {
                "Status: Disconnected (No profiles — open Settings…)".to_string()
            } else {
                format!(
                    "Status: Disconnected · Mode: {} · {}",
                    format_mode_label(config.mode),
                    profile_label
                )
            }
        }
        EngineStatus::Starting => format!(
            "Status: Connecting ({}) · {}",
            format_mode_label(state.active_mode),
            profile_label
        ),
        EngineStatus::Reconnecting => format!(
            "Status: Reconnecting ({}) · {}",
            format_mode_label(state.active_mode),
            profile_label
        ),
        EngineStatus::Disconnecting => "Status: Disconnecting…".to_string(),
        EngineStatus::Connected => {
            let endpoint = if let Some(utun) = &state.utun_name {
                format!("TUN {utun}")
            } else if let Some(addr) = &state.listen_addr {
                format!("Proxy {addr}")
            } else {
                format_mode_label(state.active_mode).to_string()
            };
            match &state.detail {
                Some(detail)
                    if detail.starts_with("RTT ") || detail.starts_with("Server check") =>
                {
                    format!("Status: Connected ({endpoint}) · {profile_label} · {detail}")
                }
                _ => format!("Status: Connected ({endpoint}) · {profile_label}"),
            }
        }
        EngineStatus::Error => match &state.detail {
            Some(detail) if !detail.trim().is_empty() => {
                format!("Status: Error — {}", detail.trim())
            }
            _ => "Status: Error (see Settings -> Logs)".to_string(),
        },
    };

    escape_muda_text(&truncate_chars(&raw, 84))
}

/// Formats the tray icon hover tooltip on macOS.
pub fn format_tray_tooltip(state: &SupervisorState, config: &AppConfig) -> String {
    match state.status {
        EngineStatus::Connected => {
            let profile = state
                .active_profile_name
                .as_deref()
                .unwrap_or("Active Profile");
            if let Some(utun) = &state.utun_name {
                format!("VLESS Tray — Connected ({utun}, {profile})")
            } else if let Some(addr) = &state.listen_addr {
                format!("VLESS Tray — Connected ({addr}, {profile})")
            } else {
                format!("VLESS Tray — Connected ({profile})")
            }
        }
        EngineStatus::Starting => "VLESS Tray — Connecting…".to_string(),
        EngineStatus::Reconnecting => "VLESS Tray — Reconnecting…".to_string(),
        EngineStatus::Disconnecting => "VLESS Tray — Disconnecting…".to_string(),
        EngineStatus::Error => match &state.detail {
            Some(d) => format!("VLESS Tray — Error: {}", truncate_chars(d, 96)),
            None => "VLESS Tray — Error".to_string(),
        },
        EngineStatus::Stopped => {
            format!(
                "VLESS Tray — Disconnected ({})",
                format_mode_label(config.mode)
            )
        }
    }
}

/// Label for the `Connect` / `Disconnect` menu item.
pub fn format_connect_action_label(state: &SupervisorState) -> &'static str {
    match state.status {
        EngineStatus::Starting | EngineStatus::Connected | EngineStatus::Reconnecting => {
            "Disconnect"
        }
        EngineStatus::Disconnecting => "Disconnecting…",
        EngineStatus::Stopped | EngineStatus::Error => "Connect",
    }
}

/// Formats a profile row label WITHOUT `&&` escaping.
///
/// NOTE on `muda` 0.17.2 macOS backend (`muda::platform_impl::macos::MenuChild::new_check`):
/// `MenuItem::new`, `Submenu::new`, and `set_text` invoke `strip_mnemonic` (turning `&&` into `&`
/// and stripping single `&`), whereas `CheckMenuItem::new` stores the string verbatim without
/// `strip_mnemonic`. Passing `format_profile_menu_label_raw` to `CheckMenuItem::new` on macOS
/// prevents profile names containing `&` (e.g. `"Work & Home"`) from rendering as `"Work && Home"`.
pub fn format_profile_menu_label_raw(profile: &Profile) -> String {
    let badge = match &profile.security {
        ProfileSecurity::Reality { .. } => "REALITY",
        ProfileSecurity::Ktls { .. } => "kTLS",
    };
    format!(
        "{} ({badge} · {})",
        profile.name,
        profile.server_addr_display()
    )
}

/// Formats a profile row inside the `Profiles` submenu (`muda`-escaped for `set_text` / `MenuItem`).
pub fn format_profile_menu_label(profile: &Profile) -> String {
    escape_muda_text(&format_profile_menu_label_raw(profile))
}

/// Passively checks whether the `launchd` helper Unix domain socket exists on disk without
/// calling `connect()` (so `launchd` never spawns the root helper while the client is idle).
#[cfg(unix)]
pub fn is_helper_socket_present(socket_path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::symlink_metadata(socket_path)
        .map(|meta| meta.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn is_helper_socket_present(_socket_path: &std::path::Path) -> bool {
    false
}

/// Returns `true` if differences between `old_cfg` and `new_cfg` affect an active `vless-engine`
/// session (selected profile contents/existence, connection mode, DNS resolver, proxy port, or
/// bypass rules).
pub fn active_engine_inputs_changed(old_cfg: &AppConfig, new_cfg: &AppConfig) -> bool {
    old_cfg.mode != new_cfg.mode
        || old_cfg.selected_profile_id != new_cfg.selected_profile_id
        || old_cfg.selected_profile() != new_cfg.selected_profile()
        || old_cfg.system_proxy_port != new_cfg.system_proxy_port
        || old_cfg.dns_resolver != new_cfg.dns_resolver
        || old_cfg.bypass_list != new_cfg.bypass_list
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use vless_ipc::parse_vless_link;

    use super::*;

    #[test]
    fn all_four_tray_icon_states_produce_distinct_valid_36x36_rgba_templates() {
        let disconnected = render_tray_icon_rgba(TrayVisualState::Disconnected);
        let connecting = render_tray_icon_rgba(TrayVisualState::Connecting);
        let connected = render_tray_icon_rgba(TrayVisualState::Connected);
        let error = render_tray_icon_rgba(TrayVisualState::Error);

        let expected_len = (TRAY_ICON_SIZE * TRAY_ICON_SIZE * 4) as usize;
        for buf in [&disconnected, &connecting, &connected, &error] {
            assert_eq!(buf.len(), expected_len);
            // Template invariant: RGB channels are 0, and non-zero alpha pixels exist
            let mut non_zero_alpha = 0usize;
            for px in buf.as_chunks::<4>().0 {
                assert_eq!(px[0], 0);
                assert_eq!(px[1], 0);
                assert_eq!(px[2], 0);
                if px[3] > 0 {
                    non_zero_alpha += 1;
                }
            }
            assert!(
                non_zero_alpha > 80,
                "icon had too few opaque pixels: {non_zero_alpha}"
            );
        }

        // Every state must look visually distinct
        assert_ne!(disconnected, connecting);
        assert_ne!(disconnected, connected);
        assert_ne!(disconnected, error);
        assert_ne!(connecting, connected);
        assert_ne!(connecting, error);
        assert_ne!(connected, error);

        assert_eq!(
            TrayVisualState::from_engine_status(EngineStatus::Stopped),
            TrayVisualState::Disconnected
        );
        assert_eq!(
            TrayVisualState::from_engine_status(EngineStatus::Starting),
            TrayVisualState::Connecting
        );
        assert_eq!(
            TrayVisualState::from_engine_status(EngineStatus::Reconnecting),
            TrayVisualState::Connecting
        );
        assert_eq!(
            TrayVisualState::from_engine_status(EngineStatus::Connected),
            TrayVisualState::Connected
        );
        assert_eq!(
            TrayVisualState::from_engine_status(EngineStatus::Error),
            TrayVisualState::Error
        );
    }

    #[test]
    fn menu_labels_escape_ampersands_and_detect_active_config_changes() {
        assert_eq!(escape_muda_text("US & EU"), "US && EU");

        let pbk = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
        let p1 = parse_vless_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={pbk}#Work%20%26%20Home"
        ))
        .unwrap()
        .profile;
        let p2 = parse_vless_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ktls.example.com:8443?security=tls&sni=ktls.example.com#Backup",
        )
        .unwrap()
        .profile;

        assert_eq!(
            format_profile_menu_label_raw(&p1),
            "Work & Home (REALITY · edge.example.com:443)"
        );
        assert_eq!(
            format_profile_menu_label(&p1),
            "Work && Home (REALITY · edge.example.com:443)"
        );
        assert_eq!(
            format_profile_menu_label(&p2),
            "Backup (kTLS · ktls.example.com:8443)"
        );

        let cfg1 = AppConfig {
            profiles: vec![p1.clone(), p2.clone()],
            selected_profile_id: Some(p1.id),
            mode: ConnectionMode::Tun,
            ..AppConfig::default()
        };

        // Renaming an UNSELECTED profile does NOT trigger active engine reconnect
        let mut cfg_inactive_edit = cfg1.clone();
        cfg_inactive_edit.profiles[1].name = "Backup Renamed".to_string();
        assert!(!active_engine_inputs_changed(&cfg1, &cfg_inactive_edit));

        // Changing bypass list or selected profile DOES trigger active engine reconnect
        let mut cfg_bypass_edit = cfg1.clone();
        cfg_bypass_edit
            .bypass_list
            .push("*.internal.corp".to_string());
        assert!(active_engine_inputs_changed(&cfg1, &cfg_bypass_edit));

        let st = SupervisorState {
            status: EngineStatus::Connected,
            active_mode: ConnectionMode::Tun,
            active_profile_name: Some("Work & Home".to_string()),
            utun_name: Some("utun6".to_string()),
            ..SupervisorState::default()
        };
        assert_eq!(
            format_tray_status_line(&st, &cfg1, None),
            "Status: Connected (TUN utun6) · Work && Home"
        );
        assert_eq!(format_connect_action_label(&st), "Disconnect");
    }

    #[cfg(unix)]
    #[test]
    fn helper_socket_presence_distinguishes_unix_socket_from_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("helper.sock");
        let reg_path = dir.path().join("regular.txt");

        assert!(!is_helper_socket_present(&sock_path));
        std::fs::write(&reg_path, b"not a socket").unwrap();
        assert!(!is_helper_socket_present(&reg_path));

        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        assert!(is_helper_socket_present(&sock_path));
    }
}
