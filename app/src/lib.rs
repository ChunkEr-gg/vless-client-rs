//! `vless-tray` library modules: child `vless-engine` supervisor, cross-platform `egui`
//! Settings window (`--settings`), privileged helper installer (`install-helper`), Retina menu-bar
//! template icon generator, and macOS menu-bar `winit` + `tray-icon` + `muda` application.

pub mod cli;
pub mod installer;
pub mod settings_ui;
pub mod supervisor;
pub mod tray_icons;

#[cfg(target_os = "macos")]
pub mod tray_macos;

use std::path::PathBuf;

use vless_ipc::default_config_dir;

use crate::cli::{CliCommand, parse_args, usage_text};

/// Resolves `config_dir` from an explicit CLI override or the platform default
/// (`~/Library/Application Support/vless-tray` on macOS).
pub fn resolve_effective_config_dir(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    match explicit {
        Some(dir) => Ok(dir),
        None => default_config_dir()
            .map_err(|err| format!("failed to resolve user configuration directory: {err}")),
    }
}

/// Executes `vless-tray` according to `std::env::args_os()`.
pub fn run_from_env() -> Result<(), String> {
    let cmd = parse_args(std::env::args_os().skip(1))?;
    match cmd {
        CliCommand::Help => {
            print!("{}", usage_text());
            Ok(())
        }
        CliCommand::Version => {
            println!("vless-tray {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::InstallHelper { overrides, dry_run } => {
            let output = installer::run_install_helper(&overrides, dry_run)
                .map_err(|err| err.to_string())?;
            println!("{output}");
            Ok(())
        }
        CliCommand::Settings { config_dir } => {
            let dir = resolve_effective_config_dir(config_dir)?;
            settings_ui::run_settings_window(dir)
        }
        CliCommand::Tray { config_dir } => {
            let dir = resolve_effective_config_dir(config_dir)?;
            run_platform_tray(dir)
        }
    }
}

#[cfg(target_os = "macos")]
fn run_platform_tray(config_dir: PathBuf) -> Result<(), String> {
    tray_macos::run_tray_app(config_dir)
}

#[cfg(not(target_os = "macos"))]
fn run_platform_tray(_config_dir: PathBuf) -> Result<(), String> {
    Err(
        "macOS menu-bar mode is only supported on macOS; run `vless-tray --settings` to open the Settings window or `vless-tray --help` for options"
            .to_string(),
    )
}
