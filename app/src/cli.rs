//! Command-line argument parser for `vless-tray`.
//!
//! Supported invocations (`PLAN.md` §4 & §7):
//! - `vless-tray [--config-dir <dir>]` — macOS menu-bar agent (`ControlFlow::Wait`, no GPU window)
//! - `vless-tray --settings [--config-dir <dir>]` — short-lived `eframe`/`egui` Settings window
//! - `vless-tray install-helper [--uid <uid>] [--helper <path>] [--plist <path>] [--script <path>] [--dry-run]`
//! - `vless-tray --help` / `vless-tray --version`

use std::ffi::OsString;
use std::path::PathBuf;

use crate::installer::InstallerOverrides;

/// Parsed top-level command for the `vless-tray` binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    /// Default macOS menu-bar agent mode.
    Tray { config_dir: Option<PathBuf> },
    /// Short-lived Settings window (`vless-tray --settings`).
    Settings { config_dir: Option<PathBuf> },
    /// Privileged root LaunchDaemon installer (`vless-tray install-helper`).
    InstallHelper {
        overrides: InstallerOverrides,
        dry_run: bool,
    },
    /// Print CLI help and exit `0`.
    Help,
    /// Print package version and exit `0`.
    Version,
}

/// Returns human-readable usage instructions for `vless-tray`.
pub fn usage_text() -> &'static str {
    concat!(
        "vless-tray ",
        env!("CARGO_PKG_VERSION"),
        " — macOS menu-bar VLESS (REALITY + kTLS) client\n\n",
        "USAGE:\n",
        "  vless-tray [--config-dir <dir>]                 Run menu-bar agent (macOS)\n",
        "  vless-tray --settings [--config-dir <dir>]      Open short-lived Settings window\n",
        "  vless-tray install-helper [OPTIONS]             Install privileged LaunchDaemon helper\n\n",
        "INSTALL-HELPER OPTIONS:\n",
        "  --uid <uid>        Authorized console owner UID (defaults to current user UID)\n",
        "  --helper <path>    Explicit path to compiled vless-tray-helper binary\n",
        "  --plist <path>     Explicit path to io.vless-tray.helper.plist manifest\n",
        "  --script <path>    Explicit path to install-helper.sh script\n",
        "  --dry-run          Print resolved osascript invocation without executing\n\n",
        "GLOBAL OPTIONS:\n",
        "  --config-dir <dir> Override user config directory\n",
        "  -h, --help         Print help information\n",
        "  -V, --version      Print version information\n"
    )
}

/// Parses an iterator of raw OS arguments (excluding `argv[0]`) into a [`CliCommand`].
pub fn parse_args<I>(args: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = OsString>,
{
    let raw: Vec<String> = args
        .into_iter()
        // Ignore macOS LaunchServices `-psn_0_...` ProcessSerialNumber arguments when launched via Finder.
        .filter(|os| !os.to_string_lossy().starts_with("-psn_"))
        .map(|os| {
            os.into_string()
                .map_err(|_| "CLI argument is not valid UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    if raw.is_empty() {
        return Ok(CliCommand::Tray { config_dir: None });
    }

    if raw[0] == "install-helper" {
        return parse_install_helper_args(&raw[1..]);
    }

    let mut is_settings = false;
    let mut config_dir: Option<PathBuf> = None;
    let mut idx = 0usize;

    while idx < raw.len() {
        match raw[idx].as_str() {
            "-h" | "--help" | "help" => return Ok(CliCommand::Help),
            "-V" | "--version" | "version" => return Ok(CliCommand::Version),
            "--settings" | "settings" => {
                is_settings = true;
                idx += 1;
            }
            // Ignore macOS LaunchServices / Xcode document-revisions debug argument pair.
            "-NSDocumentRevisionsDebugMode" => {
                idx = (idx + 2).min(raw.len());
            }
            "--config-dir" => {
                let val = raw
                    .get(idx + 1)
                    .ok_or_else(|| "--config-dir requires a directory path".to_string())?;
                if val.is_empty() {
                    return Err("--config-dir must not be empty".to_string());
                }
                config_dir = Some(PathBuf::from(val));
                idx += 2;
            }
            arg if arg.starts_with("--config-dir=") => {
                let val = &arg["--config-dir=".len()..];
                if val.is_empty() {
                    return Err("--config-dir must not be empty".to_string());
                }
                config_dir = Some(PathBuf::from(val));
                idx += 1;
            }
            other => {
                return Err(format!(
                    "unknown argument {other:?} (pass --help for usage)"
                ));
            }
        }
    }

    if is_settings {
        Ok(CliCommand::Settings { config_dir })
    } else {
        Ok(CliCommand::Tray { config_dir })
    }
}

fn parse_install_helper_args(args: &[String]) -> Result<CliCommand, String> {
    let mut overrides = InstallerOverrides::default();
    let mut dry_run = false;
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => return Ok(CliCommand::Help),
            "--dry-run" => {
                dry_run = true;
                idx += 1;
            }
            "--uid" => {
                let val = args
                    .get(idx + 1)
                    .ok_or_else(|| "--uid requires a numeric UID argument".to_string())?;
                let parsed = val
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --uid {val:?}: expected base-10 u32"))?;
                overrides.owner_uid = Some(parsed);
                idx += 2;
            }
            arg if arg.starts_with("--uid=") => {
                let val = &arg["--uid=".len()..];
                let parsed = val
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --uid {val:?}: expected base-10 u32"))?;
                overrides.owner_uid = Some(parsed);
                idx += 1;
            }
            "--helper" => {
                let val = args
                    .get(idx + 1)
                    .ok_or_else(|| "--helper requires a path argument".to_string())?;
                overrides.helper_path = Some(PathBuf::from(val));
                idx += 2;
            }
            arg if arg.starts_with("--helper=") => {
                overrides.helper_path = Some(PathBuf::from(&arg["--helper=".len()..]));
                idx += 1;
            }
            "--plist" => {
                let val = args
                    .get(idx + 1)
                    .ok_or_else(|| "--plist requires a path argument".to_string())?;
                overrides.plist_path = Some(PathBuf::from(val));
                idx += 2;
            }
            arg if arg.starts_with("--plist=") => {
                overrides.plist_path = Some(PathBuf::from(&arg["--plist=".len()..]));
                idx += 1;
            }
            "--script" => {
                let val = args
                    .get(idx + 1)
                    .ok_or_else(|| "--script requires a path argument".to_string())?;
                overrides.script_path = Some(PathBuf::from(val));
                idx += 2;
            }
            arg if arg.starts_with("--script=") => {
                overrides.script_path = Some(PathBuf::from(&arg["--script=".len()..]));
                idx += 1;
            }
            other => {
                return Err(format!(
                    "unknown install-helper option {other:?} (pass --help for usage)"
                ));
            }
        }
    }

    Ok(CliCommand::InstallHelper { overrides, dry_run })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(items: &[&str]) -> Result<CliCommand, String> {
        parse_args(items.iter().map(OsString::from))
    }

    #[test]
    fn parses_tray_settings_finder_psn_and_install_helper_invocations() {
        assert_eq!(
            parse_strs(&[]).unwrap(),
            CliCommand::Tray { config_dir: None }
        );
        assert_eq!(
            parse_strs(&["-psn_0_123456"]).unwrap(),
            CliCommand::Tray { config_dir: None }
        );
        assert_eq!(
            parse_strs(&["--settings", "--config-dir", "/tmp/cfg"]).unwrap(),
            CliCommand::Settings {
                config_dir: Some(PathBuf::from("/tmp/cfg"))
            }
        );
        assert_eq!(
            parse_strs(&["--config-dir=/tmp/cfg2", "--settings"]).unwrap(),
            CliCommand::Settings {
                config_dir: Some(PathBuf::from("/tmp/cfg2"))
            }
        );
        assert_eq!(
            parse_strs(&[
                "install-helper",
                "--uid",
                "501",
                "--helper=/tmp/h",
                "--plist",
                "/tmp/p.plist",
                "--dry-run"
            ])
            .unwrap(),
            CliCommand::InstallHelper {
                overrides: InstallerOverrides {
                    script_path: None,
                    helper_path: Some(PathBuf::from("/tmp/h")),
                    plist_path: Some(PathBuf::from("/tmp/p.plist")),
                    owner_uid: Some(501),
                },
                dry_run: true,
            }
        );
        assert_eq!(parse_strs(&["--help"]).unwrap(), CliCommand::Help);
        assert_eq!(parse_strs(&["--version"]).unwrap(), CliCommand::Version);
        assert!(parse_strs(&["--unknown-flag"]).is_err());
    }
}
