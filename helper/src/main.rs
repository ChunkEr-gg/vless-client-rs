//! Binary entrypoint for `vless-tray-helper`.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use log::{LevelFilter, Metadata, Record};
use vless_tray_helper::{
    CLI_USAGE, CliAction, parse_cli_args, run_daemon_entrypoint, run_recover_only,
};

struct StderrLogger {
    max_level: LevelFilter,
}

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            let _ = writeln!(
                std::io::stderr(),
                "[vless-tray-helper {}] {}",
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

fn init_logger() {
    let max_level = match std::env::var("RUST_LOG")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" | "warning" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    };

    let logger = Box::leak(Box::new(StderrLogger { max_level }));
    if log::set_logger(logger).is_ok() {
        log::set_max_level(max_level);
    }
}

#[cfg(target_os = "macos")]
fn create_default_backend() -> Arc<vless_tray_helper::MacosSystemBackend> {
    Arc::new(vless_tray_helper::MacosSystemBackend::new())
}

#[cfg(not(target_os = "macos"))]
fn create_default_backend() -> Arc<vless_tray_helper::MockSystemBackend> {
    Arc::new(vless_tray_helper::MockSystemBackend::new_dual_stack_default())
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logger();

    let action = match parse_cli_args(std::env::args().skip(1)) {
        Ok(act) => act,
        Err(err) => {
            eprintln!("vless-tray-helper: error: {err}");
            return ExitCode::from(2);
        }
    };

    match action {
        CliAction::Help => {
            print!("{CLI_USAGE}");
            ExitCode::SUCCESS
        }
        CliAction::Version => {
            println!("vless-tray-helper {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        CliAction::RecoverOnly { state_path } => {
            let backend = create_default_backend();
            match run_recover_only(&*backend, &state_path) {
                Ok(_) => ExitCode::SUCCESS,
                Err(err) => {
                    log::error!(
                        "failed to recover state journal {}: {err}",
                        state_path.display()
                    );
                    ExitCode::FAILURE
                }
            }
        }
        CliAction::RunDaemon {
            socket_path,
            config,
        } => {
            let backend = create_default_backend();
            match run_daemon_entrypoint(backend, config, socket_path.as_deref()).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    log::error!("daemon exited with error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
