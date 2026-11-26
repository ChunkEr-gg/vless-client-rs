use std::process::ExitCode;

fn main() -> ExitCode {
    match vless_tray::run_from_env() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vless-tray: error: {err}");
            ExitCode::FAILURE
        }
    }
}
