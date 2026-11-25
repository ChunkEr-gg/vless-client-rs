//! Command-line interface parser for `vless-engine` (`PLAN.md` §4, §6, §8).
//!
//! Supports both the newline-delimited JSON child-process IPC mode (`vless-engine` /
//! `vless-engine ipc`, spawned by `vless-tray`) and standalone CLI execution
//! (`vless-engine run --link 'vless://…' ...`).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnetwork::IpNetwork;
use vless_ipc::{
    BypassEntry, DEFAULT_DNS_RESOLVER, DEFAULT_SYSTEM_PROXY_PORT, Profile, parse_bypass_entry,
    parse_vless_link, validate_server_ip,
};

/// Default listen address for `vless-engine run` when neither `--listen` nor `--tun-fd` is passed.
pub const DEFAULT_CLI_LISTEN_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_SYSTEM_PROXY_PORT);

/// Top-level CLI dispatch action for `vless-engine`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliAction {
    /// Run the `stdin`/`stdout` JSON-lines IPC loop (`vless-engine`, `vless-engine ipc`, `--ipc`).
    Ipc,
    /// Run a standalone MixedProxy or raw-TUN-fd session until `SIGINT`/`SIGTERM`.
    Run(Box<RunArgs>),
    /// Print help text to `stdout` and exit `0`.
    Help(&'static str),
    /// Print version string to `stdout` and exit `0`.
    Version,
}

/// Validated arguments for `vless-engine run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunArgs {
    pub profile: Profile,
    pub warnings: Vec<String>,
    pub mode: RunInboundMode,
    pub outbound_if_index: Option<u32>,
    pub dns_resolver: IpAddr,
    pub bypass_cidrs: Vec<IpNetwork>,
    pub bypass_domains: Vec<String>,
}

/// Inbound mode selected via `vless-engine run` flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunInboundMode {
    /// Local HTTP/1.1 + SOCKS5 mixed proxy listener.
    MixedProxy { listen_addr: SocketAddr },
    /// Raw TUN file descriptor passed via `--tun-fd N`.
    TunFd { raw_fd: i32, af_header: bool },
}

/// Error returned when parsing `vless-engine` CLI arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

pub const MAIN_HELP: &str = "\
Usage:
  vless-engine [ipc | --ipc]
  vless-engine run --link 'vless://...' [OPTIONS]
  vless-engine --help | --version

Commands:
  ipc     Run newline-delimited JSON IPC loop over stdin/stdout (default when no args are given)
  run     Run standalone VLESS client in Mixed Proxy or raw TUN FD mode

Options:
  -h, --help       Show this help message
  -V, --version    Show version information
";

pub const RUN_HELP: &str = "\
Usage:
  vless-engine run --link 'vless://...' [OPTIONS]

Required:
  -l, --link <URI>                VLESS share URI, or - to read one from stdin

Options:
      --listen <IP:PORT>          Listen address for HTTP/1.1 + SOCKS5 mixed proxy
                                  (default: 127.0.0.1:2080 when --tun-fd is not set)
      --tun-fd <FD>               Open TUN file descriptor to attach smoltcp stack
      --tun-af-header             Expect 4-byte BSD/utun address-family packet header on --tun-fd
      --outbound-if-index <IDX>   Bind outbound sockets to physical interface index (IP_BOUND_IF)
      --dns-resolver <IP>         Upstream DNS resolver IP for TUN port-53 XUDP forwarding
                                  (default: 1.1.1.1)
      --bypass <CIDR|DOMAIN>      Bypass CIDR or domain pattern (repeatable or comma-separated)
  -h, --help                      Show help for `vless-engine run`
";

/// Parses CLI arguments (excluding `argv[0]`) into a [`CliAction`].
pub fn parse_cli_args<I, S>(args: I) -> Result<CliAction, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let raw: Vec<String> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();
    let Some(first) = raw.first().map(String::as_str) else {
        return Ok(CliAction::Ipc);
    };

    match first {
        "-h" | "--help" | "help" => Ok(CliAction::Help(MAIN_HELP)),
        "-V" | "--version" | "version" => Ok(CliAction::Version),
        "ipc" | "--ipc" => {
            if raw.len() == 1 {
                Ok(CliAction::Ipc)
            } else if raw.len() == 2 && matches!(raw[1].as_str(), "-h" | "--help") {
                Ok(CliAction::Help(MAIN_HELP))
            } else {
                Err(CliError::new(format!(
                    "unexpected argument {:?} after `{first}` (see `vless-engine --help`)",
                    raw[1]
                )))
            }
        }
        "run" => parse_run_args(&raw[1..]),
        other => Err(CliError::new(format!(
            "unknown subcommand or flag {other:?} (expected `ipc`, `run`, `--help`, or `--version`)"
        ))),
    }
}

fn parse_run_args(args: &[String]) -> Result<CliAction, CliError> {
    let mut link: Option<String> = None;
    let mut listen_addr: Option<SocketAddr> = None;
    let mut tun_fd: Option<i32> = None;
    let mut tun_af_header = false;
    let mut outbound_if_index: Option<u32> = None;
    let mut dns_resolver: IpAddr = DEFAULT_DNS_RESOLVER;
    let mut bypass_cidrs: Vec<IpNetwork> = Vec::new();
    let mut bypass_domains: Vec<String> = Vec::new();

    let mut idx = 0usize;
    while idx < args.len() {
        let token = args[idx].as_str();
        if matches!(token, "-h" | "--help") {
            return Ok(CliAction::Help(RUN_HELP));
        }

        let (flag, inline_val) = match token.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (token, None),
        };

        let mut next_value = |flag_name: &str| -> Result<String, CliError> {
            if let Some(v) = inline_val {
                return Ok(v.to_owned());
            }
            idx += 1;
            args.get(idx).cloned().ok_or_else(|| {
                CliError::new(format!(
                    "missing value for `{flag_name}` (see `vless-engine run --help`)"
                ))
            })
        };

        match flag {
            "-l" | "--link" => {
                if link.is_some() {
                    return Err(CliError::new("duplicate `--link` argument"));
                }
                link = Some(next_value("--link")?);
            }
            "--listen" => {
                if listen_addr.is_some() {
                    return Err(CliError::new("duplicate `--listen` argument"));
                }
                let raw_val = next_value("--listen")?;
                let parsed = raw_val.parse::<SocketAddr>().map_err(|e| {
                    CliError::new(format!(
                        "invalid `--listen` socket address {raw_val:?}: {e}"
                    ))
                })?;
                listen_addr = Some(parsed);
            }
            "--tun-fd" => {
                if tun_fd.is_some() {
                    return Err(CliError::new("duplicate `--tun-fd` argument"));
                }
                let raw_val = next_value("--tun-fd")?;
                let fd = raw_val.parse::<i32>().map_err(|e| {
                    CliError::new(format!("invalid `--tun-fd` descriptor {raw_val:?}: {e}"))
                })?;
                if fd < 0 {
                    return Err(CliError::new(format!(
                        "`--tun-fd` must be a non-negative file descriptor, got {fd}"
                    )));
                }
                tun_fd = Some(fd);
            }
            "--tun-af-header" => {
                if let Some(v) = inline_val {
                    return Err(CliError::new(format!(
                        "`--tun-af-header` does not take a value, got {v:?}"
                    )));
                }
                tun_af_header = true;
            }
            "--outbound-if-index" => {
                if outbound_if_index.is_some() {
                    return Err(CliError::new("duplicate `--outbound-if-index` argument"));
                }
                let raw_val = next_value("--outbound-if-index")?;
                let parsed = raw_val.parse::<u32>().map_err(|e| {
                    CliError::new(format!("invalid `--outbound-if-index` {raw_val:?}: {e}"))
                })?;
                if parsed == 0 {
                    return Err(CliError::new(
                        "`--outbound-if-index` must be greater than 0",
                    ));
                }
                outbound_if_index = Some(parsed);
            }
            "--dns-resolver" => {
                let raw_val = next_value("--dns-resolver")?;
                let ip = raw_val.parse::<IpAddr>().map_err(|e| {
                    CliError::new(format!("invalid `--dns-resolver` IP {raw_val:?}: {e}"))
                })?;
                validate_server_ip(&ip)
                    .map_err(|e| CliError::new(format!("invalid `--dns-resolver`: {e}")))?;
                dns_resolver = ip;
            }
            "--bypass" => {
                let raw_val = next_value("--bypass")?;
                for part in raw_val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    match parse_bypass_entry(part)
                        .map_err(|e| CliError::new(format!("invalid `--bypass` entry: {e}")))?
                    {
                        BypassEntry::Cidr(cidr) => {
                            if !bypass_cidrs.contains(&cidr) {
                                bypass_cidrs.push(cidr);
                            }
                        }
                        BypassEntry::Domain(dom) => {
                            if !bypass_domains.contains(&dom) {
                                bypass_domains.push(dom);
                            }
                        }
                    }
                }
            }
            unknown => {
                return Err(CliError::new(format!(
                    "unknown `vless-engine run` flag {unknown:?} (see `vless-engine run --help`)"
                )));
            }
        }
        idx += 1;
    }

    if listen_addr.is_some() && tun_fd.is_some() {
        return Err(CliError::new(
            "`--listen` and `--tun-fd` are mutually exclusive",
        ));
    }
    if tun_af_header && tun_fd.is_none() {
        return Err(CliError::new("`--tun-af-header` requires `--tun-fd <FD>`"));
    }

    let raw_link = link.ok_or_else(|| {
        CliError::new("missing required `--link 'vless://...'` (see `vless-engine run --help`)")
    })?;
    let raw_link = if raw_link == "-" {
        use std::io::Read;
        let mut text = String::new();
        std::io::stdin()
            .take(65537)
            .read_to_string(&mut text)
            .map_err(|e| CliError::new(format!("reading share link: {e}")))?;
        if text.len() > 65536 || text.trim().lines().count() != 1 {
            return Err(CliError::new("expected one share link on stdin"));
        }
        text
    } else {
        raw_link
    };
    let outcome =
        parse_vless_link(&raw_link).map_err(|e| CliError::new(format!("invalid `--link`: {e}")))?;

    let mode = match tun_fd {
        Some(raw_fd) => RunInboundMode::TunFd {
            raw_fd,
            af_header: tun_af_header || cfg!(target_os = "macos"),
        },
        None => RunInboundMode::MixedProxy {
            listen_addr: listen_addr.unwrap_or(DEFAULT_CLI_LISTEN_ADDR),
        },
    };

    Ok(CliAction::Run(Box::new(RunArgs {
        profile: outcome.profile,
        warnings: outcome.warnings,
        mode,
        outbound_if_index,
        dns_resolver,
        bypass_cidrs,
        bypass_domains,
    })))
}

#[cfg(test)]
mod tests {
    use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    fn sample_reality_link() -> String {
        let pbk = URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.10:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={pbk}&sid=0123456789abcdef#CLI"
        )
    }

    #[test]
    fn default_ipc_help_and_version_subcommands_parse() {
        assert_eq!(parse_cli_args(Vec::<&str>::new()).unwrap(), CliAction::Ipc);
        assert_eq!(parse_cli_args(["ipc"]).unwrap(), CliAction::Ipc);
        assert_eq!(parse_cli_args(["--ipc"]).unwrap(), CliAction::Ipc);
        assert_eq!(parse_cli_args(["--version"]).unwrap(), CliAction::Version);
        assert_eq!(parse_cli_args(["-V"]).unwrap(), CliAction::Version);
        assert!(matches!(
            parse_cli_args(["--help"]).unwrap(),
            CliAction::Help(_)
        ));
        assert!(matches!(
            parse_cli_args(["run", "--help"]).unwrap(),
            CliAction::Help(_)
        ));
    }

    #[test]
    fn run_subcommand_parses_mixed_proxy_and_tun_fd_modes() {
        let link = sample_reality_link();

        // Default MixedProxy listen address (`127.0.0.1:2080`)
        let CliAction::Run(args) = parse_cli_args(["run", "--link", &link]).unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            args.mode,
            RunInboundMode::MixedProxy {
                listen_addr: "127.0.0.1:2080".parse().unwrap(),
            }
        );
        assert_eq!(args.dns_resolver, DEFAULT_DNS_RESOLVER);

        // TUN FD mode with `--tun-af-header`, `--outbound-if-index`, `--dns-resolver`, and `--bypass`
        let CliAction::Run(tun_args) = parse_cli_args([
            "run",
            &format!("--link={link}"),
            "--tun-fd",
            "9",
            "--tun-af-header",
            "--outbound-if-index=5",
            "--dns-resolver",
            "9.9.9.9",
            "--bypass",
            "10.8.0.0/16,*.corp.local",
            "--bypass",
            "example.org",
        ])
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            tun_args.mode,
            RunInboundMode::TunFd {
                raw_fd: 9,
                af_header: true,
            }
        );
        assert_eq!(tun_args.outbound_if_index, Some(5));
        assert_eq!(tun_args.dns_resolver, "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(
            tun_args.bypass_cidrs,
            vec!["10.8.0.0/16".parse::<IpNetwork>().unwrap()]
        );
        assert_eq!(tun_args.bypass_domains, vec!["*.corp.local", "example.org"]);

        // Mutually exclusive flags & missing `--link` must fail cleanly
        assert!(
            parse_cli_args([
                "run",
                "--link",
                &link,
                "--listen",
                "127.0.0.1:2080",
                "--tun-fd",
                "5"
            ])
            .is_err()
        );
        assert!(parse_cli_args(["run"]).is_err());
    }
}
