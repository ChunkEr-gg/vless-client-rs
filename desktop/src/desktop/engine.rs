//! Generate configuration for the pinned desktop build of sing-box.
use std::io::{Seek, Write};
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::oneshot;

use super::{params::Params, settings::Settings, store::SavedProfile};

pub(super) enum Event {
    Listening(SocketAddr),
    Log(String, bool),
    Bytes(u64, u64),
}

fn config(profile: &SavedProfile, host: &str, listen: SocketAddr, settings: &Settings) -> Value {
    let params = Params::from_profile(profile);
    let mut tls = json!({"enabled":true,"server_name":profile.details.sni,"min_version":"1.3"});
    let mut flow = "";
    if params.query["security"] == "reality" {
        tls["reality"] = json!({"enabled":true,"public_key":params.query["pbk"],"short_id":params.query.get("sid").map_or("",String::as_str)});
        tls["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
        if params.query.get("flow").is_some_and(|v| !v.is_empty()) {
            flow = "xtls-rprx-vision";
        }
    } else {
        if !params.pin.is_empty() {
            tls["certificate_leaf_sha256"] = json!(params.pin);
        }
        if let Some(alpn) = params.query.get("alpn").filter(|s| !s.is_empty()) {
            tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
    }
    let mut inbounds = vec![
        json!({"type":"socks","tag":"local","listen":listen.ip(),"listen_port":listen.port()}),
    ];
    let mut rules = Vec::new();
    if settings.tun {
        inbounds.push(json!({"type":"tun","tag":"system","interface_name":"rk-vless0","address":["172.29.255.1/30","fd73:726b::1/126"],"auto_route":true,"strict_route":true,"dns_mode":"hijack","stack":"system"}));
        rules.push(json!({"inbound":"system","port":53,"action":"hijack-dns"}));
        if !settings.direct_domains.trim().is_empty() {
            rules.push(json!({"inbound":"system","action":"sniff"}));
        }
    }
    let domains: Vec<_> = settings.direct_domains.split_whitespace().collect();
    if !domains.is_empty() {
        rules.push(json!({"domain_suffix":domains,"action":"route","outbound":"direct"}));
    }
    if settings.resolve_domains {
        rules.push(json!({"inbound":"local","action":"resolve","server":"tunnel-dns"}));
    }
    if settings.bypass_lan {
        rules.push(json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
    }
    json!({
        "log":{"level":if settings.log_connections {"info"} else {"warn"}},
        "dns":{"servers":[{"type":"tcp","tag":"tunnel-dns","server":settings.dns,"detour":"proxy"}],"final":"tunnel-dns","reverse_mapping":true},
        "inbounds":inbounds,
        "outbounds":[{"type":"vless","tag":"proxy","server":host,"server_port":params.port.parse::<u16>().expect("validated port"),"uuid":params.uuid,"flow":flow,"packet_encoding":"","connect_timeout":format!("{}s",settings.timeout),"tls":tls},{"type":"direct","tag":"direct","domain_resolver":"tunnel-dns"}],
        "route":{"auto_detect_interface":settings.tun,"rules":rules,"final":"proxy"}
    })
}

pub(super) async fn run(
    profile: SavedProfile,
    listen: SocketAddr,
    settings: Settings,
    mut cancel: oneshot::Receiver<()>,
    emit: impl Fn(Event),
) -> Result<(), String> {
    let params = Params::from_profile(&profile);
    let port = params.port.parse::<u16>().map_err(|_| "Invalid port")?;
    let host = tokio::select! {
        _ = &mut cancel => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(settings.timeout.into()),tokio::net::lookup_host((params.host.as_str(),port))) =>
            result.map_err(|_|"Server DNS lookup timed out")?.map_err(|e|format!("Server DNS lookup: {e}"))?.next().ok_or("Server DNS returned no addresses")?.ip(),
    };
    let mut file = tempfile::tempfile().map_err(|e| e.to_string())?;
    serde_json::to_writer(
        &mut file,
        &config(&profile, &host.to_string(), listen, &settings),
    )
    .map_err(|e| e.to_string())?;
    file.flush()
        .and_then(|_| file.rewind())
        .map_err(|e| e.to_string())?;
    let binary = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name(format!("reality-sing-box{}", std::env::consts::EXE_SUFFIX));
    let mut child = Command::new(binary)
        .args(["run", "--disable-color", "-c", "stdin"])
        .env("RK_DESKTOP_EVENTS", "1")
        .stdin(file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            format!("Starting reality-sing-box: {e}. Build the desktop core beside the client.")
        })?;
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut errors = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut reading_out = true;
    let mut reading_err = true;
    let mut ready = false;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    while reading_out || reading_err {
        tokio::select! {
            _ = &mut cancel => {
                #[cfg(unix)]
                if let Some(pid)=child.id() {
                    // SAFETY: this positive PID belongs to our unreaped child.
                    unsafe {libc::kill(pid as libc::pid_t,libc::SIGTERM);}
                }
                #[cfg(windows)]
                child.start_kill().map_err(|e|e.to_string())?;
                if tokio::time::timeout(Duration::from_secs(5),child.wait()).await.is_err() {let _=child.kill().await;}
                return Ok(());
            }
            _ = &mut deadline, if !ready => return Err("Desktop core did not report a listener within 20 seconds.".into()),
            line=output.next_line(), if reading_out => match line.map_err(|e|e.to_string())? {
                None=>reading_out=false,
                Some(line)=> {
                    if let Some(addr)=line.strip_prefix("READY ") {
                        let address:SocketAddr=addr.parse().map_err(|_|"Malformed core address")?;
                        if address.ip()!=listen.ip() || (listen.port()!=0 && address.port()!=listen.port()) {return Err("Unexpected core listener address".into());}
                        ready=true;emit(Event::Listening(address));
                    } else if let Some((up,down))=line.strip_prefix("BYTES ").and_then(|s|s.split_once(' ')) {
                        if let (Ok(up),Ok(down))=(up.parse(),down.parse()) {emit(Event::Bytes(up,down));}
                    } else {emit(log_line(line));}
                }
            },
            line=errors.next_line(), if reading_err => match line.map_err(|e|e.to_string())? {
                None=>reading_err=false, Some(line)=>emit(log_line(line))
            },
        }
    }
    let status = child.wait().await.map_err(|e| e.to_string())?;
    Err(format!(
        "Desktop core exited ({status}). See Activity for details."
    ))
}

fn log_line(line: String) -> Event {
    let error = line.contains("ERROR") || line.contains("FATAL");
    Event::Log(line, error)
}
