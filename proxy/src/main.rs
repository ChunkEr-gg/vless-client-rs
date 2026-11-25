use std::env;
use std::io::{self, Read, Write};
use std::process::{Command, ExitCode, Stdio};

use serde_json::{Value, json};
use vless_profile::{Profile, ProfileSecurity, format_sha256_pin_hex, parse_vless_link};

fn configuration(profile: &Profile, port: u16) -> Value {
    let stream = match &profile.security {
        ProfileSecurity::Ktls {
            sni,
            alpn,
            cert_sha256_pin,
            fingerprint,
        } => {
            let mut tls = json!({"serverName": sni, "alpn": alpn, "minVersion":"1.3"});
            if let Some(pin) = cert_sha256_pin {
                tls["pinnedPeerCertSha256"] = json!(format_sha256_pin_hex(pin));
            }
            if let Some(fp) = fingerprint {
                tls["fingerprint"] = json!(fp);
            }
            json!({"network":"tcp","security":"tls","tlsSettings":tls})
        }
        ProfileSecurity::Reality {
            sni,
            public_key_b64,
            short_id_hex,
            fingerprint,
            ..
        } => {
            json!({"network":"tcp","security":"reality","realitySettings":{
                "serverName":sni,"password":public_key_b64,"shortId":short_id_hex,
                "fingerprint":fingerprint.as_deref().unwrap_or("chrome")
            }})
        }
    };
    json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":true}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{
            "address":profile.server_host,"port":profile.server_port,
            "users":[{"id":profile.uuid,"encryption":"none","flow":profile.security.wire_flow()}]
        }]},"streamSettings":stream}]
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let usage = "Usage: vless-proxy <xray executable path> <local SOCKS port> (read one VLESS link from stdin)";
    let engine = args.next().ok_or(usage)?;
    let port: u16 = args
        .next()
        .and_then(|s| s.into_string().ok())
        .ok_or(usage)?
        .parse()?;
    if port == 0 || args.next().is_some() {
        return Err(usage.into());
    }
    let mut link = String::new();
    io::stdin().take(65537).read_to_string(&mut link)?;
    if link.len() > 65536 || link.trim().lines().count() != 1 {
        return Err("supply one VLESS link on stdin".into());
    }
    let imported = parse_vless_link(&link)?;
    for warning in imported.warnings {
        eprintln!("{warning}");
    }
    let config = serde_json::to_vec(&configuration(&imported.profile, port))?;
    let mut child = Command::new(engine)
        .args(["run", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .spawn()?;
    let write = child.stdin.take().expect("piped stdin").write_all(&config);
    if write.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    write?;
    if !status.success() {
        return Err(format!("Xray exited with {status}").into());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vless-proxy: {err}");
            ExitCode::FAILURE
        }
    }
}
