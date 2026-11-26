use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

pub(super) const MAX_BYTES: u64 = 1_048_576;
const HTTP_STATUS_BYTES: usize = 3;

pub(super) struct Download {
    child: Child,
    response: Receiver<Result<String, String>>,
    body: Option<String>,
}

impl Download {
    pub(super) fn start(url: &str) -> Result<Self, String> {
        if url.len() as u64 > MAX_BYTES
            || url.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err("Enter a single HTTPS subscription URL.".into());
        }
        // Pass the provider URL through stdin so credentials stay out of process arguments.
        let quoted = url.replace('\\', "\\\\").replace('"', "\\\"");
        let config = format!("url = \"{quoted}\"\n");
        let child = Command::new("curl")
            .args([
                "--disable",
                "--silent",
                "--fail",
                "--globoff",
                "--location",
                "--max-redirs",
                "5",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "15",
                "--max-time",
                "30",
                "--write-out",
                "%{http_code}",
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Could not start curl to download the subscription.")?;
        let (send, response) = mpsc::channel();
        let mut download = Self {
            child,
            response,
            body: None,
        };
        let mut input = download.child.stdin.take().expect("piped curl stdin");
        let output = download.child.stdout.take().expect("piped curl stdout");
        thread::Builder::new()
            .name("subscription-download".into())
            .spawn(move || {
                let written = input.write_all(config.as_bytes());
                drop(input);
                let mut body = Vec::new();
                let result = written
                    .and_then(|_| {
                        output
                            .take(MAX_BYTES + HTTP_STATUS_BYTES as u64 + 1)
                            .read_to_end(&mut body)
                    })
                    .map_err(|_| "Could not download the subscription.".into())
                    .and_then(|_| {
                        if body.len() as u64 > MAX_BYTES + HTTP_STATUS_BYTES as u64 {
                            return Err("Import up to 1 MiB of VLESS links.".into());
                        }
                        let Some((payload, status)) = body.split_last_chunk::<HTTP_STATUS_BYTES>()
                        else {
                            return Err("Could not download the subscription.".into());
                        };
                        if status[0] != b'2' || !status[1..].iter().all(u8::is_ascii_digit) {
                            return Err("Could not download the subscription.".into());
                        }
                        body.truncate(payload.len());
                        String::from_utf8(body)
                            .map_err(|_| "The subscription must contain UTF-8 text.".into())
                    });
                let _ = send.send(result);
            })
            .map_err(|_| "Could not start the subscription download.")?;
        Ok(download)
    }

    pub(super) fn poll(&mut self) -> Option<Result<String, String>> {
        if self.body.is_none() {
            match self.response.try_recv() {
                Ok(Ok(body)) => self.body = Some(body),
                Ok(Err(error)) => return Some(Err(error)),
                Err(TryRecvError::Disconnected) => {
                    return Some(Err("Could not download the subscription.".into()));
                }
                Err(TryRecvError::Empty) => return None,
            }
        }
        match self.child.try_wait() {
            Ok(Some(status)) if status.success() => self.body.take().map(Ok),
            Ok(None) => None,
            _ => Some(Err("Could not download the subscription.".into())),
        }
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
