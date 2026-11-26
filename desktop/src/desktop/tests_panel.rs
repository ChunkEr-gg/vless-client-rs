//! On-demand diagnostics through the currently listening SOCKS5 proxy.
use std::fs::File;
use std::io::{Read, Seek};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eframe::egui::{self, Color32, Frame, Margin, Stroke, TextEdit};

use super::theme::{ButtonStyle, DANGER, INK, LINE, MUTED, PAPER, button, semibold, text};

const TRACE: &str = "https://www.cloudflare.com/cdn-cgi/trace";
const DOWNLOAD: &str = "https://speed.cloudflare.com/__down?bytes=5000000";

#[derive(Clone, Copy, PartialEq)]
enum Test {
    Ping,
    Speed,
    Url,
    Country,
}

impl Test {
    fn label(self) -> &'static str {
        match self {
            Self::Ping => "Ping",
            Self::Speed => "Speed",
            Self::Url => "URL",
            Self::Country => "Country",
        }
    }

    fn result(self, output: &str) -> Result<String, String> {
        match self {
            Self::Ping => {
                let seconds: f64 = output
                    .trim()
                    .parse()
                    .map_err(|_| "Missing response time.")?;
                Ok(format!("{:.0} ms to first byte", seconds * 1000.0))
            }
            Self::Speed => {
                let (bytes, rate) = output
                    .trim()
                    .split_once(' ')
                    .ok_or("Missing download measurement.")?;
                if bytes != "5000000" {
                    return Err("The server returned an incomplete speed sample.".into());
                }
                let rate: f64 = rate.parse().map_err(|_| "Missing transfer rate.")?;
                Ok(format!("{:.1} Mbps download", rate * 8.0 / 1e6))
            }
            Self::Url => Ok(format!("HTTP {}", output.trim())),
            Self::Country => output
                .lines()
                .find_map(|line| line.strip_prefix("loc="))
                .filter(|code| code.len() == 2 && code.bytes().all(|c| c.is_ascii_uppercase()))
                .map(|code| format!("Exit country · {code}"))
                .ok_or_else(|| "The service did not return a country code.".into()),
        }
    }
}

struct Run {
    child: Child,
    output: File,
    error: File,
}

impl Run {
    fn start(test: Test, proxy: SocketAddr, url: &str) -> Result<Self, String> {
        let output = tempfile::tempfile().map_err(|e| e.to_string())?;
        let error = tempfile::tempfile().map_err(|e| e.to_string())?;
        let mut cmd = Command::new("curl");
        cmd.args([
            "--disable",
            "--silent",
            "--show-error",
            "--globoff",
            "--noproxy",
            "",
            "--socks5-hostname",
        ])
        .arg(proxy.to_string())
        .args([
            "--proto",
            "=https,http",
            "--connect-timeout",
            "8",
            "--max-time",
            "25",
        ]);
        match test {
            Test::Ping => {
                cmd.args([
                    "--fail",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{time_starttransfer}",
                    "--url",
                    TRACE,
                ]);
            }
            Test::Speed => {
                cmd.args([
                    "--fail",
                    "--max-filesize",
                    "5000000",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{size_download} %{speed_download}",
                    "--url",
                    DOWNLOAD,
                ]);
            }
            Test::Url => {
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err("Enter a URL beginning with https:// or http://.".into());
                }
                cmd.args([
                    "--head",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{response_code}",
                    "--url",
                    url,
                ]);
            }
            Test::Country => {
                cmd.args(["--fail", "--max-filesize", "4096", "--url", TRACE]);
            }
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(output.try_clone().map_err(|e| e.to_string())?)
            .stderr(error.try_clone().map_err(|e| e.to_string())?)
            .spawn()
            .map_err(|e| format!("Could not start curl: {e}"))?;
        Ok(Self {
            child,
            output,
            error,
        })
    }

    fn poll(&mut self, test: Test) -> Option<Result<String, String>> {
        let status = match self.child.try_wait() {
            Ok(status) => status?,
            Err(e) => return Some(Err(e.to_string())),
        };
        let file = if status.success() {
            &mut self.output
        } else {
            &mut self.error
        };
        let mut message = String::new();
        if let Err(e) = file
            .rewind()
            .and_then(|_| file.take(4096).read_to_string(&mut message))
        {
            return Some(Err(e.to_string()));
        }
        Some(if status.success() {
            test.result(&message)
        } else {
            Err(if message.trim().is_empty() {
                format!("curl exited with {status}")
            } else {
                message.trim().into()
            })
        })
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(super) struct Panel {
    test: Test,
    url: String,
    run: Option<Run>,
    result: Option<Result<String, String>>,
    pub(super) completed: Option<(usize, String)>,
}

impl Default for Panel {
    fn default() -> Self {
        Self {
            test: Test::Ping,
            url: "https://example.com/".into(),
            run: None,
            result: None,
            completed: None,
        }
    }
}

impl Panel {
    fn record(&mut self, result: Result<String, String>) {
        let summary = match &result {
            Err(_) => format!("{} failed", self.test.label()),
            Ok(value) => value
                .trim_end_matches(" to first byte")
                .trim_end_matches(" download")
                .replace("Exit country · ", "Exit "),
        };
        self.completed = Some((self.test as usize, summary));
        self.result = Some(result);
    }

    pub(super) fn show(&mut self, ctx: &egui::Context, proxy: SocketAddr, profile: &str) -> bool {
        if let Some(run) = &mut self.run {
            if let Some(result) = run.poll(self.test) {
                self.record(result);
                self.run = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let modal = egui::Modal::new(egui::Id::unique("connection-tests"))
            .backdrop_color(Color32::from_black_alpha(90))
            .frame(
                Frame::new()
                    .fill(PAPER)
                    .stroke(Stroke::new(1.0, LINE))
                    .corner_radius(16)
                    .inner_margin(Margin::same(24)),
            )
            .show(ctx, |ui| {
                ui.set_width(360.0);
                ui.label(semibold("Connection tests", 23.0, INK));
                ui.add(egui::Label::new(text(profile, 14.0, MUTED)).truncate());
                ui.add_space(8.0);
                ui.add_enabled_ui(self.run.is_none(), |ui| {
                    ui.horizontal(|ui| {
                        for test in [Test::Ping, Test::Speed, Test::Url, Test::Country] {
                            if ui
                                .selectable_value(&mut self.test, test, test.label())
                                .changed()
                            {
                                self.result = None;
                            }
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(text(
                        match self.test {
                            Test::Ping => "Time to the first HTTPS response byte from Cloudflare.",
                            Test::Speed => "Download 5 MB from Cloudflare through this profile.",
                            Test::Url => "Check the HTTP status with a HEAD request.",
                            Test::Country => "Look up the proxy’s exit country with Cloudflare.",
                        },
                        14.0,
                        MUTED,
                    ));
                    if self.test == Test::Url
                        && ui
                            .add(TextEdit::singleline(&mut self.url).desired_width(f32::INFINITY))
                            .changed()
                    {
                        self.result = None;
                    }
                });
                if let Some(result) = &self.result {
                    let (message, color) = match result {
                        Ok(s) => (s, INK),
                        Err(s) => (s, DANGER),
                    };
                    ui.label(text(message, 15.0, color));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if self.run.is_some() {
                        ui.spinner();
                        if ui
                            .add(button("Cancel test", ButtonStyle::Secondary))
                            .clicked()
                        {
                            self.run = None;
                            self.result = Some(Ok("Cancelled".into()));
                        }
                    } else if ui.add(button("Run test", ButtonStyle::Primary)).clicked() {
                        self.result = None;
                        match Run::start(self.test, proxy, self.url.trim()) {
                            Ok(run) => {
                                self.run = Some(run);
                                ctx.request_repaint();
                            }
                            Err(e) => self.record(Err(e)),
                        }
                    }
                    if ui.add(button("Close", ButtonStyle::Secondary)).clicked() {
                        ui.close();
                    }
                });
            });
        modal.should_close()
    }
}
