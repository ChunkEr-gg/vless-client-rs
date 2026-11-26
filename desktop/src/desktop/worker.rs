use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::{self, JoinHandle};

use eframe::egui;
use tokio::sync::oneshot;

use super::store::SavedProfile;
use super::{
    engine::{self, Event},
    settings::Settings,
};

pub struct Worker {
    stop: Option<oneshot::Sender<()>>,
    pub events: Receiver<Event>,
    handle: JoinHandle<Result<(), String>>,
}

impl Worker {
    pub fn start(
        profile: &SavedProfile,
        listen: SocketAddr,
        settings: Settings,
        ctx: egui::Context,
    ) -> Result<Self, String> {
        let profile = profile.clone();
        let (stop, cancel) = oneshot::channel();
        let (emit, events) = sync_channel(64);
        let handle = thread::Builder::new()
            .name("vless-client".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = rt.block_on(engine::run(profile, listen, settings, cancel, |event| {
                    if emit.try_send(event).is_ok() {
                        ctx.request_repaint();
                    }
                }));
                ctx.request_repaint();
                result
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            stop: Some(stop),
            events,
            handle,
        })
    }

    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    pub fn stopping(&self) -> bool {
        self.stop.is_none()
    }

    pub fn finished(&self) -> bool {
        self.handle.is_finished()
    }

    pub fn finish(self) -> Result<(), String> {
        self.handle
            .join()
            .map_err(|_| "Proxy worker exited unexpectedly.")?
    }
}
