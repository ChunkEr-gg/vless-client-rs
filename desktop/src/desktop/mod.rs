//! Desktop front end for the same in-process SOCKS5 client as the CLI.

mod dialogs;
mod engine;
mod params;
mod settings;
mod store;
mod tests_panel;
mod theme;
mod worker;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, SystemTime};

use eframe::egui::{
    self, Align, Button, Color32, Frame, Label, Layout, Margin, Rect, ScrollArea, Stroke, TextEdit,
    Ui, Vec2, pos2, vec2,
};

use super::parse_listen;

use dialogs::{Action, Dialog, ProfileForm};
use engine::Event;
use store::{Book, SavedProfile, Store};
use theme::{
    ButtonStyle, CANVAS, DANGER, EMBER, INK, Icon, LINE, MUTED, NIGHT_LINE, NIGHT_MUTED,
    NIGHT_TEXT, PAPER, SELECTED, button, semibold, text,
};
use worker::Worker;

const FAILED_TEXT: Color32 = Color32::from_rgb(255, 174, 177);
const MAX_LOG: usize = 80;

pub fn run() -> Result<(), String> {
    let (store, book) = Store::open()?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 680.0])
            .with_min_inner_size([800.0, 540.0])
            .with_app_id("reality-ktls"),
        renderer: eframe::Renderer::Glow,
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Reality · VLESS",
        options,
        Box::new(move |cc| {
            theme::configure(&cc.egui_ctx);
            Ok(Box::new(Desktop::new(store, book)))
        }),
    )
    .map_err(|e| e.to_string())
}

struct Desktop {
    store: Store,
    book: Book,
    query: String,
    activity_open: bool,
    auto_start: bool,
    traffic: Traffic,
    tests: Option<tests_panel::Panel>,
    worker: Option<Worker>,
    listening: Option<SocketAddr>,
    start_failed: bool,
    copied: bool,
    logs: VecDeque<LogEntry>,
    dialog: Option<Dialog>,
}

struct LogEntry {
    time: String,
    message: String,
    error: bool,
}

impl Desktop {
    fn new(store: Store, book: Book) -> Self {
        Self {
            auto_start: book.settings.auto_start,
            traffic: Traffic::default(),
            store,
            book,
            query: String::new(),
            activity_open: false,
            tests: None,
            worker: None,
            listening: None,
            start_failed: false,
            copied: false,
            logs: VecDeque::new(),
            dialog: None,
        }
    }

    fn log(&mut self, message: impl Into<String>, error: bool) {
        let message = message.into();
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % 86400;
        let timestamp = format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60);
        if let Some(last) = self.logs.back_mut()
            && last.message == message
        {
            last.time = timestamp;
            return;
        }
        if self.logs.len() == MAX_LOG {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry {
            time: timestamp,
            message,
            error,
        });
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some(profile) = self.book.profiles.get(self.book.selected) else {
            return;
        };
        self.start_failed = false;
        self.traffic = Traffic::default();
        match Worker::start(
            profile,
            self.book.listen,
            self.book.settings.clone(),
            ctx.clone(),
        ) {
            Ok(worker) => {
                self.log(format!("Starting {}", profile.label), false);
                self.worker = Some(worker);
            }
            Err(e) => {
                self.start_failed = true;
                self.log(e, true);
            }
        }
    }

    fn stop(&mut self) {
        if let Some(worker) = &mut self.worker {
            worker.stop();
        }
    }

    fn save(&mut self, book: Book) -> Result<(), String> {
        self.store.save(&book)?;
        self.book = book;
        Ok(())
    }

    fn import(&mut self) {
        self.dialog = Some(Dialog::Profile(ProfileForm::default()));
    }

    fn rail(&mut self, ui: &mut Ui, rect: Rect) {
        ui.painter().rect_filled(rect, 0, INK);
        let brand =
            Rect::from_center_size(pos2(rect.center().x, rect.top() + 43.0), Vec2::splat(38.0));
        theme::brand_tile(ui.painter(), brand);
        let actions = Rect::from_min_size(
            pos2(rect.left() + 14.0, rect.bottom() - 106.0),
            vec2(36.0, 88.0),
        );
        let mut bar = region(ui, "rail-actions", actions);
        if theme::icon_button(&mut bar, Icon::Activity, "Activity", true, true).clicked() {
            self.activity_open = true;
        }
        if theme::icon_button(
            &mut bar,
            Icon::Settings,
            "Proxy settings",
            self.worker.is_none(),
            true,
        )
        .clicked()
        {
            self.dialog = Some(Dialog::Settings(settings::Form::new(&self.book)));
        }
    }

    fn profiles(&mut self, ui: &mut Ui) {
        let offline = self.worker.is_none();
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 40.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.label(semibold("Profiles", 31.0, INK));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add_enabled(offline, button("+  Import links", ButtonStyle::Primary))
                        .clicked()
                    {
                        self.import();
                    }
                });
            },
        );
        ui.add_space(14.0);

        if self.book.profiles.is_empty() {
            ui.add_space(38.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(50.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 14, SELECTED);
                theme::icon(ui.painter(), Icon::Server, rect.shrink(14.0), INK);
                ui.add_space(7.0);
                ui.label(semibold("No profiles yet", 17.0, INK));
                ui.label(text(
                    "Paste a VLESS share link to add a server.",
                    13.0,
                    MUTED,
                ));
            });
            return;
        }

        self.search_field(ui);
        ui.add_space(13.0);
        let query = self.query.trim().to_lowercase();
        let mut visible = false;
        let mut next = None;
        ScrollArea::vertical().id_salt("profiles").show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for (index, profile) in self.book.profiles.iter().enumerate() {
                if !query.is_empty()
                    && ![
                        &profile.label[..],
                        &profile.details.endpoint,
                        profile.details.security,
                    ]
                    .iter()
                    .any(|part| part.to_lowercase().contains(&query))
                {
                    continue;
                }
                visible = true;
                let selected = index == self.book.selected;
                if profile_row(ui, profile, selected, offline).clicked() {
                    next = Some(index);
                }
            }
        });
        if let Some(index) = next.filter(|&index| index != self.book.selected) {
            let mut book = self.book.clone();
            book.selected = index;
            match self.save(book) {
                Ok(()) => self.start_failed = false,
                Err(error) => self.log(error, true),
            }
        }
        if !visible {
            ui.add_space(20.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                ui.label(text("No matching profiles", 14.0, MUTED));
            });
        }
    }

    fn search_field(&mut self, ui: &mut Ui) {
        Frame::new()
            .fill(PAPER)
            .stroke(Stroke::new(1.0, LINE))
            .corner_radius(9)
            .inner_margin(Margin::symmetric(12, 2))
            .show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    vec2(ui.available_width(), 35.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        let (glyph, _) =
                            ui.allocate_exact_size(Vec2::splat(16.0), egui::Sense::hover());
                        theme::icon(ui.painter(), Icon::Search, glyph, MUTED);
                        let edit = TextEdit::singleline(&mut self.query)
                            .hint_text(text("Search profiles", 14.0, MUTED))
                            .margin(Margin::ZERO)
                            .frame(Frame::NONE)
                            .desired_width(f32::INFINITY);
                        ui.add(edit).widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::Role::TextInput,
                                true,
                                "Search profiles",
                            )
                        });
                    },
                );
            });
    }

    fn connection(&mut self, ui: &mut Ui, rect: Rect) {
        ui.painter().rect_filled(rect, 20, INK);
        let listening = self.listening.is_some();
        draw_dot_grid(ui.painter(), rect);
        let content = rect.shrink(26.0);
        let (state, state_color) = match &self.worker {
            Some(worker) if worker.stopping() => ("Stopping", NIGHT_MUTED),
            Some(_) if listening => ("Proxy listening", EMBER),
            Some(_) => ("Starting", EMBER),
            None if self.start_failed => ("Start failed", FAILED_TEXT),
            None => ("Proxy offline", NIGHT_MUTED),
        };
        let mut top = region(ui, "connection-details", content);
        top.set_width(content.width());
        top.allocate_ui_with_layout(
            vec2(content.width(), 36.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
                ui.painter().circle_filled(dot.center(), 4.0, state_color);
                ui.label(semibold(state, 13.0, state_color));
                if let Some(profile) = self.book.profiles.get(self.book.selected) {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let trigger = theme::icon_button(
                            ui,
                            Icon::More,
                            "Profile actions",
                            self.worker.is_none(),
                            true,
                        );
                        egui::Popup::menu(&trigger).show(|ui| {
                            ui.set_min_width(132.0);
                            if ui.button("Edit profile").clicked() {
                                self.dialog = Some(Dialog::Profile(ProfileForm {
                                    editing: Some(self.book.selected),
                                    params: Some(params::Params::from_profile(profile)),
                                    label: profile.label.clone(),
                                    links: profile.link.clone(),
                                    pin: profile.pin.clone().unwrap_or_default(),
                                    ..Default::default()
                                }));
                                ui.close();
                            }
                            if ui
                                .button(semibold("Remove profile", 13.0, DANGER))
                                .clicked()
                            {
                                self.dialog = Some(Dialog::Remove {
                                    index: self.book.selected,
                                    error: String::new(),
                                });
                                ui.close();
                            }
                        });
                    });
                }
            },
        );

        top.add_space(30.0);
        let Some(profile) = self.book.profiles.get(self.book.selected) else {
            top.label(semibold("No profile selected", 31.0, NIGHT_TEXT));
            let mut footer = region(
                ui,
                "connection-action",
                Rect::from_min_max(pos2(content.left(), content.bottom() - 46.0), content.max),
            );
            if footer
                .add_sized(
                    vec2(content.width(), 46.0),
                    button("Import links", ButtonStyle::Accent),
                )
                .clicked()
            {
                self.import();
            }
            return;
        };
        top.add(Label::new(semibold(&profile.label, 34.0, NIGHT_TEXT)).truncate())
            .on_hover_text(&profile.label);
        top.label(text(profile.details.security, 15.0, NIGHT_MUTED));
        top.add_space(22.0);
        // Detail rows stay above the actions when the window is shortened.
        detail(&mut top, "Server", &profile.details.endpoint);
        top.add_space(13.0);
        detail(&mut top, "Server name", &profile.details.sni);

        if top
            .add_enabled(listening, button("Connection tests", ButtonStyle::OnDark))
            .on_disabled_hover_text("Start this proxy to run tests through it.")
            .clicked()
        {
            self.tests = Some(tests_panel::Panel::default());
        }

        let footer =
            Rect::from_min_max(pos2(content.left(), content.bottom() - 129.0), content.max);
        let mut footer = region(ui, "connection-actions", footer);
        footer.set_width(content.width());
        footer.painter().hline(
            footer.max_rect().x_range(),
            footer.max_rect().top(),
            Stroke::new(1.0, NIGHT_LINE),
        );
        footer.add_space(14.0);
        let address = self.listening.unwrap_or(self.book.listen).to_string();
        footer.allocate_ui_with_layout(
            vec2(content.width(), 41.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.vertical(|ui| detail(ui, "SOCKS5 address", &address));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let label = if self.copied {
                        "Address copied"
                    } else {
                        "Copy SOCKS5 address"
                    };
                    let glyph = if self.copied { Icon::Check } else { Icon::Copy };
                    if theme::icon_button(ui, glyph, label, listening, true).clicked() {
                        ui.ctx().copy_text(address);
                        self.copied = true;
                    }
                });
            },
        );
        footer.add_space(11.0);
        if let Some(worker) = &self.worker {
            if footer
                .add_enabled_ui(!worker.stopping(), |ui| {
                    ui.add_sized(
                        vec2(content.width(), 46.0),
                        button("Stop proxy", ButtonStyle::OnDark),
                    )
                })
                .inner
                .clicked()
            {
                self.stop();
            }
        } else if footer
            .add_sized(
                vec2(content.width(), 46.0),
                button("Start proxy", ButtonStyle::Accent),
            )
            .clicked()
        {
            self.start(ui.ctx());
        }
    }

    fn show_activity(&mut self, ctx: &egui::Context) {
        let response = egui::Modal::new(egui::Id::unique("activity"))
            .backdrop_color(Color32::from_black_alpha(90))
            .frame(
                Frame::new()
                    .fill(PAPER)
                    .stroke(Stroke::new(1.0, LINE))
                    .corner_radius(16)
                    .inner_margin(Margin::same(24)),
            )
            .show(ctx, |ui| {
                ui.set_width(470.0);
                ui.horizontal(|ui| {
                    ui.label(semibold("Activity", 23.0, INK));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                !self.logs.is_empty(),
                                button("Clear", ButtonStyle::Secondary),
                            )
                            .clicked()
                        {
                            self.logs.clear();
                        }
                    });
                });
                self.traffic.draw(ui);
                ui.add_space(10.0);
                if self.logs.is_empty() {
                    ui.label(text("No proxy activity yet", 14.0, MUTED));
                }
                ScrollArea::vertical()
                    .id_salt("events")
                    .max_height(330.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for entry in &self.logs {
                            ui.horizontal_top(|ui| {
                                ui.label(text(&entry.time, 12.0, MUTED).monospace());
                                ui.add(
                                    Label::new(text(
                                        &entry.message,
                                        14.0,
                                        if entry.error { DANGER } else { INK },
                                    ))
                                    .wrap(),
                                );
                            });
                        }
                    });
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add(button("Done", ButtonStyle::Primary))
                })
                .inner
                .clicked()
            });
        if response.inner || response.should_close() {
            self.activity_open = false;
        }
    }

    fn show_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };
        let label = match &dialog {
            Dialog::Remove { index, .. } => self
                .book
                .profiles
                .get(*index)
                .map(|profile| profile.label.as_str()),
            _ => None,
        };
        let action = dialog.show(ctx, label);
        if action == Action::Cancel {
            return;
        }
        if action == Action::Apply {
            let result = match &mut dialog {
                Dialog::Profile(form) => self.apply_profiles(form),
                Dialog::Settings(form) => {
                    let mut book = self.book.clone();
                    form.apply(&mut book).and_then(|()| self.save(book))
                }
                Dialog::Remove { index, .. } => {
                    let mut book = self.book.clone();
                    book.profiles.remove(*index);
                    book.selected = (*index).min(book.profiles.len().saturating_sub(1));
                    self.save(book).map(|()| {
                        self.start_failed = false;
                    })
                }
            };
            match result {
                Ok(()) => return,
                Err(message) => match &mut dialog {
                    Dialog::Profile(form) => form.error = message,
                    Dialog::Settings(form) => form.error = message,
                    Dialog::Remove { error, .. } => *error = message,
                },
            }
        }
        self.dialog = Some(dialog);
    }

    fn apply_profiles(&mut self, form: &ProfileForm) -> Result<(), String> {
        if let (Some(index), Some(params)) = (form.editing, &form.params) {
            let link = params.link()?;
            let pin = if params.query.get("security").is_some_and(|v| v == "tls") {
                &params.pin
            } else {
                ""
            };
            let profile = SavedProfile::new(&form.label, &link, pin)?;
            let mut book = self.book.clone();
            book.insert(profile, Some(index))?;
            return self.save(book);
        }
        if form.links.len() > 1024 * 1024 {
            return Err("Import up to 1 MiB of links at a time.".into());
        }
        let decoded =
            vless_profile::decode_profile_list(&form.links).map_err(|err| err.to_string())?;
        let mut links = decoded
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .peekable();
        let first = links.next().ok_or("Paste a VLESS share link.")?;
        if links.peek().is_some()
            && (form.editing.is_some()
                || !form.pin.trim().is_empty()
                || !form.label.trim().is_empty())
        {
            return Err("Use a single link when setting a label or TLS pin.".into());
        }
        let next = form.editing.unwrap_or(self.book.profiles.len());
        let mut book = self.book.clone();
        for (i, link) in std::iter::once(first).chain(links).enumerate() {
            let profile = SavedProfile::new(&form.label, link, &form.pin)
                .map_err(|e| format!("Link {}: {e}", i + 1))?;
            book.insert(profile, form.editing)?;
        }
        book.selected = next;
        self.save(book)?;
        self.query.clear();
        self.start_failed = false;
        Ok(())
    }
}

impl eframe::App for Desktop {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if std::mem::take(&mut self.auto_start) {
            self.start(ctx);
        }
        let Some(worker) = &self.worker else {
            return;
        };
        let mut events = Vec::new();
        let mut disconnected = false;
        for _ in 0..64 {
            match worker.events.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        let finished = worker.finished();
        if worker.stopping() || self.listening.is_none() || disconnected {
            ctx.request_repaint_after(Duration::from_millis(80));
        }
        for event in events {
            match event {
                Event::Listening(address) => {
                    self.listening = Some(address);
                    self.log(format!("SOCKS5 listening on {address}"), false);
                }
                Event::Log(line, error) => self.log(line, error),
                Event::Bytes(up, down) => self.traffic.sample(up, down),
            }
        }
        if finished {
            let worker = self.worker.take().expect("worker checked above");
            let was_listening = self.listening.take().is_some();
            self.copied = false;
            match worker.finish() {
                Ok(()) => self.log("Proxy stopped", false),
                Err(e) => {
                    self.start_failed = !was_listening;
                    self.log(e, true);
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut Ui, _: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let rect = ui.available_rect_before_wrap();
        ui.painter().rect_filled(rect, 0, CANVAS);

        let rail = Rect::from_min_size(rect.min, vec2(64.0, rect.height()));
        self.rail(ui, rail);
        let width = (rect.width() * 0.394).clamp(335.0, 460.0);
        let panel = Rect::from_min_max(
            pos2(rect.right() - width - 14.0, rect.top() + 14.0),
            rect.right_bottom() - Vec2::splat(14.0),
        );
        let list = Rect::from_min_max(
            pos2(rail.right() + 29.0, rect.top() + 29.0),
            pos2(panel.left() - 29.0, rect.bottom() - 22.0),
        );
        self.profiles(&mut region(ui, "profile-list", list));
        self.connection(ui, panel);
        if self.activity_open {
            self.show_activity(&ctx);
        }
        self.show_dialog(&ctx);
        if let Some(panel) = &mut self.tests {
            let close = match (self.listening, self.book.profiles.get(self.book.selected)) {
                (Some(address), Some(profile)) => panel.show(&ctx, address, &profile.label),
                _ => true,
            };
            if let Some((test, result)) = panel.completed.take() {
                let mut book = self.book.clone();
                if let Some(profile) = book.profiles.get_mut(self.book.selected) {
                    profile.results[test] = result;
                    if let Err(e) = self.save(book) {
                        self.log(e, true);
                    }
                }
            }
            if close {
                self.tests = None;
            }
        }
    }

    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        if let Some(mut worker) = self.worker.take() {
            worker.stop();
            let _ = worker.finish();
        }
    }
}

fn region(ui: &mut Ui, id: &'static str, rect: Rect) -> Ui {
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .id_salt(id)
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
    );
    child.set_clip_rect(ui.clip_rect().intersect(rect));
    child
}

fn detail(ui: &mut Ui, label: &str, value: &str) {
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.label(text(label, 12.0, NIGHT_MUTED));
        ui.add(Label::new(text(value, 14.0, NIGHT_TEXT).monospace()).truncate())
            .on_hover_text(value);
    });
}

fn profile_row(
    ui: &mut Ui,
    profile: &SavedProfile,
    selected: bool,
    selectable: bool,
) -> egui::Response {
    let sense = if selectable {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let name = &profile.label;
    let mode = profile.details.security;
    let response = ui.add(
        Button::new("")
            .frame(false)
            .min_size(vec2(ui.available_width(), 62.0))
            .sense(sense),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::ListBoxOption, selectable, selected, name)
    });
    let rect = response.rect.shrink2(vec2(1.0, 1.0));
    let painter = ui.painter();
    if selected || response.hovered() {
        painter.rect_filled(rect, 10, if selected { SELECTED } else { PAPER });
    }
    if response.has_focus() {
        painter.rect_stroke(rect, 10, Stroke::new(1.0, INK), egui::StrokeKind::Inside);
    }
    let tile = Rect::from_center_size(pos2(rect.left() + 30.0, rect.center().y), Vec2::splat(36.0));
    painter.rect_filled(tile, 9, if selected { PAPER } else { CANVAS });
    theme::icon(
        painter,
        Icon::Server,
        tile.shrink(9.0),
        if selected { INK } else { MUTED },
    );

    let row_mode = if mode == "REALITY + Vision" {
        "Vision"
    } else {
        mode
    };
    let values: Vec<_> = profile
        .results
        .iter()
        .filter(|value| !value.is_empty())
        .collect();
    let right = rect.right() - 13.0;
    let mut available_right = right;
    if values.is_empty() {
        let bounds = painter.text(
            pos2(right, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            row_mode,
            egui::FontId::proportional(12.0),
            MUTED,
        );
        available_right = bounds.left();
    } else {
        for column in values.chunks(2).rev() {
            let mut left = available_right;
            for (row, value) in column.iter().enumerate() {
                let y = if column.len() == 1 {
                    rect.center().y
                } else {
                    rect.center().y - 10.0 + 20.0 * row as f32
                };
                let bounds = painter.text(
                    pos2(available_right, y),
                    egui::Align2::RIGHT_CENTER,
                    value,
                    egui::FontId::proportional(12.0),
                    if value.ends_with("failed") {
                        DANGER
                    } else {
                        INK
                    },
                );
                left = left.min(bounds.left());
            }
            available_right = left - 8.0;
        }
    }
    let origin = rect.left() + 61.0;
    let width = (available_right - origin - 10.0).max(0.0);
    for (label, delta) in [
        (semibold(name, 14.0, INK), -17.0),
        (text(&profile.details.endpoint, 12.0, MUTED), 3.0),
    ] {
        let galley = egui::WidgetText::from(label).into_galley(
            ui,
            Some(egui::TextWrapMode::Truncate),
            width,
            egui::FontSelection::Default,
        );
        painter.galley(pos2(origin, rect.center().y + delta), galley, INK);
    }
    if !selected && !response.hovered() {
        painter.hline(
            rect.left() + 61.0..=rect.right() - 12.0,
            rect.bottom(),
            Stroke::new(1.0, LINE),
        );
    }
    response.on_hover_text(format!("{} · {}", name, profile.details.security))
}

fn draw_dot_grid(painter: &egui::Painter, panel: Rect) {
    let spacing = 14.0;
    let bounds = panel.shrink(spacing * 0.5);
    let mut y = bounds.top();
    while y <= bounds.bottom() {
        let mut x = bounds.left();
        while x <= bounds.right() {
            painter.circle_filled(pos2(x, y), 0.85, Color32::from_gray(55));
            x += spacing;
        }
        y += spacing;
    }
}

#[derive(Default)]
struct Traffic {
    samples: VecDeque<(f32, f32)>,
    previous: Option<(std::time::Instant, u64, u64)>,
}
impl Traffic {
    fn sample(&mut self, up: u64, down: u64) {
        let now = std::time::Instant::now();
        let (elapsed, old_up, old_down) = self
            .previous
            .replace((now, up, down))
            .map_or((1.0, 0, 0), |(t, u, d)| {
                ((now - t).as_secs_f32().max(0.001), u, d)
            });
        if self.samples.len() == 60 {
            self.samples.pop_front();
        }
        self.samples.push_back((
            up.saturating_sub(old_up) as f32 / elapsed,
            down.saturating_sub(old_down) as f32 / elapsed,
        ));
    }
    fn draw(&self, ui: &mut Ui) {
        let (up, down) = self.samples.back().copied().unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label(semibold(
                &format!("Upload  {:.1} KB/s", up / 1000.0),
                13.0,
                INK,
            ));
            ui.label(semibold(
                &format!("Download  {:.1} KB/s", down / 1000.0),
                13.0,
                DANGER,
            ));
        });
        let (rect, _) =
            ui.allocate_exact_size(vec2(ui.available_width(), 72.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 6, CANVAS);
        let plot = rect.shrink(6.0);
        let peak = self
            .samples
            .iter()
            .fold(1.0f32, |m, (u, d)| m.max(*u).max(*d));
        for (download, color) in [(true, DANGER), (false, INK)] {
            let points: Vec<_> = self
                .samples
                .iter()
                .rev()
                .enumerate()
                .map(|(i, (u, d))| {
                    pos2(
                        plot.right() - i as f32 * plot.width() / 59.0,
                        plot.bottom() - (if download { *d } else { *u }) / peak * plot.height(),
                    )
                })
                .collect();
            if points.len() > 1 {
                painter.add(egui::Shape::line(points, Stroke::new(1.6, color)));
            }
        }
    }
}
