//! Profile and listener settings dialogs.

use eframe::egui::{
    self, Align, CollapsingHeader, Color32, Frame, Id, Layout, Margin, RichText, ScrollArea,
    Shadow, Stroke, TextEdit, TextStyle, Ui,
};

use super::theme::{ButtonStyle, DANGER, INK, LINE, MUTED, PAPER, button, semibold};

const FIELD: Color32 = Color32::from_gray(246);

pub(super) enum Dialog {
    Profile(ProfileForm),
    Settings(super::settings::Form),
    Remove { index: usize, error: String },
}

#[derive(Default)]
pub(super) struct ProfileForm {
    pub(super) editing: Option<usize>,
    pub(super) params: Option<super::params::Params>,
    pub(super) label: String,
    pub(super) links: String,
    pub(super) pin: String,
    pub(super) error: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    KeepOpen,
    Apply,
    Cancel,
}

impl Dialog {
    pub(super) fn show(&mut self, ctx: &egui::Context, profile_label: Option<&str>) -> Action {
        let (id, width) = match self {
            Dialog::Profile(form) if form.editing.is_some() => ("edit-profile", 440.0_f32),
            Dialog::Profile(_) => ("import-profiles", 440.0_f32),
            Dialog::Settings(_) => ("proxy-settings", 420.0_f32),
            Dialog::Remove { .. } => ("remove-profile", 340.0_f32),
        };
        let response = egui::Modal::new(Id::unique(id))
            .backdrop_color(Color32::from_black_alpha(96))
            .frame(
                Frame::new()
                    .fill(PAPER)
                    .stroke(Stroke::new(1.0, LINE))
                    .corner_radius(16.0)
                    .inner_margin(Margin::same(26))
                    .shadow(Shadow {
                        offset: [0, 12],
                        blur: 36,
                        spread: 0,
                        color: Color32::from_black_alpha(38),
                    }),
            )
            .show(ctx, |ui| {
                ui.set_width(width.min((ctx.content_rect().width() - 80.0).max(120.0)));
                match self {
                    Dialog::Profile(form) => form.ui(ui),
                    Dialog::Settings(form) => {
                        ui.label(semibold("Settings", 23.0, INK));
                        form.ui(ui);
                        dialog_actions(ui, &form.error, "Save", ButtonStyle::Primary)
                    }
                    Dialog::Remove { error, .. } => {
                        ui.label(semibold("Remove profile?", 23.0, INK));
                        ui.add_space(5.0);
                        if let Some(label) = profile_label {
                            ui.label(
                                RichText::new(format!(
                                    "“{label}” will be removed from your saved profiles."
                                ))
                                .size(14.0)
                                .color(MUTED),
                            );
                        }
                        dialog_actions(ui, error, "Remove", ButtonStyle::Danger)
                    }
                }
            });
        if response.should_close() {
            Action::Cancel
        } else {
            response.inner
        }
    }
}

impl ProfileForm {
    fn ui(&mut self, ui: &mut Ui) -> Action {
        let editing = self.editing.is_some();
        let title = if editing {
            "Edit profile"
        } else {
            "Import profiles"
        };
        ui.label(semibold(title, 23.0, INK));
        ui.add_space(12.0);
        ScrollArea::vertical()
            .id_salt("profile-fields")
            .max_height((ui.ctx().content_rect().height() - 180.0).max(120.0))
            .show(ui, |ui| self.fields(ui, editing));
        dialog_actions(
            ui,
            &self.error,
            if editing { "Save" } else { "Import" },
            ButtonStyle::Primary,
        )
    }

    fn fields(&mut self, ui: &mut Ui, editing: bool) {
        if let Some(params) = &mut self.params {
            ui.label("Profile name");
            ui.text_edit_singleline(&mut self.label);
            params.ui(ui);
            return;
        }
        let label = field_label(
            ui,
            if editing {
                "VLESS share link"
            } else {
                "VLESS share links"
            },
        );
        let edit = ScrollArea::vertical()
            .id_salt("share-links")
            .max_height(132.0)
            .show(ui, |ui| {
                ui.add(input(
                    TextEdit::multiline(&mut self.links)
                        .hint_text("vless://…")
                        .font(TextStyle::Monospace)
                        .desired_rows(4),
                ))
            })
            .inner
            .labelled_by(label);
        if ui.memory(|memory| memory.focused().is_none()) {
            edit.request_focus();
        }
        if editing {
            self.options(ui);
        } else {
            ui.label(
                RichText::new("Paste one link per line or a base64 subscription.")
                    .size(13.0)
                    .color(MUTED),
            );
            ui.add_space(5.0);
            CollapsingHeader::new(semibold("Profile options", 13.0, INK))
                .default_open(false)
                .show_unindented(ui, |ui| {
                    ui.label(
                        RichText::new("These options apply when importing one link.")
                            .size(13.0)
                            .color(MUTED),
                    );
                    self.options(ui);
                });
        }
    }

    fn options(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        let name = field_label(ui, "Profile name");
        ui.add(input(
            TextEdit::singleline(&mut self.label).hint_text("Use the name from the share link"),
        ))
        .labelled_by(name);
        ui.add_space(3.0);
        let pin = field_label(ui, "TLS certificate pin");
        ui.add(input(
            TextEdit::singleline(&mut self.pin).hint_text("Optional · SHA-256 fingerprint"),
        ))
        .labelled_by(pin);
    }
}

fn field_label(ui: &mut Ui, label: &str) -> Id {
    ui.label(semibold(label, 13.0, INK)).id
}

fn input(edit: TextEdit<'_>) -> TextEdit<'_> {
    edit.background_color(FIELD)
        .text_color(INK)
        .margin(Margin::symmetric(11, 9))
        .desired_width(f32::INFINITY)
}

fn dialog_actions(ui: &mut Ui, error: &str, apply: &str, appearance: ButtonStyle) -> Action {
    if !error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(DANGER, error);
    }
    ui.add_space(10.0);
    ui.separator();
    ui.add_space(5.0);
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        let apply = ui.add(button(apply, appearance));
        let cancel = ui.add(button("Cancel", ButtonStyle::Secondary));
        if apply.clicked() {
            Action::Apply
        } else if cancel.clicked() {
            Action::Cancel
        } else {
            Action::KeepOpen
        }
    })
    .inner
}
