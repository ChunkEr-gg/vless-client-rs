use eframe::egui::{
    self, Button, Color32, CornerRadius, FontId, Painter, Pos2, Rect, Response, RichText, Stroke,
    StrokeKind, Ui, Vec2, pos2, vec2,
};

pub(super) const CANVAS: Color32 = Color32::from_gray(234);
pub(super) const PAPER: Color32 = Color32::WHITE;
pub(super) const INK: Color32 = Color32::from_gray(18);
pub(super) const MUTED: Color32 = Color32::from_gray(91);
pub(super) const LINE: Color32 = Color32::from_gray(208);
pub(super) const EMBER: Color32 = Color32::from_rgb(255, 54, 22);
pub(super) const DANGER: Color32 = Color32::from_rgb(155, 37, 20);
pub(super) const SELECTED: Color32 = Color32::from_gray(223);
pub(super) const NIGHT_LINE: Color32 = Color32::from_gray(64);
pub(super) const NIGHT_MUTED: Color32 = Color32::from_gray(187);
pub(super) const NIGHT_TEXT: Color32 = Color32::from_gray(248);

pub(super) fn text(value: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(value).size(size).color(color)
}

pub(super) fn semibold(value: impl Into<String>, size: f32, color: Color32) -> RichText {
    text(value, size, color).variation(b"wght", 600.0)
}

pub(super) fn configure(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".into(),
        egui::FontData::from_static(include_bytes!("fonts/Inter.ttf")).into(),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter".into());
    ctx.set_fonts(fonts);
    ctx.set_theme(egui::Theme::Light);
    let mut style = egui::Style {
        visuals: egui::Visuals::light(),
        ..Default::default()
    };
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, FontId::monospace(13.0));
    style.visuals.panel_fill = CANVAS;
    style.visuals.window_fill = PAPER;
    style.visuals.extreme_bg_color = CANVAS;
    style.visuals.text_edit_bg_color = Some(PAPER);
    style.visuals.widgets.noninteractive.fg_stroke.color = INK;
    style.visuals.widgets.noninteractive.bg_stroke.color = LINE;
    style.visuals.widgets.inactive.fg_stroke.color = INK;
    style.visuals.widgets.inactive.bg_fill = PAPER;
    style.visuals.widgets.inactive.weak_bg_fill = PAPER;
    style.visuals.widgets.inactive.bg_stroke.color = LINE;
    style.visuals.widgets.hovered.bg_fill = SELECTED;
    style.visuals.widgets.hovered.weak_bg_fill = SELECTED;
    style.visuals.widgets.hovered.bg_stroke.color = INK;
    style.visuals.widgets.active.bg_stroke.color = INK;
    style.visuals.selection.bg_fill = SELECTED;
    style.visuals.selection.stroke.color = INK;
    style.spacing.button_padding = vec2(12.0, 6.0);
    style.spacing.item_spacing = vec2(8.0, 8.0);
    ctx.set_global_style(style);
}

#[derive(Clone, Copy)]
pub(super) enum ButtonStyle {
    Primary,
    Secondary,
    Danger,
    Accent,
    OnDark,
}

pub(super) fn button(label: &str, appearance: ButtonStyle) -> Button<'_> {
    let (fill, foreground, border) = match appearance {
        ButtonStyle::Primary => (INK, PAPER, INK),
        ButtonStyle::Secondary => (PAPER, INK, LINE),
        ButtonStyle::Danger => (DANGER, PAPER, DANGER),
        ButtonStyle::Accent => (EMBER, INK, EMBER),
        ButtonStyle::OnDark => (Color32::from_gray(44), NIGHT_TEXT, NIGHT_LINE),
    };
    Button::new(semibold(label, 13.0, foreground))
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(8.0)
        .min_size(vec2(0.0, 35.0))
}

#[derive(Clone, Copy)]
pub(super) enum Icon {
    Reality,
    Search,
    Server,
    Settings,
    Activity,
    Copy,
    More,
    Check,
}

pub(super) fn icon_button(
    ui: &mut Ui,
    glyph: Icon,
    label: &str,
    enabled: bool,
    dark: bool,
) -> Response {
    let size = vec2(36.0, 36.0);
    let response = ui.add_enabled(enabled, Button::new("").frame(false).min_size(size));
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));
    let (color, hover) = if dark {
        (NIGHT_TEXT, NIGHT_LINE)
    } else {
        (INK, SELECTED)
    };
    if enabled && (response.hovered() || response.has_focus()) {
        ui.painter().rect_filled(response.rect, 8, hover);
    }
    icon(
        ui.painter(),
        glyph,
        Rect::from_center_size(response.rect.center(), vec2(18.0, 18.0)),
        if enabled {
            color
        } else {
            color.gamma_multiply(0.43)
        },
    );
    response.on_hover_text(label)
}

pub(super) fn icon(painter: &Painter, glyph: Icon, rect: Rect, color: Color32) {
    let point = |x: f32, y: f32| lerp_in_rect(rect, x, y);
    let stroke = Stroke::new(rect.width().max(16.0) * 0.087, color);
    let line = |a: (f32, f32), b: (f32, f32)| {
        painter.line_segment([point(a.0, a.1), point(b.0, b.1)], stroke);
    };
    let outline = |min: (f32, f32), max: (f32, f32), radius: u8| {
        painter.rect_stroke(
            Rect::from_min_max(point(min.0, min.1), point(max.0, max.1)),
            radius,
            stroke,
            StrokeKind::Inside,
        );
    };
    match glyph {
        Icon::Reality => {
            let weight = Stroke::new(rect.width() * 0.115, color);
            for offset in [0.0, 0.31] {
                painter.add(egui::Shape::line(
                    vec![
                        point(0.03 + offset, 0.77),
                        point(0.30 + offset, 0.22),
                        point(0.64 + offset, 0.22),
                    ],
                    weight,
                ));
            }
            painter.circle_filled(point(0.77, 0.77), rect.width() * 0.064, color);
        }
        Icon::Search => {
            painter.circle_stroke(point(0.41, 0.41), rect.width() * 0.30, stroke);
            line((0.64, 0.64), (0.91, 0.91));
        }
        Icon::Server => {
            outline((0.05, 0.10), (0.95, 0.46), 2);
            outline((0.05, 0.54), (0.95, 0.90), 2);
            for y in [0.28, 0.72] {
                painter.circle_filled(point(0.72, y), rect.width() * 0.06, color);
            }
        }
        Icon::Settings => {
            for (y, knob) in [(0.20, 0.38), (0.50, 0.68), (0.80, 0.44)] {
                line((0.08, y), (0.92, y));
                line((knob, y - 0.12), (knob, y + 0.12));
            }
        }
        Icon::Activity => {
            painter.add(egui::Shape::line(
                vec![
                    point(0.02, 0.53),
                    point(0.26, 0.53),
                    point(0.40, 0.22),
                    point(0.62, 0.80),
                    point(0.76, 0.53),
                    point(0.98, 0.53),
                ],
                stroke,
            ));
        }
        Icon::Copy => {
            outline((0.29, 0.27), (0.94, 0.95), 2);
            painter.add(egui::Shape::line(
                vec![point(0.09, 0.68), point(0.09, 0.08), point(0.69, 0.08)],
                stroke,
            ));
        }
        Icon::More => {
            for x in [0.18, 0.50, 0.82] {
                painter.circle_filled(point(x, 0.50), rect.width() * 0.075, color);
            }
        }
        Icon::Check => {
            painter.add(egui::Shape::line(
                vec![point(0.10, 0.53), point(0.37, 0.79), point(0.90, 0.22)],
                stroke,
            ));
        }
    }
}

fn lerp_in_rect(rect: Rect, x: f32, y: f32) -> Pos2 {
    pos2(
        rect.left() + rect.width() * x,
        rect.top() + rect.height() * y,
    )
}

pub(super) fn brand_tile(painter: &Painter, rect: Rect) {
    painter.rect_filled(rect, CornerRadius::same(12), CANVAS);
    icon(
        painter,
        Icon::Reality,
        Rect::from_center_size(rect.center(), Vec2::splat(22.0)),
        INK,
    );
}
