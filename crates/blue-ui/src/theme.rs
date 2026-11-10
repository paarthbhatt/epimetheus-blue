//! Blue's native operator palette, bundled typography, and vector navigation icons.
//!
//! Recessed work planes and raised controls leave sculptural depth to the armor.
//! Cobalt is a material/accent, not a body-text color; mint denotes
//! active controls, amber review or reduced coverage, and coral danger.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Pos2, Rect, Sense,
    Shape, Stroke, StrokeKind, TextStyle,
};

/// Ink canvas.
pub const BG: Color32 = Color32::from_rgb(16, 26, 53);
/// Midnight work planes.
pub const PANEL: Color32 = Color32::from_rgb(21, 32, 66);
pub const PANEL_HOVER: Color32 = Color32::from_rgb(32, 49, 90);
/// Functional control boundaries; at least 3:1 against the operator surfaces.
pub const BORDER: Color32 = Color32::from_rgb(113, 132, 176);
/// Pearl body copy.
pub const TEXT: Color32 = Color32::from_rgb(239, 243, 255);
/// Secondary copy, still at least 4.5:1 against every operator surface.
pub const MUTED: Color32 = Color32::from_rgb(173, 187, 221);
/// Active controls only, not an inspection or cleanliness certificate.
pub const GREEN: Color32 = Color32::from_rgb(102, 216, 176);
/// Review required or reduced coverage.
pub const AMBER: Color32 = Color32::from_rgb(255, 169, 107);
/// Danger and actionable errors.
pub const RED: Color32 = Color32::from_rgb(255, 107, 122);
/// Cast cobalt. Use white, not pearl, text on a custom solid `BLUE` button.
pub const BLUE: Color32 = Color32::from_rgb(65, 102, 255);

pub(super) const CHASSIS: Color32 = Color32::from_rgb(9, 16, 34);
pub(super) const RECESS: Color32 = Color32::from_rgb(11, 20, 42);
pub(super) const DECK: Color32 = Color32::from_rgb(26, 42, 75);
pub(super) const NAV_SELECTED: Color32 = Color32::from_rgb(25, 40, 73);
pub(super) const SEAM: Color32 = Color32::from_rgb(49, 65, 102);
pub(super) const EDGE: Color32 = Color32::from_rgb(87, 109, 151);
pub(super) const FOCUS: Color32 = Color32::from_rgb(201, 160, 255);
// Darker cobalt preserves AA contrast for pearl labels and selected text.
const PRESSED: Color32 = Color32::from_rgb(51, 80, 204);
const SELECTED: Color32 = Color32::from_rgb(37, 59, 136);
const BODY_FONT: &str = "IBM Plex Sans";
const DISPLAY_FONT: &str = "IBM Plex Sans Condensed SemiBold";
const MONO_FONT: &str = "IBM Plex Mono";

/// Apply at creation, and again when the reduced-motion preference changes.
///
/// Fonts are installed once per context from the repository's `assets/fonts/`.
/// `Proportional` is Plex Sans, `Monospace` is Plex Mono, and the named family
/// `Display` is Plex Sans Condensed SemiBold. Monospace is for technical values,
/// not navigation or body copy. The named `Display` text style is 34 points.
///
/// Keyboard focus uses egui's active widget state with a two-point orchid
/// boundary. Disabled controls retain readable text but lose interactive chrome.
/// Reduced motion disables transitions, scroll inertia, and cursor blinking;
/// it does not disable any control or change any protection state.
pub fn apply(ctx: &egui::Context, reduced_motion: bool) {
    install_fonts(ctx);
    ctx.set_theme(egui::Theme::Dark);
    ctx.all_styles_mut(|style| {
        style.override_font_id = None;
        style.override_text_style = None;
        style.text_styles.extend([
            (
                TextStyle::Name("Display".into()),
                FontId::new(34.0, FontFamily::Name("Display".into())),
            ),
            (
                TextStyle::Heading,
                FontId::new(28.0, FontFamily::Name("Display".into())),
            ),
            (TextStyle::Body, FontId::proportional(15.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Small, FontId::proportional(13.0)),
            (TextStyle::Monospace, FontId::monospace(14.0)),
        ]);
        style.drag_value_text_style = TextStyle::Body;
        style.wrap_mode = Some(egui::TextWrapMode::Wrap);
        style.animation_time = if reduced_motion { 0.0 } else { 0.15 };
        style.scroll_animation = if reduced_motion {
            egui::style::ScrollAnimation::none()
        } else {
            egui::style::ScrollAnimation::duration(0.16)
        };

        let spacing = &mut style.spacing;
        spacing.item_spacing = egui::vec2(10.0, 8.0);
        spacing.window_margin = egui::Margin::same(18);
        spacing.menu_margin = egui::Margin::same(10);
        spacing.button_padding = egui::vec2(12.0, 7.0);
        spacing.interact_size = egui::vec2(34.0, 34.0);
        spacing.indent = 18.0;
        spacing.icon_width = 20.0;
        spacing.icon_width_inner = 12.0;
        spacing.icon_spacing = 8.0;
        spacing.extra_text_line_spacing = 1.0;
        spacing.text_edit_width = 320.0;
        spacing.combo_width = 220.0;
        spacing.slider_width = 240.0;
        spacing.tooltip_width = 360.0;
        spacing.menu_width = 300.0;
        // Allocated, always-visible scrollbars never cover safety controls.
        spacing.scroll = egui::style::ScrollStyle::solid();
        spacing.scroll.bar_width = 9.0;
        spacing.scroll.handle_min_length = 36.0;
        spacing.scroll.bar_inner_margin = 6.0;
        spacing.scroll.foreground_color = true;
        spacing.scroll.kinetic.decay_time = if reduced_motion { 0.0 } else { 0.18 };
        spacing.scroll.kinetic.rubber_band = false;

        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(TEXT);
        visuals.weak_text_color = Some(MUTED);
        visuals.panel_fill = BG;
        visuals.window_fill = PANEL;
        visuals.faint_bg_color = PANEL;
        visuals.extreme_bg_color = RECESS;
        visuals.text_edit_bg_color = Some(RECESS);
        visuals.code_bg_color = RECESS;
        visuals.hyperlink_color = FOCUS;
        visuals.warn_fg_color = AMBER;
        visuals.error_fg_color = RED;
        visuals.selection.bg_fill = SELECTED;
        visuals.selection.stroke = Stroke::new(1.0, TEXT);
        visuals.ime_composition.active_underline_stroke = Stroke::new(2.0, FOCUS);
        visuals.ime_composition.inactive_underline_stroke = Stroke::new(1.0, MUTED);
        visuals.window_corner_radius = CornerRadius::same(12);
        visuals.menu_corner_radius = CornerRadius::same(6);
        visuals.window_stroke = Stroke::new(1.0, SEAM);
        visuals.window_shadow = egui::epaint::Shadow {
            offset: [0, 6],
            blur: 14,
            spread: 0,
            color: Color32::from_black_alpha(88),
        };
        visuals.popup_shadow = visuals.window_shadow;
        visuals.window_highlight_topmost = false;
        visuals.button_frame = true;
        visuals.collapsing_header_frame = false;
        visuals.indent_has_left_vline = true;
        visuals.striped = false;
        visuals.disabled_alpha = 0.80;
        visuals.text_cursor.stroke = Stroke::new(2.0, FOCUS);
        visuals.text_cursor.blink = !reduced_motion;
        visuals.text_cursor.preview = false;
        visuals.image_loading_spinners = !reduced_motion;
        visuals.widgets.noninteractive = widget(PANEL, Stroke::new(1.0, SEAM), 0);
        visuals.widgets.inactive = widget(DECK, Stroke::new(1.0, BORDER), 5);
        visuals.widgets.hovered = widget(PANEL_HOVER, Stroke::new(1.0, MUTED), 5);
        // egui uses this state for keyboard focus as well as presses/drags.
        visuals.widgets.active = widget(PRESSED, Stroke::new(2.0, FOCUS), 5);
        visuals.widgets.open = widget(SELECTED, Stroke::new(1.5, FOCUS), 5);
        style.visuals = visuals;
    });
}

fn widget(fill: Color32, outline: Stroke, radius: u8) -> egui::style::WidgetVisuals {
    egui::style::WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: fill,
        bg_stroke: outline,
        corner_radius: CornerRadius::same(radius),
        fg_stroke: Stroke::new(1.5, TEXT),
        expansion: 0.0,
    }
}

pub(super) fn inset_plane(ui: &egui::Ui, rect: Rect, top: Color32, bottom: Color32) {
    if !rect.is_finite() || rect.width() <= 2.0 || rect.height() <= 2.0 {
        return;
    }
    let painter = ui
        .painter()
        .with_clip_rect(rect.expand(3.0).intersect(ui.clip_rect()));
    let radius = 10.0_f32.min(rect.width() * 0.5).min(rect.height() * 0.5);
    painter.rect_filled(rect.translate(egui::vec2(0.0, 2.0)), radius, CHASSIS);
    painter.rect_filled(rect, radius, RECESS);
    painter.add(material_mesh(rect.shrink(1.0), radius - 1.0, top, bottom));
    painter.rect_stroke(
        rect.shrink(1.0),
        radius - 1.0,
        Stroke::new(1.0, SEAM),
        StrokeKind::Inside,
    );
    painter.line_segment(
        [
            egui::pos2(rect.left() + radius + 1.0, rect.top() + 1.5),
            egui::pos2(rect.right() - radius - 1.0, rect.top() + 1.5),
        ],
        Stroke::new(1.0, EDGE),
    );
}

fn material_mesh(rect: Rect, radius: f32, top: Color32, bottom: Color32) -> egui::epaint::Mesh {
    use std::f32::consts::FRAC_PI_2;

    const STEPS: u32 = 6;
    let mut mesh = egui::epaint::Mesh::default();
    mesh.vertices.reserve_exact(29);
    mesh.indices.reserve_exact(84);
    mesh.colored_vertex(rect.center(), material_color(top, bottom, 0.5));
    for (corner, center) in [
        egui::pos2(rect.right() - radius, rect.top() + radius),
        egui::pos2(rect.right() - radius, rect.bottom() - radius),
        egui::pos2(rect.left() + radius, rect.bottom() - radius),
        egui::pos2(rect.left() + radius, rect.top() + radius),
    ]
    .into_iter()
    .enumerate()
    {
        for step in 0..=STEPS {
            let angle = (corner as f32 - 1.0 + step as f32 / STEPS as f32) * FRAC_PI_2;
            let point = center + egui::vec2(angle.cos(), angle.sin()) * radius;
            let amount = ((point.y - rect.top()) / rect.height()).clamp(0.0, 1.0);
            mesh.colored_vertex(point, material_color(top, bottom, amount));
        }
    }
    let last = mesh.vertices.len() as u32 - 1;
    for index in 1..=last {
        mesh.add_triangle(0, index, if index == last { 1 } else { index + 1 });
    }
    mesh
}

fn material_color(top: Color32, bottom: Color32, amount: f32) -> Color32 {
    let channel = |a: u8, b: u8| egui::lerp(f32::from(a)..=f32::from(b), amount).round() as u8;
    Color32::from_rgb(
        channel(top.r(), bottom.r()),
        channel(top.g(), bottom.g()),
        channel(top.b(), bottom.b()),
    )
}

fn install_fonts(ctx: &egui::Context) {
    let id = egui::Id::unique("epimetheus-blue.theme.ibm-plex.v1");
    if ctx.data_mut(|data| data.get_temp::<bool>(id).unwrap_or(false)) {
        return;
    }
    ctx.set_fonts(font_definitions());
    ctx.data_mut(|data| data.insert_temp(id, true));
}

fn font_definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    for (name, bytes) in [
        (
            BODY_FONT,
            include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf").as_slice(),
        ),
        (
            DISPLAY_FONT,
            include_bytes!("../assets/fonts/IBMPlexSansCondensed-SemiBold.ttf").as_slice(),
        ),
        (
            MONO_FONT,
            include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf").as_slice(),
        ),
    ] {
        fonts
            .font_data
            .insert(name.to_owned(), FontData::from_static(bytes).into());
    }
    // Keep egui's fallback coverage behind our bundled primary faces.
    let body = fonts.families.entry(FontFamily::Proportional).or_default();
    body.insert(0, BODY_FONT.to_owned());
    let mut display = vec![DISPLAY_FONT.to_owned()];
    display.extend(body.iter().cloned());
    fonts
        .families
        .insert(FontFamily::Name("Display".into()), display);
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, MONO_FONT.to_owned());
    fonts
}

/// Neutral workspace symbols, not claims about the current protection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Icon {
    Overview,
    Scanner,
    Integrity,
    Network,
    Firewall,
    Reputation,
    Cleanup,
    Quarantine,
    Feeds,
    Browser,
    Settings,
}

/// Allocate a square and paint a static icon on a shared 24-point construction
/// grid. Use an adjacent text label for the action's accessible name; icons are
/// decorative, never independent buttons. Parent clipping and disabled opacity
/// are preserved. Invalid or non-positive sizes draw and allocate nothing.
pub fn icon(ui: &mut egui::Ui, kind: Icon, size: f32, color: Color32) {
    if !size.is_finite() || size <= 0.0 {
        return;
    }
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
    let pen = IconPainter {
        painter: &painter,
        origin: rect.min,
        scale: size / 24.0,
        stroke: Stroke::new((size * 1.75 / 24.0).max(1.0), color),
    };

    match kind {
        Icon::Overview => {
            pen.path(
                &[
                    [12.0, 3.0],
                    [20.0, 6.5],
                    [19.0, 14.0],
                    [16.5, 18.5],
                    [12.0, 21.0],
                    [7.5, 18.5],
                    [5.0, 14.0],
                    [4.0, 6.5],
                ],
                true,
            );
            pen.path(&[[8.0, 8.0], [12.0, 6.3], [16.0, 8.0]], false);
            pen.line([12.0, 6.3], [12.0, 17.0]);
        }
        Icon::Scanner => {
            for corner in [
                [[4.0, 9.0], [4.0, 4.0], [9.0, 4.0]],
                [[15.0, 4.0], [20.0, 4.0], [20.0, 9.0]],
                [[20.0, 15.0], [20.0, 20.0], [15.0, 20.0]],
                [[9.0, 20.0], [4.0, 20.0], [4.0, 15.0]],
            ] {
                pen.path(&corner, false);
            }
            pen.line([3.5, 12.0], [20.5, 12.0]);
        }
        Icon::Integrity => {
            pen.path(
                &[
                    [5.5, 3.5],
                    [14.5, 3.5],
                    [19.0, 8.0],
                    [19.0, 20.5],
                    [5.5, 20.5],
                ],
                true,
            );
            pen.path(&[[14.5, 3.5], [14.5, 8.0], [19.0, 8.0]], false);
            pen.line([8.5, 12.0], [15.5, 12.0]);
            pen.line([8.5, 16.0], [11.5, 16.0]);
            pen.dot([15.0, 16.0], 0.9);
        }
        Icon::Network => {
            pen.rect([9.0, 3.0], [15.0, 8.0], 1.0);
            pen.rect([3.0, 16.0], [9.0, 21.0], 1.0);
            pen.rect([15.0, 16.0], [21.0, 21.0], 1.0);
            pen.line([12.0, 8.0], [12.0, 12.5]);
            pen.path(
                &[[6.0, 16.0], [6.0, 12.5], [18.0, 12.5], [18.0, 16.0]],
                false,
            );
        }
        Icon::Firewall => {
            pen.rect([4.0, 5.0], [20.0, 19.0], 1.0);
            pen.line([4.0, 9.5], [20.0, 9.5]);
            pen.line([4.0, 14.0], [20.0, 14.0]);
            pen.line([10.0, 5.0], [10.0, 9.5]);
            pen.line([14.0, 9.5], [14.0, 14.0]);
            pen.line([10.0, 14.0], [10.0, 19.0]);
        }
        Icon::Reputation => {
            pen.circle([10.5, 10.5], 6.5);
            pen.line([15.2, 15.2], [20.5, 20.5]);
            pen.line([7.5, 8.5], [13.5, 8.5]);
            pen.line([7.5, 12.0], [11.5, 12.0]);
        }
        Icon::Cleanup => {
            pen.line([14.0, 10.0], [20.0, 4.0]);
            pen.path(&[[12.0, 9.0], [15.0, 12.0], [9.0, 20.0], [4.0, 16.0]], true);
            pen.line([8.0, 14.0], [11.0, 17.3]);
            pen.line([10.5, 12.0], [13.0, 14.8]);
        }
        Icon::Quarantine => {
            pen.rect([4.0, 7.0], [20.0, 21.0], 1.5);
            pen.rect([3.0, 3.0], [21.0, 7.0], 1.0);
            pen.curve([[9.5, 12.5], [9.5, 8.5], [14.5, 8.5], [14.5, 12.5]]);
            pen.rect([8.5, 12.5], [15.5, 18.5], 1.0);
            pen.dot([12.0, 15.5], 0.8);
        }
        Icon::Feeds => {
            pen.dot([5.0, 19.0], 1.3);
            pen.curve([[5.0, 11.0], [9.42, 11.0], [13.0, 14.58], [13.0, 19.0]]);
            pen.curve([[5.0, 5.0], [12.73, 5.0], [19.0, 11.27], [19.0, 19.0]]);
        }
        Icon::Browser => {
            pen.rect([3.0, 4.5], [21.0, 20.0], 2.0);
            pen.line([3.0, 9.0], [21.0, 9.0]);
            pen.line([5.5, 6.8], [9.0, 6.8]);
            pen.circle([12.0, 14.5], 3.0);
            pen.line([12.0, 11.5], [12.0, 17.5]);
            pen.line([9.0, 14.5], [15.0, 14.5]);
        }
        Icon::Settings => {
            for (y, x) in [(6.0, 9.0), (12.0, 15.0), (18.0, 7.0)] {
                pen.line([4.0, y], [x - 2.0, y]);
                pen.line([x + 2.0, y], [20.0, y]);
                pen.circle([x, y], 2.0);
            }
        }
    }
}

struct IconPainter<'a> {
    painter: &'a egui::Painter,
    origin: Pos2,
    scale: f32,
    stroke: Stroke,
}

impl IconPainter<'_> {
    fn point(&self, [x, y]: [f32; 2]) -> Pos2 {
        self.origin + egui::vec2(x, y) * self.scale
    }

    fn line(&self, from: [f32; 2], to: [f32; 2]) {
        self.painter
            .line_segment([self.point(from), self.point(to)], self.stroke);
    }

    fn path(&self, points: &[[f32; 2]], closed: bool) {
        let points = points.iter().map(|&point| self.point(point)).collect();
        self.painter.add(if closed {
            Shape::closed_line(points, self.stroke)
        } else {
            Shape::line(points, self.stroke)
        });
    }

    fn rect(&self, min: [f32; 2], max: [f32; 2], radius: f32) {
        self.painter.rect_stroke(
            Rect::from_min_max(self.point(min), self.point(max)),
            CornerRadius::same((radius * self.scale).round().clamp(0.0, 255.0) as u8),
            self.stroke,
            StrokeKind::Middle,
        );
    }

    fn circle(&self, center: [f32; 2], radius: f32) {
        self.painter
            .circle_stroke(self.point(center), radius * self.scale, self.stroke);
    }

    fn dot(&self, center: [f32; 2], radius: f32) {
        self.painter
            .circle_filled(self.point(center), radius * self.scale, self.stroke.color);
    }

    fn curve(&self, points: [[f32; 2]; 4]) {
        self.painter
            .add(egui::epaint::CubicBezierShape::from_points_stroke(
                points.map(|point| self.point(point)),
                false,
                Color32::TRANSPARENT,
                self.stroke,
            ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(color: Color32) -> f64 {
        let linear = |channel: u8| {
            let channel = f64::from(channel) / 255.0;
            if channel <= 0.04045 {
                channel / 12.92
            } else {
                ((channel + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let a = luminance(a);
        let b = luminance(b);
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn body_and_semantic_copy_meet_aa() {
        for surface in [CHASSIS, RECESS, BG, PANEL, DECK, PANEL_HOVER, NAV_SELECTED] {
            for text in [TEXT, MUTED, GREEN, AMBER, RED, FOCUS] {
                assert!(contrast(text, surface) >= 4.5, "{text:?} on {surface:?}");
            }
        }
        for surface in [PRESSED, SELECTED] {
            assert!(contrast(TEXT, surface) >= 4.5);
        }
        assert!(contrast(Color32::WHITE, BLUE) >= 4.5);
    }

    #[test]
    fn boundaries_and_focus_meet_non_text_contrast() {
        for surface in [CHASSIS, RECESS, BG, PANEL, DECK, PANEL_HOVER, NAV_SELECTED] {
            assert!(contrast(BORDER, surface) >= 3.0);
        }
        for surface in [
            BG,
            RECESS,
            PANEL,
            DECK,
            PANEL_HOVER,
            NAV_SELECTED,
            PRESSED,
            SELECTED,
        ] {
            assert!(contrast(FOCUS, surface) >= 3.0);
        }
        assert!(contrast(BLUE, RECESS) >= 3.0);
    }

    #[test]
    fn inset_materials_retain_contrast_across_the_whole_plane() {
        assert!(luminance(CHASSIS) < luminance(RECESS));
        assert!(luminance(RECESS) < luminance(BG));
        assert!(luminance(BG) < luminance(PANEL));
        assert!(luminance(PANEL) < luminance(DECK));
        for (top, bottom) in [(DECK, BG), (PANEL, BG)] {
            for step in 0..=100 {
                let surface = material_color(top, bottom, step as f32 / 100.0);
                assert_eq!(surface.a(), 255);
                for text in [TEXT, MUTED, AMBER, RED, GREEN] {
                    assert!(contrast(text, surface) >= 4.5);
                }
                assert!(contrast(FOCUS, surface) >= 3.0);
            }
        }
    }

    #[test]
    fn material_mesh_is_bounded_and_uses_only_opaque_palette_colors() {
        let rect = Rect::from_min_size(egui::pos2(10.0, 15.0), egui::vec2(120.0, 72.0));
        let mesh = material_mesh(rect, 9.0, DECK, BG);
        assert_eq!(mesh.vertices.len(), 29);
        assert_eq!(mesh.indices.len(), 84);
        for vertex in &mesh.vertices {
            assert!(rect.expand(0.001).contains(vertex.pos));
            assert_eq!(vertex.color.a(), 255);
            for (channel, low, high) in [
                (vertex.color.r(), BG.r(), DECK.r()),
                (vertex.color.g(), BG.g(), DECK.g()),
                (vertex.color.b(), BG.b(), DECK.b()),
            ] {
                assert!((low..=high).contains(&channel));
            }
        }
        assert!(mesh
            .indices
            .iter()
            .all(|&index| index < mesh.vertices.len() as u32));
    }

    #[test]
    fn controls_have_distinct_recess_rest_hover_and_pressed_states() {
        let ctx = egui::Context::default();
        apply(&ctx, true);
        let style = ctx.global_style();
        let visuals = &style.visuals;
        assert_eq!(visuals.text_edit_bg_color, Some(RECESS));
        assert_eq!(visuals.widgets.inactive.bg_fill, DECK);
        assert_eq!(visuals.widgets.hovered.bg_fill, PANEL_HOVER);
        assert_eq!(visuals.widgets.active.bg_fill, PRESSED);
        assert_eq!(visuals.widgets.active.bg_stroke, Stroke::new(2.0, FOCUS));
        assert_eq!(
            visuals.widgets.inactive.corner_radius,
            CornerRadius::same(5)
        );
        for state in [
            visuals.widgets.inactive,
            visuals.widgets.hovered,
            visuals.widgets.active,
        ] {
            assert!(contrast(state.fg_stroke.color, state.bg_fill) >= 4.5);
            assert!(contrast(state.bg_stroke.color, state.bg_fill) >= 3.0);
        }
    }

    #[test]
    fn bundled_faces_lead_each_family() {
        let fonts = font_definitions();
        assert_eq!(fonts.families[&FontFamily::Proportional][0], BODY_FONT);
        assert_eq!(fonts.families[&FontFamily::Monospace][0], MONO_FONT);
        let display = &fonts.families[&FontFamily::Name("Display".into())];
        assert_eq!(display[0], DISPLAY_FONT);
        assert_eq!(display[1], BODY_FONT);
    }

    #[test]
    fn reduced_motion_is_reversible_without_changing_typography() {
        let ctx = egui::Context::default();
        apply(&ctx, true);
        let style = ctx.global_style();
        assert_eq!(style.animation_time, 0.0);
        assert_eq!(style.scroll_animation.duration.max, 0.0);
        assert_eq!(style.spacing.scroll.kinetic.decay_time, 0.0);
        assert!(!style.visuals.text_cursor.blink);
        assert_eq!(style.text_styles[&TextStyle::Body].size, 15.0);
        apply(&ctx, false);
        let style = ctx.global_style();
        assert!(style.animation_time > 0.0);
        assert!(style.visuals.text_cursor.blink);
        assert_eq!(style.text_styles[&TextStyle::Body].size, 15.0);
    }
}
