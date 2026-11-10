//! Native workspace chrome. Navigation and inspection never enable protection.

use crate::{theme, BlueApp, Page};
use eframe::egui::{
    self, Align, Align2, Color32, FontFamily, FontId, Frame, Layout, Rect, Response, RichText,
    Sense, Stroke, StrokeKind, Ui, UiBuilder,
};
use theme::{
    Icon, AMBER, BG, BLUE, BORDER, CHASSIS, DECK, EDGE, FOCUS, MUTED, NAV_SELECTED, PANEL,
    PANEL_HOVER, RECESS, RED, SEAM, TEXT,
};

const SIDEBAR_WIDTH: f32 = 208.0;
const SIDEBAR_MARGIN: i8 = 12;
const BRAND_HEIGHT: f32 = 42.0;
const BRAND_GAP: f32 = 12.0;
const FOOTER_HEIGHT: f32 = 72.0;
const NAV_ROW_HEIGHT: f32 = 34.0;
const NAV_ROW_GAP: f32 = 2.0;
const NAV_GROUP_HEIGHT: f32 = 18.0;
const NAV_GROUP_GAP: f32 = 8.0;
const WORKSPACE_MARGIN: f32 = 18.0;
const DESTINATION_SHIFT: f32 = 6.0;
const DESTINATION_DURATION: f64 = 0.18;

const NAVIGATION_GROUPS: [(&str, usize, usize); 3] =
    [("Inspect", 0, 5), ("Respond", 5, 3), ("Configure", 8, 3)];

const NAVIGATION: [(Page, Icon, &str, &str); 11] = [
    (
        Page::Overview,
        Icon::Overview,
        "Overview",
        "Reported coverage and recorded evidence",
    ),
    (
        Page::Scanner,
        Icon::Scanner,
        "Scanner",
        "Inspect a file or folder",
    ),
    (
        Page::Integrity,
        Icon::Integrity,
        "Integrity",
        "Review recorded changes",
    ),
    (
        Page::Network,
        Icon::Network,
        "Network",
        "Observe an egress snapshot",
    ),
    (
        Page::Reputation,
        Icon::Reputation,
        "Reputation",
        "Check exact file hashes",
    ),
    (
        Page::Firewall,
        Icon::Firewall,
        "Firewall",
        "Review, stage, keep or undo an inbound policy",
    ),
    (
        Page::Quarantine,
        Icon::Quarantine,
        "Quarantine",
        "Review held files and restores",
    ),
    (
        Page::Cleanup,
        Icon::Cleanup,
        "Cleanup",
        "Analyze first; delete only with approval",
    ),
    (
        Page::Filters,
        Icon::Feeds,
        "Filter feeds",
        "Update sources and review retained versions",
    ),
    (
        Page::Browser,
        Icon::Browser,
        "Browser",
        "Browser-local tools and the read-only companion",
    ),
    (
        Page::Settings,
        Icon::Settings,
        "Settings",
        "Services, policy and explicit setup plans",
    ),
];

pub(super) fn display_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("Display".into()))
}

pub(super) fn sidebar(app: &mut BlueApp, root: &mut Ui) {
    egui::Panel::left("blue-navigation")
        .exact_size(SIDEBAR_WIDTH)
        .frame(
            Frame::new()
                .fill(CHASSIS)
                .inner_margin(egui::Margin::same(SIDEBAR_MARGIN)),
        )
        .show(root, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            theme::inset_plane(ui, ui.max_rect().expand(7.0), DECK, BG);
            seed_destination(ui.ctx(), app.page);
            brand(ui);
            ui.add_space(BRAND_GAP);

            // Only the destinations scroll. Motion and pause state remain
            // visible even when all eleven workspaces do not fit at 900x620.
            egui::ScrollArea::vertical()
                .id_salt("blue-navigation-scroll")
                .max_height((ui.available_height() - FOOTER_HEIGHT).max(1.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let selected_rect = navigation_rows(ui, &mut app.page);
                    let destination = destination_frame(
                        ui.ctx(),
                        app.page,
                        app.reduced_motion,
                        Some(selected_rect.center().y),
                    );
                    let marker = Rect::from_center_size(
                        egui::pos2(selected_rect.left() + 6.5, destination.indicator_y),
                        egui::vec2(3.0, 18.0),
                    );
                    let painter = ui.painter().with_clip_rect(ui.clip_rect());
                    painter.rect_filled(marker.expand(1.0), 2.0, RECESS);
                    painter.rect_filled(marker, 1.0, BLUE);
                });

            let paused = app.deps.db.kill_switch();
            sidebar_footer(ui, &mut app.reduced_motion, paused);
        });
}

fn sidebar_footer(ui: &mut Ui, reduced_motion: &mut bool, paused: bool) -> Rect {
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = 24.0;
        ui.spacing_mut().item_spacing.x = 8.0;
        let top = ui.cursor().top();
        ui.painter().line_segment(
            [
                egui::pos2(ui.max_rect().left(), top),
                egui::pos2(ui.max_rect().right(), top),
            ],
            Stroke::new(1.0, SEAM),
        );
        ui.add_space(12.0);
        let motion = ui
            .checkbox(reduced_motion, RichText::new("Reduced motion").size(13.0))
            .on_hover_text("Use static armor and immediate controls. Protection settings are unchanged.");
        focus_ring(ui, &motion);
        if motion.changed() {
            theme::apply(ui.ctx(), *reduced_motion);
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            status_dot(ui, 7.0, if paused { AMBER } else { MUTED });
            ui.label(
                RichText::new(if paused {
                    "File actions paused"
                } else {
                    "File actions not paused"
                })
                .size(12.5)
                .color(if paused { AMBER } else { MUTED }),
            )
            .on_hover_text("The automatic-quarantine pause gate only; not a scan or protection verdict. Firewall and system DNS are separate.");
        });
    })
    .response
    .rect
}

fn brand(ui: &mut Ui) {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), BRAND_HEIGHT),
        Sense::hover(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Label, ui.is_enabled(), "Epimetheus Blue")
    });
    let mut icon_ui = ui.new_child(
        UiBuilder::new()
            .id_salt("blue-brand-vector")
            .max_rect(Rect::from_min_size(
                rect.min + egui::vec2(5.0, 7.0),
                egui::vec2(30.0, 30.0),
            ))
            .layout(Layout::left_to_right(Align::Center)),
    );
    theme::icon(&mut icon_ui, Icon::Overview, 30.0, TEXT);
    ui.painter().text(
        rect.min + egui::vec2(46.0, 0.0),
        Align2::LEFT_TOP,
        "Epimetheus",
        FontId::proportional(12.0),
        MUTED,
    );
    ui.painter().text(
        rect.min + egui::vec2(45.0, 12.0),
        Align2::LEFT_TOP,
        "Blue",
        display_font(27.0),
        TEXT,
    );
}

fn navigation_rows(ui: &mut Ui, page: &mut Page) -> Rect {
    ui.spacing_mut().item_spacing.y = 0.0;
    let mut rects = [Rect::NOTHING; NAVIGATION.len()];
    for (group_index, (group, start, count)) in NAVIGATION_GROUPS.into_iter().enumerate() {
        if group_index != 0 {
            ui.add_space(NAV_GROUP_GAP);
        }
        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), NAV_GROUP_HEIGHT),
            Sense::hover(),
        );
        response
            .widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, ui.is_enabled(), group));
        ui.painter().text(
            egui::pos2(rect.left() + 12.0, rect.center().y),
            Align2::LEFT_CENTER,
            group,
            FontId::proportional(12.0),
            MUTED,
        );
        ui.add_space(NAV_ROW_GAP);
        for (index, &(destination, icon, label, description)) in
            NAVIGATION[start..start + count].iter().enumerate()
        {
            if index != 0 {
                ui.add_space(NAV_ROW_GAP);
            }
            let response = ui
                .push_id(label, |ui| {
                    navigation_item(ui, *page == destination, icon, label)
                })
                .inner
                .on_hover_text(description);
            rects[start + index] = response.rect;
            if response.gained_focus() {
                response.scroll_to_me(Some(Align::Center));
            }
            if response.clicked() {
                *page = destination;
                ui.ctx().request_repaint();
            }
        }
    }
    let index = NAVIGATION
        .iter()
        .position(|(destination, _, _, _)| *destination == *page)
        .expect("every workspace has a navigation destination");
    rects[index]
}

fn navigation_item(ui: &mut Ui, selected: bool, icon: Icon, label: &str) -> Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), NAV_ROW_HEIGHT),
        Sense::click(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Tab, ui.is_enabled(), selected, label)
    });
    if ui.is_rect_visible(rect) {
        let color = if selected || response.hovered() || response.has_focus() {
            TEXT
        } else {
            MUTED
        };
        let fill = if response.is_pointer_button_down_on() {
            ui.visuals().widgets.active.bg_fill
        } else if selected {
            NAV_SELECTED
        } else if response.hovered() {
            PANEL_HOVER
        } else {
            Color32::TRANSPARENT
        };
        let painter = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
        painter.rect_filled(rect, 5.0, fill);
        if selected && !response.is_pointer_button_down_on() {
            painter.line_segment(
                [
                    egui::pos2(rect.left() + 9.0, rect.top() + 0.5),
                    egui::pos2(rect.right() - 9.0, rect.top() + 0.5),
                ],
                Stroke::new(1.0, EDGE),
            );
        }
        let mut icon_ui = ui.new_child(
            UiBuilder::new()
                .id_salt("navigation-vector")
                .max_rect(Rect::from_min_size(
                    egui::pos2(rect.left() + 13.0, rect.center().y - 9.0),
                    egui::vec2(18.0, 18.0),
                ))
                .layout(Layout::left_to_right(Align::Center)),
        );
        theme::icon(&mut icon_ui, icon, 18.0, color);
        painter.text(
            egui::pos2(rect.left() + 43.0, rect.center().y),
            Align2::LEFT_CENTER,
            label,
            FontId::proportional(14.0),
            color,
        );
        focus_ring(ui, &response);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

#[derive(Clone, Copy)]
struct DestinationPresentation {
    page: Page,
    started_at: f64,
    offset_from: f32,
    indicator_from: f32,
    indicator_to: f32,
}

#[derive(Clone, Copy)]
struct DestinationFrame {
    offset: f32,
    indicator_y: f32,
    active: bool,
}

impl DestinationPresentation {
    fn new(page: Page, indicator_y: f32, now: f64) -> Self {
        Self {
            page,
            started_at: now,
            offset_from: 0.0,
            indicator_from: indicator_y,
            indicator_to: indicator_y,
        }
    }

    fn sample(self, now: f64) -> DestinationFrame {
        let progress = if now.is_finite() && self.started_at.is_finite() {
            ((now - self.started_at) / DESTINATION_DURATION).clamp(0.0, 1.0) as f32
        } else {
            1.0
        };
        let remaining = (1.0 - progress).powi(3);
        DestinationFrame {
            offset: self.offset_from * remaining,
            indicator_y: self.indicator_to + (self.indicator_from - self.indicator_to) * remaining,
            active: progress < 1.0
                && (self.offset_from != 0.0 || self.indicator_from != self.indicator_to),
        }
    }

    fn synchronize(&mut self, page: Page, indicator_y: f32, now: f64, animate: bool) {
        if self.page != page {
            let current = self.sample(now);
            self.page = page;
            self.started_at = now;
            self.offset_from = if animate {
                if current.active {
                    current.offset
                } else {
                    DESTINATION_SHIFT
                }
            } else {
                0.0
            };
            self.indicator_from = current.indicator_y;
            self.indicator_to = indicator_y;
        } else {
            self.indicator_from += indicator_y - self.indicator_to;
            self.indicator_to = indicator_y;
        }
        if !animate {
            self.started_at = now;
            self.offset_from = 0.0;
            self.indicator_from = indicator_y;
            self.indicator_to = indicator_y;
        }
    }
}

fn presentation_id() -> egui::Id {
    egui::Id::unique("epimetheus-blue.destination.presentation.v1")
}

fn seed_destination(ctx: &egui::Context, page: Page) {
    let now = ctx.input(|input| input.time);
    ctx.data_mut(|data| {
        let id = presentation_id();
        if data.get_temp::<DestinationPresentation>(id).is_none() {
            data.insert_temp(id, DestinationPresentation::new(page, 0.0, now));
        }
    });
}

fn destination_frame(
    ctx: &egui::Context,
    page: Page,
    reduced_motion: bool,
    indicator_y: Option<f32>,
) -> DestinationFrame {
    let (now, focused) = ctx.input(|input| {
        (
            input.time,
            input.focused && !input.viewport().minimized.unwrap_or(false),
        )
    });
    let frame = ctx.data_mut(|data| {
        let id = presentation_id();
        let mut presentation = data
            .get_temp::<DestinationPresentation>(id)
            .unwrap_or_else(|| DestinationPresentation::new(page, indicator_y.unwrap_or(0.0), now));
        let target = indicator_y.unwrap_or(presentation.indicator_to);
        presentation.synchronize(page, target, now, !reduced_motion && focused);
        let frame = presentation.sample(now);
        data.insert_temp(id, presentation);
        frame
    });
    if frame.active {
        ctx.request_repaint();
    }
    frame
}

fn destination_content<R>(
    ui: &mut Ui,
    offset: f32,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    let mut content = ui.available_rect_before_wrap();
    content.max.x = (content.max.x - DESTINATION_SHIFT).max(content.min.x + 1.0);
    content.max.y = content.max.y.max(content.min.y + 1.0);
    // Keep paint, widgets and scroll hit-testing on the panel's actual Area layer.
    // A transformed, non-Area sublayer fails ScrollArea's layer_id_at hover check,
    // including after its transform settles to identity. Translate layout instead.
    content = content.translate(egui::vec2(offset, 0.0));
    ui.scope_builder(
        UiBuilder::new()
            .id_salt("blue-destination-content")
            .max_rect(content),
        add_contents,
    )
}

pub(super) fn workspace(app: &mut BlueApp, root: &mut Ui) {
    egui::CentralPanel::default()
        .frame(
            Frame::new()
                .fill(CHASSIS)
                .inner_margin(egui::Margin::same(12)),
        )
        .show(root, |ui| {
            let deck = ui.max_rect();
            theme::inset_plane(ui, deck, PANEL, BG);
            ui.scope_builder(
                UiBuilder::new()
                    .id_salt("blue-workdeck")
                    .max_rect(deck.shrink(WORKSPACE_MARGIN)),
                |ui| {
                    ui.set_clip_rect(ui.max_rect().intersect(ui.clip_rect()));
                    // This warning is outside page scrolling and is never a dismissible
                    // job toast. Navigation cannot hide an outstanding staged policy.
                    staged_firewall_warning(app, ui);
                    let destination =
                        destination_frame(ui.ctx(), app.page, app.reduced_motion, None);
                    destination_content(ui, destination.offset, |ui| match app.page {
                        // These workspaces already own their scroll areas. Do not put
                        // an unbounded outer scroll around their full-height scrollers.
                        Page::Overview => app.overview(ui),
                        Page::Scanner => app.scanner(ui),
                        Page::Integrity => app.integrity(ui),
                        Page::Quarantine => app.quarantine(ui),
                        Page::Network => app.network(ui),
                        Page::Filters => app.filters(ui),
                        Page::Browser => app.browser(ui),
                        Page::Cleanup => app.cleanup(ui),
                        page => {
                            egui::ScrollArea::vertical()
                                .id_salt(("blue-workspace", page))
                                .auto_shrink([false, false])
                                .show(ui, |ui| match page {
                                    Page::Firewall => app.firewall(ui),
                                    Page::Reputation => app.reputation(ui),
                                    Page::Settings => app.settings(ui),
                                    Page::Overview
                                    | Page::Scanner
                                    | Page::Integrity
                                    | Page::Quarantine
                                    | Page::Network
                                    | Page::Filters
                                    | Page::Browser
                                    | Page::Cleanup => unreachable!(),
                                });
                        }
                    });
                },
            );
        });
}

pub(super) fn header(app: &mut BlueApp, ui: &mut Ui, title: &str, subtitle: &str) {
    if ui.available_width() >= 560.0 {
        let heading_width = ui.available_width() - 174.0 - ui.spacing().item_spacing.x;
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(heading_width);
                page_heading(ui, title, subtitle);
            });
            ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                pause_action(app, ui)
            });
        });
    } else {
        page_heading(ui, title, subtitle);
        pause_action(app, ui);
    }
    ui.add_space(10.0);
    let (rule, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().line_segment(
        [rule.left_center(), rule.right_center()],
        Stroke::new(1.0, SEAM),
    );
    ui.add_space(12.0);
    if let Some((message, good)) = &app.message {
        Frame::new()
            .fill(RECESS)
            .stroke(Stroke::new(1.0, if *good { SEAM } else { RED }))
            .corner_radius(5.0)
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .id_salt("blue-job-message")
                    .max_height(112.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(message).size(14.0).color(TEXT)).wrap(),
                        );
                    });
            });
        ui.add_space(12.0);
    }
}

fn page_heading(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).font(display_font(30.0)).color(TEXT));
    ui.add(egui::Label::new(RichText::new(subtitle).size(14.0).color(MUTED)).wrap());
}

fn pause_action(app: &mut BlueApp, ui: &mut Ui) {
    let paused = app.deps.db.kill_switch();
    let response = ui.add(egui::Button::new(RichText::new(if paused {
        "Resume file actions"
    } else {
        "Emergency pause"
    }).size(14.0).color(TEXT))
        .stroke(Stroke::new(1.0, if paused { AMBER } else { BORDER }))
        .min_size(egui::vec2(170.0, 34.0)))
        .on_hover_text("Pauses automatic file quarantine only; detection continues. Firewall, system DNS and service settings are not changed.");
    focus_ring(ui, &response);
    if response.clicked() {
        app.toggle_kill_switch();
    }
}

fn staged_firewall_warning(app: &mut BlueApp, ui: &mut Ui) {
    if !app.firewall_status.pending {
        return;
    }
    let busy = app.jobs.contains("firewall");
    let ready = app.firewall_status.installed && !busy;
    Frame::new()
        .fill(RECESS)
        .stroke(Stroke::new(1.0, AMBER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                theme::icon(ui, Icon::Firewall, 20.0, AMBER);
                ui.label(RichText::new("Firewall change is staged").font(display_font(20.0)).color(AMBER));
            });
            ui.add(egui::Label::new(RichText::new(
                "Keep only after checking connectivity, or undo now. Unconfirmed changes revert under the helper's 60-second deadline; no live countdown is available.",
            ).size(14.0).color(MUTED)).wrap());
            ui.horizontal_wrapped(|ui| {
                let keep = ui.add_enabled(ready, egui::Button::new(
                    RichText::new("Keep staged policy").color(Color32::WHITE),
                ).fill(BLUE));
                focus_ring(ui, &keep);
                if keep.clicked() {
                    app.run_firewall("confirm");
                }
                // Recheck the job gate after Keep so one frame cannot submit
                // both operations through separate controls.
                let undo = ui.add_enabled(
                    ready && !app.jobs.contains("firewall"),
                    egui::Button::new("Undo staged change"),
                );
                focus_ring(ui, &undo);
                if undo.clicked() {
                    app.run_firewall("rollback");
                }
                if busy {
                    ui.label(RichText::new("Firewall operation in progress").size(13.0).color(AMBER));
                }
            });
            if !app.firewall_status.installed {
                ui.add(egui::Label::new(RichText::new(
                    "The helper is unavailable or untrusted. The last reported staged change still needs attention; Keep and Undo are unavailable.",
                ).size(13.0).color(AMBER)).wrap());
            }
        });
    ui.add_space(14.0);
}

fn focus_ring(ui: &Ui, response: &Response) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.shrink(1.0),
            5.0,
            Stroke::new(4.0, RECESS),
            StrokeKind::Inside,
        );
        ui.painter().rect_stroke(
            response.rect.shrink(1.0),
            5.0,
            Stroke::new(2.0, FOCUS),
            StrokeKind::Inside,
        );
    }
}

pub(super) fn status_dot(ui: &mut Ui, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().circle_filled(rect.center(), size * 0.5, color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn navigation_has_one_named_vector_destination_per_page() {
        let mut pages = HashSet::new();
        let mut icons = HashSet::new();
        for (page, icon, label, description) in NAVIGATION {
            assert!(pages.insert(page));
            assert!(icons.insert(icon));
            assert!(!label.is_empty() && !description.is_empty());
            assert!(label.is_ascii());
            assert_ne!(label, label.to_uppercase());
        }
        assert_eq!(pages.len(), 11);
    }

    #[test]
    fn navigation_groups_cover_every_destination_once() {
        let mut covered = HashSet::new();
        for (label, start, count) in NAVIGATION_GROUPS {
            assert!(!label.is_empty());
            assert_ne!(label, label.to_uppercase());
            assert!(count > 0 && start + count <= NAVIGATION.len());
            for index in start..start + count {
                assert!(covered.insert(index));
            }
        }
        assert_eq!(covered.len(), NAVIGATION.len());
    }

    #[test]
    fn all_navigation_and_persistent_controls_fit_the_minimum_window() {
        let groups = NAVIGATION_GROUPS.len() as f32;
        let rows = NAVIGATION.len() as f32;
        let navigation_height = rows * NAV_ROW_HEIGHT
            + groups * NAV_GROUP_HEIGHT
            + rows * NAV_ROW_GAP
            + (groups - 1.0) * NAV_GROUP_GAP;
        let required_height = 2.0 * f32::from(SIDEBAR_MARGIN)
            + BRAND_HEIGHT
            + BRAND_GAP
            + navigation_height
            + FOOTER_HEIGHT;
        assert_eq!(navigation_height, 466.0);
        assert!(
            required_height <= 620.0,
            "requires {required_height} points"
        );
        let workspace_width =
            900.0 - SIDEBAR_WIDTH - 24.0 - 2.0 * WORKSPACE_MARGIN - DESTINATION_SHIFT;
        assert!(workspace_width >= 560.0);
        const { assert!(NAV_ROW_HEIGHT >= 24.0) };
    }

    #[test]
    fn native_minimum_layout_keeps_all_destinations_and_footer_visible() {
        for paused in [false, true] {
            let ctx = egui::Context::default();
            theme::apply(&ctx, true);
            let mut reduced_motion = true;
            let mut page = Page::Settings;
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 620.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run_ui(input, |root| {
                egui::Panel::left("blue-navigation")
                    .exact_size(SIDEBAR_WIDTH)
                    .frame(Frame::new().inner_margin(egui::Margin::same(SIDEBAR_MARGIN)))
                    .show(root, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        brand(ui);
                        ui.add_space(BRAND_GAP);
                        let navigation = egui::ScrollArea::vertical()
                            .max_height((ui.available_height() - FOOTER_HEIGHT).max(1.0))
                            .auto_shrink([false, false])
                            .show(ui, |ui| navigation_rows(ui, &mut page));
                        assert!(
                            navigation.content_size.y <= navigation.inner_rect.height() + 0.5,
                            "navigation requires scrolling at the minimum size"
                        );
                        assert!(navigation.inner_rect.contains_rect(navigation.inner));
                        let footer = sidebar_footer(ui, &mut reduced_motion, paused);
                        assert!(footer.height() <= FOOTER_HEIGHT);
                        assert!(footer.bottom() <= ui.max_rect().bottom() + 0.5);
                        assert!(footer.right() <= ui.max_rect().right() + 0.5);
                    });
            });
        }
    }

    #[test]
    fn destination_transition_is_finite_monotonic_and_non_bouncy() {
        let mut presentation = DestinationPresentation::new(Page::Overview, 80.0, 0.0);
        assert!(!presentation.sample(0.0).active);
        presentation.synchronize(Page::Scanner, 116.0, 0.0, true);
        let mut previous = presentation.sample(0.0);
        assert_eq!(previous.offset, DESTINATION_SHIFT);
        assert_eq!(previous.indicator_y, 80.0);
        for step in 1..=18 {
            let current = presentation.sample(f64::from(step) * 0.01);
            assert!(current.offset >= 0.0 && current.offset <= previous.offset);
            assert!(current.indicator_y >= previous.indicator_y);
            assert!(current.indicator_y <= 116.0);
            previous = current;
        }
        let settled = presentation.sample(1.0);
        assert_eq!(settled.offset, 0.0);
        assert_eq!(settled.indicator_y, 116.0);
        assert!(!settled.active);
    }

    #[test]
    fn interrupted_navigation_retargets_the_visible_position() {
        let mut presentation = DestinationPresentation::new(Page::Overview, 80.0, 0.0);
        presentation.synchronize(Page::Scanner, 116.0, 0.0, true);
        let before = presentation.sample(0.06);
        presentation.synchronize(Page::Settings, 500.0, 0.06, true);
        let after = presentation.sample(0.06);
        assert_eq!(presentation.page, Page::Settings);
        assert_eq!(after.offset, before.offset);
        assert!((after.indicator_y - before.indicator_y).abs() < 0.001);
        assert!(after.offset < DESTINATION_SHIFT);
        let settled = presentation.sample(1.0);
        assert!(!settled.active);
        assert_eq!(settled.indicator_y, 500.0);
    }

    #[test]
    fn reduced_motion_or_lost_focus_finishes_immediately_without_replay() {
        let mut presentation = DestinationPresentation::new(Page::Overview, 80.0, 0.0);
        presentation.synchronize(Page::Scanner, 116.0, 0.0, true);
        presentation.synchronize(Page::Scanner, 116.0, 0.04, false);
        let stopped = presentation.sample(0.04);
        assert_eq!(stopped.offset, 0.0);
        assert_eq!(stopped.indicator_y, 116.0);
        assert!(!stopped.active);
        presentation.synchronize(Page::Scanner, 116.0, 0.05, true);
        assert!(!presentation.sample(0.05).active);
        presentation.synchronize(Page::Settings, 500.0, 0.06, false);
        let next = presentation.sample(0.06);
        assert_eq!(next.offset, 0.0);
        assert_eq!(next.indicator_y, 500.0);
        assert!(!next.active);
    }

    #[test]
    fn scroll_and_resize_do_not_start_a_destination_transition() {
        let mut presentation = DestinationPresentation::new(Page::Scanner, 116.0, 0.0);
        presentation.synchronize(Page::Scanner, 72.0, 0.1, true);
        let moved = presentation.sample(0.1);
        assert_eq!(moved.offset, 0.0);
        assert_eq!(moved.indicator_y, 72.0);
        assert!(!moved.active);
    }

    #[test]
    fn native_focus_and_reduced_motion_cancel_presentation_repaints() {
        let ctx = egui::Context::default();
        let input = |time, focused| egui::RawInput {
            time: Some(time),
            focused,
            ..Default::default()
        };
        let _ = ctx.run_ui(input(0.0, true), |_| {
            assert!(!destination_frame(&ctx, Page::Overview, false, Some(80.0)).active);
        });
        let _ = ctx.run_ui(input(0.02, true), |_| {
            assert!(destination_frame(&ctx, Page::Scanner, false, Some(116.0)).active);
        });
        let _ = ctx.run_ui(input(0.04, false), |_| {
            let frame = destination_frame(&ctx, Page::Scanner, false, Some(116.0));
            assert_eq!(frame.offset, 0.0);
            assert!(!frame.active);
        });
        let _ = ctx.run_ui(input(0.05, true), |_| {
            assert!(!destination_frame(&ctx, Page::Scanner, false, Some(116.0)).active);
        });
        let _ = ctx.run_ui(input(0.06, true), |_| {
            let frame = destination_frame(&ctx, Page::Settings, true, Some(500.0));
            assert_eq!(frame.offset, 0.0);
            assert_eq!(frame.indicator_y, 500.0);
            assert!(!frame.active);
        });
    }

    fn destination_input(time: f64, events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 620.0),
            )),
            time: Some(time),
            events,
            ..Default::default()
        }
    }

    #[test]
    fn destination_wheel_input_works_during_and_after_the_transition() {
        for shift in [DESTINATION_SHIFT, 0.0] {
            let ctx = egui::Context::default();
            theme::apply(&ctx, true);
            let mut viewport = Rect::NOTHING;
            let mut offset = 0.0;
            for frame in 0..3 {
                let mut events = Vec::new();
                if frame != 0 {
                    events.push(egui::Event::PointerMoved(viewport.center()));
                }
                if frame == 2 {
                    events.push(egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0.0, -7.0),
                        phase: egui::TouchPhase::Move,
                        source: egui::MouseWheelSource::Unknown,
                        modifiers: egui::Modifiers::NONE,
                    });
                }
                let _ = ctx.run_ui(destination_input(f64::from(frame) / 60.0, events), |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        let panel_layer = ui.layer_id();
                        destination_content(ui, shift, |ui| {
                            assert_eq!(ui.layer_id(), panel_layer);
                            let scroll = egui::ScrollArea::vertical().show(ui, |ui| {
                                for _ in 0..30 {
                                    ui.allocate_exact_size(
                                        egui::vec2(ui.available_width(), 40.0),
                                        Sense::hover(),
                                    );
                                }
                            });
                            viewport = scroll.inner_rect;
                            offset = scroll.state.clamped_offset().y;
                        });
                    });
                });
            }
            assert!(offset > 0.0, "wheel input was rejected at shift {shift}");
        }
    }

    #[test]
    fn destination_buttons_accept_clicks_at_their_presented_position() {
        for shift in [DESTINATION_SHIFT, 0.0] {
            let ctx = egui::Context::default();
            theme::apply(&ctx, true);
            let mut button_rect = Rect::NOTHING;
            let mut clicked = false;
            for frame in 0..4 {
                let mut events = Vec::new();
                if frame != 0 {
                    let pos = button_rect.center();
                    events.push(egui::Event::PointerMoved(pos));
                    if frame >= 2 {
                        events.push(egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed: frame == 2,
                            modifiers: egui::Modifiers::NONE,
                        });
                    }
                }
                let _ = ctx.run_ui(destination_input(f64::from(frame) / 60.0, events), |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        let left = ui.available_rect_before_wrap().left();
                        destination_content(ui, shift, |ui| {
                            let button = ui.button("Review deletion approval");
                            button_rect = button.rect;
                            clicked |= button.clicked();
                            assert!((button_rect.left() - left - shift).abs() <= 0.5);
                        });
                    });
                });
            }
            assert!(clicked, "button click was rejected at shift {shift}");
        }
    }
}
