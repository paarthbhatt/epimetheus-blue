use crate::*;

#[derive(Clone, Default)]
struct QuarantinePresentation {
    search: String,
    selected: Option<i64>,
    review: Option<RestoreReview>,
    focus_review: bool,
    last_frame: Option<u64>,
}

#[derive(Clone)]
struct RestoreReview {
    id: i64,
    destination: String,
    sha256: String,
    reason: String,
    tier: Tier,
    acknowledged: bool,
}

impl RestoreReview {
    fn new(item: &Quarantined) -> Self {
        Self {
            id: item.id,
            destination: item.original_path.clone(),
            sha256: item.sha256.clone(),
            reason: item.reason.clone(),
            tier: item.tier,
            acknowledged: false,
        }
    }

    fn matches(&self, item: &Quarantined) -> bool {
        item.restored_at_ms.is_none()
            && self.id == item.id
            && self.destination == item.original_path
            && self.sha256 == item.sha256
            && self.reason == item.reason
            && self.tier == item.tier
    }

    fn allows_restore(&self, item: &Quarantined, busy: bool, stale: bool) -> bool {
        self.acknowledged && self.matches(item) && !busy && !stale
    }
}

impl QuarantinePresentation {
    fn select(&mut self, id: i64) {
        if self.selected != Some(id) {
            self.selected = Some(id);
            self.review = None;
            self.focus_review = false;
        }
    }

    fn keep_quarantined(&mut self) {
        self.review = None;
        self.focus_review = true;
    }
}

impl BlueApp {
    pub(crate) fn quarantine(&mut self, ui: &mut egui::Ui) {
        let presentation_id = ui.make_persistent_id("quarantine-presentation");
        let mut view = ui.ctx().data_mut(|data| {
            data.get_temp::<QuarantinePresentation>(presentation_id)
                .unwrap_or_default()
        });
        let frame = ui.ctx().cumulative_frame_nr();
        // Keep search/selection, but never carry an approval across a page visit.
        if view
            .last_frame
            .is_some_and(|previous| frame.saturating_sub(previous) > 1)
        {
            view.review = None;
            view.focus_review = false;
        }
        view.last_frame = Some(frame);
        if view.review.is_some()
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            view.keep_quarantined();
        }
        let items = self.snapshot.quarantine.clone();

        egui::ScrollArea::vertical()
            .id_salt("quarantine-workspace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                self.header(
                    ui,
                    "Quarantine",
                    "Held files, recorded evidence, and reviewed restores.",
                );

                if let Some(error) = &self.refresh_error {
                    ui.label(RichText::new("The held-file ledger could not be refreshed. This is the last available snapshot; restore review is unavailable until refresh succeeds.").color(AMBER));
                    ui.add(egui::Label::new(RichText::new(error).size(12.0).color(AMBER)).wrap().selectable(true));
                    view.review = None;
                }
                if self.jobs.contains("restore") {
                    view.review = None;
                    ui.horizontal_wrapped(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("A restore is running. Another restore cannot start until it finishes.").size(12.0).color(MUTED));
                    });
                }

                let held_count = items.iter().filter(|item| item.restored_at_ms.is_none()).count();
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Held-file ledger").size(19.0).strong().color(TEXT));
                    ui.label(RichText::new(format!("{held_count} held")).size(13.0).color(MUTED));
                });
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 64.0 - ui.spacing().item_spacing.x).max(1.0);
                    let search = ui.add_sized(
                        [width, 32.0],
                        egui::TextEdit::singleline(&mut view.search)
                            .id_salt("quarantine-ledger-search")
                            .hint_text("Search path, reason, tier, record ID or SHA-256"),
                    );
                    if search.changed() {
                        view.review = None;
                        view.focus_review = false;
                    }
                    if ui.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
                        search.request_focus();
                        search.scroll_to_me(Some(Align::Center));
                    }
                    if ui.add_enabled_ui(!view.search.is_empty(), |ui| {
                        ui.add_sized([64.0, 32.0], egui::Button::new("Clear"))
                    }).inner.clicked() {
                        view.search.clear();
                        view.review = None;
                        view.focus_review = false;
                        search.request_focus();
                    }
                });

                let visible: Vec<_> = items.iter()
                    .filter(|item| held_item_matches(item, &view.search))
                    .collect();
                if view.selected.is_some_and(|id| !visible.iter().any(|item| item.id == id)) {
                    view.selected = None;
                    view.review = None;
                    view.focus_review = false;
                }
                if view.selected.is_none() {
                    if let Some(first) = visible.first() {
                        view.select(first.id);
                    }
                }
                if view.review.as_ref().is_some_and(|review| {
                    !visible.iter().any(|item| review.matches(item))
                }) {
                    view.review = None;
                }

                ui.add_space(8.0);
                if held_count == 0 {
                    ui.label(RichText::new(if self.refresh_error.is_some() {
                        "No held-file records are available in this snapshot."
                    } else {
                        "No files are held in quarantine."
                    }).strong().color(TEXT));
                    ui.label(RichText::new("Files moved under the T2 quarantine policy appear here with their original path and evidence. T1 candidates stay in place.").size(13.0).color(MUTED));
                    return;
                }
                if visible.is_empty() {
                    ui.label(RichText::new("No held files match this search.").strong().color(TEXT));
                    ui.label(RichText::new("Clear the search or try a recorded path, reason, tier, ID or hash. No files were changed.").size(13.0).color(MUTED));
                    return;
                }
                ui.label(RichText::new(format!("{} of {held_count} held records shown", visible.len())).size(12.0).color(MUTED));
                ui.add_space(8.0);

                if ui.available_width() >= 760.0 {
                    ui.columns(2, |columns| {
                        held_ledger(&mut columns[0], &visible, &mut view, 380.0);
                        if let Some(item) = visible.iter().find(|item| Some(item.id) == view.selected) {
                            self.held_file_dossier(&mut columns[1], item, &mut view);
                        }
                    });
                } else {
                    // At 900×620, stack the dossier instead of squeezing or clipping its warning.
                    held_ledger(ui, &visible, &mut view, 190.0);
                    ui.add_space(18.0);
                    if let Some(item) = visible.iter().find(|item| Some(item.id) == view.selected) {
                        self.held_file_dossier(ui, item, &mut view);
                    }
                }
            });
        ui.ctx()
            .data_mut(|data| data.insert_temp(presentation_id, view));
    }

    fn held_file_dossier(
        &mut self,
        ui: &mut egui::Ui,
        item: &Quarantined,
        view: &mut QuarantinePresentation,
    ) {
        ui.push_id(("held-dossier", item.id), |ui| {
            ui.label(RichText::new(held_filename(item)).size(21.0).strong().color(TEXT));
            ui.horizontal_wrapped(|ui| {
                tier_badge(ui, item.tier);
                ui.label(RichText::new(item.tier.label()).size(12.0).color(TEXT));
                ui.label(RichText::new(format!("Record #{}", item.id)).size(12.0).color(MUTED));
            });
            held_value(ui, "Original path", &item.original_path);
            ui.label(RichText::new("Reason for hold").size(12.0).color(MUTED));
            ui.add(egui::Label::new(RichText::new(if item.reason.is_empty() {
                "No reason was recorded."
            } else {
                &item.reason
            }).size(13.0).color(TEXT)).wrap().selectable(true));
            held_value(ui, "SHA-256", &item.sha256);
            held_value(ui, "Held at (Unix milliseconds)", &item.created_at_ms.to_string());
            egui::CollapsingHeader::new("Quarantine policy")
                .id_salt("held-policy")
                .show(ui, |ui| {
                    ui.label("Automatic quarantine requires T2 corroborated or T3 confirmed evidence and respects Emergency pause. Restoring does not lower the recorded tier. There is no deletion action here.");
                });
            ui.add_space(8.0);

            let busy = self.jobs.contains("restore");
            let stale = self.refresh_error.is_some();
            let mut focus_keep = false;
            if view.review.is_none() {
                ui.label(RichText::new("Default decision: keep quarantined.").size(13.0).color(TEXT));
                let review = ui.add_enabled(
                    !busy && !stale,
                    egui::Button::new("Review restore")
                        .stroke(Stroke::new(1.0, AMBER))
                        .min_size(Vec2::new(140.0, 34.0)),
                );
                if view.focus_review && !busy && !stale {
                    review.request_focus();
                    review.scroll_to_me(None);
                    view.focus_review = false;
                }
                if review.clicked() {
                    view.review = Some(RestoreReview::new(item));
                    focus_keep = true;
                }
            }

            if let Some(review) = &mut view.review {
                let mut keep_clicked = false;
                let mut restore_clicked = false;
                Frame::new()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0, AMBER))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        ui.label(RichText::new("Review restore").size(17.0).strong().color(AMBER));
                        held_value(ui, "Exact restore destination", &review.destination);
                        ui.label(RichText::new("This returns the held file to its original path and reapplies its original permissions. It may be runnable again.").color(TEXT));
                        ui.label(RichText::new("If the destination exists, Blue refuses the restore. Nothing is overwritten; move the existing file aside yourself before retrying.").size(13.0).color(AMBER));
                        ui.add_space(6.0);
                        ui.checkbox(
                            &mut review.acknowledged,
                            "I understand the destination above and that this file may become runnable again.",
                        );
                        let allowed = review.allows_restore(item, busy, stale);
                        ui.horizontal_wrapped(|ui| {
                            let keep = ui.add(
                                egui::Button::new(RichText::new("Keep quarantined").strong().color(TEXT))
                                    .fill(BLUE)
                                    .stroke(Stroke::new(1.0, BLUE))
                                    .min_size(Vec2::new(152.0, 36.0)),
                            );
                            if focus_keep {
                                keep.request_focus();
                                keep.scroll_to_me(Some(Align::Max));
                            }
                            keep_clicked = keep.clicked();
                            restore_clicked = ui.add_enabled(
                                allowed,
                                egui::Button::new("Restore to original path")
                                    .stroke(Stroke::new(1.0, AMBER))
                                    .min_size(Vec2::new(166.0, 36.0)),
                            ).clicked();
                        });
                        ui.label(RichText::new("Escape keeps the file quarantined. Restore never opens the file.").size(12.0).color(MUTED));
                    });
                if keep_clicked {
                    view.keep_quarantined();
                } else if restore_clicked {
                    // The existing async worker retains its job gate and no-overwrite check.
                    self.restore(item.id);
                    view.review = None;
                    view.focus_review = false;
                }
            }
        });
    }
}

fn held_ledger(
    ui: &mut egui::Ui,
    items: &[&Quarantined],
    view: &mut QuarantinePresentation,
    height: f32,
) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt("held-file-ledger-rows")
                .max_height(height)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for item in items {
                        ui.push_id(item.id, |ui| {
                            ui.horizontal(|ui| {
                                let width =
                                    (ui.available_width() - 44.0 - ui.spacing().item_spacing.x)
                                        .max(1.0);
                                let row = ui.add_sized(
                                    [width, 32.0],
                                    egui::Button::selectable(
                                        view.selected == Some(item.id),
                                        RichText::new(format!(
                                            "#{}  {}",
                                            item.id,
                                            held_filename(item)
                                        ))
                                        .size(13.0)
                                        .color(TEXT),
                                    )
                                    .wrap(),
                                );
                                if row.gained_focus() {
                                    row.scroll_to_me(None);
                                }
                                if row.clicked() {
                                    view.select(item.id);
                                }
                                tier_badge(ui, item.tier);
                            });
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&item.original_path)
                                        .monospace()
                                        .size(11.0)
                                        .color(MUTED),
                                )
                                .truncate(),
                            );
                            ui.separator();
                        });
                    }
                });
        });
}

fn held_filename(item: &Quarantined) -> &str {
    Path::new(&item.original_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(&item.original_path)
}

fn held_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(12.0).color(MUTED));
    let mut text = value;
    ui.add(
        egui::TextEdit::multiline(&mut text)
            .id_salt(label)
            .font(FontId::monospace(12.0))
            .desired_width(f32::INFINITY)
            .desired_rows(1)
            .lock_focus(false),
    );
}

fn held_item_matches(item: &Quarantined, search: &str) -> bool {
    if item.restored_at_ms.is_some() {
        return false;
    }
    let query = search.trim().to_lowercase();
    query.is_empty()
        || item.original_path.to_lowercase().contains(&query)
        || item.reason.to_lowercase().contains(&query)
        || item.sha256.to_lowercase().contains(&query)
        || item.tier.label().to_lowercase().contains(&query)
        || format!("#{}", item.id).contains(&query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> Quarantined {
        Quarantined {
            id: 41,
            original_path: "/home/user/Downloads/sample".into(),
            sha256: "ABC123".into(),
            reason: "ClamAV and YARA evidence".into(),
            tier: Tier::Corroborated,
            created_at_ms: 1000,
            restored_at_ms: None,
        }
    }

    #[test]
    fn ledger_search_uses_real_held_fields() {
        let item = item();
        for query in [" downloads ", "abc123", "YARA", "T2", "41", "#41", ""] {
            assert!(held_item_matches(&item, query));
        }
        assert!(!held_item_matches(&item, "clean"));
        let mut restored = item;
        restored.restored_at_ms = Some(2000);
        assert!(!held_item_matches(&restored, ""));
    }

    #[test]
    fn restore_defaults_to_keep_and_requires_current_acknowledged_record() {
        let item = item();
        let view = QuarantinePresentation::default();
        assert!(view.review.is_none());
        let mut review = RestoreReview::new(&item);
        assert!(!review.allows_restore(&item, false, false));
        review.acknowledged = true;
        assert!(review.allows_restore(&item, false, false));
        assert!(!review.allows_restore(&item, true, false));
        assert!(!review.allows_restore(&item, false, true));

        let mut changed = item.clone();
        changed.original_path = "/different/destination".into();
        assert!(!review.allows_restore(&changed, false, false));
        changed = item.clone();
        changed.sha256 = "different hash".into();
        assert!(!review.allows_restore(&changed, false, false));
        changed = item;
        changed.restored_at_ms = Some(2000);
        assert!(!review.allows_restore(&changed, false, false));
    }

    #[test]
    fn selecting_another_record_or_keeping_clears_review() {
        let item = item();
        let mut view = QuarantinePresentation::default();
        view.select(item.id);
        view.review = Some(RestoreReview::new(&item));
        view.review.as_mut().unwrap().acknowledged = true;
        view.select(item.id + 1);
        assert!(view.review.is_none());
        view.review = Some(RestoreReview::new(&item));
        view.keep_quarantined();
        assert!(view.review.is_none());
        assert!(view.focus_review);
    }
}
