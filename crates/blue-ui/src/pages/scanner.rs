use crate::*;

#[derive(Clone, Default)]
struct ScannerPresentation {
    search: String,
    selected_event: Option<i64>,
}

impl BlueApp {
    pub(crate) fn scanner(&mut self, ui: &mut egui::Ui) {
        let presentation_id = ui.make_persistent_id("scanner-presentation");
        let mut view = ui.ctx().data_mut(|data| {
            data.get_temp::<ScannerPresentation>(presentation_id)
                .unwrap_or_default()
        });

        egui::ScrollArea::vertical()
            .id_salt("scanner-workspace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                self.header(
                    ui,
                    "Scanner",
                    "Inspect a target without enabling realtime protection.",
                );

                // One target runway, rather than a collection of detector/status cards.
                Frame::new()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0, BLUE))
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::same(18))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("Inspect a file or folder")
                                .size(23.0)
                                .strong()
                                .color(TEXT),
                        );
                        ui.add_space(8.0);
                        ui.label(RichText::new("Target path").size(12.0).color(MUTED));

                        let busy = self.jobs.contains("scan");
                        let (edit, clicked) = if ui.available_width() >= 400.0 {
                            ui.horizontal(|ui| {
                                let width = ui.available_width()
                                    - 112.0
                                    - ui.spacing().item_spacing.x;
                                let edit = scanner_target(ui, &mut self.scan_path, busy, width);
                                let clicked = ui
                                    .add_enabled(
                                        !busy && !self.scan_path.trim().is_empty(),
                                        scanner_button(busy),
                                    )
                                    .clicked();
                                (edit, clicked)
                            })
                            .inner
                        } else {
                            let width = ui.available_width();
                            let edit = scanner_target(ui, &mut self.scan_path, busy, width);
                            let clicked = ui
                                .add_enabled(
                                    !busy && !self.scan_path.trim().is_empty(),
                                    scanner_button(busy),
                                )
                                .clicked();
                            (edit, clicked)
                        };
                        let enter = edit.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter));
                        if !busy && !self.scan_path.trim().is_empty() && (clicked || enter) {
                            self.start_scan();
                        }

                        ui.horizontal_wrapped(|ui| {
                            let enabled = !self.jobs.contains("scan");
                            for (label, path) in [("Downloads", "~/Downloads"), ("Home", "~")] {
                                if ui
                                    .add_enabled(enabled, egui::Button::new(label).small())
                                    .on_hover_text(format!("Set the target to {path}; does not start a scan."))
                                    .clicked()
                                {
                                    self.scan_path = path.into();
                                }
                            }
                            if let Some(root) = self.deps.config.scan.roots.first() {
                                if ui
                                    .add_enabled(
                                        enabled,
                                        egui::Button::new("First configured folder").small(),
                                    )
                                    .on_hover_text(root)
                                    .clicked()
                                {
                                    self.scan_path = root.clone();
                                }
                            }
                        });

                        if self.jobs.contains("scan") {
                            ui.horizontal_wrapped(|ui| {
                                ui.spinner();
                                ui.label(
                                    RichText::new("Scan running. Results arrive when the worker finishes.")
                                        .size(12.0)
                                        .color(MUTED),
                                );
                            });
                        } else if self.scan_path.trim().is_empty() {
                            ui.label(
                                RichText::new("Enter a path to enable Scan now.")
                                    .size(12.0)
                                    .color(AMBER),
                            );
                        } else {
                            ui.label(
                                RichText::new("Enter starts the scan. Shortcuts only change the target.")
                                    .size(12.0)
                                    .color(MUTED),
                            );
                        }
                        ui.label(
                            RichText::new(format!(
                                "Folders recurse without following symlinks. Limit: {} MiB per file.",
                                self.deps.config.scan.max_file_size_mb
                            ))
                            .size(12.0)
                            .color(MUTED),
                        );
                        let online = self.deps.config.reputation.virustotal_enabled
                            && self.deps.config.reputation.virustotal_query_on_scan;
                        ui.label(RichText::new(if online {
                            "File contents stay here. Configured VirusTotal lookups may send SHA-256 hashes online."
                        } else {
                            "File contents stay here. Online hash lookups on scan are not enabled."
                        }).size(12.0).color(if online { AMBER } else { MUTED }));
                        egui::CollapsingHeader::new("Scope and quarantine policy")
                            .id_salt("scanner-scope")
                            .show(ui, |ui| {
                                ui.label("This manual scan skips .git, node_modules, target and .cache folders. Configured watcher exclusion globs are not applied to this scan.");
                                ui.label("T1 candidates stay in place. Automatic quarantine requires T2 corroborated or T3 confirmed evidence and respects Emergency pause. Scanning never deletes files.");
                                if self.deps.db.kill_switch() {
                                    ui.label(RichText::new("Automatic quarantine is currently paused; scanning can still record evidence.").color(AMBER));
                                }
                                ui.label(if self.deps.config.scan.clamav.required {
                                    "ClamAV is required by configuration; engine startup fails if its socket is missing. Detector health is not measured by this page."
                                } else {
                                    "Configuration allows reduced coverage when ClamAV is missing. Detector health is not measured by this page."
                                });
                            });
                    });

                ui.add_space(18.0);
                Frame::new()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.label(RichText::new("Last completed scan").size(16.0).strong().color(TEXT));
                        ui.add_space(8.0);
                        if let Some(summary) = &self.last_scan {
                            let totals = [
                                ("Processed", summary.files, TEXT),
                                ("T1 candidates", summary.candidates, AMBER),
                                ("T2+ files", summary.threats, RED),
                                ("Quarantined", summary.quarantined, BLUE),
                                ("Errors", summary.errors, AMBER),
                            ];
                            ui.columns(totals.len(), |columns| {
                                for (column, (label, value, color)) in columns.iter_mut().zip(totals) {
                                    column.add(egui::Label::new(
                                        RichText::new(value.to_string())
                                            .size(25.0)
                                            .strong()
                                            .color(if value == 0 { TEXT } else { color }),
                                    ).truncate());
                                    column.label(RichText::new(label).size(11.0).color(MUTED));
                                }
                            });
                            ui.add_space(8.0);
                            ui.label(RichText::new("Processed includes size-skipped files, not just fully inspected files. These totals are not a cleanliness certificate.").size(12.0).color(MUTED));
                            if summary.errors > 0 {
                                ui.label(RichText::new("Some paths could not be processed. Check the target and its permissions; this summary has no per-path error details.").size(12.0).color(AMBER));
                            }
                            if summary.containment_failures > 0 {
                                ui.label(RichText::new(format!("{} T2+ detected file(s) could not be quarantined. See recorded containment errors; these files are not contained.", summary.containment_failures)).size(12.0).color(RED));
                            }
                            if self.jobs.contains("scan") {
                                ui.label(RichText::new("The active scan has not replaced these totals. No progress estimate is available.").size(12.0).color(MUTED));
                            }
                        } else {
                            ui.label(RichText::new("No completed scan in this session.").color(TEXT));
                            ui.label(RichText::new(if self.jobs.contains("scan") {
                                "The worker is running; no totals are available yet."
                            } else {
                                "Choose a target and select Scan now. Recorded evidence from earlier scans may still appear below."
                            }).size(12.0).color(MUTED));
                        }
                    });

                ui.add_space(18.0);
                section_title(
                    ui,
                    "Recorded scan evidence",
                    "From the recent activity snapshot, across targets and sessions. Select a path to inspect its record.",
                );
                if let Some(error) = &self.refresh_error {
                    ui.label(RichText::new("Evidence refresh failed. Showing the last available snapshot, not current state.").color(AMBER));
                    ui.add(egui::Label::new(RichText::new(error).size(12.0).color(AMBER)).wrap().selectable(true));
                }
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 64.0 - ui.spacing().item_spacing.x).max(1.0);
                    let search = ui.add_sized(
                        [width, 32.0],
                        egui::TextEdit::singleline(&mut view.search)
                            .id_salt("scanner-evidence-search")
                            .hint_text("Filter paths or recorded evidence"),
                    );
                    if search.changed() {
                        view.selected_event = None;
                    }
                    if ui.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
                        search.request_focus();
                        search.scroll_to_me(Some(Align::Center));
                    }
                    if ui.add_enabled_ui(!view.search.is_empty(), |ui| {
                        ui.add_sized([64.0, 32.0], egui::Button::new("Clear"))
                    }).inner.clicked() {
                        view.search.clear();
                        view.selected_event = None;
                        search.request_focus();
                    }
                });

                let events: Vec<_> = self.snapshot.events.iter()
                    .filter(|event| scanner_event_matches(event, &view.search))
                    .collect();
                let total = self.snapshot.events.iter().filter(|event| event.kind == "scan").count();
                if view.selected_event.is_some_and(|id| !events.iter().any(|event| event.id == id)) {
                    view.selected_event = None;
                }
                if events.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new(if total == 0 {
                        "No scan events in this snapshot."
                    } else {
                        "No recorded scan events match this filter."
                    }).color(TEXT));
                    ui.label(RichText::new(if total == 0 {
                        "A scan records file-level evidence. Skipped files and walk failures may have no event; absence is not proof of safety."
                    } else {
                        "Clear the filter to inspect the available records."
                    }).size(12.0).color(MUTED));
                } else {
                    ui.label(RichText::new(format!("{} of {total} scan records in the current snapshot", events.len())).size(12.0).color(MUTED));
                    let now = blue_core::now_ms();
                    for event in events {
                        ui.push_id(event.id, |ui| {
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(format!("Event #{}", event.id)).size(11.0).color(MUTED));
                                ui.label(RichText::new(scan_event_age(event.ts_ms, now)).size(11.0).color(MUTED));
                                ui.label(RichText::new(format!("Recorded level: {}", event.level)).size(11.0).color(match event.level.as_str() {
                                    "error" => RED,
                                    "warn" => AMBER,
                                    _ => MUTED,
                                }));
                            });
                            let selected = view.selected_event == Some(event.id);
                            let path = ui.add(
                                egui::Button::selectable(
                                    selected,
                                    RichText::new(event.subject.as_deref().unwrap_or("No path recorded"))
                                        .monospace().size(12.0).color(TEXT),
                                )
                                .wrap()
                                .min_size(Vec2::new(ui.available_width(), 30.0)),
                            );
                            if path.gained_focus() {
                                path.scroll_to_me(None);
                            }
                            if path.clicked() {
                                view.selected_event = if selected { None } else { Some(event.id) };
                            }
                            if view.selected_event == Some(event.id) {
                                ui.label(RichText::new("Recorded payload").size(13.0).strong().color(TEXT));
                                ui.label(RichText::new(format!("Timestamp: {} Unix ms", event.ts_ms)).monospace().size(11.0).color(MUTED));
                                if event.payload.is_empty() {
                                    ui.label(RichText::new("No payload was recorded.").size(12.0).color(MUTED));
                                } else {
                                    // &str is an immutable TextBuffer: selectable/copyable, never editable.
                                    let mut payload = event.payload.as_str();
                                    ui.add(egui::TextEdit::multiline(&mut payload)
                                        .id_salt("scan-recorded-payload")
                                        .font(FontId::monospace(12.0))
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(4)
                                        .lock_focus(false));
                                }
                            }
                        });
                    }
                }
            });
        ui.ctx()
            .data_mut(|data| data.insert_temp(presentation_id, view));
    }
}

fn scanner_target(ui: &mut egui::Ui, path: &mut String, busy: bool, width: f32) -> egui::Response {
    ui.add_enabled_ui(!busy, |ui| {
        ui.add_sized(
            [width.max(1.0), 44.0],
            egui::TextEdit::singleline(path)
                .id_salt("scanner-target-path")
                .hint_text("~/Downloads or /path/to/file")
                .font(FontId::monospace(15.0))
                .margin(egui::Margin::symmetric(10, 11)),
        )
    })
    .inner
}

fn scanner_button(busy: bool) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(if busy { "Scanning…" } else { "Scan now" })
            .color(TEXT)
            .strong(),
    )
    .min_size(Vec2::new(112.0, 44.0))
    .fill(BLUE)
    .stroke(Stroke::new(1.0, BLUE))
}

fn scanner_event_matches(event: &Event, search: &str) -> bool {
    if event.kind != "scan" {
        return false;
    }
    let query = search.trim().to_lowercase();
    query.is_empty()
        || event
            .subject
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(&query)
        || event.payload.to_lowercase().contains(&query)
        || event.level.to_lowercase().contains(&query)
        || format!("#{}", event.id).contains(&query)
}

fn scan_event_age(timestamp_ms: i64, now_ms: i64) -> String {
    if timestamp_ms <= 0 {
        return "Timestamp unavailable".into();
    }
    if timestamp_ms > now_ms {
        return "Future timestamp".into();
    }
    let seconds = now_ms.saturating_sub(timestamp_ms) / 1000;
    match seconds {
        0..=59 => format!("{seconds} s ago"),
        60..=3599 => format!("{} min ago", seconds / 60),
        3600..=86399 => format!("{} h ago", seconds / 3600),
        _ => format!("{} d ago", seconds / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> Event {
        Event {
            id: 17,
            ts_ms: 1000,
            kind: "scan".into(),
            level: "warn".into(),
            subject: Some("/home/user/Downloads/sample".into()),
            payload: r#"{"tier":"T2 corroborated","sha256":"ABC123","detectors":[]}"#.into(),
        }
    }

    #[test]
    fn search_uses_recorded_fields_without_inventing_verdicts() {
        let event = event();
        for query in [
            " downloads ",
            "abc123",
            "T2 CORROBORATED",
            "17",
            "#17",
            "warn",
            "",
        ] {
            assert!(scanner_event_matches(&event, query));
        }
        assert!(!scanner_event_matches(&event, "clean"));
        let mut unrelated = event;
        unrelated.kind = "quarantine".into();
        assert!(!scanner_event_matches(&unrelated, ""));
    }

    #[test]
    fn recorded_age_handles_missing_and_future_timestamps() {
        assert_eq!(scan_event_age(0, 1000), "Timestamp unavailable");
        assert_eq!(scan_event_age(2000, 1000), "Future timestamp");
        assert_eq!(scan_event_age(1000, 61_000), "1 min ago");
    }
}
