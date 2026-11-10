use super::integrity::{finding_group_review, finding_review_label};
use crate::visuals::{LayerState, ShieldLayer, ShieldState};
use crate::*;

#[derive(Clone, Copy)]
struct OverviewReading {
    current: bool,
    paused: bool,
    pending_groups: i64,
    socket_present: Option<bool>,
    layers: ShieldState,
}

impl BlueApp {
    pub(crate) fn overview(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("overview-workspace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                self.overview_header(ui);

                let current = self.refresh_error.is_none();
                let socket = blue_core::config::expand_tilde(&self.deps.config.scan.clamav.socket);
                let socket_check = socket.try_exists();
                let socket_present = socket_check.as_ref().ok().copied();
                let reading = OverviewReading {
                    current,
                    paused: self.deps.db.kill_switch(),
                    pending_groups: self.snapshot.counts.findings,
                    socket_present,
                    layers: ShieldState {
                        files: overview_file_layer(current, self.realtime, socket_present),
                        dns: overview_layer(current, self.dns, !self.dns_routed),
                        // An earlier manual check is evidence, not an active guard.
                        integrity: overview_layer(current, self.guard_timer, false),
                        scanning: self.jobs.contains("scan"),
                    },
                };

                // The status owns the larger plane; armor is the only sculptural
                // element. Both columns wrap, and the whole workspace scrolls.
                if ui.available_width() >= 540.0 {
                    let gap = 24.0;
                    let usable = (ui.available_width() - gap).max(1.0);
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = gap;
                        ui.vertical(|ui| {
                            ui.set_width(usable * 0.40);
                            self.overview_status(ui, reading);
                        });
                        ui.vertical(|ui| {
                            ui.set_width(usable * 0.60);
                            self.overview_armor(ui, reading.layers);
                        });
                    });
                } else {
                    self.overview_status(ui, reading);
                    ui.add_space(20.0);
                    self.overview_armor(ui, reading.layers);
                }

                if let Some(error) = &self.refresh_error {
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("Status refresh error")
                        .id_salt("overview-refresh-error")
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(error).color(AMBER))
                                    .wrap()
                                    .selectable(true),
                            );
                        });
                }
                if let Err(error) = &socket_check {
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("Socket path check error")
                        .id_salt("overview-socket-error")
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(socket.to_string_lossy())
                                        .monospace()
                                        .color(TEXT),
                                )
                                .wrap()
                                .selectable(true),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(error.to_string()).color(AMBER))
                                    .wrap()
                                    .selectable(true),
                            );
                        });
                }

                ui.add_space(24.0);
                self.overview_finding_groups(ui);
                ui.add_space(24.0);
                egui::CollapsingHeader::new("Manage protection controls")
                    .id_salt("overview-protection-controls")
                    .show(ui, |ui| self.overview_controls(ui, socket_present));
                ui.add_space(24.0);
                self.overview_activity(ui);
                ui.add_space(16.0);
            });
    }

    fn overview_header(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Overview",
            "Inspect reported controls and recorded evidence.",
        );
    }

    fn overview_status(&mut self, ui: &mut egui::Ui, reading: OverviewReading) {
        let (headline, explanation, color) = overview_headline(reading);
        let display_size = if ui.available_width() < 280.0 {
            25.0
        } else {
            28.0
        };
        ui.add(
            egui::Label::new(
                RichText::new(headline)
                    .font(overview_display(display_size))
                    .color(color),
            )
            .wrap(),
        );
        ui.add_space(8.0);
        ui.add(egui::Label::new(RichText::new(explanation).color(MUTED)).wrap());
        ui.add_space(12.0);
        if reading.current {
            let note = overview_pending_groups_note(reading.pending_groups);
            ui.add(
                egui::Label::new(RichText::new(note).color(if reading.pending_groups > 0 {
                    AMBER
                } else {
                    MUTED
                }))
                .wrap(),
            );
        }
        ui.add(egui::Label::new(RichText::new("Quiet conservative assessment groups related records and leaves unassessed evidence pending. Informational source history is retained. It does not lower tiers, acknowledge records, enable protection or authorize remediation.").size(12.0).color(MUTED)).wrap());
        if reading.layers.scanning && headline != "Scan in progress" {
            ui.add(
                egui::Label::new(
                    RichText::new("Scan in progress; the final result is not available yet.")
                        .size(14.0)
                        .color(MUTED),
                )
                .wrap(),
            );
        }
        if self.jobs.contains("guard") {
            ui.label(
                RichText::new("Integrity check in progress.")
                    .size(14.0)
                    .color(MUTED),
            );
        }
        ui.add_space(18.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("Open scanner").color(Color32::WHITE))
                        .fill(BLUE)
                        .min_size(Vec2::new(0.0, 38.0)),
                )
                .on_hover_text(
                    "Choose and inspect a target. Opening Scanner does not start a scan.",
                )
                .clicked()
            {
                self.page = Page::Scanner;
            }
            if ui
                .add(egui::Button::new("Open change groups").min_size(Vec2::new(0.0, 38.0)))
                .on_hover_text(
                    "Open grouped integrity, startup-path and package evidence. Navigation does not acknowledge records.",
                )
                .clicked()
            {
                self.page = Page::Integrity;
            }
            if !reading.current && ui.button("Retry status").clicked() {
                self.refresh();
            }
        });
        ui.add_space(22.0);
        self.overview_inspection(ui, reading);
    }

    fn overview_inspection(&mut self, ui: &mut egui::Ui, reading: OverviewReading) {
        ui.label(
            RichText::new("Selected control")
                .font(overview_display(21.0))
                .color(TEXT),
        );
        self.overview_inspection_detail(ui, reading);
    }

    fn overview_inspection_detail(&mut self, ui: &mut egui::Ui, reading: OverviewReading) {
        let Some(layer) = self.guardian.inspected_layer() else {
            ui.add(egui::Label::new(RichText::new("Select a layer to inspect its reported scope. Nothing is enabled by inspection.").size(14.0).color(MUTED)).wrap());
            return;
        };
        let (title, state, action, page) = match layer {
            ShieldLayer::Files => (
                "File protection",
                reading.layers.files,
                "Inspect scan scope",
                Page::Scanner,
            ),
            ShieldLayer::Dns => (
                "DNS protection",
                reading.layers.dns,
                "Inspect DNS setup",
                Page::Settings,
            ),
            ShieldLayer::Integrity => (
                "Integrity checks",
                reading.layers.integrity,
                "Review change evidence",
                Page::Integrity,
            ),
        };
        ui.add_space(12.0);
        ui.label(RichText::new(title).strong().color(TEXT));
        ui.label(
            RichText::new(format!("Reported state: {state:?}"))
                .size(14.0)
                .color(MUTED),
        );
        self.overview_inspection_facts(ui, layer, reading.current);
        if ui.button(action).clicked() {
            self.page = page;
        }
    }

    fn overview_inspection_facts(&self, ui: &mut egui::Ui, layer: ShieldLayer, current: bool) {
        let detail = match layer {
            ShieldLayer::Files => format!("{} configured folders. Quarantine requires corroborated evidence. ClamAV socket presence does not verify engine health.", self.deps.config.scan.roots.len()),
            ShieldLayer::Dns => overview_dns_facts(current, self.dns, self.dns_routed),
            ShieldLayer::Integrity => "Scheduled checks record changes in configured paths. An active timer is not a cleanliness certificate.".to_owned(),
        };
        ui.add(egui::Label::new(RichText::new(detail).size(14.0).color(MUTED)).wrap());
        ui.add_space(8.0);
    }

    fn overview_armor(&mut self, ui: &mut egui::Ui, layers: ShieldState) {
        // The response belongs to inspection only. Never wire a 3D click to a
        // toggle or setup operation; the ordinary controls remain independent.
        let before = self.guardian.inspected_layer();
        let _ = self.guardian.paint(ui, layers, self.reduced_motion);
        if before != self.guardian.inspected_layer() {
            ui.ctx().request_repaint();
        }
        ui.horizontal_wrapped(|ui| {
            for (label, layer, help) in [
                (
                    "Files",
                    ShieldLayer::Files,
                    "Inspect the file layer; protection is unchanged.",
                ),
                (
                    "DNS",
                    ShieldLayer::Dns,
                    "Inspect the resolver layer; system DNS is unchanged.",
                ),
                (
                    "Integrity",
                    ShieldLayer::Integrity,
                    "Review recorded changes; no check is started.",
                ),
            ] {
                if ui
                    .selectable_label(self.guardian.inspected_layer() == Some(layer), label)
                    .on_hover_text(help)
                    .clicked()
                {
                    self.guardian.set_inspected_layer(Some(layer));
                    ui.ctx().request_repaint();
                }
            }
            if ui.small_button("Whole assembly").clicked() {
                self.guardian.set_inspected_layer(None);
                ui.ctx().request_repaint();
            }
        });
        ui.add(
            egui::Label::new(
                RichText::new("Layers show reported controls, not a safety verdict.")
                    .size(14.0)
                    .color(MUTED),
            )
            .wrap(),
        );
    }

    fn overview_controls(&mut self, ui: &mut egui::Ui, socket_present: Option<bool>) {
        ui.label(
            RichText::new("Protection controls")
                .font(overview_display(24.0))
                .color(TEXT),
        );
        ui.add(
            egui::Label::new(
                RichText::new("Change a control explicitly. Inspection never enables protection.")
                    .size(14.0)
                    .color(MUTED),
            )
            .wrap(),
        );
        ui.add_space(8.0);

        let file_detail = if !self.realtime {
            "Realtime watcher is off. Manual scanning remains available."
        } else if socket_present == Some(false) {
            "Watcher enabled; the configured ClamAV socket is missing."
        } else if socket_present.is_none() {
            "Watcher reported enabled; the configured ClamAV socket path could not be checked."
        } else if self.watch_unit_installed {
            "Folder watcher reported active by the user service; engine health is unverified."
        } else {
            "Folder watcher enabled for this app session; engine health is unverified."
        };
        let file_control = if self.realtime { "Disable" } else { "Enable" };
        if overview_control_row(
            ui,
            "File protection",
            file_detail,
            file_control,
            if self.realtime { GREEN } else { MUTED },
            true,
        ) {
            // Leave the reported bool untouched until the existing callback
            // succeeds. A failed start must not leave an optimistic On state.
            self.toggle_realtime(!self.realtime);
        }
        ui.separator();

        let (dns_detail, dns_color) = match (self.dns, self.dns_routed) {
            (true, true) => (
                "Resolver reported enabled; a system DNS route to loopback is detected.",
                GREEN,
            ),
            (true, false) => (
                "Local resolver enabled; system DNS is not reported routed to it.",
                AMBER,
            ),
            (false, true) => (
                "Resolver off; a loopback DNS route remains detected. Review DNS setup.",
                AMBER,
            ),
            (false, false) => (
                "Off. Enabling the local resolver does not change system DNS.",
                MUTED,
            ),
        };
        if overview_control_row(
            ui,
            "DNS protection",
            dns_detail,
            if self.dns { "Disable" } else { "Enable" },
            dns_color,
            true,
        ) {
            // This retains the callback's system-DNS shutdown safety gate.
            self.toggle_dns(!self.dns);
        }
        ui.separator();

        let checking = self.jobs.contains("guard");
        let integrity_detail = if checking {
            "Check in progress; the result of this run is not available yet."
        } else if self.guard_timer {
            "Check timer reported active. Checks record changes, not trust."
        } else {
            "Check timer is not reported active. A manual check records change evidence."
        };
        if overview_control_row(
            ui,
            "Integrity checks",
            integrity_detail,
            if checking { "Checking…" } else { "Run check" },
            if self.guard_timer { GREEN } else { MUTED },
            !checking,
        ) {
            self.run_guard();
        }

        ui.add_space(8.0);
        let coverage_note = match socket_present {
            Some(true) => {
                "Configured ClamAV socket path is present. Socket existence does not verify engine health."
            }
            Some(false) if self.deps.config.scan.clamav.required => {
                "Configured ClamAV socket is missing. ClamAV is required; scans may fail until a connection succeeds. Other engine health is unverified."
            }
            Some(false) => {
                "Configured ClamAV socket is missing; scan coverage is reduced. Other detector coverage and engine health are not verified here."
            }
            None => {
                "Configured ClamAV socket path could not be checked. Scan coverage and engine health are unverified."
            }
        };
        ui.add(
            egui::Label::new(RichText::new(coverage_note).size(14.0).color(
                if socket_present == Some(true) {
                    MUTED
                } else {
                    AMBER
                },
            ))
            .wrap(),
        );
        if self.refresh_error.is_some() {
            ui.add(
                egui::Label::new(
                    RichText::new("These are last reported control states; the recorded view could not refresh.")
                        .size(14.0)
                        .color(AMBER),
                )
                .wrap(),
            );
        }
    }

    fn overview_finding_groups(&mut self, ui: &mut egui::Ui) {
        section_title(
            ui,
            "Pending finding groups",
            "Groups need investigation or action; they are not a count of raw observations.",
        );
        let groups = &self.snapshot.finding_groups;
        ui.add(egui::Label::new(RichText::new(format!("Showing the latest {} of {} loaded pending groups; the snapshot reports {} pending groups across all sources. The shared window is capped at 250 groups, so older groups may be absent.", groups.len().min(3), groups.len(), self.snapshot.counts.findings)).size(12.0).color(if self.refresh_error.is_some() { AMBER } else { MUTED })).wrap());
        if self.refresh_error.is_some() {
            ui.add(egui::Label::new(RichText::new("These are last loaded assessments; refresh failed and current evidence may be absent.").size(12.0).color(AMBER)).wrap());
        }
        ui.add(egui::Label::new(RichText::new("Occurrences include acknowledged source history. Unique observations count identities; pending counts include only unacknowledged records requiring investigation or action. Informational history is retained outside this pending-only view.").size(12.0).color(MUTED)).wrap());
        ui.add_space(8.0);
        if groups.is_empty() {
            ui.add(egui::Label::new(RichText::new("No pending groups in this loaded window. An empty queue is not a safety verdict; raw source history is retained.").color(MUTED)).wrap());
        }
        for group in groups.iter().take(3) {
            let source = &group.representative.finding;
            ui.push_id(&group.group_key, |ui| {
                ui.add(egui::Label::new(RichText::new(&source.subject).strong().color(TEXT)).wrap());
                finding_group_review(ui, group);
                egui::CollapsingHeader::new("Representative source evidence")
                    .id_salt(("overview-group-source", source.id))
                    .show(ui, |ui| {
                        ui.label(RichText::new(format!("Source record {} · {} · {}", source.id, source.kind, overview_event_age(source.ts_ms, blue_core::now_ms()))).size(12.0).color(MUTED));
                        ui.add(egui::Label::new(RichText::new(&source.detail).monospace().size(12.0).color(TEXT)).wrap().selectable(true));
                        ui.add(egui::Label::new(RichText::new(format!("Representative assessment: {}; reason code {}; policy version {}. Other source records are not loaded here.", finding_review_label(group.representative.review.classification), group.representative.review.reason_code, group.representative.review.policy_version)).size(12.0).color(MUTED)).wrap());
                    });
                ui.separator();
            });
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open change groups").clicked() {
                self.page = Page::Integrity;
            }
            if ui.button("Open network groups").clicked() {
                self.page = Page::Network;
            }
        });
    }

    fn overview_activity(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Recorded source activity")
                .font(overview_display(24.0))
                .color(TEXT),
        );
        ui.add(
            egui::Label::new(
                RichText::new(if self.refresh_error.is_some() {
                    "Last loaded records; refresh failed. New activity may be absent."
                } else {
                    "Recent stored source events, separate from grouped finding counts; not a live feed or a statement of device safety."
                })
                .size(14.0)
                .color(if self.refresh_error.is_some() {
                    AMBER
                } else {
                    MUTED
                }),
            )
            .wrap(),
        );
        ui.add_space(12.0);
        if self.snapshot.events.is_empty() {
            let (title, detail) = if self.refresh_error.is_some() {
                (
                    "Activity unavailable",
                    "Retry status to load recorded events.",
                )
            } else {
                (
                    "No recorded events in this view",
                    "Open Scanner or run an integrity check to inspect this device.",
                )
            };
            ui.label(RichText::new(title).color(TEXT));
            ui.add(egui::Label::new(RichText::new(detail).color(MUTED)).wrap());
        } else {
            let now = blue_core::now_ms();
            for event in self.snapshot.events.iter().take(6) {
                overview_recorded_event(ui, event, now);
                ui.separator();
            }
            ui.label(
                RichText::new(format!(
                    "Showing {} of {} loaded recent records.",
                    self.snapshot.events.len().min(6),
                    self.snapshot.events.len(),
                ))
                .size(14.0)
                .color(MUTED),
            );
        }
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            if self.refresh_error.is_none() {
                ui.label(
                    RichText::new(format!(
                        "{} held files recorded.",
                        self.snapshot.counts.quarantined
                    ))
                    .size(14.0)
                    .color(MUTED),
                );
            }
            if ui
                .button("Review held files")
                .on_hover_text(
                    "Open the quarantine ledger. No file is restored or removed by navigation.",
                )
                .clicked()
            {
                self.page = Page::Quarantine;
            }
        });
    }
}

fn overview_display(size: f32) -> FontId {
    FontId::new(size, egui::FontFamily::Name("Display".into()))
}

fn overview_dns_facts(current: bool, enabled: bool, routed: bool) -> String {
    let resolver = if enabled { "enabled" } else { "off" };
    let route = if routed { "detected" } else { "not detected" };
    let scope = "Enabling the resolver does not change system DNS.";
    if current {
        format!("Resolver {resolver}. System route to loopback {route}. {scope}")
    } else {
        format!("Last-reported resolver {resolver}. Last-reported system route to loopback {route}. Current resolver state and system DNS routing are unverified. {scope}")
    }
}

fn overview_layer(current: bool, enabled: bool, limited: bool) -> LayerState {
    if !current {
        LayerState::Unknown
    } else if !enabled {
        LayerState::Off
    } else if limited {
        LayerState::Limited
    } else {
        LayerState::On
    }
}

fn overview_file_layer(current: bool, enabled: bool, socket_present: Option<bool>) -> LayerState {
    if !current || (enabled && socket_present.is_none()) {
        LayerState::Unknown
    } else {
        overview_layer(current, enabled, socket_present == Some(false))
    }
}

fn overview_headline(reading: OverviewReading) -> (&'static str, &'static str, Color32) {
    if !reading.current {
        (
            "Status unknown",
            "The recorded view could not refresh. Counts and activity may be stale.",
            AMBER,
        )
    } else if reading.paused {
        (
            "Automatic actions paused",
            "Detection can continue. Automatic file quarantine is paused; firewall and system DNS are unchanged.",
            AMBER,
        )
    } else if reading.pending_groups > 0 {
        (
            "Finding groups need investigation",
            "Review the stored classifications and reasons. Grouping is not confirmation of a threat or authorization for an action.",
            AMBER,
        )
    } else if reading.socket_present.is_none() {
        (
            "Scan coverage unknown",
            "The configured ClamAV socket path could not be checked. Engine coverage is unverified.",
            AMBER,
        )
    } else if reading.socket_present == Some(false) {
        (
            "Reduced scan coverage",
            "The configured ClamAV socket was not found. Scans may have reduced coverage or fail.",
            AMBER,
        )
    } else if reading.layers.scanning {
        (
            "Scan in progress",
            "A manual scan is running. Its final result is not available yet.",
            TEXT,
        )
    } else if [
        reading.layers.files,
        reading.layers.dns,
        reading.layers.integrity,
    ]
    .iter()
    .all(|layer| *layer == LayerState::Off)
    {
        (
            "Protection controls are off",
            "Manual scans and checks remain available. No folder watcher, local resolver or check timer is reported enabled.",
            TEXT,
        )
    } else if [
        reading.layers.files,
        reading.layers.dns,
        reading.layers.integrity,
    ]
    .iter()
    .any(|layer| *layer != LayerState::On)
    {
        (
            "Coverage is limited",
            "One or more controls are off or limited. Review the scope of each layer below.",
            AMBER,
        )
    } else {
        (
            "Protection controls enabled",
            "Folder watcher, local resolver and check timer are reported enabled. Engine health and protection scope are not verified here.",
            TEXT,
        )
    }
}

fn overview_pending_groups_note(count: i64) -> String {
    match count {
        0 => "No pending finding groups in this snapshot. This is not a safety verdict.".to_owned(),
        1 => "1 finding group needs investigation.".to_owned(),
        count => format!("{count} finding groups need investigation."),
    }
}

fn overview_control_row(
    ui: &mut egui::Ui,
    title: &str,
    detail: &str,
    action: &str,
    state_color: Color32,
    action_enabled: bool,
) -> bool {
    let mut clicked = false;
    ui.horizontal_top(|ui| {
        let control_width = 96.0;
        let copy_width =
            (ui.available_width() - control_width - ui.spacing().item_spacing.x).max(1.0);
        ui.vertical(|ui| {
            ui.set_width(copy_width);
            ui.label(RichText::new(title).strong().color(state_color));
            ui.add(egui::Label::new(RichText::new(detail).size(14.0).color(MUTED)).wrap());
        });
        clicked = ui
            .add_enabled(
                action_enabled,
                egui::Button::new(action).min_size(Vec2::new(control_width, 36.0)),
            )
            .clicked();
    });
    clicked
}

fn overview_recorded_event(ui: &mut egui::Ui, event: &Event, now_ms: i64) {
    let color = match event.level.as_str() {
        "error" => RED,
        "warn" => AMBER,
        _ => MUTED,
    };
    let recorded = |ui: &mut egui::Ui| {
        if let Some(subject) = event
            .subject
            .as_deref()
            .filter(|subject| !subject.is_empty())
        {
            ui.add(
                egui::Label::new(RichText::new(subject).monospace().size(15.0).color(TEXT))
                    .wrap()
                    .selectable(true),
            );
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(&event.kind)
                    .monospace()
                    .size(14.0)
                    .color(TEXT),
            );
            ui.label(RichText::new(&event.level).size(14.0).color(color));
        });
    };
    let age = |ui: &mut egui::Ui| {
        ui.add(
            egui::Label::new(
                RichText::new(overview_event_age(event.ts_ms, now_ms))
                    .size(14.0)
                    .color(MUTED),
            )
            .wrap(),
        )
        .on_hover_text(format!(
            "Record #{}; stored timestamp: {} ms since Unix epoch.",
            event.id, event.ts_ms
        ));
    };
    if ui.available_width() >= 440.0 {
        let usable = (ui.available_width() - ui.spacing().item_spacing.x).max(1.0);
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(100.0);
                age(ui);
            });
            ui.vertical(|ui| {
                ui.set_width((usable - 100.0).max(1.0));
                recorded(ui);
            });
        });
    } else {
        age(ui);
        recorded(ui);
    }
}

fn overview_event_age(timestamp_ms: i64, now_ms: i64) -> String {
    if timestamp_ms <= 0 {
        return "Time unavailable".into();
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

    fn enabled_reading() -> OverviewReading {
        OverviewReading {
            current: true,
            paused: false,
            pending_groups: 0,
            socket_present: Some(true),
            layers: ShieldState {
                files: LayerState::On,
                dns: LayerState::On,
                integrity: LayerState::On,
                scanning: false,
            },
        }
    }

    #[test]
    fn failed_refresh_takes_precedence_over_other_status() {
        let mut reading = enabled_reading();
        reading.current = false;
        reading.paused = true;
        reading.pending_groups = 7;
        reading.socket_present = Some(false);
        reading.layers.scanning = true;
        assert_eq!(overview_headline(reading).0, "Status unknown");
        assert_eq!(overview_layer(false, true, false), LayerState::Unknown);
        assert_eq!(overview_layer(false, false, true), LayerState::Unknown);
    }

    #[test]
    fn pending_groups_are_not_promoted_to_threats_or_raw_observation_counts() {
        let mut reading = enabled_reading();
        reading.pending_groups = 3;
        assert_eq!(
            overview_headline(reading).0,
            "Finding groups need investigation"
        );
        assert_eq!(
            overview_pending_groups_note(3),
            "3 finding groups need investigation."
        );
        assert_eq!(
            overview_pending_groups_note(1),
            "1 finding group needs investigation."
        );
        assert!(overview_pending_groups_note(0).contains("not a safety verdict"));
    }

    #[test]
    fn socket_presence_is_not_a_health_certificate() {
        let reading = enabled_reading();
        let (_, explanation, _) = overview_headline(reading);
        assert!(explanation.contains("not verified"));
        let mut missing = reading;
        missing.socket_present = Some(false);
        missing.layers.files = overview_file_layer(true, true, Some(false));
        assert_eq!(missing.layers.files, LayerState::Limited);
        assert_eq!(overview_headline(missing).0, "Reduced scan coverage");
    }

    #[test]
    fn socket_check_errors_are_not_reported_as_missing() {
        let mut reading = enabled_reading();
        reading.socket_present = None;
        reading.layers.files = overview_file_layer(true, true, None);
        assert_eq!(reading.layers.files, LayerState::Unknown);
        assert_eq!(overview_headline(reading).0, "Scan coverage unknown");
        assert_eq!(overview_file_layer(true, false, None), LayerState::Off);
    }

    #[test]
    fn local_dns_and_disabled_controls_remain_limited_or_off() {
        assert_eq!(overview_layer(true, true, true), LayerState::Limited);
        assert_eq!(overview_layer(true, false, true), LayerState::Off);
        assert_eq!(overview_layer(true, true, false), LayerState::On);
        let mut reading = enabled_reading();
        reading.layers.dns = LayerState::Limited;
        assert_eq!(overview_headline(reading).0, "Coverage is limited");
        reading.layers.files = LayerState::Off;
        reading.layers.dns = LayerState::Off;
        reading.layers.integrity = LayerState::Off;
        assert_eq!(overview_headline(reading).0, "Protection controls are off");
    }

    #[test]
    fn stale_dns_inspection_facts_are_last_reported_and_unverified() {
        let mut reading = enabled_reading();
        reading.current = false;
        for enabled in [false, true] {
            for routed in [false, true] {
                let detail = overview_dns_facts(reading.current, enabled, routed);
                let resolver = if enabled { "enabled" } else { "off" };
                let route = if routed { "detected" } else { "not detected" };
                assert!(detail.starts_with(&format!("Last-reported resolver {resolver}.")));
                assert!(
                    detail.contains(&format!("Last-reported system route to loopback {route}."))
                );
                assert!(detail
                    .contains("Current resolver state and system DNS routing are unverified."));
                assert!(detail.contains("Enabling the resolver does not change system DNS."));
            }
        }
    }

    #[test]
    fn current_dns_inspection_facts_preserve_reported_scope() {
        let reading = enabled_reading();
        for enabled in [false, true] {
            for routed in [false, true] {
                let resolver = if enabled { "enabled" } else { "off" };
                let route = if routed { "detected" } else { "not detected" };
                assert_eq!(
                    overview_dns_facts(reading.current, enabled, routed),
                    format!("Resolver {resolver}. System route to loopback {route}. Enabling the resolver does not change system DNS.")
                );
            }
        }
    }

    #[test]
    fn event_age_does_not_invent_a_timestamp() {
        assert_eq!(overview_event_age(0, 1000), "Time unavailable");
        assert_eq!(overview_event_age(2000, 1000), "Future timestamp");
        assert_eq!(overview_event_age(1000, 61_000), "1 min ago");
    }
}
