use crate::*;

const INTEGRITY_ORCHID: Color32 = Color32::from_rgb(201, 160, 255);

impl BlueApp {
    pub(crate) fn integrity(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("integrity-review-workspace")
            .auto_shrink([false, false])
            .show(ui, |ui| self.integrity_workspace(ui));
    }

    fn integrity_workspace(&mut self, ui: &mut egui::Ui) {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        self.header(
            ui,
            "Integrity review",
            "Recorded file, startup-path and package changes. Evidence to review, not a malware verdict.",
        );
        ui.horizontal_wrapped(|ui| {
            let check = ui.add_enabled(
                !self.jobs.contains("guard"),
                egui::Button::new(RichText::new("Run integrity check").color(TEXT))
                    .fill(BLUE)
                    .min_size(Vec2::new(178.0, 38.0)),
            );
            integrity_focus(ui, &check);
            if check.clicked() {
                self.run_guard();
            }
            if self.jobs.contains("guard") {
                ui.spinner();
                ui.label(
                    RichText::new("Checking; the previous completed report remains below.")
                        .color(AMBER),
                );
            } else {
                ui.label(
                    RichText::new(
                        "Reads watched paths and stores a comparison; does not repair files.",
                    )
                    .color(MUTED),
                );
            }
        });
        if let Some((message, good)) = &self.message {
            if !*good && message.starts_with("Integrity check failed:") {
                ui.add(egui::Label::new(RichText::new("The latest check failed. Review the error above before retrying; the report below may be from an earlier successful check.").color(AMBER)).wrap());
            }
        }
        ui.add_space(14.0);

        Frame::new()
            .fill(PANEL)
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.label(RichText::new("Last completed check in this session").size(17.0).strong().color(TEXT));
                if let Some(report) = self.last_guard {
                    if report.baseline {
                        ui.add(egui::Label::new(RichText::new("Reference established, not a clean bill of health.").strong().color(AMBER)).wrap());
                        ui.add(egui::Label::new(RichText::new(format!("{} entries recorded as the initial reference. The first pass does not emit change findings; another check is needed for comparison.", report.entries)).color(MUTED)).wrap());
                    } else {
                        ui.add_space(8.0);
                        ui.horizontal_wrapped(|ui| {
                            integrity_change_count(ui, "Added", report.added, BLUE);
                            integrity_change_count(ui, "Modified", report.modified, AMBER);
                            integrity_change_count(ui, "Removed", report.removed, INTEGRITY_ORCHID);
                        });
                        ui.add(egui::Label::new(RichText::new(format!("{} entries observed; {} source findings recorded by this check, not a pending-group count. Compared with the previous completed reference, which this check replaces.", report.entries, report.findings)).color(MUTED)).wrap());
                    }
                    ui.add_space(8.0);
                    if let Some(checked) = report.packages_checked {
                        ui.label(RichText::new(format!("Package validation completed: {checked} packages checked.")).color(MUTED));
                    } else if self.deps.config.guard.watch_packages {
                        ui.add(egui::Label::new(RichText::new("No completed package-validation result in this report. Coverage may be reduced; review recent check notes.").color(AMBER)).wrap());
                    } else {
                        ui.label(RichText::new("Package validation is disabled in the current configuration.").color(MUTED));
                    }
                } else {
                    ui.add_space(8.0);
                    ui.add(egui::Label::new(RichText::new("No completed check in this session. Recorded findings from earlier or scheduled checks can still appear below. Run a check to establish or compare the stored reference.").color(MUTED)).wrap());
                }
            });

        let scope = egui::CollapsingHeader::new("Watched paths and check coverage")
            .id_salt("integrity-configured-scope")
            .show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new("These are configured locations, not a list of everything on this machine. Inventory is bounded and does not follow symbolic links. A check does not enable protection, establish trust or prove the absence of malware.").color(MUTED)).wrap());
                if self.deps.config.guard.watch_paths.is_empty() {
                    ui.label(RichText::new("No watched paths configured.").color(AMBER));
                }
                for path in &self.deps.config.guard.watch_paths {
                    let expanded = blue_core::config::expand_tilde(path);
                    ui.add(egui::Label::new(RichText::new(expanded.to_string_lossy()).monospace().size(12.0).color(TEXT)).wrap().selectable(true));
                }
                ui.label(RichText::new(if self.guard_timer { "Scheduled check timer is active." } else { "Scheduled check timer is not active." }).color(MUTED));
            });
        integrity_focus(ui, &scope.header_response);
        ui.add_space(16.0);

        if let Some(error) = self.refresh_error.clone() {
            Frame::new()
                .stroke(Stroke::new(1.0, AMBER))
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.label(RichText::new("Recorded view could not refresh").strong().color(AMBER));
                    ui.add(egui::Label::new(RichText::new(error).color(TEXT)).wrap().selectable(true));
                    ui.add(egui::Label::new(RichText::new("The last loaded records may remain visible. Retry loading before treating this view as current.").color(MUTED)).wrap());
                    let retry = ui.button("Retry loading records");
                    integrity_focus(ui, &retry);
                    if retry.clicked() {
                        self.refresh();
                    }
                });
            ui.add_space(12.0);
        }

        let loaded_groups = self.snapshot.finding_groups.len();
        let groups = self
            .snapshot
            .finding_groups
            .iter()
            .filter(|group| integrity_kind(&group.kind))
            .collect::<Vec<_>>();
        let pending_records = groups
            .iter()
            .fold(0_i64, |count, group| count.saturating_add(group.pending));
        section_title(ui, "Pending change groups", "Stored review classifications and reasons accompany the representative source's evidence tier. Assessment is not a safety verdict.");
        ui.add(egui::Label::new(RichText::new(format!("Showing {} integrity, persistence and package groups with {pending_records} pending source records within {loaded_groups} loaded pending groups. The snapshot reports {} pending groups across all sources; the shared window is capped at 250 groups, not source records.", groups.len(), self.snapshot.counts.findings)).size(12.0).color(AMBER)).wrap());
        ui.add(egui::Label::new(RichText::new("Occurrences include all retained source history, including acknowledged records. Unique observations are observation identities, not a claim that all recorded evidence is identical. Informational history is excluded from this pending-only view.").size(12.0).color(MUTED)).wrap());
        ui.add(egui::Label::new(RichText::new("Acknowledge source record changes only the displayed representative record. Other pending members can keep the group here. It does not reverse a change, decide trust or authorize remediation.").size(12.0).color(MUTED)).wrap());
        ui.add_space(8.0);
        let mut acknowledge = None;
        if groups.is_empty() {
            Frame::new()
                .fill(PANEL)
                .inner_margin(egui::Margin::same(16))
                .show(ui, |ui| {
                    ui.label(RichText::new("No pending change groups in the loaded window").strong().color(TEXT));
                    ui.add(egui::Label::new(RichText::new("Run a check to record a comparison. Informational, acknowledged and older source history can still be retained. An empty queue is not a safety verdict, and this capped view is not a complete history.").color(MUTED)).wrap());
                });
        } else {
            egui::ScrollArea::vertical()
                .id_salt("integrity-recorded-ledger")
                .max_height(360.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for group in &groups {
                        if integrity_group(ui, group) {
                            acknowledge = finding_source_acknowledgement(group);
                        }
                    }
                });
        }
        if let Some(id) = acknowledge {
            self.acknowledge(id);
        }

        ui.add_space(16.0);
        let events = self
            .snapshot
            .events
            .iter()
            .filter(|event| matches!(event.kind.as_str(), "guard" | "guard.packages"))
            .collect::<Vec<_>>();
        let notes = egui::CollapsingHeader::new(format!("Recent check notes ({})", events.len()))
            .id_salt("integrity-recent-check-notes")
            .show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new("Only guard events within the latest 60 events across all sources are loaded. This is not a complete check history. Recorded payloads can include truncation or reduced package coverage.").size(12.0).color(AMBER)).wrap());
                if events.is_empty() {
                    ui.label(RichText::new("No guard events in the loaded recent window.").color(MUTED));
                }
                for event in events {
                    ui.push_id(event.id, |ui| {
                        ui.add_space(8.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(if event.kind == "guard.packages" { "Package check note" } else { "Recorded comparison" }).strong().color(if event.level == "warn" { AMBER } else { TEXT }));
                            ui.label(RichText::new(integrity_record_age(event.ts_ms, blue_core::now_ms())).size(12.0).color(MUTED));
                        });
                        if let Some(subject) = &event.subject {
                            ui.add(egui::Label::new(RichText::new(subject).color(MUTED)).wrap());
                        }
                        ui.add(egui::Label::new(RichText::new(&event.payload).monospace().size(12.0).color(TEXT)).wrap().selectable(true));
                        let copy = ui.button("Copy check note");
                        integrity_focus(ui, &copy);
                        if copy.clicked() {
                            ui.ctx().copy_text(format!("{}\nRecorded at {} Unix ms\n{}", event.kind, event.ts_ms, event.payload));
                        }
                        ui.separator();
                    });
                }
            });
        integrity_focus(ui, &notes.header_response);
    }
}

fn integrity_kind(kind: &str) -> bool {
    matches!(kind, "integrity" | "persistence" | "package")
}

fn integrity_change_count(ui: &mut egui::Ui, label: &str, count: usize, color: Color32) {
    ui.vertical(|ui| {
        ui.set_min_width(128.0);
        ui.label(RichText::new(label).size(12.0).color(MUTED));
        ui.label(
            RichText::new(count.to_string())
                .size(26.0)
                .strong()
                .color(color),
        );
    });
}

fn integrity_group(ui: &mut egui::Ui, group: &blue_core::FindingGroup) -> bool {
    let finding = &group.representative.finding;
    let assessment = &group.representative.review;
    let mut reviewed = false;
    ui.push_id(&group.group_key, |ui| {
        ui.horizontal_wrapped(|ui| {
            let label = match finding.kind.as_str() {
                "persistence" => "Startup-path change",
                "package" => "Package observation",
                _ => "Integrity observation",
            };
            ui.label(RichText::new(label).size(12.0).color(INTEGRITY_ORCHID));
            ui.label(RichText::new(integrity_record_age(group.last_seen_ms, blue_core::now_ms())).size(12.0).color(MUTED));
        });
        finding_group_review(ui, group);
        let record = egui::CollapsingHeader::new(RichText::new(&finding.subject).strong().color(TEXT))
            .id_salt(("integrity-evidence", finding.id))
            .show(ui, |ui| {
                ui.label(RichText::new("Representative source record detail, not the entire group history").size(12.0).color(MUTED));
                ui.add(egui::Label::new(RichText::new(&finding.detail).monospace().size(12.0).color(TEXT)).wrap().selectable(true));
                ui.label(RichText::new(format!("Source record {} at {} Unix ms", finding.id, finding.ts_ms)).monospace().size(11.0).color(MUTED));
                ui.add(egui::Label::new(RichText::new(format!("Review reason code: {}; policy version {}. Group first/last retained timestamps: {} / {} Unix ms.", assessment.reason_code, assessment.policy_version, group.first_seen_ms, group.last_seen_ms)).size(12.0).color(MUTED)).wrap());
                ui.horizontal_wrapped(|ui| {
                    let copy = ui.button("Copy source evidence");
                    integrity_focus(ui, &copy);
                    if copy.clicked() {
                        ui.ctx().copy_text(format!("Source record {}\n{}\n{}\nT{}\nRecorded at {} Unix ms\nAssessment: {}\nReason: {}\n{}", finding.id, finding.subject, finding.kind, finding.tier.as_i64(), finding.ts_ms, finding_review_label(assessment.classification), assessment.reason, finding.detail));
                    }
                    let review = ui.add_enabled(finding_source_acknowledgement(group).is_some(), egui::Button::new("Acknowledge source record"))
                        .on_hover_text(format!("Acknowledge source record {} only, not the entire group. Other pending records remain; no repair or trust decision is made.", finding.id));
                    integrity_focus(ui, &review);
                    reviewed = review.clicked();
                });
            });
        integrity_focus(ui, &record.header_response);
        ui.separator();
    });
    reviewed
}

pub(super) fn finding_review_label(
    classification: blue_core::ReviewClassification,
) -> &'static str {
    match classification {
        blue_core::ReviewClassification::Unreviewed => "Unreviewed",
        blue_core::ReviewClassification::Informational => "Informational",
        blue_core::ReviewClassification::NeedsInvestigation => "Needs investigation",
        blue_core::ReviewClassification::Actionable => "Actionable",
    }
}

pub(super) fn finding_group_counts(group: &blue_core::FindingGroup) -> String {
    format!(
        "{} retained source occurrences · {} unique observation identities · {} unacknowledged source records · {} pending source records",
        group.occurrences, group.unique_observations, group.unacknowledged, group.pending,
    )
}

pub(super) fn finding_group_review(ui: &mut egui::Ui, group: &blue_core::FindingGroup) {
    let color = match group.classification {
        blue_core::ReviewClassification::Actionable => RED,
        blue_core::ReviewClassification::Informational => MUTED,
        blue_core::ReviewClassification::Unreviewed
        | blue_core::ReviewClassification::NeedsInvestigation => AMBER,
    };
    ui.horizontal_wrapped(|ui| {
        tier_badge(ui, group.representative.finding.tier);
        ui.label(
            RichText::new(format!(
                "Assessment: {}",
                finding_review_label(group.classification)
            ))
            .size(12.0)
            .strong()
            .color(color),
        );
    });
    ui.add(
        egui::Label::new(RichText::new(&group.reason).size(13.0).color(TEXT))
            .wrap()
            .selectable(true),
    );
    ui.add(
        egui::Label::new(
            RichText::new(finding_group_counts(group))
                .size(12.0)
                .color(MUTED),
        )
        .wrap(),
    );
}

pub(super) fn finding_source_acknowledgement(group: &blue_core::FindingGroup) -> Option<i64> {
    let source = &group.representative.finding;
    source.acknowledged_at_ms.is_none().then_some(source.id)
}

fn integrity_record_age(recorded_ms: i64, now_ms: i64) -> String {
    let Some(elapsed) = now_ms.checked_sub(recorded_ms) else {
        return "Recorded time cannot be compared with this clock".to_owned();
    };
    if elapsed < 0 {
        return "Recorded timestamp is ahead of this clock".to_owned();
    }
    let minutes = elapsed / 60_000;
    if minutes == 0 {
        "Recorded within the last minute".to_owned()
    } else if minutes < 60 {
        format!("Recorded {minutes} min ago")
    } else if minutes < 24 * 60 {
        format!("Recorded {} h ago", minutes / 60)
    } else {
        format!("Recorded {} d ago", minutes / (24 * 60))
    }
}

fn integrity_focus(ui: &egui::Ui, response: &egui::Response) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.expand(2.0),
            6.0,
            Stroke::new(2.0, BLUE),
            egui::StrokeKind::Outside,
        );
        if response.gained_focus() {
            response.scroll_to_me(Some(Align::Center));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blue_core::Finding;

    fn source_fixture() -> Finding {
        Finding {
            id: 41,
            ts_ms: 1000,
            kind: "integrity".into(),
            tier: Tier::Candidate,
            subject: "Fixture watched path".into(),
            detail: "Fixture evidence".into(),
            acknowledged_at_ms: None,
        }
    }

    fn grouped_history() -> blue_core::FindingGroup {
        let finding = source_fixture();
        let review = blue_core::assess_finding(&finding, 1000);
        blue_core::FindingGroup {
            group_key: review.group_key.clone(),
            classification: review.classification,
            reason_code: review.reason_code.clone(),
            reason: review.reason.clone(),
            kind: finding.kind.clone(),
            first_seen_ms: 100,
            last_seen_ms: 1000,
            occurrences: 899,
            unique_observations: 3,
            unacknowledged: 17,
            pending: 2,
            representative: blue_core::ReviewedFinding { finding, review },
        }
    }

    #[test]
    fn grouped_caption_distinguishes_history_from_pending_sources() {
        let caption = finding_group_counts(&grouped_history());
        assert!(caption.contains("899 retained source occurrences"));
        assert!(caption.contains("3 unique observation identities"));
        assert!(caption.contains("17 unacknowledged source records"));
        assert!(caption.contains("2 pending source records"));
    }

    #[test]
    fn acknowledgement_targets_only_the_representative_source() {
        let mut group = grouped_history();
        assert_eq!(finding_source_acknowledgement(&group), Some(41));
        group.representative.finding.acknowledged_at_ms = Some(2000);
        assert_eq!(finding_source_acknowledgement(&group), None);
        assert_eq!(group.pending, 2);
    }

    #[test]
    fn review_labels_preserve_the_stored_classification() {
        use blue_core::ReviewClassification::*;
        for (class, label) in [
            (Unreviewed, "Unreviewed"),
            (Informational, "Informational"),
            (NeedsInvestigation, "Needs investigation"),
            (Actionable, "Actionable"),
        ] {
            assert_eq!(finding_review_label(class), label);
        }
    }

    #[test]
    fn recorded_integrity_view_does_not_include_other_finding_sources() {
        for kind in ["integrity", "persistence", "package"] {
            assert!(integrity_kind(kind));
        }
        for kind in ["network", "reputation", "scan", "Integrity", ""] {
            assert!(!integrity_kind(kind));
        }
    }

    #[test]
    fn record_age_uses_recorded_time_without_inventing_a_recent_check() {
        assert_eq!(
            integrity_record_age(60_000, 60_001),
            "Recorded within the last minute"
        );
        assert_eq!(integrity_record_age(0, 120_000), "Recorded 2 min ago");
        assert_eq!(
            integrity_record_age(120_000, 60_000),
            "Recorded timestamp is ahead of this clock"
        );
        assert_eq!(
            integrity_record_age(i64::MIN, i64::MAX),
            "Recorded time cannot be compared with this clock"
        );
    }
}
