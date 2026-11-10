use crate::*;

const CLEANUP_ORCHID: Color32 = Color32::from_rgb(201, 160, 255);
const CLEANUP_LEDGER_MIN_HEIGHT: f32 = 240.0;
const CLEANUP_REVIEW_RESERVE: f32 = 320.0;
const CLEANUP_RECEIPTS_MAX_HEIGHT: f32 = 160.0;

impl BlueApp {
    pub(crate) fn cleanup(&mut self, ui: &mut egui::Ui) {
        cleanup_workspace(ui, |ui, viewport_height| {
            self.cleanup_content(ui, viewport_height);
        });
    }

    fn cleanup_content(&mut self, ui: &mut egui::Ui, viewport_height: f32) {
        let page_top = ui.cursor().top();
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        self.header(
            ui,
            "Cleanup review",
            "Read-only analysis, manual selection, then exact approval for permanent deletion.",
        );
        ui.horizontal_wrapped(|ui| {
            let analyze = ui
                .add_enabled(
                    !self.jobs.contains("cleanup-scan") && !self.jobs.contains("cleanup-apply"),
                    egui::Button::new(RichText::new("Analyze storage").color(TEXT))
                        .fill(BLUE)
                        .min_size(Vec2::new(160.0, 38.0)),
                )
                .on_hover_text("Inventory bounded cleanup locations without deleting files.");
            cleanup_focus(ui, &analyze);
            if analyze.clicked() {
                self.run_cleanup_scan();
            }
            if self.jobs.contains("cleanup-scan") {
                ui.spinner();
                ui.label(
                    RichText::new("Analyzing; the previous inventory may remain below.")
                        .color(AMBER),
                );
            } else if self.jobs.contains("cleanup-apply") {
                ui.spinner();
                ui.label(
                    RichText::new("Applying approved deletion. Selection is locked.").color(AMBER),
                );
            } else {
                ui.label(RichText::new("Nothing is selected automatically.").color(MUTED));
            }
        });
        ui.add(egui::Label::new(
            RichText::new("EFI, backups, snapshots and partial downloads remain protected. Elevated or unsupported items are list-only.")
                .size(12.0)
                .color(MUTED),
        ).wrap());
        ui.add_space(16.0);

        let Some(report) = self.cleanup_report.clone() else {
            cleanup_note(
                ui,
                "No completed storage analysis",
                "Analyze storage to create a candidate ledger. If analysis failed, review the error above and retry. Analysis itself does not delete anything.",
                BLUE,
            );
            if let Some(applied) = &self.last_cleanup_apply {
                ui.add_space(16.0);
                cleanup_receipts(ui, applied);
            }
            return;
        };

        if let Some((message, good)) = &self.message {
            if !*good && message.starts_with("Cleanup analysis failed:") {
                ui.add(egui::Label::new(RichText::new("The latest analysis failed. These are the previous completed results; review the error above before retrying.").color(AMBER)).wrap());
                ui.add_space(8.0);
            } else if !*good && message.starts_with("Cleanup refused:") {
                ui.add(egui::Label::new(RichText::new("Cleanup did not complete successfully. Review the error and reanalyze before retrying; some approved actions may already have run.").color(AMBER)).wrap());
                ui.add_space(8.0);
            }
        }

        let list_only = report
            .candidates
            .iter()
            .filter(|item| !cleanup_selectable(item))
            .count();
        Frame::new()
            .fill(PANEL)
            .inner_margin(egui::Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    cleanup_estimate(ui, "Safe category", &format_bytes(report.safe_bytes), CLEANUP_ORCHID);
                    cleanup_estimate(ui, "Review category", &format_bytes(report.review_bytes), AMBER);
                    cleanup_estimate(ui, "List-only candidates", &list_only.to_string(), MUTED);
                });
                ui.add_space(4.0);
                ui.add(egui::Label::new(
                    RichText::new("Category totals are estimates, not all selectable. Bounded walks and hard links can affect sizes; freed space is not guaranteed.")
                        .size(12.0)
                        .color(MUTED),
                ).wrap());
            });
        ui.add_space(12.0);

        if report.truncated {
            cleanup_note(
                ui,
                "Analysis reached a limit",
                "This is a partial inventory. The ledger and its size estimates do not cover every candidate or location.",
                AMBER,
            );
            ui.add_space(8.0);
        }
        if !report.diagnostics.is_empty() {
            let notes = egui::CollapsingHeader::new(
                RichText::new(format!("Analysis notes ({})", report.diagnostics.len()))
                    .color(AMBER),
            )
            .id_salt("cleanup-analysis-notes")
            .default_open(true)
            .show(ui, |ui| {
                for diagnostic in &report.diagnostics {
                    ui.add(
                        egui::Label::new(RichText::new(diagnostic).color(AMBER))
                            .wrap()
                            .selectable(true),
                    );
                    ui.add_space(4.0);
                }
            });
            cleanup_focus(ui, &notes.header_response);
            ui.add_space(8.0);
        }

        let detail_key = egui::Id::unique("cleanup-reviewed-candidate");
        let mut detail_id = ui.ctx().data(|data| data.get_temp::<String>(detail_key));
        if !report
            .candidates
            .iter()
            .any(|item| Some(&item.id) == detail_id.as_ref())
        {
            detail_id = None;
        }
        let ledger_height = cleanup_ledger_height(viewport_height, ui.cursor().top() - page_top);
        let review_approval;
        if ui.available_width() >= 800.0 && !report.candidates.is_empty() {
            review_approval = ui.columns(2, |columns| {
                let review =
                    self.cleanup_ledger(&mut columns[0], &report, &mut detail_id, ledger_height);
                cleanup_details(&mut columns[1], &report, detail_id.as_deref());
                review
            });
        } else {
            review_approval = self.cleanup_ledger(ui, &report, &mut detail_id, ledger_height);
            if detail_id.is_some() {
                ui.add_space(12.0);
                cleanup_details(ui, &report, detail_id.as_deref());
            }
        }
        ui.ctx().data_mut(|data| {
            if let Some(id) = detail_id {
                data.insert_temp(detail_key, id);
            } else {
                data.remove::<String>(detail_key);
            }
        });

        ui.add_space(16.0);
        let approval_rect = self.cleanup_approval(ui, &report);
        if review_approval {
            // This only navigates to approval; it never fills or submits the phrase.
            ui.scroll_to_rect(approval_rect, Some(Align::Center));
        }

        if let Some(applied) = &self.last_cleanup_apply {
            ui.add_space(16.0);
            cleanup_receipts(ui, applied);
        }

        ui.add_space(16.0);
        let system_plan = egui::CollapsingHeader::new("Read-only system cleanup plan")
            .id_salt("cleanup-system-plan")
            .show(ui, |ui| {
                ui.add(egui::Label::new(
                    RichText::new("Elevated items cannot be deleted here. Copying this plan command does not execute it or approve deletion.").color(MUTED),
                ).wrap());
                let copy = ui.button("Copy read-only system plan command");
                cleanup_focus(ui, &copy);
                if copy.clicked() {
                    let setup_dir = extension_path()
                        .parent()
                        .map(|path| path.join("scripts"))
                        .unwrap_or_else(|| PathBuf::from("scripts"));
                    ui.ctx().copy_text(script_plan_command(&setup_dir.join("cleanup-system.sh")));
                    self.message = Some(("Read-only system cleanup plan command copied".into(), true));
                }
            });
        cleanup_focus(ui, &system_plan.header_response);

        if let Some(performance) = &self.cleanup_performance {
            let observation = egui::CollapsingHeader::new("Memory and processes at analysis")
                .id_salt("cleanup-performance-observation")
                .show(ui, |ui| cleanup_performance(ui, performance));
            cleanup_focus(ui, &observation.header_response);
        }
    }

    fn cleanup_ledger(
        &mut self,
        ui: &mut egui::Ui,
        report: &blue_cleanup::CleanupReport,
        detail_id: &mut Option<String>,
        height: f32,
    ) -> bool {
        section_title(
            ui,
            "Candidate ledger",
            "Select only what you reviewed. View details does not select an item.",
        );
        let (selected_count, selected_bytes) = report
            .candidates
            .iter()
            .filter(|item| cleanup_selectable(item) && self.cleanup_selected.contains(&item.id))
            .fold((0usize, 0u64), |(count, bytes), item| {
                (count + 1, bytes.saturating_add(item.bytes))
            });
        let mut review_approval = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{selected_count} selected in this inventory, {} estimated",
                    format_bytes(selected_bytes)
                ))
                .color(if selected_count == 0 { MUTED } else { AMBER }),
            );
            if selected_count != 0 {
                let review = ui.button("Review deletion approval").on_hover_text(
                    "Go to the exact typed approval. This does not approve or delete anything.",
                );
                cleanup_focus(ui, &review);
                review_approval = review.clicked();
            }
        });
        ui.add_space(8.0);
        if report.candidates.is_empty() {
            cleanup_note(
                ui,
                "No candidates in this analysis",
                "The configured, bounded locations produced no candidates. This is not a full disk audit. Review analysis notes or analyze again.",
                MUTED,
            );
            return false;
        }

        let busy = self.jobs.contains("cleanup-scan") || self.jobs.contains("cleanup-apply");
        cleanup_ledger_scroller(ui, height).show(ui, |ui| {
            for candidate in &report.candidates {
                ui.push_id(&candidate.id, |ui| {
                    let selectable = cleanup_selectable(candidate);
                    let mut selected = selectable && self.cleanup_selected.contains(&candidate.id);
                    let inspecting = detail_id.as_deref() == Some(candidate.id.as_str());
                    Frame::new()
                        .fill(if inspecting {
                            PANEL_HOVER
                        } else {
                            Color32::TRANSPARENT
                        })
                        .inner_margin(egui::Margin::symmetric(8, 10))
                        .show(ui, |ui| {
                            let response = ui.add_enabled(
                                selectable && !busy,
                                egui::Checkbox::new(
                                    &mut selected,
                                    RichText::new(&candidate.label).strong().color(TEXT),
                                ),
                            );
                            cleanup_focus(ui, &response);
                            if response.changed() {
                                if selected {
                                    self.cleanup_selected.insert(candidate.id.clone());
                                } else {
                                    self.cleanup_selected.remove(&candidate.id);
                                }
                                self.cleanup_confirmation.clear();
                            }
                            ui.horizontal_wrapped(|ui| {
                                cleanup_risk_label(ui, candidate.risk);
                                ui.label(
                                    RichText::new(cleanup_candidate_size(candidate))
                                        .monospace()
                                        .color(TEXT),
                                );
                                if !selectable {
                                    ui.label(RichText::new("List only").color(MUTED));
                                }
                                let details = ui.button(if inspecting {
                                    "Viewing details"
                                } else {
                                    "View details"
                                });
                                cleanup_focus(ui, &details);
                                if details.clicked() {
                                    *detail_id = Some(candidate.id.clone());
                                }
                            });
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&candidate.reason).size(12.0).color(MUTED),
                                )
                                .wrap(),
                            );
                            if let Some(warning) = &candidate.warning {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(warning).size(12.0).color(AMBER),
                                    )
                                    .wrap(),
                                );
                            }
                            if !selectable {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(cleanup_unavailable_reason(candidate))
                                            .size(12.0)
                                            .color(AMBER),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                    ui.separator();
                });
            }
        });
        review_approval
    }

    fn cleanup_approval(
        &mut self,
        ui: &mut egui::Ui,
        report: &blue_cleanup::CleanupReport,
    ) -> egui::Rect {
        let selected = report
            .candidates
            .iter()
            .filter(|candidate| {
                cleanup_selectable(candidate) && self.cleanup_selected.contains(&candidate.id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let busy = self.jobs.contains("cleanup-scan") || self.jobs.contains("cleanup-apply");
        let selection_current = selected.len() == self.cleanup_selected.len();
        let required = blue_cleanup::CleanupEngine::required_confirmation(&selected);
        Frame::new()
            .fill(PANEL)
            .stroke(Stroke::new(1.5, if self.cleanup_selected.is_empty() { BORDER } else { RED }))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Deletion approval").size(19.0).strong().color(TEXT));
                    ui.label(RichText::new(format!("{} selected, {} estimated", selected.len(), format_bytes(cleanup_selected_bytes(&selected)))).strong().color(AMBER));
                });
                ui.add(egui::Label::new(
                    RichText::new("Permanent deletion, not quarantine. Cleanup provides no restore action. The engine rescans and revalidates every selected path before deleting.").color(MUTED),
                ).wrap());
                ui.add_space(8.0);
                if !selection_current {
                    ui.add(egui::Label::new(RichText::new("Selection no longer matches this analysis. Deletion is disabled. Clear selection or analyze again.").strong().color(AMBER)).wrap());
                } else if selected.is_empty() {
                    ui.label(RichText::new("Nothing selected. Choose reviewed candidates to begin approval.").color(MUTED));
                } else {
                    ui.add(egui::Label::new(RichText::new("TYPE the exact phrase below, including case and spaces, then press Delete selected. Clicking the phrase does not delete anything.").color(TEXT)).wrap());
                    ui.add(egui::Label::new(RichText::new(&required).monospace().size(22.0).strong().color(AMBER)).wrap());
                    let confirmation = ui.add_enabled_ui(!busy, |ui| ui.add_sized(
                        [ui.available_width(), 38.0],
                        egui::TextEdit::singleline(&mut self.cleanup_confirmation)
                            .id(egui::Id::unique("cleanup-exact-confirmation"))
                            .hint_text("Type the phrase above; nothing is prefilled"),
                    )).inner;
                    cleanup_focus(ui, &confirmation);
                    if !busy && self.cleanup_confirmation != required {
                        ui.label(RichText::new("Deletion stays disabled until the phrase matches exactly.").size(12.0).color(MUTED));
                    }
                }
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    let clear = ui.add_enabled(!busy && !self.cleanup_selected.is_empty(), egui::Button::new("Clear selection"));
                    cleanup_focus(ui, &clear);
                    if clear.clicked() {
                        self.cleanup_selected.clear();
                        self.cleanup_confirmation.clear();
                    }
                    let delete = ui.add_enabled(
                        cleanup_approval_ready(&selected, &self.cleanup_selected, &self.cleanup_confirmation, busy),
                        egui::Button::new(RichText::new("Delete selected").strong().color(BG))
                            .fill(RED)
                            .stroke(Stroke::new(1.0, RED))
                            .min_size(Vec2::new(150.0, 38.0)),
                    );
                    cleanup_focus(ui, &delete);
                    if delete.clicked() {
                        self.apply_cleanup();
                    }
                    if self.jobs.contains("cleanup-apply") {
                        ui.spinner();
                        ui.label(RichText::new("Deleting approved selection; controls are locked.").color(AMBER));
                    } else if self.jobs.contains("cleanup-scan") {
                        ui.label(RichText::new("Approval is locked while analysis runs.").color(AMBER));
                    }
                });
                let key = ui.make_persistent_id("cleanup-last-apply-error");
                if let Some(error) = &self.cleanup_apply_error {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Last deletion attempt needs attention").strong().color(RED));
                    let shown = ui.add(egui::Label::new(RichText::new(error).color(RED)).wrap());
                    let changed = ui.data_mut(|data| {
                        let changed = data.get_temp::<String>(key).as_deref() != Some(error.as_str());
                        if changed { data.insert_temp(key, error.clone()); }
                        changed
                    });
                    if changed { shown.scroll_to_me(Some(Align::BOTTOM)); }
                } else {
                    ui.data_mut(|data| data.remove::<String>(key));
                }
            })
            .response
            .rect
    }
}

fn cleanup_workspace<R>(
    ui: &mut egui::Ui,
    content: impl FnOnce(&mut egui::Ui, f32) -> R,
) -> egui::scroll_area::ScrollAreaOutput<R> {
    let viewport_height = ui.available_height().max(1.0);
    egui::ScrollArea::vertical()
        .id_salt("cleanup-workspace")
        .max_height(viewport_height)
        .min_scrolled_height(1.0)
        .auto_shrink([false, false])
        // Safety-control jumps must settle before the next frame's layout.
        // egui's animated target updates after laying out the child, even when
        // ScrollAnimation::none() is selected. Wheel scrolling is unaffected.
        .animated(false)
        .show(ui, |ui| content(ui, viewport_height))
}

fn cleanup_ledger_height(viewport_height: f32, prefix_height: f32) -> f32 {
    // Use the remaining viewport on roomy windows. When notes/approval do not fit,
    // the page scrolls instead of letting the nested ledger collapse to 64 points.
    (viewport_height - prefix_height - CLEANUP_REVIEW_RESERVE)
        .max(CLEANUP_LEDGER_MIN_HEIGHT)
        .min(viewport_height.max(1.0))
}

fn cleanup_ledger_scroller(ui: &egui::Ui, height: f32) -> egui::ScrollArea {
    cleanup_bounded_scroller(ui, "cleanup-candidate-ledger", height)
}

fn cleanup_bounded_scroller(ui: &egui::Ui, id_salt: &str, height: f32) -> egui::ScrollArea {
    let top = ui.available_rect_before_wrap().top();
    let clip = ui.clip_rect();
    let fully_visible = top >= clip.top() - 0.5 && top + height <= clip.bottom() + 0.5;
    // If the page clips a bounded list, wheel the page to expose its viewport first.
    // Once exposed, egui routes wheel input to the list and chains at its edges.
    egui::ScrollArea::vertical()
        .id_salt(id_salt)
        .min_scrolled_height(height)
        .max_height(height)
        .auto_shrink([false, true])
        .scroll_source(egui::scroll_area::ScrollSource {
            mouse_wheel: fully_visible,
            ..Default::default()
        })
}

fn cleanup_receipts(
    ui: &mut egui::Ui,
    applied: &blue_cleanup::ApplyReport,
) -> egui::scroll_area::ScrollAreaOutput<()> {
    let succeeded = applied
        .receipts
        .iter()
        .filter(|receipt| receipt.success)
        .count();
    let failed = applied.receipts.len() - succeeded;
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, if failed == 0 { BORDER } else { AMBER }))
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.label(RichText::new("Last completed cleanup attempt").size(19.0).strong().color(TEXT));
            ui.add(egui::Label::new(RichText::new(format!(
                "{succeeded} succeeded, {failed} failed; {} reclaimed (estimate)",
                format_bytes(applied.reclaimed_estimate),
            )).color(if failed == 0 { TEXT } else { AMBER })).wrap());
            ui.add(egui::Label::new(RichText::new(
                "Recorded outcomes retained after reanalysis, not the current selection. Analyzing again does not retry these actions; actual freed space is not guaranteed.",
            ).size(12.0).color(MUTED)).wrap());
            ui.add_space(8.0);
            cleanup_bounded_scroller(ui, "cleanup-apply-receipts", CLEANUP_RECEIPTS_MAX_HEIGHT)
                .show(ui, |ui| {
                    if applied.receipts.is_empty() {
                        ui.add(egui::Label::new(RichText::new("No per-candidate receipts were returned for this attempt.").color(MUTED)).wrap());
                    }
                    for receipt in &applied.receipts {
                        ui.push_id(&receipt.id, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(if receipt.success { "Succeeded" } else { "Failed" })
                                    .size(12.0).strong().color(if receipt.success { TEXT } else { AMBER }));
                                ui.add(egui::Label::new(RichText::new(&receipt.label).strong().color(TEXT)).wrap());
                            });
                            if let Some(error) = &receipt.error {
                                ui.add(egui::Label::new(RichText::new(error).size(12.0).color(AMBER)).wrap().selectable(true));
                            } else if !receipt.success {
                                ui.add(egui::Label::new(RichText::new("The action failed; no error details were returned.").size(12.0).color(AMBER)).wrap());
                            }
                            ui.separator();
                        });
                    }
                })
        })
        .inner
}

fn cleanup_selectable(candidate: &blue_cleanup::CleanupCandidate) -> bool {
    candidate.supported
        && !candidate.requires_root
        && candidate.risk != blue_cleanup::CleanupRisk::Protected
}

fn cleanup_selected_bytes(selected: &[blue_cleanup::CleanupCandidate]) -> u64 {
    selected
        .iter()
        .fold(0, |total: u64, item| total.saturating_add(item.bytes))
}

fn cleanup_approval_ready(
    selected: &[blue_cleanup::CleanupCandidate],
    ids: &HashSet<String>,
    confirmation: &str,
    busy: bool,
) -> bool {
    if busy
        || selected.is_empty()
        || selected.len() != ids.len()
        || !selected.iter().all(cleanup_selectable)
    {
        return false;
    }
    let current_ids = selected
        .iter()
        .map(|item| item.id.as_str())
        .collect::<HashSet<_>>();
    current_ids.len() == ids.len()
        && ids.iter().all(|id| current_ids.contains(id.as_str()))
        && confirmation == blue_cleanup::CleanupEngine::required_confirmation(selected)
}

fn cleanup_unavailable_reason(candidate: &blue_cleanup::CleanupCandidate) -> &'static str {
    if candidate.risk == blue_cleanup::CleanupRisk::Protected {
        "Protected by the cleanup policy; cannot be selected."
    } else if candidate.requires_root {
        "Requires elevated privileges; cannot be selected here."
    } else {
        "No supported deletion action; cannot be selected."
    }
}

fn cleanup_candidate_size(candidate: &blue_cleanup::CleanupCandidate) -> String {
    if candidate.risk == blue_cleanup::CleanupRisk::Protected && candidate.bytes == 0 {
        "Not sized".to_owned()
    } else {
        format_bytes(candidate.bytes)
    }
}

fn cleanup_risk_label(ui: &mut egui::Ui, risk: blue_cleanup::CleanupRisk) {
    let (label, color) = match risk {
        blue_cleanup::CleanupRisk::Safe => ("Safe category", CLEANUP_ORCHID),
        blue_cleanup::CleanupRisk::Review => ("Review required", AMBER),
        blue_cleanup::CleanupRisk::Protected => ("Protected", MUTED),
    };
    ui.label(RichText::new(label).size(12.0).strong().color(color));
}

fn cleanup_estimate(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    ui.vertical(|ui| {
        ui.set_min_width(158.0);
        ui.label(RichText::new(label).size(12.0).color(MUTED));
        ui.label(RichText::new(value).size(21.0).strong().color(color));
    });
}

fn cleanup_note(ui: &mut egui::Ui, title: &str, detail: &str, color: Color32) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, color))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(color));
            ui.add(egui::Label::new(RichText::new(detail).color(MUTED)).wrap());
        });
}

fn cleanup_details(
    ui: &mut egui::Ui,
    report: &blue_cleanup::CleanupReport,
    detail_id: Option<&str>,
) {
    Frame::new()
        .fill(PANEL)
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            section_title(ui, "Candidate details", "Inspection is not deletion approval.");
            let Some(candidate) = report.candidates.iter().find(|item| Some(item.id.as_str()) == detail_id) else {
                ui.add_space(12.0);
                ui.add(egui::Label::new(RichText::new("Choose View details in the ledger to inspect a path, its reason and any restrictions. Nothing is selected by opening details.").color(MUTED)).wrap());
                return;
            };
            ui.add_space(12.0);
            ui.add(egui::Label::new(RichText::new(&candidate.label).size(17.0).strong().color(TEXT)).wrap());
            cleanup_risk_label(ui, candidate.risk);
            let size = if candidate.risk == blue_cleanup::CleanupRisk::Protected && candidate.bytes == 0 {
                "Size not measured".to_owned()
            } else {
                format!("{} estimated", format_bytes(candidate.bytes))
            };
            ui.label(RichText::new(size).monospace().color(TEXT));
            ui.add_space(8.0);
            ui.add(egui::Label::new(RichText::new(&candidate.reason).color(TEXT)).wrap());
            if let Some(warning) = &candidate.warning {
                ui.add_space(8.0);
                ui.add(egui::Label::new(RichText::new(warning).color(AMBER)).wrap());
            }
            if !cleanup_selectable(candidate) {
                ui.add(egui::Label::new(RichText::new(cleanup_unavailable_reason(candidate)).strong().color(AMBER)).wrap());
            }
            ui.add_space(10.0);
            ui.label(RichText::new("Recorded path").color(MUTED));
            if let Some(path) = &candidate.path {
                ui.add(egui::Label::new(RichText::new(path.to_string_lossy()).monospace().size(12.0).color(TEXT)).wrap().selectable(true));
                let copy = ui.button("Copy path");
                cleanup_focus(ui, &copy);
                if copy.clicked() {
                    ui.ctx().copy_text(path.to_string_lossy().into_owned());
                }
            } else {
                ui.add(egui::Label::new(RichText::new("No filesystem path recorded for this observation.").color(MUTED)).wrap());
            }
            ui.add_space(8.0);
            ui.label(RichText::new(if candidate.reproducible { "Marked reproducible by the analysis." } else { "Not marked reproducible; review what would be lost." }).color(MUTED));
            let identity = egui::CollapsingHeader::new("Candidate ID")
                .id_salt(("cleanup-candidate-id", &candidate.id))
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(&candidate.id).monospace().size(12.0).color(MUTED)).wrap().selectable(true));
                });
            cleanup_focus(ui, &identity.header_response);
        });
}

fn cleanup_performance(ui: &mut egui::Ui, performance: &blue_cleanup::PerformanceSnapshot) {
    ui.add(egui::Label::new(RichText::new("Captured during the last completed storage analysis, not live. Observation only: Blue does not kill applications here or promise a faster system.").color(MUTED)).wrap());
    egui::Grid::new("cleanup-memory-observation")
        .num_columns(2)
        .spacing(Vec2::new(24.0, 8.0))
        .show(ui, |ui| {
            for (label, value) in [
                (
                    "Memory available",
                    format_bytes(performance.memory_available_bytes),
                ),
                (
                    "Memory used",
                    format_bytes(
                        performance
                            .memory_total_bytes
                            .saturating_sub(performance.memory_available_bytes),
                    ),
                ),
                (
                    "Swap used",
                    format_bytes(
                        performance
                            .swap_total_bytes
                            .saturating_sub(performance.swap_free_bytes),
                    ),
                ),
                ("Processes observed", performance.process_count.to_string()),
            ] {
                ui.label(RichText::new(label).color(MUTED));
                ui.label(RichText::new(value).monospace().color(TEXT));
                ui.end_row();
            }
        });
    ui.add_space(12.0);
    section_title(
        ui,
        "Largest resident processes",
        "Exited or unreadable processes can be omitted from this snapshot.",
    );
    if performance.top_memory.is_empty() {
        ui.label(RichText::new("No readable process details were captured.").color(MUTED));
    } else {
        egui::Grid::new("cleanup-process-observation")
            .num_columns(3)
            .max_col_width((ui.available_width() * 0.5).max(100.0))
            .spacing(Vec2::new(20.0, 8.0))
            .show(ui, |ui| {
                ui.label(RichText::new("Process").color(MUTED));
                ui.label(RichText::new("PID").color(MUTED));
                ui.label(RichText::new("Resident memory").color(MUTED));
                ui.end_row();
                for process in &performance.top_memory {
                    ui.add(egui::Label::new(RichText::new(&process.name).color(TEXT)).wrap());
                    ui.label(
                        RichText::new(process.pid.to_string())
                            .monospace()
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format_bytes(process.rss_bytes))
                            .monospace()
                            .color(TEXT),
                    );
                    ui.end_row();
                }
            });
    }
}

fn cleanup_focus(ui: &egui::Ui, response: &egui::Response) {
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

    fn candidate() -> blue_cleanup::CleanupCandidate {
        blue_cleanup::CleanupCandidate {
            id: "candidate".into(),
            label: "Test cache".into(),
            path: None,
            bytes: 1024,
            risk: blue_cleanup::CleanupRisk::Safe,
            category: blue_cleanup::CleanupCategory::Cache,
            reason: "Test fixture".into(),
            reproducible: true,
            requires_root: false,
            supported: true,
            warning: None,
        }
    }

    #[test]
    fn protected_elevated_and_unsupported_candidates_are_not_selectable() {
        let mut item = candidate();
        assert!(cleanup_selectable(&item));
        item.risk = blue_cleanup::CleanupRisk::Protected;
        assert!(!cleanup_selectable(&item));
        item.risk = blue_cleanup::CleanupRisk::Safe;
        item.requires_root = true;
        assert!(!cleanup_selectable(&item));
        item.requires_root = false;
        item.supported = false;
        assert!(!cleanup_selectable(&item));
    }

    #[test]
    fn approval_requires_current_ids_exact_phrase_and_idle_job_state() {
        let selected = vec![candidate()];
        let mut ids = HashSet::from(["candidate".to_owned()]);
        assert!(cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE SAFE 1",
            false
        ));
        for phrase in [
            "delete safe 1",
            "DELETE SAFE 1 ",
            " DELETE SAFE 1",
            "DELETE SAFE 2",
        ] {
            assert!(!cleanup_approval_ready(&selected, &ids, phrase, false));
        }
        assert!(!cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE SAFE 1",
            true
        ));
        assert!(!cleanup_approval_ready(
            &selected,
            &HashSet::from(["different".into()]),
            "DELETE SAFE 1",
            false
        ));
        ids.insert("stale".into());
        assert!(!cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE SAFE 1",
            false
        ));
        assert!(!cleanup_approval_ready(
            &[],
            &HashSet::new(),
            "DELETE SAFE 0",
            false
        ));
    }

    #[test]
    fn reviewed_candidates_keep_the_engines_stronger_phrase() {
        let mut item = candidate();
        item.risk = blue_cleanup::CleanupRisk::Review;
        let ids = HashSet::from([item.id.clone()]);
        let selected = vec![item];
        assert!(!cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE SAFE 1",
            false
        ));
        assert!(cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE REVIEWED 1",
            false
        ));
    }

    #[test]
    fn selected_estimates_saturate_instead_of_overflowing() {
        let mut item = candidate();
        item.bytes = u64::MAX;
        assert_eq!(cleanup_selected_bytes(&[item, candidate()]), u64::MAX);
    }

    #[test]
    fn three_reviewed_items_still_require_the_exact_current_approval() {
        let selected = (0..3)
            .map(|index| {
                let mut item = candidate();
                item.id = format!("reviewed-{index}");
                item.risk = blue_cleanup::CleanupRisk::Review;
                item
            })
            .collect::<Vec<_>>();
        let ids = selected.iter().map(|item| item.id.clone()).collect();
        assert!(cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE REVIEWED 3",
            false
        ));
        for phrase in [
            "Delete reviewed 3",
            "DELETE REVIEWED 3 ",
            "DELETE SAFE 3",
            "DELETE REVIEWED 2",
        ] {
            assert!(!cleanup_approval_ready(&selected, &ids, phrase, false));
        }
        assert!(!cleanup_approval_ready(
            &selected,
            &ids,
            "DELETE REVIEWED 3",
            true
        ));
    }

    struct CleanupLayout {
        page_rect: egui::Rect,
        page_offset: f32,
        ledger_rect: egui::Rect,
        ledger_offset: f32,
        ledger_max_offset: f32,
        confirmation_rect: egui::Rect,
        actions_rect: egui::Rect,
    }

    fn cleanup_input(time: f64, height: f32, events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, height),
            )),
            time: Some(time),
            events,
            ..Default::default()
        }
    }

    // Exercise production scroll geometry without constructing BlueApp, probing
    // the workstation, or calling the deletion backend.
    fn cleanup_layout_frame(
        ctx: &egui::Context,
        input: egui::RawInput,
        prefix_height: f32,
        review_approval: bool,
        ledger_offset: Option<f32>,
    ) -> CleanupLayout {
        let mut layout = None;
        let _ = ctx.run_ui(input, |root| {
            egui::Panel::left("test-navigation")
                .exact_size(208.0)
                .show(root, |_| {});
            egui::CentralPanel::default()
                .frame(Frame::new().inner_margin(egui::Margin::same(30)))
                .show(root, |ui| {
                    let page = cleanup_workspace(ui, |ui, viewport_height| {
                        let page_top = ui.cursor().top();
                        ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), prefix_height),
                            egui::Sense::hover(),
                        );
                        let height =
                            cleanup_ledger_height(viewport_height, ui.cursor().top() - page_top);
                        let mut scroller = cleanup_ledger_scroller(ui, height);
                        if let Some(offset) = ledger_offset {
                            scroller = scroller.vertical_scroll_offset(offset);
                        }
                        let ledger = scroller.show(ui, |ui| {
                            for _ in 0..12 {
                                ui.allocate_exact_size(
                                    egui::vec2(ui.available_width(), 80.0),
                                    egui::Sense::hover(),
                                );
                            }
                        });
                        ui.add_space(16.0);
                        let approval =
                            Frame::new()
                                .inner_margin(egui::Margin::same(16))
                                .show(ui, |ui| {
                                    ui.label("Deletion approval");
                                    ui.allocate_exact_size(
                                        egui::vec2(ui.available_width(), 108.0),
                                        egui::Sense::hover(),
                                    );
                                    let mut phrase = String::new();
                                    let confirmation = ui.add_sized(
                                        [ui.available_width(), 38.0],
                                        egui::TextEdit::singleline(&mut phrase),
                                    );
                                    let actions = ui.horizontal_wrapped(|ui| {
                                        let _ = ui.button("Clear selection");
                                        ui.add_enabled(
                                            false,
                                            egui::Button::new("Delete selected")
                                                .min_size(Vec2::new(150.0, 38.0)),
                                        );
                                    });
                                    (confirmation.rect, actions.response.rect)
                                });
                        if review_approval {
                            ui.scroll_to_rect(approval.response.rect, Some(Align::Center));
                        }
                        ui.add_space(16.0);
                        let _ = ui.button("Read-only system cleanup plan");
                        (ledger, approval.inner)
                    });
                    let (ledger, (confirmation_rect, actions_rect)) = page.inner;
                    layout = Some(CleanupLayout {
                        page_rect: page.inner_rect,
                        page_offset: page.state.clamped_offset().y,
                        ledger_rect: ledger.inner_rect,
                        ledger_offset: ledger.state.clamped_offset().y,
                        ledger_max_offset: ledger.content_size.y - ledger.inner_rect.height(),
                        confirmation_rect,
                        actions_rect,
                    });
                });
        });
        layout.expect("cleanup fixture was laid out")
    }

    fn cleanup_wheel_at(pos: egui::Pos2) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -7.0),
                phase: egui::TouchPhase::Move,
                source: egui::MouseWheelSource::Unknown,
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }

    #[test]
    fn ledger_does_not_collapse_and_review_exposes_confirmation_and_actions() {
        let ctx = egui::Context::default();
        theme::apply(&ctx, true);
        let first =
            cleanup_layout_frame(&ctx, cleanup_input(0.0, 620.0, vec![]), 500.0, false, None);
        assert_eq!(first.ledger_rect.height(), CLEANUP_LEDGER_MIN_HEIGHT);
        let _ = cleanup_layout_frame(&ctx, cleanup_input(0.02, 620.0, vec![]), 500.0, true, None);
        let reviewed =
            cleanup_layout_frame(&ctx, cleanup_input(0.04, 620.0, vec![]), 500.0, false, None);
        assert!(reviewed.page_offset > 0.0);
        assert_eq!(reviewed.ledger_rect.height(), first.ledger_rect.height());
        assert!(reviewed.page_rect.contains_rect(reviewed.confirmation_rect));
        assert!(reviewed.page_rect.contains_rect(reviewed.actions_rect));
        assert!(cleanup_ledger_height(1000.0, 250.0) > CLEANUP_LEDGER_MIN_HEIGHT);
    }

    #[test]
    fn clipped_ledger_routes_wheel_to_page_instead_of_trapping_one_visible_row() {
        let ctx = egui::Context::default();
        theme::apply(&ctx, true);
        let _ = cleanup_layout_frame(&ctx, cleanup_input(0.0, 620.0, vec![]), 400.0, false, None);
        let first =
            cleanup_layout_frame(&ctx, cleanup_input(0.02, 620.0, vec![]), 400.0, false, None);
        assert!(first.ledger_rect.bottom() > first.page_rect.bottom());
        let pointer = first.ledger_rect.intersect(first.page_rect).center();
        let wheeled = cleanup_layout_frame(
            &ctx,
            cleanup_input(0.04, 620.0, cleanup_wheel_at(pointer)),
            400.0,
            false,
            None,
        );
        assert!(wheeled.page_offset > first.page_offset);
        assert_eq!(wheeled.ledger_offset, 0.0);
        assert_eq!(wheeled.ledger_rect.height(), CLEANUP_LEDGER_MIN_HEIGHT);
    }

    #[test]
    fn exposed_ledger_accepts_wheel_and_chains_to_page_at_its_end() {
        for at_end in [false, true] {
            let ctx = egui::Context::default();
            theme::apply(&ctx, true);
            let initial_offset = at_end.then_some(10_000.0);
            let _ = cleanup_layout_frame(
                &ctx,
                cleanup_input(0.0, 620.0, vec![]),
                40.0,
                false,
                initial_offset,
            );
            let first =
                cleanup_layout_frame(&ctx, cleanup_input(0.02, 620.0, vec![]), 40.0, false, None);
            assert!(first.page_rect.contains_rect(first.ledger_rect));
            let wheeled = cleanup_layout_frame(
                &ctx,
                cleanup_input(0.04, 620.0, cleanup_wheel_at(first.ledger_rect.center())),
                40.0,
                false,
                None,
            );
            if at_end {
                assert!(wheeled.page_offset > first.page_offset);
                assert!((wheeled.ledger_offset - first.ledger_max_offset).abs() < 0.5);
            } else {
                assert!(wheeled.ledger_offset > first.ledger_offset);
                assert_eq!(wheeled.page_offset, first.page_offset);
            }
        }
    }

    #[test]
    fn receipts_have_a_bounded_scroll_viewport_separate_from_the_candidate_ledger() {
        let ctx = egui::Context::default();
        theme::apply(&ctx, true);
        let applied = blue_cleanup::ApplyReport {
            receipts: (0..40)
                .map(|index| blue_cleanup::ApplyReceipt {
                    id: format!("receipt-{index}"),
                    label: format!("Reviewed candidate {index}"),
                    bytes_before: 1024,
                    success: index % 2 == 0,
                    error: (index % 2 != 0)
                        .then(|| "Fixture: candidate could not be removed".into()),
                })
                .collect(),
            reclaimed_estimate: 20 * 1024,
        };
        let _ = ctx.run_ui(cleanup_input(0.0, 620.0, vec![]), |root| {
            egui::CentralPanel::default().show(root, |ui| {
                cleanup_workspace(ui, |ui, _| {
                    let receipts = cleanup_receipts(ui, &applied);
                    let ledger =
                        cleanup_ledger_scroller(ui, CLEANUP_LEDGER_MIN_HEIGHT).show(ui, |ui| {
                            ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), 1000.0),
                                egui::Sense::hover(),
                            );
                        });
                    assert_ne!(receipts.id, ledger.id);
                    assert_eq!(receipts.inner_rect.height(), CLEANUP_RECEIPTS_MAX_HEIGHT);
                    assert!(receipts.content_size.y > receipts.inner_rect.height());
                    assert_eq!(ledger.inner_rect.height(), CLEANUP_LEDGER_MIN_HEIGHT);
                });
            });
        });
    }
}
