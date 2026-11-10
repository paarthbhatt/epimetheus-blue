use crate::*;

impl BlueApp {
    pub(crate) fn reputation(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Hash reputation",
            "Inspect exact hash evidence. Files are never uploaded by this tool.",
        );
        let status_request_id = egui::Id::unique("reputation-initial-status-request");
        let requested = ui
            .ctx()
            .data_mut(|data| data.get_temp::<bool>(status_request_id).unwrap_or(false));
        if self.reputation_status.is_none() && !requested {
            self.refresh_reputation_status();
            ui.ctx()
                .data_mut(|data| data.insert_temp(status_request_id, true));
        }
        let checking = self.jobs.contains("reputation-check");
        let online_enabled = self.deps.config.reputation.virustotal_enabled;
        if !online_enabled {
            self.reputation_online = false;
        }
        ui.label(
            RichText::new("File to check")
                .size(16.0)
                .strong()
                .color(TEXT),
        );
        let mut submit = false;
        ui.add_enabled_ui(!checking, |ui| {
            ui.horizontal(|ui| {
                let path = ui.add_sized(
                    [(ui.available_width() - 145.0).max(100.0), 38.0],
                    egui::TextEdit::singleline(&mut self.reputation_path)
                        .id_salt("reputation-file-path")
                        .hint_text("~/Downloads/file or /path/to/file"),
                );
                submit = ui
                    .add_enabled(
                        !self.reputation_path.trim().is_empty(),
                        egui::Button::new("Check file hash").fill(BLUE),
                    )
                    .clicked()
                    || (path.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter))
                        && !self.reputation_path.trim().is_empty());
            });
        });
        ui.add_enabled_ui(online_enabled && !checking, |ui| {
            ui.checkbox(
                &mut self.reputation_online,
                "Use VirusTotal hash lookup for this check",
            );
        });
        ui.label(RichText::new(if self.reputation_online && online_enabled {
            "Local lookup comes first. If no local IOC matches, the SHA-256 may be sent to VirusTotal; file contents are never sent."
        } else if !online_enabled {
            "Local lookup only. Online lookup is disabled in configuration; checking a file does not enable it."
        } else {
            "Local lookup only for this check. Online lookup requires the explicit choice above."
        }).size(12.0).color(MUTED));
        if submit && !checking {
            self.check_reputation();
        }
        if self.jobs.contains("reputation-check") {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(
                    RichText::new("Hashing the selected file and checking reputation…")
                        .color(MUTED),
                );
            });
        }
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(12.0);
        let height = (ui.clip_rect().bottom() - ui.cursor().top() - 8.0).max(96.0);
        egui::ScrollArea::vertical()
            .id_salt("reputation-workspace")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                let width = ui.available_width();
                if width >= 820.0 {
                    let usable = width - ui.spacing().item_spacing.x;
                    ui.horizontal_top(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(usable * 0.64);
                            reputation_evidence(
                                ui,
                                self.reputation_result.as_ref(),
                                self.jobs.contains("reputation-check"),
                            );
                        });
                        ui.vertical(|ui| {
                            ui.set_width(usable * 0.36);
                            self.reputation_context(ui);
                        });
                    });
                } else {
                    reputation_evidence(
                        ui,
                        self.reputation_result.as_ref(),
                        self.jobs.contains("reputation-check"),
                    );
                    ui.add_space(18.0);
                    ui.separator();
                    ui.add_space(10.0);
                    self.reputation_context(ui);
                }
            });
    }

    fn reputation_context(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Local evidence index")
                .size(16.0)
                .strong()
                .color(TEXT),
        );
        match self.reputation_status {
            Some(status) => {
                egui::Grid::new("reputation-index-status")
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("SHA-256 entries").color(MUTED));
                        ui.label(status.local_hashes.to_string());
                        ui.end_row();
                        ui.label(RichText::new("Loaded sources").color(MUTED));
                        ui.label(status.local_sources.to_string());
                        ui.end_row();
                    });
                ui.label(RichText::new("Counts come from the last successful index load, not a feed-freshness guarantee.").size(12.0).color(MUTED));
                if status.local_hashes == 0 {
                    ui.label(RichText::new("No local hashes are loaded. Update hash feeds before treating a missing match as useful coverage.").color(AMBER));
                }
            }
            None => {
                ui.label(RichText::new("Index status unavailable").color(AMBER));
                ui.label(RichText::new("Refresh status or update feeds. An unavailable index is not an empty, verified index.").size(12.0).color(MUTED));
            }
        }
        let syncing = self.jobs.contains("reputation-sync");
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(!syncing, egui::Button::new("Update hash feeds"))
                .clicked()
            {
                self.sync_reputation();
            }
            if ui
                .add_enabled(!syncing, egui::Button::new("Refresh index status"))
                .clicked()
            {
                self.refresh_reputation_status();
            }
        });
        if self.jobs.contains("reputation-sync") {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(
                    RichText::new("Updating and validating hash feeds…")
                        .size(12.0)
                        .color(MUTED),
                );
            });
        }
        ui.add_space(16.0);
        ui.label(RichText::new("Online lookup policy").strong().color(TEXT));
        ui.label(
            RichText::new(if self.deps.config.reputation.virustotal_enabled {
                "Available in configuration; each check still requires opt-in."
            } else {
                "Disabled in configuration."
            })
            .size(12.0)
            .color(MUTED),
        );
        egui::CollapsingHeader::new("Configured credential source")
            .id_salt("reputation-credential-source")
            .show(ui, |ui| {
                let config = &self.deps.config.reputation;
                ui.label(RichText::new(if config.virustotal_api_key_file.is_some() { "Credential file path" } else { "Environment variable name" }).size(12.0).color(MUTED));
                ui.add(egui::Label::new(RichText::new(config.virustotal_api_key_file.as_deref().unwrap_or(&config.virustotal_api_key_env)).monospace().size(12.0).color(TEXT)).wrap());
                ui.label(RichText::new("Only the configured source is shown. No credential value is read or displayed here.").size(12.0).color(MUTED));
            });
        ui.add_space(12.0);
        ui.label(RichText::new("This lookup does not move files or change their tier. Scanner owns file inspection and the fixed quarantine safety policy.").size(12.0).color(MUTED));
    }
}

fn reputation_evidence(
    ui: &mut egui::Ui,
    result: Option<&blue_reputation::ReputationResult>,
    checking: bool,
) {
    ui.label(
        RichText::new(if checking {
            "Previous completed lookup"
        } else {
            "Last completed lookup"
        })
        .size(18.0)
        .strong()
        .color(TEXT),
    );
    let Some(result) = result else {
        empty_state(ui, "No lookup completed in this session", "Choose a file and select Check file hash. A missing reputation match is not proof that a file is safe.");
        return;
    };
    ui.label(RichText::new("The recorded hash identifies this result. Editing the target or lookup mode does not update it.").size(12.0).color(MUTED));
    ui.add_space(10.0);
    ui.label(RichText::new("SHA-256").size(12.0).color(MUTED));
    ui.add(
        egui::Label::new(
            RichText::new(&result.sha256)
                .monospace()
                .size(13.0)
                .color(TEXT),
        )
        .wrap(),
    );
    if ui.small_button("Copy SHA-256").clicked() {
        ui.ctx().copy_text(result.sha256.clone());
    }
    ui.add_space(12.0);
    ui.label(RichText::new("Local IOC evidence").strong().color(TEXT));
    match &result.local_match {
        Some(source) => {
            ui.label(RichText::new("Exact local hash match").strong().color(RED));
            ui.add(egui::Label::new(RichText::new(source).color(TEXT)).wrap());
        }
        None => {
            ui.label(RichText::new("Not listed in the loaded local index").color(MUTED));
            ui.label(
                RichText::new("Not listed does not mean harmless; the index has limited coverage.")
                    .size(12.0)
                    .color(AMBER),
            );
        }
    }
    ui.add_space(14.0);
    ui.label(RichText::new("VirusTotal evidence").strong().color(TEXT));
    if let Some(record) = &result.virustotal {
        ui.add(
            egui::Label::new(
                RichText::new(format!("Reported verdict: {}", record.verdict)).color(
                    if record.malicious > 0 || record.suspicious > 0 {
                        AMBER
                    } else {
                        MUTED
                    },
                ),
            )
            .wrap(),
        );
        egui::Grid::new("reputation-provider-evidence")
            .spacing([18.0, 6.0])
            .show(ui, |ui| {
                for (label, count, color) in [
                    ("Malicious", record.malicious, AMBER),
                    ("Suspicious", record.suspicious, AMBER),
                    ("Harmless", record.harmless, MUTED),
                ] {
                    ui.label(RichText::new(label).color(MUTED));
                    ui.label(RichText::new(count.to_string()).color(if count > 0 {
                        color
                    } else {
                        MUTED
                    }));
                    ui.end_row();
                }
            });
        ui.label(
            RichText::new("Provider labels are evidence, not a cleanliness certificate.")
                .size(12.0)
                .color(MUTED),
        );
    } else {
        ui.label(
            RichText::new(if result.local_match.is_some() {
                "No online result; an exact local IOC match was available."
            } else {
                "No online result was returned for this lookup."
            })
            .color(MUTED),
        );
        ui.label(
            RichText::new(
                "The current online toggle applies to the next check, not this stored result.",
            )
            .size(12.0)
            .color(MUTED),
        );
    }
    if let Some(detector) = &result.detector {
        ui.add_space(14.0);
        egui::CollapsingHeader::new("Recorded detector evidence")
            .id_salt("reputation-detector-evidence")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(format!("Detector: {}", detector.detector.as_str()));
                ui.label(format!("Detector confidence: {:?}", detector.confidence));
                if let Some(signature) = &detector.signature {
                    ui.add(egui::Label::new(RichText::new(signature).color(TEXT)).wrap());
                }
                if let Some(detail) = &detector.detail {
                    ui.add(egui::Label::new(RichText::new(detail).size(12.0).color(MUTED)).wrap());
                }
            });
    }
}
