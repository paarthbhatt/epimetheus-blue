use crate::*;

impl BlueApp {
    pub(crate) fn filters(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Filter feeds",
            "Domain sources, update results and retained versions.",
        );

        let sources = self.deps.config.feeds.sources.clone();
        let datasets = self.snapshot.datasets.clone();
        let lists_dir = blue_core::config::expand_tilde(&self.deps.config.feeds.lists_dir);
        let last_report = self.last_feed.clone();
        let mut names = Vec::new();
        for name in sources
            .iter()
            .map(|source| &source.name)
            .chain(datasets.iter().map(|dataset| &dataset.name))
        {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }

        egui::ScrollArea::vertical()
            .id_salt("feeds-workspace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(error) = self.refresh_error.clone() {
                    ui.label(
                        RichText::new("Version records could not be refreshed")
                            .strong()
                            .color(RED),
                    );
                    ui.add(egui::Label::new(RichText::new(error).color(TEXT)).wrap());
                    ui.add(
                        egui::Label::new(
                            RichText::new("Showing the last loaded records; file checks below are separate.")
                                .color(MUTED),
                        )
                        .wrap(),
                    );
                    let response = ui.add(
                        egui::Button::new("Retry state refresh")
                            .min_size(Vec2::new(0.0, 34.0)),
                    );
                    feeds_focus(ui, &response);
                    if response.clicked() {
                        self.refresh();
                    }
                    ui.add_space(16.0);
                }

                ui.horizontal_wrapped(|ui| {
                    let busy = self.jobs.contains("feeds") || self.jobs.contains("rollback");
                    let response = ui
                        .add_enabled(
                            !busy && !sources.is_empty(),
                            egui::Button::new(
                                RichText::new("Update filters").color(Color32::WHITE),
                            )
                            .fill(BLUE)
                            .min_size(Vec2::new(144.0, 36.0)),
                        )
                        .on_hover_text("Downloads every configured domain source, validates it, then replaces its current list. DNS routing is not changed.");
                    feeds_focus(ui, &response);
                    if response.clicked() {
                        self.sync_feeds();
                    }
                    ui.label(
                        RichText::new(format!("Configured sources: {}", sources.len()))
                            .color(MUTED),
                    );
                });
                if self.jobs.contains("feeds") {
                    ui.label(
                        RichText::new("Downloading and validating configured sources…")
                            .color(MUTED),
                    );
                } else if self.jobs.contains("rollback") {
                    ui.label(RichText::new("Restoring a retained copy…").color(MUTED));
                }
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Rejected or undersized downloads do not replace a working list. Updating does not enable DNS protection.",
                        )
                        .color(MUTED),
                    )
                    .wrap(),
                );

                ui.add_space(20.0);
                section_title(
                    ui,
                    "Last completed update",
                    "Results from this session, not an automatic freshness claim.",
                );
                if let Some(report) = &last_report {
                    feeds_update_report(ui, report);
                } else {
                    ui.add(
                        egui::Label::new(
                            RichText::new("No completed update in this session. Review installed versions below or select Update filters.")
                                .color(MUTED),
                        )
                        .wrap(),
                    );
                }

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(8.0);
                section_title(
                    ui,
                    "Domain sources",
                    "Source URLs and licenses come from the loaded TOML configuration.",
                );
                ui.add_space(8.0);
                if sources.is_empty() {
                    ui.add(
                        egui::Label::new(
                            RichText::new("No domain sources configured. Add a source under feeds.sources in your local TOML, then reopen Blue.")
                                .color(AMBER),
                        )
                        .wrap(),
                    );
                }
                if names.is_empty() {
                    ui.label(RichText::new("No installed versions recorded").strong().color(TEXT));
                }

                for name in &names {
                    ui.push_id(("domain-source", name), |ui| {
                        let source = sources.iter().find(|source| &source.name == name);
                        let versions: Vec<_> = datasets
                            .iter()
                            .filter(|dataset| &dataset.name == name)
                            .collect();
                        let active = versions.iter().copied().find(|dataset| dataset.active);
                        let retained = feeds_retained_copy(&lists_dir, name);

                        ui.add_space(12.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.add(
                                egui::Label::new(RichText::new(name).size(17.0).strong().color(TEXT))
                                    .wrap(),
                            );
                            ui.label(
                                RichText::new(if active.is_some() {
                                    "Current version recorded"
                                } else {
                                    "No current version recorded"
                                })
                                .color(if active.is_some() { BLUE } else { AMBER }),
                            );
                        });
                        if source.is_none() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new("Not in the current configuration; Update filters will not fetch this source.")
                                        .color(AMBER),
                                )
                                .wrap(),
                            );
                        }
                        let url = source.map(|source| source.url.as_str()).or_else(|| {
                            versions.iter().find_map(|dataset| dataset.source_url.as_deref())
                        });
                        if let Some(url) = url {
                            ui.add(
                                egui::Label::new(RichText::new(url).monospace().color(TEXT))
                                    .wrap()
                                    .selectable(true),
                            );
                            let response = ui.add(
                                egui::Button::new("Copy source URL")
                                    .min_size(Vec2::new(0.0, 32.0)),
                            );
                            feeds_focus(ui, &response);
                            if response.clicked() {
                                ui.ctx().copy_text(url.to_owned());
                                self.message = Some((format!("{name} source URL copied"), true));
                            }
                        } else {
                            ui.label(RichText::new("Source URL not recorded").color(MUTED));
                        }
                        ui.label(
                            RichText::new(format!(
                                "Source license: {}",
                                source
                                    .and_then(|source| source.license.as_deref())
                                    .unwrap_or("not recorded")
                            ))
                            .color(MUTED),
                        );
                        if let Some(dataset) = active {
                            feeds_version_row(ui, dataset);
                        } else if source.is_some() {
                            ui.label(
                                RichText::new("Select Update filters to install this source.")
                                    .color(MUTED),
                            );
                        }
                        match &retained {
                            Ok(Some(bytes)) => {
                                ui.label(
                                    RichText::new(format!(
                                        "Retained rollback copy found ({})",
                                        format_bytes(*bytes)
                                    ))
                                    .color(TEXT),
                                );
                            }
                            Ok(None) => {
                                ui.label(RichText::new("No retained rollback copy found").color(MUTED));
                            }
                            Err(error) => {
                                ui.add(
                                    egui::Label::new(RichText::new(error).color(AMBER)).wrap(),
                                );
                            }
                        }

                        let disclosure = egui::CollapsingHeader::new("Rollback and version records")
                            .id_salt("retained-versions")
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new("Rollback replaces this source's current file with its retained .prev copy. The displaced file is also retained.")
                                            .color(MUTED),
                                    )
                                    .wrap(),
                                );
                                let can_rollback = matches!(&retained, Ok(Some(_)))
                                    && !self.jobs.contains("feeds")
                                    && !self.jobs.contains("rollback");
                                let response = ui
                                    .add_enabled(
                                        can_rollback,
                                        egui::Button::new("Rollback to retained copy")
                                            .min_size(Vec2::new(0.0, 34.0)),
                                    )
                                    .on_hover_text("Restores only this source's retained copy. It does not change DNS routing or enable protection.");
                                feeds_focus(ui, &response);
                                if response.clicked() {
                                    self.rollback_feed(name.clone());
                                }
                                if self.jobs.contains("rollback") {
                                    ui.label(RichText::new("A feed rollback is in progress…").color(MUTED));
                                }
                                if let Some((message, good)) = &self.message {
                                    if message.starts_with("Rollback failed:")
                                        || message.starts_with(&format!("Rolled {name} back "))
                                    {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(message).color(if *good { TEXT } else { RED }),
                                            )
                                            .wrap(),
                                        );
                                    }
                                }
                                if let Some(hash) = active.and_then(|dataset| dataset.sha256.as_deref()) {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("Current SHA-256").color(MUTED));
                                    ui.add(
                                        egui::Label::new(RichText::new(hash).monospace().color(TEXT))
                                            .wrap()
                                            .selectable(true),
                                    );
                                }
                                ui.add_space(12.0);
                                ui.label(RichText::new("Prior activation records").strong().color(TEXT));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new("Records are not selectable restore points. Rollback uses the actual retained file checked above.")
                                            .color(MUTED),
                                    )
                                    .wrap(),
                                );
                                let prior: Vec<_> = versions.iter().copied().filter(|dataset| !dataset.active).collect();
                                if prior.is_empty() {
                                    ui.label(RichText::new("No earlier activation records loaded").color(MUTED));
                                } else {
                                    egui::ScrollArea::vertical()
                                        .id_salt("activation-records")
                                        .max_height(200.0)
                                        .auto_shrink([false, true])
                                        .show(ui, |ui| {
                                            for dataset in prior {
                                                feeds_version_row(ui, dataset);
                                            }
                                        });
                                }
                            });
                        feeds_focus(ui, &disclosure.header_response);
                        ui.add_space(8.0);
                        ui.separator();
                    });
                }
                ui.add_space(12.0);
                ui.label(RichText::new("Local list directory").color(MUTED));
                ui.add(
                    egui::Label::new(
                        RichText::new(lists_dir.display().to_string()).monospace().color(TEXT),
                    )
                    .wrap()
                    .selectable(true),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new("Version history includes up to 100 recent database records across all sources, not a full disk inventory.")
                            .color(MUTED),
                    )
                    .wrap(),
                );
                ui.add_space(12.0);
            });
    }
}

fn feeds_update_report(ui: &mut egui::Ui, report: &SyncReport) {
    ui.label(
        RichText::new(format!(
            "Sources updated: {}; failed: {}",
            report.updated.len(),
            report.failed.len()
        ))
        .strong()
        .color(if report.failed.is_empty() {
            TEXT
        } else {
            AMBER
        }),
    );
    ui.label(
        RichText::new(format!(
            "{} usable host lines validated across updated sources",
            report.total_lines
        ))
        .color(MUTED),
    );
    for name in &report.updated {
        ui.label(RichText::new(format!("Updated {name}")).color(TEXT));
    }
    for (name, error) in &report.failed {
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                RichText::new(format!("Update failed for {name}"))
                    .strong()
                    .color(RED),
            )
            .wrap(),
        );
        ui.add(egui::Label::new(RichText::new(error).color(TEXT)).wrap());
    }
    if !report.failed.is_empty() {
        ui.add(
            egui::Label::new(
                RichText::new("Review the source URL and error, then retry with Update filters.")
                    .color(MUTED),
            )
            .wrap(),
        );
    }
}

fn feeds_version_row(ui: &mut egui::Ui, dataset: &Dataset) {
    let bytes = dataset
        .size
        .and_then(|bytes| u64::try_from(bytes).ok())
        .map(format_bytes)
        .unwrap_or_else(|| "Size not recorded".into());
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::Label::new(
                RichText::new(format!("Version {}", dataset.version))
                    .monospace()
                    .color(TEXT),
            )
            .wrap(),
        );
        ui.label(RichText::new(bytes).color(MUTED));
        ui.label(RichText::new(feeds_recorded_age(dataset.activated_at_ms)).color(MUTED))
            .on_hover_text(format!(
                "Activation timestamp: {} ms since Unix epoch",
                dataset.activated_at_ms
            ));
    });
}

fn feeds_recorded_age(timestamp: i64) -> String {
    let now = blue_core::now_ms();
    if timestamp <= 0 {
        return "Activation time not recorded".into();
    }
    if timestamp > now {
        return "Activation timestamp is in the future".into();
    }
    let seconds = now.saturating_sub(timestamp) / 1_000;
    let (value, unit) = match seconds {
        0..=59 => return "Recorded just now".into(),
        60..=3_599 => (seconds / 60, "minute"),
        3_600..=86_399 => (seconds / 3_600, "hour"),
        _ => (seconds / 86_400, "day"),
    };
    format!(
        "Recorded {value} {unit}{} ago",
        if value == 1 { "" } else { "s" }
    )
}

fn feeds_retained_copy(directory: &Path, name: &str) -> std::result::Result<Option<u64>, String> {
    // Match the updater's filename boundary before inspecting a configured path.
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(
            "Retained copy cannot be inspected: use a source name of 1–128 letters, digits, '-' or '_'."
                .into(),
        );
    }
    let path = directory.join(format!("{name}.txt.prev"));
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(Some(metadata.len())),
        Ok(_) => Err("Retained copy is not a regular file; rollback is unavailable.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("Retained copy could not be inspected: {error}")),
    }
}

fn feeds_focus(ui: &egui::Ui, response: &egui::Response) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.expand(2.0),
            CornerRadius::same(6),
            Stroke::new(2.0, BLUE),
            egui::StrokeKind::Outside,
        );
    }
}
