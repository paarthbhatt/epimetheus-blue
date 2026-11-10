use crate::*;

const IBM_PLEX_LICENSE: &str = include_str!("../../assets/fonts/LICENSE.txt");

impl BlueApp {
    pub(crate) fn settings(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Settings",
            "Services, fixed safety policy and explicit system setup.",
        );
        if let Some(error) = self.refresh_error.clone() {
            ui.label(
                RichText::new("Stored evidence could not be refreshed")
                    .strong()
                    .color(RED),
            );
            ui.add(egui::Label::new(RichText::new(error).color(TEXT)).wrap());
            let response =
                ui.add(egui::Button::new("Retry state refresh").min_size(Vec2::new(0.0, 34.0)));
            settings_focus(ui, &response);
            if response.clicked() {
                self.refresh();
            }
            ui.add_space(16.0);
        }

        section_title(
            ui,
            "Services",
            "Installed user timers continue outside this window; state is last reported.",
        );
        ui.add(
            egui::Label::new(
                RichText::new("A checked schedule has an active timer, not a check in progress. Cadences below are the bundled schedules.")
                    .color(MUTED),
            )
            .wrap(),
        );
        ui.add_space(10.0);
        for (title, detail, unit, installed, value) in [
            (
                "Integrity schedule",
                "Every 15 minutes. Detect changes in configured sensitive paths.",
                "blue-guard.timer",
                self.guard_unit_installed,
                &mut self.guard_timer,
            ),
            (
                "Network observation schedule",
                "Every 5 minutes. Inventory connections; never add firewall rules.",
                "blue-net.timer",
                self.net_unit_installed,
                &mut self.net_timer,
            ),
            (
                "Hash feed schedule",
                "Daily. Update local SHA-256 threat indicators without uploading files.",
                "blue-reputation.timer",
                self.reputation_unit_installed,
                &mut self.reputation_timer,
            ),
            (
                "Filter update schedule",
                "Daily. Update configured domain lists; keep rejected downloads out.",
                "blue-feeds.timer",
                self.feed_unit_installed,
                &mut self.feed_timer,
            ),
        ] {
            if let Some(message) = settings_timer_row(ui, title, detail, unit, installed, value) {
                self.message = Some(message);
            }
            settings_operation_feedback(ui, &self.message, title);
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);
        }

        ui.add_space(14.0);
        section_title(
            ui,
            "Policies",
            "Loaded configuration and fixed safety gates. These values are read-only.",
        );
        ui.add_space(8.0);
        settings_value(
            ui,
            "Quarantine threshold",
            "T2 corroborated is the minimum tier (fixed safety policy). T0 observations and T1 candidates are evidence, not quarantine approvals.",
            false,
        );
        settings_value(
            ui,
            "Automatic quarantine",
            if self.deps.db.kill_switch() {
                "Paused by the emergency control. Firewall and system DNS are unchanged."
            } else {
                "Not paused. The fixed evidence threshold still applies."
            },
            false,
        );
        settings_value(
            ui,
            "Full package drift audit",
            if self.deps.config.guard.watch_packages {
                "Included in integrity checks by the loaded TOML."
            } else {
                "Not included. This expensive check is opt-in through TOML."
            },
            false,
        );
        settings_value(
            ui,
            "ClamAV requirement",
            if self.deps.config.scan.clamav.required {
                "Required. Scans fail if ClamAV cannot be reached."
            } else {
                "Optional. Scans may continue without ClamAV evidence."
            },
            false,
        );
        settings_value(
            ui,
            "Online hash lookup",
            if !self.deps.config.reputation.virustotal_enabled {
                "Not enabled in TOML. Local hash lookup remains available."
            } else if self.deps.config.reputation.virustotal_query_on_scan {
                "Hash-only scan lookup is configured. Files are never uploaded; credentials are still required."
            } else {
                "Configured for explicit hash-only checks. Files are never uploaded; credentials are still required."
            },
            false,
        );
        let paths = egui::CollapsingHeader::new("Inspect local paths and DNS configuration")
            .id_salt("settings-local-paths")
            .show(ui, |ui| {
                settings_value(ui, "State directory", &self.deps.config.state_dir().display().to_string(), true);
                settings_value(ui, "Database", &self.deps.config.db_path().display().to_string(), true);
                settings_value(ui, "DNS bind", &self.deps.config.dns.bind, true);
                settings_value(ui, "DNS block response", &self.deps.config.dns.block_response, true);
                settings_value(ui, "DNS upstreams", &self.deps.config.dns.upstreams.join("\n"), true);
                settings_value(ui, "Configuration", "Layered system and user TOML, including sorted conf.d drop-ins. Reopen Blue after editing configuration.", false);
            });
        settings_focus(ui, &paths.header_response);

        ui.add_space(22.0);
        ui.separator();
        ui.add_space(10.0);
        section_title(
            ui,
            "System setup",
            "Copy a read-only plan. This screen never installs or activates system changes.",
        );
        ui.add(
            egui::Label::new(
                RichText::new("Run the plan in your terminal and review it before using its separate confirmation command.")
                    .color(MUTED),
            )
            .wrap(),
        );
        let setup_dir = extension_path()
            .parent()
            .map(|path| path.join("scripts"))
            .unwrap_or_else(|| PathBuf::from("scripts"));

        ui.add_space(12.0);
        ui.label(RichText::new("ClamAV").size(17.0).strong().color(TEXT));
        let socket = blue_core::config::expand_tilde(&self.deps.config.scan.clamav.socket);
        let (socket_notice, socket_color) = match socket.try_exists() {
            Ok(true) => (
                "Configured socket path exists; daemon health has not been checked.".to_owned(),
                TEXT,
            ),
            Ok(false) => (
                "Configured socket path is missing; ClamAV availability is not confirmed."
                    .to_owned(),
                AMBER,
            ),
            Err(error) => (
                format!("Configured socket path could not be inspected: {error}"),
                AMBER,
            ),
        };
        ui.add(egui::Label::new(RichText::new(socket_notice).color(socket_color)).wrap());
        ui.add(
            egui::Label::new(
                RichText::new(socket.display().to_string())
                    .monospace()
                    .color(TEXT),
            )
            .wrap()
            .selectable(true),
        );
        if settings_plan_command(ui, "ClamAV", &setup_dir.join("setup-clamav.sh")) {
            self.message = Some((
                "ClamAV plan command copied; nothing was executed".into(),
                true,
            ));
        }
        settings_operation_feedback(ui, &self.message, "ClamAV plan command copied");

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("System DNS").size(17.0).strong().color(TEXT));
        let (dns_notice, dns_color) = if !self.dns_routed {
            ("System DNS is not reported routed to loopback.", AMBER)
        } else if !self.dns_unit_installed {
            (
                "Loopback route detected; Blue's DNS user service was not detected.",
                AMBER,
            )
        } else if !self.dns {
            (
                "Loopback route detected; Blue DNS is not reported active.",
                AMBER,
            )
        } else {
            (
                "Loopback route detected; Blue DNS is reported active.",
                GREEN,
            )
        };
        ui.add(egui::Label::new(RichText::new(dns_notice).color(dns_color)).wrap());
        ui.add(
            egui::Label::new(
                RichText::new("A local resolver alone does not change system DNS. Network changes require separate, explicit confirmation.")
                    .color(MUTED),
            )
            .wrap(),
        );
        if settings_plan_command(ui, "System DNS", &setup_dir.join("setup-system-dns.sh")) {
            self.message = Some((
                "System DNS plan command copied; nothing was executed".into(),
                true,
            ));
        }
        settings_operation_feedback(ui, &self.message, "System DNS plan command copied");

        ui.add_space(22.0);
        ui.separator();
        ui.add_space(10.0);
        section_title(ui, "About", "Epimetheus Blue, a native security workspace.");
        settings_value(ui, "Version", env!("CARGO_PKG_VERSION"), true);
        ui.add(
            egui::Label::new(
                RichText::new("Native egui interface. No embedded web view and no listening HTTP port. Opening or inspecting this screen does not enable protection.")
                    .color(MUTED),
            )
            .wrap(),
        );
        ui.add_space(8.0);
        let fonts = egui::CollapsingHeader::new("IBM Plex font attribution and license")
            .id_salt("settings-ibm-plex-license")
            .show(ui, |ui| {
                ui.label(RichText::new("IBM Plex Sans and IBM Plex Sans Condensed").strong().color(TEXT));
                ui.add(
                    egui::Label::new(
                        RichText::new("Copyright © 2017 IBM Corp. Reserved Font Name: Plex. Bundled under the SIL Open Font License 1.1.")
                            .color(TEXT),
                    )
                    .wrap(),
                );
                let response = ui.add(
                    egui::Button::new("Copy font license").min_size(Vec2::new(0.0, 34.0)),
                );
                settings_focus(ui, &response);
                if response.clicked() {
                    ui.ctx().copy_text(IBM_PLEX_LICENSE.to_owned());
                    self.message = Some(("IBM Plex font license copied".into(), true));
                }
                settings_operation_feedback(ui, &self.message, "IBM Plex font license copied");
                egui::ScrollArea::vertical()
                    .id_salt("ibm-plex-license-text")
                    .max_height(250.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(IBM_PLEX_LICENSE).size(13.0).color(TEXT))
                                .wrap()
                                .selectable(true),
                        );
                    });
            });
        settings_focus(ui, &fonts.header_response);
        ui.add_space(16.0);
    }
}

fn settings_timer_row(
    ui: &mut egui::Ui,
    title: &str,
    detail: &str,
    unit: &str,
    installed: bool,
    value: &mut bool,
) -> Option<(String, bool)> {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(title).strong().color(TEXT));
        let (state, color) = if !installed {
            ("Unit not detected", AMBER)
        } else if *value {
            ("Timer active", GREEN)
        } else {
            ("Timer stopped", MUTED)
        };
        ui.label(RichText::new(state).color(color));
    });
    ui.add(egui::Label::new(RichText::new(detail).color(MUTED)).wrap());
    ui.label(RichText::new(unit).monospace().color(MUTED));
    let previous = *value;
    let response = ui
        .add_enabled_ui(installed, |ui| {
            ui.add_sized(
                [ui.available_width(), 32.0],
                egui::Checkbox::new(value, format!("Run {}", title.to_lowercase())),
            )
        })
        .inner
        .on_hover_text("Starts or stops this installed user timer now, and enables or disables it for future logins. No unit is installed here.");
    settings_focus(ui, &response);
    if !installed {
        ui.add(
            egui::Label::new(
                RichText::new("Control unavailable: the user unit was not detected. No service is created by this screen.")
                    .color(MUTED),
            )
            .wrap(),
        );
        return None;
    }
    if !response.changed() {
        return None;
    }
    Some(match set_user_unit(unit, *value) {
        Ok(()) => (
            format!("{title} {}", if *value { "started" } else { "stopped" }),
            true,
        ),
        Err(error) => {
            *value = previous;
            (format!("{title} could not be changed: {error:#}"), false)
        }
    })
}

fn settings_value(ui: &mut egui::Ui, label: &str, value: &str, technical: bool) {
    ui.label(RichText::new(label).size(12.0).color(MUTED));
    let text = RichText::new(value).color(TEXT);
    ui.add(
        egui::Label::new(if technical { text.monospace() } else { text })
            .wrap()
            .selectable(true),
    );
    ui.add_space(8.0);
}

fn settings_plan_command(ui: &mut egui::Ui, label: &str, script: &Path) -> bool {
    let available = script.is_file();
    let command = script_plan_command(script);
    ui.add(
        egui::Label::new(RichText::new(&command).monospace().color(TEXT))
            .wrap()
            .selectable(true),
    );
    if !available {
        ui.add(
            egui::Label::new(
                RichText::new("Plan script not found at this path. Restore the installed scripts before copying a plan.")
                    .color(AMBER),
            )
            .wrap(),
        );
    }
    let response = ui
        .add_enabled(
            available,
            egui::Button::new(format!("Copy {label} plan command"))
                .min_size(Vec2::new(0.0, 34.0)),
        )
        .on_hover_text("Copies the quoted script path and its plan argument. Nothing is executed, installed, or enabled.");
    settings_focus(ui, &response);
    if response.clicked() {
        ui.ctx().copy_text(command);
        true
    } else {
        false
    }
}

fn settings_operation_feedback(ui: &mut egui::Ui, message: &Option<(String, bool)>, prefix: &str) {
    if let Some((message, good)) = message {
        if message.starts_with(prefix) {
            ui.add(
                egui::Label::new(RichText::new(message).color(if *good { TEXT } else { RED }))
                    .wrap(),
            );
        }
    }
}

fn settings_focus(ui: &egui::Ui, response: &egui::Response) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.expand(2.0),
            CornerRadius::same(6),
            Stroke::new(2.0, BLUE),
            egui::StrokeKind::Outside,
        );
    }
}
