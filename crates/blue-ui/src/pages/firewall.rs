use crate::*;

impl BlueApp {
    pub(crate) fn firewall(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Firewall",
            "Stage an inbound policy. Outgoing traffic and DNS stay unchanged.",
        );
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Reported rules").color(MUTED));
            let (label, color) = if self.firewall_status.pending {
                ("Staged, awaiting confirmation", AMBER)
            } else if self.firewall_status.active {
                ("Active (reported)", GREEN)
            } else {
                ("No active rules reported", MUTED)
            };
            ui.label(RichText::new(label).strong().color(color));
            if let Some(profile) = self.firewall_status.profile {
                ui.label(format!("Profile: {}", firewall_profile_name(profile)));
            }
            if !self.firewall_status.installed {
                ui.label(RichText::new("Management unavailable").color(AMBER));
            }
        });
        if !self.firewall_status.message.is_empty() {
            ui.add(egui::Label::new(&self.firewall_status.message).wrap());
        }
        ui.label(
            RichText::new("Helper-published status, not a live verification of the kernel rules.")
                .size(12.0)
                .color(MUTED),
        );
        ui.add_space(10.0);
        // Safety controls stay ahead of every potentially long rule/code view.
        self.firewall_actions(ui);
        ui.add_space(14.0);
        let height = (ui.clip_rect().bottom() - ui.cursor().top() - 8.0).clamp(96.0, 540.0);
        egui::ScrollArea::vertical()
            .id_salt("firewall-workbench")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                if !self.firewall_status.installed {
                    ui.label(
                        RichText::new("The helper is unavailable or untrusted. You can still prepare and inspect a draft.")
                            .color(AMBER),
                    );
                    if ui.button("Copy firewall installer plan command").clicked() {
                        let base = extension_path()
                            .parent()
                            .map(Path::to_path_buf)
                            .unwrap_or_default();
                        let installed = base.join("firewall-install/scripts/install-firewall.sh");
                        let script = if installed.exists() {
                            installed
                        } else {
                            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                                .join("../../scripts/install-firewall.sh")
                        };
                        ui.ctx().copy_text(script_plan_command(&script));
                    }
                    ui.label(
                        RichText::new("Copying a plan does not install or activate anything.")
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.add_space(14.0);
                }
                self.firewall_editor(ui);
            });
    }

    pub(crate) fn firewall_editor(&mut self, ui: &mut egui::Ui) {
        let editable = !self.firewall_status.pending && !self.jobs.contains("firewall");
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Draft policy")
                    .size(18.0)
                    .strong()
                    .color(TEXT),
            );
            ui.label(
                RichText::new("Not the reported active rule set")
                    .size(12.0)
                    .color(MUTED),
            );
        });
        ui.add_enabled_ui(editable, |ui| {
            ui.horizontal_wrapped(|ui| {
                let public = ui.selectable_value(
                    &mut self.firewall_policy.profile,
                    blue_firewall::FirewallProfile::Public,
                    "Public",
                );
                let private = ui.selectable_value(
                    &mut self.firewall_policy.profile,
                    blue_firewall::FirewallProfile::Private,
                    "Private / LAN discovery",
                );
                if public.changed() || private.changed() {
                    self.firewall_approval = false;
                }
            });
        });
        ui.label(
            RichText::new(match self.firewall_policy.profile {
                blue_firewall::FirewallProfile::Public => {
                    "Deny new unsolicited inbound connections; preserve existing connections, ICMP and DHCP."
                }
                blue_firewall::FirewallProfile::Private => {
                    "The same inbound baseline, with private LAN discovery. This does not allow arbitrary LAN services."
                }
            })
            .size(12.0)
            .color(MUTED),
        );
        if !editable {
            ui.label(RichText::new("Draft editing is paused while a change is pending or a firewall operation is running.").color(AMBER));
        }
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        let width = ui.available_width();
        if width >= 820.0 {
            let usable = width - ui.spacing().item_spacing.x;
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(usable * 0.60);
                    self.firewall_rule_editor(ui);
                });
                ui.vertical(|ui| {
                    ui.set_width(usable * 0.40);
                    firewall_policy_preview(ui, &self.firewall_policy);
                });
            });
        } else {
            self.firewall_rule_editor(ui);
            ui.add_space(14.0);
            egui::CollapsingHeader::new("Generated draft policy")
                .id_salt("firewall-draft-code")
                .show(ui, |ui| firewall_policy_preview(ui, &self.firewall_policy));
        }
        ui.add_space(12.0);
        ui.label(RichText::new("Only table inet epimetheus_blue is managed. Output and forwarded Docker/VPN traffic are outside this policy.").size(12.0).color(MUTED));
    }

    pub(crate) fn firewall_rule_editor(&mut self, ui: &mut egui::Ui) {
        let editable = !self.firewall_status.pending && !self.jobs.contains("firewall");
        ui.label(RichText::new("Inbound exceptions").strong().color(TEXT));
        ui.add_enabled_ui(editable, |ui| {
            ui.label(RichText::new("Rule name").size(12.0).color(MUTED));
            let name = ui.add(
                egui::TextEdit::singleline(&mut self.firewall_rule_name)
                    .id_salt("firewall-rule-name")
                    .hint_text("For example: SSH from LAN")
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal_wrapped(|ui| {
                ui.label("Protocol");
                let tcp = ui.selectable_value(&mut self.firewall_rule_udp, false, "TCP");
                let udp = ui.selectable_value(&mut self.firewall_rule_udp, true, "UDP");
                ui.label("Port");
                let port = ui.add(
                    egui::TextEdit::singleline(&mut self.firewall_rule_port)
                        .id_salt("firewall-rule-port")
                        .hint_text("1–65535")
                        .desired_width(82.0),
                );
                if tcp.changed() || udp.changed() || port.changed() {
                    self.firewall_approval = false;
                }
            });
            ui.label(RichText::new("Source address or CIDR (optional)").size(12.0).color(MUTED));
            let source = ui.add(
                egui::TextEdit::singleline(&mut self.firewall_rule_source)
                    .id_salt("firewall-rule-source")
                    .hint_text("192.168.1.0/24 or an IPv6 address")
                    .desired_width(f32::INFINITY),
            );
            if name.changed() || source.changed() {
                self.firewall_approval = false;
            }
            let validation = firewall_rule_draft(self).and_then(|draft| draft.validate());
            let has_input = !self.firewall_rule_name.is_empty()
                || !self.firewall_rule_port.is_empty()
                || !self.firewall_rule_source.is_empty();
            if has_input {
                if let Err(error) = &validation {
                    ui.add(egui::Label::new(RichText::new(error.to_string()).color(AMBER)).wrap());
                } else if self.firewall_rule_source.trim().is_empty() {
                    ui.label(RichText::new("Any source: this exception would allow the port from any remote address.").size(12.0).color(AMBER));
                }
            }
            if ui.add_enabled(validation.is_ok(), egui::Button::new("Add to draft")).clicked() {
                self.add_firewall_rule();
            }
        });
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Draft exceptions").strong());
            ui.label(
                RichText::new(format!("{} rule(s)", self.firewall_policy.inbound.len()))
                    .color(MUTED),
            );
        });
        if self.firewall_policy.inbound.is_empty() {
            ui.label(RichText::new("No inbound exceptions in this draft.").color(MUTED));
            return;
        }
        let mut remove = None;
        egui::ScrollArea::vertical()
            .id_salt("firewall-rule-ledger")
            .max_height(190.0)
            .show(ui, |ui| {
                for (index, rule) in self.firewall_policy.inbound.iter().enumerate() {
                    ui.push_id(index, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(&rule.name).strong().color(TEXT));
                            ui.label(
                                RichText::new(format!(
                                    "{}/{}",
                                    firewall_protocol_name(rule.protocol),
                                    rule.port
                                ))
                                .monospace()
                                .color(TEXT),
                            );
                            if ui
                                .add_enabled(editable, egui::Button::new("Remove").small())
                                .clicked()
                            {
                                remove = Some(index);
                            }
                        });
                        ui.add(
                            egui::Label::new(
                                RichText::new(rule.source.as_deref().unwrap_or("Any source"))
                                    .monospace()
                                    .size(12.0)
                                    .color(if rule.source.is_some() { MUTED } else { AMBER }),
                            )
                            .wrap(),
                        );
                        ui.separator();
                    });
                }
            });
        if let Some(index) = remove {
            self.firewall_policy.inbound.remove(index);
            self.firewall_approval = false;
        }
    }

    pub(crate) fn add_firewall_rule(&mut self) {
        if self.firewall_status.pending || self.jobs.contains("firewall") {
            return;
        }
        match firewall_rule_draft(self).and_then(|draft| {
            draft.validate()?;
            Ok(draft)
        }) {
            Ok(draft) => {
                self.firewall_policy = draft;
                self.firewall_approval = false;
                self.firewall_rule_name.clear();
                self.firewall_rule_port.clear();
                self.firewall_rule_source.clear();
            }
            Err(error) => self.message = Some((error.to_string(), false)),
        }
    }

    pub(crate) fn firewall_actions(&mut self, ui: &mut egui::Ui) {
        let ready = self.firewall_status.installed && !self.jobs.contains("firewall");
        let review_id = egui::Id::unique("firewall-disable-review");
        let approval_id = egui::Id::unique("firewall-reviewed-draft-action");
        let mut disabling = ui
            .ctx()
            .data_mut(|data| data.get_temp::<bool>(review_id).unwrap_or(false));
        if disabling && (self.firewall_status.pending || !self.firewall_status.active) {
            self.firewall_approval = false;
            disabling = false;
        }
        if disabling && ui.input(|input| input.key_pressed(egui::Key::Escape)) {
            disabling = false;
            self.firewall_approval = false;
        }
        // Approval belongs to one exact draft and action, even across navigation.
        let approved = ui
            .ctx()
            .data_mut(|data| data.get_temp::<(blue_firewall::FirewallPolicy, bool)>(approval_id));
        if self.firewall_approval
            && !approved.as_ref().is_some_and(|(policy, action)| {
                policy == &self.firewall_policy && *action == disabling
            })
        {
            self.firewall_approval = false;
        }
        Frame::new()
            .fill(PANEL)
            .stroke(Stroke::new(1.0, if self.firewall_status.pending { AMBER } else if disabling { RED } else { BORDER }))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                if self.firewall_status.pending {
                    self.firewall_approval = false;
                    ui.label(RichText::new("Keep or undo the staged change").strong().color(AMBER));
                    ui.label(RichText::new("The helper sets a 60-second rollback deadline. Check its reported status above; recovery failures need administrator attention.").size(12.0).color(MUTED));
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(ready, egui::Button::new("Keep staged policy").fill(BLUE)).clicked() {
                            self.run_firewall("confirm");
                        }
                        if ui.add_enabled(ready, egui::Button::new("Undo staged change now")).clicked() {
                            self.run_firewall("rollback");
                        }
                    });
                } else {
                    ui.label(RichText::new(if disabling { "Review removing protection" } else { "Review before staging" }).strong().color(if disabling { RED } else { TEXT }));
                    ui.label(RichText::new(if disabling {
                        "Disabling removes Blue's rules and confirmed boot policy. This action is not staged for automatic rollback."
                    } else {
                        "Administrator authorization is required. Staging alone does not keep or persist the policy."
                    }).size(12.0).color(MUTED));
                    ui.add_enabled_ui(ready, |ui| {
                        ui.checkbox(&mut self.firewall_approval, if disabling {
                            "I reviewed and approve disabling Blue's firewall rules"
                        } else {
                            "I reviewed this draft and approve staging it"
                        });
                    });
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(ready && self.firewall_approval && !disabling && self.firewall_policy.validate().is_ok(), egui::Button::new("Stage firewall policy").fill(BLUE)).clicked() {
                            self.run_firewall("apply");
                        }
                        if disabling {
                            if ui.add_enabled(ready && self.firewall_approval && self.firewall_status.active, egui::Button::new("Disable Blue rules").stroke(Stroke::new(1.0, RED))).clicked() {
                                self.run_firewall("disable");
                                self.firewall_approval = false;
                                disabling = false;
                            }
                            if ui.button("Cancel disable review").clicked() {
                                disabling = false;
                                self.firewall_approval = false;
                            }
                        } else if ui.add_enabled(ready && self.firewall_status.active, egui::Button::new("Review disabling…")).clicked() {
                            disabling = true;
                            self.firewall_approval = false;
                        }
                    });
                    if !self.firewall_status.installed {
                        ui.label(RichText::new("Activation is unavailable until the trusted helper is installed separately.").size(12.0).color(AMBER));
                    }
                }
                if self.jobs.contains("firewall") {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Waiting for administrator authorization or the helper result…").size(12.0).color(MUTED));
                    });
                }
            });
        ui.ctx().data_mut(|data| {
            data.insert_temp(review_id, disabling);
            if self.firewall_approval {
                data.insert_temp(approval_id, (self.firewall_policy.clone(), disabling));
            } else {
                data.remove::<(blue_firewall::FirewallPolicy, bool)>(approval_id);
            }
        });
    }
}

fn firewall_rule_draft(app: &BlueApp) -> Result<blue_firewall::FirewallPolicy> {
    let port = app
        .firewall_rule_port
        .trim()
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("Enter a valid port from 1 to 65535"))?;
    let mut draft = app.firewall_policy.clone();
    draft.inbound.push(blue_firewall::InboundRule {
        name: app.firewall_rule_name.trim().to_owned(),
        protocol: if app.firewall_rule_udp {
            blue_firewall::Protocol::Udp
        } else {
            blue_firewall::Protocol::Tcp
        },
        port,
        source: (!app.firewall_rule_source.trim().is_empty())
            .then(|| app.firewall_rule_source.trim().to_owned()),
    });
    Ok(draft)
}

fn firewall_profile_name(profile: blue_firewall::FirewallProfile) -> &'static str {
    match profile {
        blue_firewall::FirewallProfile::Public => "Public",
        blue_firewall::FirewallProfile::Private => "Private / LAN discovery",
    }
}

fn firewall_protocol_name(protocol: blue_firewall::Protocol) -> &'static str {
    match protocol {
        blue_firewall::Protocol::Tcp => "TCP",
        blue_firewall::Protocol::Udp => "UDP",
    }
}

fn firewall_policy_preview(ui: &mut egui::Ui, draft: &blue_firewall::FirewallPolicy) {
    ui.label(RichText::new("Generated draft policy").strong().color(TEXT));
    ui.label(
        RichText::new("Read-only preview, not the current kernel rules.")
            .size(12.0)
            .color(MUTED),
    );
    match draft.render_nft() {
        Ok(policy) => {
            if ui.button("Copy draft policy").clicked() {
                ui.ctx().copy_text(policy.clone());
            }
            egui::ScrollArea::both()
                .id_salt("firewall-policy-code")
                .max_height(300.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(policy).monospace().size(12.0).color(TEXT))
                            .wrap_mode(egui::TextWrapMode::Extend),
                    );
                });
        }
        Err(error) => {
            ui.add(egui::Label::new(RichText::new(error.to_string()).color(RED)).wrap());
        }
    }
}
