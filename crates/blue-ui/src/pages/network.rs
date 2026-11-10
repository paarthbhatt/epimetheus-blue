use super::integrity::{
    finding_group_review, finding_review_label, finding_source_acknowledgement,
};
use crate::*;

#[derive(Clone, PartialEq, Eq)]
struct NetworkSocketSelection {
    protocol: String,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    inode: u64,
}

impl NetworkSocketSelection {
    fn from_connection(connection: &blue_net::Connection) -> Self {
        Self {
            protocol: connection.protocol.clone(),
            local: connection.local,
            remote: connection.remote,
            inode: connection.inode,
        }
    }

    fn matches(&self, connection: &blue_net::Connection) -> bool {
        self.protocol == connection.protocol
            && self.local == connection.local
            && self.remote == connection.remote
            && self.inode == connection.inode
    }
}

impl BlueApp {
    pub(crate) fn network(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Network",
            "Inspect an egress snapshot. Observation never changes firewall rules.",
        );
        let observing = self.jobs.contains("network");
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !observing,
                    egui::Button::new("Observe connections").fill(BLUE),
                )
                .clicked()
            {
                self.run_network();
            }
            if observing {
                ui.spinner();
                ui.label(RichText::new("Reading a new socket snapshot…").color(MUTED));
            }
        });
        ui.label(RichText::new(if self.deps.config.network.ignore_private {
            "Established TCP and connected UDP only. Private, loopback, multicast and link-local addresses are excluded."
        } else {
            "Established TCP and connected UDP only. Private addresses are included; loopback, multicast and unspecified peers are excluded."
        }).size(12.0).color(MUTED));
        ui.label(RichText::new("This page holds the last completed observation, not a live feed. The background schedule does not refresh these socket rows.").size(12.0).color(MUTED));
        ui.add_space(12.0);
        let height = (ui.clip_rect().bottom() - ui.cursor().top() - 8.0).max(96.0);
        egui::ScrollArea::vertical()
            .id_salt("network-workspace")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                match &self.last_net {
                    None => empty_state(
                        ui,
                        "No observation in this session",
                        "Select Observe connections. The first run establishes a baseline, not a safety verdict.",
                    ),
                    Some(report) => network_report(ui, report, observing),
                }
                ui.add_space(18.0);
                self.network_findings(ui);
            });
    }

    fn network_findings(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        ui.add_space(8.0);
        ui.label(
            RichText::new("Pending network finding groups")
                .size(16.0)
                .strong()
                .color(TEXT),
        );
        ui.add(egui::Label::new(RichText::new("Stored conservative assessments distinguish informational history from pending investigation or action. Acknowledge source record changes only the displayed representative record, not its group, and never allows or blocks traffic.").size(12.0).color(MUTED)).wrap());
        if let Some(error) = &self.refresh_error {
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "Showing previously loaded groups and assessments: {error}"
                    ))
                    .color(AMBER),
                )
                .wrap(),
            );
        }
        let groups: Vec<_> = self
            .snapshot
            .finding_groups
            .iter()
            .filter(|group| group.kind == "network")
            .collect();
        let pending_records = groups
            .iter()
            .fold(0_i64, |count, group| count.saturating_add(group.pending));
        ui.add(egui::Label::new(RichText::new(format!("Showing {} network groups with {pending_records} pending source records within {} loaded pending groups. The snapshot reports {} pending groups across all sources; the shared window is capped at 250 groups, not source records.", groups.len(), self.snapshot.finding_groups.len(), self.snapshot.counts.findings)).size(12.0).color(MUTED)).wrap());
        ui.add(egui::Label::new(RichText::new("Occurrences include all retained source records, including acknowledged history. Unique observations count identities, not identical evidence. Informational history is not loaded in this pending-only view; other pending records can keep a group here after source acknowledgement.").size(12.0).color(MUTED)).wrap());
        if groups.is_empty() {
            ui.label(
                RichText::new("No pending network groups in the loaded window; informational, acknowledged and older source history can still be retained. This is not a network safety verdict.")
                    .color(MUTED),
            );
            return;
        }
        let mut acknowledge = None;
        egui::ScrollArea::vertical()
            .id_salt("network-findings")
            .max_height(210.0)
            .show(ui, |ui| {
                for group in groups {
                    if let Some(id) = network_finding_group(ui, group) {
                        acknowledge = Some(id);
                    }
                }
            });
        if let Some(id) = acknowledge {
            self.acknowledge(id);
        }
    }
}

fn network_finding_group(ui: &mut egui::Ui, group: &blue_core::FindingGroup) -> Option<i64> {
    let source = &group.representative.finding;
    let assessment = &group.representative.review;
    let mut acknowledge = None;
    ui.push_id(&group.group_key, |ui| {
        ui.add(egui::Label::new(RichText::new(&source.subject).strong().color(TEXT)).wrap());
        finding_group_review(ui, group);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("Representative source record {}", source.id)).size(12.0).color(MUTED));
            let source_id = finding_source_acknowledgement(group);
            let review = ui.add_enabled(source_id.is_some(), egui::Button::new("Acknowledge source record"))
                .on_hover_text(format!("Acknowledge source record {} only, not the entire group. Other pending members remain; traffic and trust decisions are unchanged.", source.id));
            if review.clicked() {
                acknowledge = source_id;
            }
        });
        egui::CollapsingHeader::new("Representative source evidence")
            .id_salt(("network-group-source", source.id))
            .show(ui, |ui| {
                ui.label(RichText::new(format!("Source {} at {} Unix ms. Group first/last retained timestamps: {} / {} Unix ms.", source.id, source.ts_ms, group.first_seen_ms, group.last_seen_ms)).size(12.0).color(MUTED));
                ui.add(egui::Label::new(RichText::new(format!("Review reason code: {}; policy version {}. Other source records are retained but not loaded here.", assessment.reason_code, assessment.policy_version)).size(12.0).color(MUTED)).wrap());
                ui.add(egui::Label::new(RichText::new(&source.detail).monospace().size(12.0).color(TEXT)).wrap().selectable(true));
                if ui.small_button("Copy source evidence").clicked() {
                    ui.ctx().copy_text(format!("Source record {}\n{}\n{}\nT{}\nRecorded at {} Unix ms\nAssessment: {}\nReason: {}\n{}", source.id, source.subject, source.kind, source.tier.as_i64(), source.ts_ms, finding_review_label(assessment.classification), assessment.reason, source.detail));
                }
            });
        ui.separator();
    });
    acknowledge
}

fn network_report(ui: &mut egui::Ui, report: &blue_net::NetReport, observing: bool) {
    ui.label(
        RichText::new(if observing {
            "Previous completed observation"
        } else {
            "Last completed observation"
        })
        .size(18.0)
        .strong()
        .color(TEXT),
    );
    let endpoints: HashSet<_> = report
        .connections
        .iter()
        .map(|connection| (connection.protocol.as_str(), connection.remote))
        .collect();
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("{} socket rows", report.observed));
        ui.label(RichText::new(format!("{} endpoint identities", endpoints.len())).color(MUTED));
        if report.baseline {
            ui.label(RichText::new("Baseline established").color(MUTED));
        } else {
            ui.label(
                RichText::new(format!(
                    "{} previously unseen endpoint(s)",
                    report.new_remote
                ))
                .color(if report.new_remote > 0 { AMBER } else { MUTED }),
            );
        }
    });
    ui.add(egui::Label::new(RichText::new(format!("These are raw socket snapshot rows and endpoint identities, not pending finding groups. This observation recorded {} source findings; their grouped assessments appear separately below.", report.findings)).size(12.0).color(MUTED)).wrap());
    if report.baseline {
        ui.label(RichText::new("These endpoints have not been marked safe. Later observations compare against previously seen protocol/address/port identities.").size(12.0).color(MUTED));
    }
    if report.truncated {
        ui.label(RichText::new("Incomplete observation: the configured socket limit was reached. These rows are not a complete inventory.").color(AMBER));
    }
    if report.connections.is_empty() {
        empty_state(ui, "No eligible sockets observed", "This snapshot includes only established TCP and connected UDP within the configured address scope.");
        return;
    }
    let search_id = egui::Id::unique("network-socket-search");
    let selection_id = egui::Id::unique("network-socket-selection");
    let mut search = ui
        .ctx()
        .data_mut(|data| data.get_temp::<String>(search_id).unwrap_or_default());
    let mut selection = ui
        .ctx()
        .data_mut(|data| data.get_temp::<NetworkSocketSelection>(selection_id));
    if selection.as_ref().is_some_and(|key| {
        !report
            .connections
            .iter()
            .any(|connection| key.matches(connection))
    }) {
        selection = None;
    }
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        let width = (ui.available_width() - 70.0).max(100.0);
        ui.add_sized(
            [width, 34.0],
            egui::TextEdit::singleline(&mut search)
                .id_salt("network-search-input")
                .hint_text("Filter process, PID, IP, port, protocol or state"),
        );
        if ui
            .add_enabled(!search.is_empty(), egui::Button::new("Clear"))
            .clicked()
        {
            search.clear();
        }
    });
    let needle = search.trim().to_lowercase();
    let mut visible: Vec<_> = report
        .connections
        .iter()
        .filter(|connection| network_matches_search(connection, &needle))
        .collect();
    visible.sort_by(|a, b| {
        a.process
            .as_deref()
            .unwrap_or("")
            .cmp(b.process.as_deref().unwrap_or(""))
            .then_with(|| a.pid.cmp(&b.pid))
            .then_with(|| a.remote.cmp(&b.remote))
            .then_with(|| a.protocol.cmp(&b.protocol))
    });
    ui.label(
        RichText::new(format!(
            "Showing {} of {} socket rows; sorted by process and PID",
            visible.len(),
            report.connections.len()
        ))
        .size(12.0)
        .color(MUTED),
    );
    ui.add_space(8.0);
    let width = ui.available_width();
    if width >= 820.0 {
        let usable = width - ui.spacing().item_spacing.x;
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(usable * 0.66);
                network_ledger(ui, &visible, &mut selection);
            });
            ui.vertical(|ui| {
                ui.set_width(usable * 0.34);
                network_inspector(ui, report, selection.as_ref());
            });
        });
    } else {
        network_ledger(ui, &visible, &mut selection);
        ui.add_space(12.0);
        egui::CollapsingHeader::new("Selected socket")
            .id_salt("network-compact-inspector")
            .default_open(true)
            .show(ui, |ui| network_inspector(ui, report, selection.as_ref()));
    }
    ui.ctx().data_mut(|data| {
        data.insert_temp(search_id, search);
        if let Some(selection) = selection {
            data.insert_temp(selection_id, selection);
        } else {
            data.remove::<NetworkSocketSelection>(selection_id);
        }
    });
}

fn network_matches_search(connection: &blue_net::Connection, needle: &str) -> bool {
    needle.is_empty()
        || connection
            .process
            .as_deref()
            .unwrap_or("not attributed")
            .to_lowercase()
            .contains(needle)
        || connection.protocol.to_lowercase().contains(needle)
        || connection.state.to_lowercase().contains(needle)
        || connection.local.to_string().to_lowercase().contains(needle)
        || connection
            .remote
            .to_string()
            .to_lowercase()
            .contains(needle)
        || connection
            .pid
            .is_some_and(|pid| pid.to_string().contains(needle))
}

fn network_ledger(
    ui: &mut egui::Ui,
    connections: &[&blue_net::Connection],
    selection: &mut Option<NetworkSocketSelection>,
) {
    let usable = (ui.available_width() - 2.0 * ui.spacing().item_spacing.x).max(120.0);
    let widths = [usable * 0.32, usable * 0.42, usable * 0.26];
    ui.horizontal(|ui| {
        for (width, heading) in
            widths
                .into_iter()
                .zip(["Process / PID", "Remote / local", "Protocol / state"])
        {
            ui.add_sized(
                [width, 22.0],
                egui::Label::new(RichText::new(heading).size(12.0).color(MUTED)),
            );
        }
    });
    ui.separator();
    if connections.is_empty() {
        ui.label(
            RichText::new("No socket rows match this filter. Clear it to inspect the snapshot.")
                .color(MUTED),
        );
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt("network-socket-ledger")
        .max_height(310.0)
        .auto_shrink([false, true])
        .show_rows(ui, 52.0, connections.len(), |ui, range| {
            for index in range {
                let connection = connections[index];
                let selected = selection
                    .as_ref()
                    .is_some_and(|key| key.matches(connection));
                ui.push_id(
                    (
                        connection.inode,
                        connection.local,
                        connection.remote,
                        &connection.protocol,
                    ),
                    |ui| {
                        ui.horizontal(|ui| {
                            let process = connection.process.as_deref().unwrap_or("Not attributed");
                            let pid = connection
                                .pid
                                .map(|pid| format!("PID {pid}"))
                                .unwrap_or_else(|| "PID unavailable".into());
                            if ui
                                .add_sized(
                                    [widths[0], 52.0],
                                    egui::Button::new(
                                        RichText::new(format!("{process}\n{pid}"))
                                            .size(13.0)
                                            .color(TEXT),
                                    )
                                    .wrap_mode(egui::TextWrapMode::Truncate)
                                    .selected(selected)
                                    .frame_when_inactive(false),
                                )
                                .on_hover_text(format!(
                                    "Select socket for {process}; remote {}",
                                    connection.remote
                                ))
                                .clicked()
                            {
                                *selection =
                                    Some(NetworkSocketSelection::from_connection(connection));
                            }
                            ui.allocate_ui(Vec2::new(widths[1], 52.0), |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(connection.remote.to_string())
                                            .monospace()
                                            .size(13.0)
                                            .color(TEXT),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(connection.remote.to_string());
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(connection.local.to_string())
                                            .monospace()
                                            .size(11.0)
                                            .color(MUTED),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(format!("Local socket: {}", connection.local));
                            });
                            ui.allocate_ui(Vec2::new(widths[2], 52.0), |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&connection.protocol)
                                            .monospace()
                                            .size(12.0)
                                            .color(TEXT),
                                    )
                                    .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&connection.state).size(12.0).color(MUTED),
                                    )
                                    .truncate(),
                                );
                            });
                        });
                    },
                );
            }
        });
}

fn network_inspector(
    ui: &mut egui::Ui,
    report: &blue_net::NetReport,
    selection: Option<&NetworkSocketSelection>,
) {
    ui.label(
        RichText::new("Socket detail")
            .size(16.0)
            .strong()
            .color(TEXT),
    );
    let connection = selection.and_then(|key| {
        report
            .connections
            .iter()
            .find(|connection| key.matches(connection))
    });
    let Some(connection) = connection else {
        ui.label(RichText::new("Select a process row to inspect its local and remote socket. Tab and Enter also select rows.").color(MUTED));
        return;
    };
    ui.add_space(8.0);
    ui.add(
        egui::Label::new(
            RichText::new(
                connection
                    .process
                    .as_deref()
                    .unwrap_or("Process attribution unavailable"),
            )
            .strong()
            .color(TEXT),
        )
        .wrap(),
    );
    ui.label(
        connection
            .pid
            .map(|pid| format!("PID {pid}"))
            .unwrap_or_else(|| "PID unavailable in this observation".into()),
    );
    ui.label(
        RichText::new("A missing process name is not a malicious verdict.")
            .size(12.0)
            .color(MUTED),
    );
    ui.add_space(10.0);
    for (label, value) in [
        ("Local socket", connection.local.to_string()),
        ("Remote endpoint", connection.remote.to_string()),
        ("Protocol", connection.protocol.clone()),
        ("Socket inode", connection.inode.to_string()),
    ] {
        ui.label(RichText::new(label).size(12.0).color(MUTED));
        ui.add(egui::Label::new(RichText::new(&value).monospace().color(TEXT)).wrap());
    }
    ui.label(format!("Observed state: {}", connection.state));
    ui.horizontal_wrapped(|ui| {
        if ui.small_button("Copy remote endpoint").clicked() {
            ui.ctx().copy_text(connection.remote.to_string());
        }
        if ui.small_button("Copy socket details").clicked() {
            ui.ctx().copy_text(format!(
                "Process: {}\nPID: {}\nProtocol: {}\nLocal: {}\nRemote: {}\nState: {}\nInode: {}",
                connection.process.as_deref().unwrap_or("unavailable"),
                connection
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unavailable".into()),
                connection.protocol,
                connection.local,
                connection.remote,
                connection.state,
                connection.inode
            ));
        }
    });
    ui.add_space(8.0);
    ui.label(RichText::new("Snapshot metadata only. No packet rates, hostname lookup or blocking action is inferred.").size(12.0).color(MUTED));
}
