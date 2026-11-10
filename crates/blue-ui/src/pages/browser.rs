use crate::*;

impl BlueApp {
    pub(crate) fn browser(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Browser companion",
            "Search-page tools, browser-local rules, and a read-only desktop bridge.",
        );
        egui::ScrollArea::vertical()
            .id_salt("browser-companion-page")
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "This page explains the companion. It does not check whether the extension is installed or connected.",
                    )
                    .color(MUTED),
                );
                ui.add_space(20.0);
                if ui.available_width() >= 820.0 {
                    ui.columns(2, |columns| {
                        browser_local_scope(&mut columns[0]);
                        browser_bridge_scope(&mut columns[1]);
                    });
                } else {
                    browser_local_scope(ui);
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(16.0);
                    browser_bridge_scope(ui);
                }
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);
                section_title(
                    ui,
                    "Load Blue Search Guard",
                    "Use Chromium or Brave's extension manager. Loading the folder does not register the desktop bridge.",
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new("1. Open chrome://extensions or brave://extensions.")
                        .color(TEXT),
                );
                ui.label(RichText::new("2. Enable Developer mode.").color(TEXT));
                ui.label(
                    RichText::new("3. Select Load unpacked and choose the folder below.")
                        .color(TEXT),
                );
                ui.add_space(12.0);
                let path = extension_path();
                surface(ui, |ui| {
                    ui.label(RichText::new("Extension folder").strong().color(TEXT));
                    ui.add(
                        egui::Label::new(
                            RichText::new(path.to_string_lossy())
                                .monospace()
                                .color(TEXT),
                        )
                        .wrap(),
                    );
                    ui.add_space(8.0);
                    if ui.button("Copy extension path").clicked() {
                        ui.ctx().copy_text(path.to_string_lossy().into_owned());
                        self.message = Some(("Extension path copied".into(), true));
                    }
                });
                ui.add_space(12.0);
                ui.label(
                    RichText::new(
                        "The read-only bridge needs the com.epimetheus.blue Native Messaging host registered separately. Check it in the browser popup; browser-only features can be used without it.",
                    )
                    .color(MUTED),
                );
            });
    }
}

fn browser_local_scope(ui: &mut egui::Ui) {
    section_title(
        ui,
        "In this browser profile",
        "The popup controls browser preferences, not desktop protection.",
    );
    ui.add_space(12.0);
    for (title, detail) in [
        (
            "Search-page cleanup",
            "Removes identified sponsored results and common tracking parameters on supported Google, Bing, DuckDuckGo and Brave Search pages.",
        ),
        (
            "Local site rules",
            "A small built-in request ruleset and your explicit allow/block rules stay in the browser profile. Allowing a site does not override desktop DNS blocking.",
        ),
        (
            "Provider choice",
            "Blue opens your chosen search provider and can request its strict SafeSearch filter. The provider's privacy policy still applies.",
        ),
    ] {
        ui.label(RichText::new(title).strong().color(TEXT));
        ui.label(RichText::new(detail).color(MUTED));
        ui.add_space(10.0);
    }
}

fn browser_bridge_scope(ui: &mut egui::Ui) {
    section_title(
        ui,
        "Read-only desktop bridge",
        "A local reply is not a live-protection or desktop-window check.",
    );
    ui.add_space(12.0);
    for (title, detail) in [
        (
            "List matches, not infection findings",
            "Checks batches of up to 200 visible search-result domains against active desktop feeds. An unmatched or unchecked domain is not certified safe.",
        ),
        (
            "Read-only boundary",
            "Can read status, recorded findings and domain-list matches. Cannot change desktop settings, files, feeds, DNS or firewall policy.",
        ),
        (
            "Separate coverage",
            "Full desktop feeds are not copied into the browser request ruleset. If the bridge is unavailable, browser-only features remain controlled by your browser settings.",
        ),
    ] {
        ui.label(RichText::new(title).strong().color(TEXT));
        ui.label(RichText::new(detail).color(MUTED));
        ui.add_space(10.0);
    }
}
