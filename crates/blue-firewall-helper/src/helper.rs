use crate::commands::{Command, CommandRunner, MAX_OUTPUT};
use crate::state::{Pending, State, MAX_POLICY, MAX_TABLE};
use anyhow::{bail, Result};
use blue_firewall::{FirewallPolicy, FirewallProfile, FirewallStatus, InboundRule, Protocol};
use serde::Deserialize;
use std::ffi::OsString;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

const DELETE_TABLE: &str = "delete table inet epimetheus_blue\n";
const APPLIED: &str = "Firewall applied; confirm within 60 seconds or it will roll back.";
const CONFIRMED: &str = "Firewall confirmed, saved, and enabled for boot.";
const RESTORED: &str = "Previous owned firewall table restored.";
const DISABLED: &str = "Owned firewall and boot service disabled; other tables are unchanged.";
const RECOVERY_FAILED: &str =
    "Firewall recovery needs administrator attention; rollback remains pending.";
const ENABLE_FAILED: &str = "Firewall confirmed and saved, but boot service enable failed; reboot protection is not guaranteed.";
const DISABLE_BOOT_FAILED: &str = "Owned firewall and confirmed policy removed, but boot service disable failed; reboot-service state is uncertain.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Apply,
    Confirm,
    Rollback,
    Disable,
    Boot,
}

impl Verb {
    pub fn parse(args: &[OsString]) -> Result<Self> {
        let [arg] = args else {
            bail!("Expected exactly one fixed firewall verb.")
        };
        match arg.to_str() {
            Some("apply") => Ok(Self::Apply),
            Some("confirm") => Ok(Self::Confirm),
            Some("rollback") => Ok(Self::Rollback),
            Some("disable") => Ok(Self::Disable),
            Some("boot") => Ok(Self::Boot),
            _ => bail!("Unknown firewall verb."),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Identity {
    pub real_uid: u32,
    pub effective_uid: u32,
}

impl Identity {
    pub fn current() -> Self {
        // SAFETY: getuid and geteuid have no arguments or preconditions.
        unsafe {
            Self {
                real_uid: libc::getuid(),
                effective_uid: libc::geteuid(),
            }
        }
    }
}

pub fn require_root(identity: Identity) -> Result<()> {
    if identity.real_uid != 0 || identity.effective_uid != 0 {
        bail!("Root authorization is required; use the installed Polkit helper.");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    profile: FirewallProfile,
    inbound: Vec<RuleInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    name: String,
    protocol: Protocol,
    port: u16,
    source: Option<String>,
}

pub fn read_input(verb: Verb, reader: &mut impl Read) -> Result<Option<FirewallPolicy>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_POLICY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Cannot read firewall policy input."))?;
    if bytes.len() > MAX_POLICY {
        bail!("Firewall policy input exceeds 64 KiB.");
    }
    if verb != Verb::Apply {
        if bytes.iter().any(|byte| !byte.is_ascii_whitespace()) {
            bail!("Only apply accepts policy input.");
        }
        return Ok(None);
    }
    let input: PolicyInput = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid firewall policy JSON."))?;
    let policy = FirewallPolicy {
        profile: input.profile,
        inbound: input
            .inbound
            .into_iter()
            .map(|rule| InboundRule {
                name: rule.name,
                protocol: rule.protocol,
                port: rule.port,
                source: rule.source,
            })
            .collect(),
    };
    policy
        .validate()
        .map_err(|_| anyhow::anyhow!("Invalid firewall policy."))?;
    Ok(Some(policy))
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| anyhow::anyhow!("Cannot determine firewall confirmation deadline."))
}

fn profile(policy: &FirewallPolicy) -> FirewallProfile {
    match &policy.profile {
        FirewallProfile::Public => FirewallProfile::Public,
        FirewallProfile::Private => FirewallProfile::Private,
    }
}

fn copy_profile(profile: &Option<FirewallProfile>) -> Option<FirewallProfile> {
    match profile {
        Some(FirewallProfile::Public) => Some(FirewallProfile::Public),
        Some(FirewallProfile::Private) => Some(FirewallProfile::Private),
        None => None,
    }
}

// Accept exactly one table declaration. Strings/comments may contain braces, but
// no trailing commands, includes, or second/foreign table can escape this scope.
fn owned_table(script: &str) -> Result<()> {
    if script.len() > MAX_TABLE {
        bail!("Owned firewall table exceeds its snapshot limit.");
    }
    let mut remainder = script.trim();
    for expected in ["table", "inet", "epimetheus_blue"] {
        let split = remainder
            .find(char::is_whitespace)
            .ok_or_else(|| anyhow::anyhow!("Invalid owned firewall table."))?;
        if &remainder[..split] != expected {
            bail!("Refusing a transaction outside the owned firewall table.");
        }
        remainder = remainder[split..].trim_start();
    }
    if !remainder.starts_with('{') {
        bail!("Invalid owned firewall table.");
    }
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = false;
    let mut closed = false;
    for character in remainder.chars() {
        if comment {
            comment = character != '\n';
        } else if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
        } else if character == '#' {
            comment = true;
        } else if closed {
            if !character.is_whitespace() && character != ';' {
                bail!("Refusing commands outside the owned firewall table.");
            }
        } else {
            match character {
                '"' => quoted = true,
                '{' => depth += 1,
                '}' if depth > 0 => {
                    depth -= 1;
                    closed = depth == 0;
                }
                '}' => bail!("Invalid owned firewall table."),
                _ => {}
            }
        }
    }
    if !closed || quoted {
        bail!("Invalid owned firewall table.");
    }
    Ok(())
}

fn render(policy: &FirewallPolicy) -> Result<String> {
    policy
        .validate()
        .map_err(|_| anyhow::anyhow!("Invalid firewall policy."))?;
    if serde_json::to_vec(policy)
        .map_err(|_| anyhow::anyhow!("Cannot encode firewall policy."))?
        .len()
        > MAX_POLICY
    {
        bail!("Canonical firewall policy exceeds 64 KiB.");
    }
    let script = policy
        .render_nft()
        .map_err(|_| anyhow::anyhow!("Cannot render a safe firewall policy."))?;
    owned_table(&script)?;
    Ok(script)
}

pub struct Helper<R> {
    pub state: State,
    pub runner: R,
}

impl<R: CommandRunner> Helper<R> {
    pub fn new(state: State, runner: R) -> Self {
        Self { state, runner }
    }

    fn command(&mut self, command: Command<'_>) -> Result<Vec<u8>> {
        let output = self
            .runner
            .run(command)
            .map_err(|_| anyhow::anyhow!("Required firewall command could not complete."))?;
        if !output.success || output.stdout.len() > MAX_OUTPUT {
            bail!("Required firewall command failed.");
        }
        Ok(output.stdout)
    }

    fn table_present(&mut self) -> Result<bool> {
        let bytes = self.command(Command::ListTables)?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("Cannot inspect owned firewall table."))?;
        let entries = json
            .get("nftables")
            .and_then(|value| value.as_array())
            .ok_or_else(|| anyhow::anyhow!("Cannot inspect owned firewall table."))?;
        let mut found = false;
        for entry in entries {
            if let Some(table) = entry.get("table") {
                let family = table
                    .get("family")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Invalid firewall table listing."))?;
                let name = table
                    .get("name")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Invalid firewall table listing."))?;
                if family == "inet" && name == "epimetheus_blue" {
                    if found {
                        bail!("Duplicate owned firewall table.");
                    }
                    found = true;
                }
            } else if entry.get("metainfo").is_none() {
                bail!("Invalid firewall table listing.");
            }
        }
        Ok(found)
    }

    fn cancel_timer(&mut self, with_service: bool) -> Result<()> {
        let bytes = self.command(Command::TimerState { with_service })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| anyhow::anyhow!("Cannot inspect rollback timer."))?;
        let states: Vec<_> = text.lines().filter(|line| !line.is_empty()).collect();
        if states.len() != if with_service { 2 } else { 1 }
            || states
                .iter()
                .any(|state| !matches!(*state, "loaded" | "not-found"))
        {
            bail!("Cannot inspect rollback timer.");
        }
        let timer = states[0] == "loaded";
        let service = with_service && states[1] == "loaded";
        if timer || service {
            self.command(Command::StopTimer { timer, service })?;
        }
        Ok(())
    }

    fn publish(
        &self,
        active: bool,
        pending: bool,
        profile: Option<FirewallProfile>,
        message: &str,
    ) -> Result<()> {
        self.state.status(&FirewallStatus {
            installed: true,
            active,
            pending,
            profile,
            message: message.to_owned(),
        })
    }

    fn pending_status(&self, pending: &Pending, message: &str) -> Result<()> {
        let (active, profile) = if pending.applied {
            (true, Some(profile(&pending.policy)))
        } else {
            (
                pending.previous_table.is_some(),
                copy_profile(&pending.previous_profile),
            )
        };
        self.publish(active, true, profile, message)
    }

    fn recovery_status(&mut self, pending: &Pending) -> Result<()> {
        // An unsuccessful command may have committed before timing out. Inspect
        // presence again; never claim an uncertain profile or expose raw errors.
        let active = match self.table_present() {
            Ok(active) => active,
            Err(_) => pending.applied || pending.previous_table.is_some(),
        };
        self.publish(active, true, None, RECOVERY_FAILED)
    }

    fn get_pending(&self) -> Result<Option<Pending>> {
        let pending = self.state.pending()?;
        if let Some(pending) = &pending {
            render(&pending.policy)?;
            if let Some(previous) = &pending.previous_table {
                owned_table(previous)?;
            } else if pending.previous_profile.is_some() {
                bail!("Invalid pending firewall state.");
            }
        }
        Ok(pending)
    }

    fn replace(&mut self, present: bool, table: Option<&str>) -> Result<()> {
        let mut transaction = String::new();
        if present {
            transaction.push_str(DELETE_TABLE);
        }
        if let Some(table) = table {
            owned_table(table)?;
            transaction.push_str(table);
            transaction.push('\n');
        }
        if !transaction.is_empty() {
            self.command(Command::Check(&transaction))?;
            self.command(Command::Replace(&transaction))?;
        }
        Ok(())
    }

    fn rollback_pending(&mut self, mut pending: Pending) -> Result<()> {
        let present = self.table_present()?;
        self.replace(present, pending.previous_table.as_deref())?;
        pending.applied = false;
        self.state.save_pending(&pending)?;
        // Never stop our own service: a timer-triggered rollback must finish its
        // state cleanup. The next apply cancels any stale service before staging.
        self.cancel_timer(false)?;
        self.state.clear_pending()?;
        self.publish(
            pending.previous_table.is_some(),
            false,
            pending.previous_profile,
            RESTORED,
        )
    }

    fn recover(&mut self) -> Result<()> {
        let Some(pending) = self.get_pending()? else {
            return Ok(());
        };
        self.recover_snapshot(pending)
    }

    fn recover_snapshot(&mut self, pending: Pending) -> Result<()> {
        // Also handles a failed directory sync after pending state was unlinked.
        // Try to retain a durable snapshot, but do not skip immediate recovery
        // merely because the state filesystem itself is failing.
        let _ = self.state.save_pending(&pending);
        match self.rollback_pending(pending) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Commands can partially fail, including timer cancellation.
                // Keep the snapshot and try to ensure an independent retry.
                let _ = self.cancel_timer(true);
                let _ = self.command(Command::ArmTimer);
                if let Ok(Some(pending)) = self.get_pending() {
                    let _ = self.recovery_status(&pending);
                }
                bail!("Firewall rollback could not complete; recovery remains pending.");
            }
        }
    }

    fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        let script = render(&policy)?;
        if self.get_pending()?.is_some() {
            bail!("A firewall change is already pending; confirm or roll it back first.");
        }
        // A stale rollback service must never pick up the next apply's snapshot.
        self.cancel_timer(true)?;
        let present = self.table_present()?;
        let previous_table = if present {
            let bytes = self.command(Command::SaveTable)?;
            let table = String::from_utf8(bytes)
                .map_err(|_| anyhow::anyhow!("Invalid owned firewall snapshot."))?;
            owned_table(&table)?;
            Some(table)
        } else {
            None
        };
        let previous_profile = if present {
            self.state.policy()?.as_ref().map(profile)
        } else {
            None
        };
        let mut pending = Pending {
            policy,
            previous_table,
            previous_profile,
            expires_at: now()?
                .checked_add(60)
                .ok_or_else(|| anyhow::anyhow!("Invalid confirmation deadline."))?,
            applied: false,
        };
        self.state.save_pending(&pending)?;
        if self.command(Command::ArmTimer).is_err() {
            // No nft mutation is permitted when independent rollback did not arm.
            if self.cancel_timer(true).is_ok() {
                self.state.clear_pending()?;
                self.publish(
                    present,
                    false,
                    pending.previous_profile,
                    "Firewall was not changed; rollback timer could not arm.",
                )?;
            } else {
                let _ = self.pending_status(&pending, RECOVERY_FAILED);
            }
            bail!("Cannot arm independent rollback; firewall was not changed.");
        }
        let result = (|| {
            let transaction = if present {
                format!("{DELETE_TABLE}{script}\n")
            } else {
                format!("{script}\n")
            };
            self.command(Command::Check(&transaction))?;
            if now()? >= pending.expires_at {
                bail!("Firewall confirmation deadline expired before mutation.");
            }
            self.command(Command::Replace(&transaction))?;
            pending.applied = true;
            self.state.save_pending(&pending)?;
            self.pending_status(&pending, APPLIED)
        })();
        if result.is_err() {
            self.recover()?;
            bail!("Firewall apply failed; the previous owned table was restored.");
        }
        Ok(())
    }

    fn finish_confirmation(&mut self, persist: bool) -> Result<()> {
        let Some(pending) = self.get_pending()? else {
            // Explicit confirm can retry a partial enable failure without a new
            // live apply. Only an already-durable, confirmed policy is eligible.
            if persist {
                if let Some(policy) = self.state.policy()? {
                    if self.table_present()? {
                        return self.enable_confirmed(&policy);
                    }
                }
            }
            bail!("No firewall change is awaiting confirmation.")
        };
        if !pending.applied {
            bail!("The pending firewall change was not applied; roll it back first.");
        }
        if now()? >= pending.expires_at {
            self.recover()?;
            bail!("Confirmation expired; the previous owned table was restored.");
        }
        if !self.table_present()? {
            self.recover()?;
            bail!("The pending firewall table is absent; confirmation refused.");
        }
        let previous_policy = self.state.policy()?;
        if self.cancel_timer(true).is_err() {
            self.recover()?;
            bail!("Cannot cancel rollback; the previous owned table was restored.");
        }
        let commit = (|| {
            if persist {
                self.state.save_policy(&pending.policy)?;
            }
            self.state.clear_pending()
        })();
        if commit.is_err() {
            // Atomic rename can succeed before its directory sync fails. Restore
            // the old boot policy too, not just the old live table.
            let config_result = if persist {
                self.restore_policy(previous_policy)
            } else {
                Ok(())
            };
            let recovery_result = self.recover_snapshot(pending);
            if config_result.is_err() {
                bail!("Cannot restore confirmed boot policy; administrator attention is required.");
            }
            recovery_result?;
            bail!("Cannot finish confirmation; the previous owned table was restored.");
        }
        // save_policy and clear_pending both fsync before returning. Never
        // enable a boot unit while the new policy is unconfirmed or pending.
        if persist {
            return self.enable_confirmed(&pending.policy);
        }
        self.publish(
            true,
            false,
            Some(profile(&pending.policy)),
            "Confirmed boot firewall policy loaded.",
        )
    }

    fn partial_failure(
        &self,
        active: bool,
        pending: bool,
        profile: Option<FirewallProfile>,
        message: &'static str,
    ) -> Result<()> {
        if self.publish(active, pending, profile, message).is_err() {
            bail!("{message} Sanitized status could not be updated.");
        }
        bail!("{message}");
    }

    fn enable_confirmed(&mut self, policy: &FirewallPolicy) -> Result<()> {
        if self.command(Command::EnableBootService).is_err() {
            // Confirmation is committed already. Do not roll back a confirmed
            // live table or erase its durable policy because enablement failed.
            return self.partial_failure(true, false, Some(profile(policy)), ENABLE_FAILED);
        }
        self.publish(true, false, Some(profile(policy)), CONFIRMED)
            .map_err(|_| anyhow::anyhow!("Firewall confirmed and enabled for boot, but sanitized status could not be updated."))
    }

    fn disable(&mut self) -> Result<()> {
        // No --now / stop: deleting the owned table is the helper's job, not a
        // unit's ExecStop. Continue cleanup if enablement state cannot be changed.
        let boot_result = self.command(Command::DisableBootService);
        let cleanup_result = (|| {
            if let Some(pending) = self.get_pending()? {
                self.rollback_pending(pending)?;
            }
            self.cancel_timer(true)?;
            let present = self.table_present()?;
            self.replace(present, None)?;
            self.state.clear_policy()
        })();
        match (boot_result.is_ok(), cleanup_result.is_ok()) {
            (true, true) => self.publish(false, false, None, DISABLED),
            (false, true) => self.partial_failure(false, false, None, DISABLE_BOOT_FAILED),
            (boot_disabled, false) => {
                // Inspection errors must not masquerade as completed cleanup.
                let active = !matches!(self.table_present(), Ok(false));
                let pending = self
                    .state
                    .pending()
                    .map_or(true, |pending| pending.is_some());
                let message = if boot_disabled {
                    "Boot service disabled, but owned firewall cleanup failed; administrator attention is required."
                } else {
                    "Boot service disable and owned firewall cleanup failed; administrator attention is required."
                };
                self.partial_failure(active, pending, None, message)
            }
        }
    }

    fn restore_policy(&self, previous: Option<FirewallPolicy>) -> Result<()> {
        let current = self.state.policy()?;
        let encode = |policy: &Option<FirewallPolicy>| {
            serde_json::to_vec(policy)
                .map_err(|_| anyhow::anyhow!("Cannot verify confirmed boot policy."))
        };
        if encode(&current)? == encode(&previous)? {
            return Ok(());
        }
        match previous {
            Some(policy) => self.state.save_policy(&policy),
            None => self.state.clear_policy(),
        }
    }

    pub fn execute(
        &mut self,
        identity: Identity,
        verb: Verb,
        policy: Option<FirewallPolicy>,
    ) -> Result<&'static str> {
        require_root(identity)?;
        if (verb == Verb::Apply) != policy.is_some() {
            bail!("Only apply requires and accepts a firewall policy.");
        }
        self.state.initialize()?;
        // Rollback waits so a timer firing during a slow apply cannot be lost.
        let _lock = self.state.lock(verb == Verb::Rollback)?;
        match verb {
            Verb::Apply => {
                let Some(policy) = policy else {
                    bail!("Apply requires a firewall policy.")
                };
                self.apply_policy(policy)?;
                Ok(APPLIED)
            }
            Verb::Confirm => {
                self.finish_confirmation(true)?;
                Ok(CONFIRMED)
            }
            Verb::Rollback => {
                if let Some(pending) = self.get_pending()? {
                    if self.rollback_pending(pending).is_err() {
                        if let Ok(Some(pending)) = self.get_pending() {
                            let _ = self.recovery_status(&pending);
                        }
                        bail!("Firewall rollback could not complete; recovery remains pending.");
                    }
                } else {
                    let active = self.table_present()?;
                    let profile = if active {
                        self.state.policy()?.as_ref().map(profile)
                    } else {
                        None
                    };
                    self.publish(active, false, profile, "No firewall rollback is pending.")?;
                }
                Ok(RESTORED)
            }
            Verb::Disable => {
                self.disable()?;
                Ok(DISABLED)
            }
            Verb::Boot => {
                if self.get_pending()?.is_some() {
                    bail!("A firewall change is already pending.");
                }
                match self.state.policy()? {
                    Some(policy) => {
                        // This policy was explicitly confirmed previously. Reuse
                        // the safety transaction, but never persist a new policy.
                        self.apply_policy(policy)?;
                        self.finish_confirmation(false)?;
                        Ok("Confirmed boot firewall policy loaded.")
                    }
                    None => {
                        let active = self.table_present()?;
                        self.publish(active, false, None, "No confirmed boot firewall policy.")?;
                        Ok("No confirmed boot firewall policy; firewall was not changed.")
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
