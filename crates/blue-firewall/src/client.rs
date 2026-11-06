//! Unprivileged client for the fixed, separately installed firewall helper.

use crate::policy::{FirewallPolicy, FirewallProfile};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

const PKEXEC_PATH: &str = "/usr/bin/pkexec";
const HELPER_PATH: &str = "/usr/lib/epimetheus-blue/blue-firewall-helper";
const STATUS_PATH: &str = "/run/epimetheus-blue/firewall-status.json";
const MAX_POLICY_JSON_BYTES: usize = 64 * 1024;
const MAX_STATUS_JSON_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_CHARS: usize = 1024;

/// Sanitized status published by the privileged helper, not a live nft probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FirewallStatus {
    pub installed: bool,
    pub active: bool,
    pub pending: bool,
    pub profile: Option<FirewallProfile>,
    pub message: String,
}

/// No helper override, arbitrary privileged path, or automatic mutations.
#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallClient;

impl FirewallClient {
    pub fn new() -> Self {
        Self
    }

    pub fn status(&self) -> Result<FirewallStatus> {
        status_at(Path::new(HELPER_PATH), Path::new(STATUS_PATH))
    }

    pub fn apply(&self, policy: &FirewallPolicy) -> Result<String> {
        let input = policy_json(policy)?;
        mutate(Mutation::Apply, &input)
    }

    pub fn confirm(&self) -> Result<String> {
        mutate(Mutation::Confirm, &[])
    }

    pub fn rollback(&self) -> Result<String> {
        mutate(Mutation::Rollback, &[])
    }

    pub fn disable(&self) -> Result<String> {
        mutate(Mutation::Disable, &[])
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    Apply,
    Confirm,
    Rollback,
    Disable,
}

impl Mutation {
    fn verb(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Confirm => "confirm",
            Self::Rollback => "rollback",
            Self::Disable => "disable",
        }
    }
}

fn policy_json(policy: &FirewallPolicy) -> Result<Vec<u8>> {
    policy.validate()?;
    let input = serde_json::to_vec(policy).context("Could not encode firewall policy")?;
    ensure!(
        input.len() <= MAX_POLICY_JSON_BYTES,
        "firewall policy exceeds the {MAX_POLICY_JSON_BYTES}-byte request limit"
    );
    Ok(input)
}

fn mutation_command(mutation: Mutation) -> Command {
    // No shell and no PATH lookup. Do not inherit loader or helper-specific
    // environment variables from the GUI; pkexec performs the authorization.
    let mut command = Command::new(PKEXEC_PATH);
    command
        .arg(HELPER_PATH)
        .arg(mutation.verb())
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C");
    command
}

fn mutate(mutation: Mutation, input: &[u8]) -> Result<String> {
    ensure!(
        trusted_helper(Path::new(HELPER_PATH))?,
        "firewall helper is missing or unsafe; install the root-owned helper first"
    );
    run_command(mutation_command(mutation), input)
}

fn run_command(mut command: Command, input: &[u8]) -> Result<String> {
    ensure!(
        input.len() <= MAX_POLICY_JSON_BYTES,
        "firewall helper request is too large"
    );
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Could not start firewall authorization")?;
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(input),
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "helper stdin was not available",
        )),
    };
    // The stdin handle has been dropped: the helper reads one bounded JSON
    // document to EOF. Reap failures instead of leaving an orphan helper.
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("Could not send firewall policy to the helper");
    }
    let output = child
        .wait_with_output()
        .context("Could not collect firewall helper result")?;
    if !output.status.success() {
        let message = sanitized_message(&String::from_utf8_lossy(&output.stderr));
        if message.is_empty() {
            bail!("firewall authorization/helper failed ({})", output.status);
        }
        bail!("firewall authorization/helper failed: {message}");
    }
    let message =
        String::from_utf8(output.stdout).context("Firewall helper returned invalid UTF-8")?;
    Ok(sanitized_message(&message))
}

fn trusted_helper(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("Could not inspect firewall helper"),
    };
    if !secure_file(&metadata) || metadata.permissions().mode() & 0o100 == 0 {
        return Ok(false);
    }
    secure_parents(path)
}

fn secure_file(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == 0
        && metadata.permissions().mode() & 0o022 == 0
}

fn secure_parents(path: &Path) -> Result<bool> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)
            .context("Could not inspect firewall helper/status directory")?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn status_at(helper_path: &Path, status_path: &Path) -> Result<FirewallStatus> {
    let installed = trusted_helper(helper_path)?;
    let metadata = match fs::symlink_metadata(status_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(FirewallStatus {
                installed,
                message: if installed {
                    "Firewall helper installed; runtime status is not available.".into()
                } else {
                    "Firewall helper is not installed or is unsafe.".into()
                },
                ..FirewallStatus::default()
            });
        }
        Err(error) => return Err(error).context("Could not inspect firewall runtime status"),
    };
    ensure!(
        secure_file(&metadata) && secure_parents(status_path)?,
        "firewall runtime status must be a root-owned, non-writable regular file in trusted directories"
    );
    let file = File::open(status_path).context("Could not read firewall runtime status")?;
    let opened_metadata = file
        .metadata()
        .context("Could not inspect opened firewall runtime status")?;
    ensure!(
        secure_file(&opened_metadata)
            && metadata.dev() == opened_metadata.dev()
            && metadata.ino() == opened_metadata.ino(),
        "firewall runtime status changed while opening it"
    );
    parse_status(file, installed)
}

fn parse_status(reader: impl Read, installed: bool) -> Result<FirewallStatus> {
    let mut input = Vec::new();
    reader
        .take(MAX_STATUS_JSON_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .context("Could not read firewall runtime status")?;
    ensure!(
        input.len() <= MAX_STATUS_JSON_BYTES,
        "firewall runtime status exceeds the {MAX_STATUS_JSON_BYTES}-byte limit"
    );
    let mut status: FirewallStatus =
        serde_json::from_slice(&input).context("Invalid firewall runtime status JSON")?;
    // A stale snapshot cannot claim that a missing/untrusted helper is installed.
    // Retain active/pending: kernel rules may outlive an uninstalled helper.
    status.installed = installed;
    status.message = if installed {
        sanitized_message(&status.message)
    } else {
        sanitized_message(&format!(
            "Firewall helper is not installed or is unsafe. {}",
            status.message
        ))
    };
    Ok(status)
}

fn sanitized_message(message: &str) -> String {
    message
        .chars()
        .filter(|character| {
            !character.is_control()
                && !matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_MESSAGE_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{InboundRule, Protocol};
    use std::{io::Cursor, os::unix::fs::symlink};
    use tempfile::tempdir;

    #[test]
    fn missing_helper_and_status_are_read_only_and_not_errors() {
        let directory = tempdir().unwrap();
        let status = status_at(
            &directory.path().join("missing-helper"),
            &directory.path().join("missing-status.json"),
        )
        .unwrap();
        assert!(!status.installed);
        assert!(!status.active);
        assert!(!status.pending);
        assert_eq!(status.profile, None);
        assert!(status.message.contains("not installed"));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn pending_runtime_json_is_parsed_without_commands() {
        let json = br#"{"installed":true,"active":true,"pending":true,"profile":"Private","message":"Awaiting confirmation."}"#;
        let status = parse_status(Cursor::new(json), true).unwrap();
        assert_eq!(
            status,
            FirewallStatus {
                installed: true,
                active: true,
                pending: true,
                profile: Some(FirewallProfile::Private),
                message: "Awaiting confirmation.".into(),
            }
        );
    }

    #[test]
    fn stale_installed_flag_does_not_hide_active_or_pending_rules() {
        let json = br#"{"installed":true,"active":true,"pending":true,"profile":"Public","message":"Awaiting confirmation."}"#;
        let status = parse_status(Cursor::new(json), false).unwrap();
        assert!(!status.installed);
        assert!(status.active);
        assert!(status.pending);
        assert!(status.message.contains("not installed"));
    }

    #[test]
    fn status_default_is_inactive_and_round_trips() {
        let status = FirewallStatus::default();
        assert_eq!(
            serde_json::from_str::<FirewallStatus>(&serde_json::to_string(&status).unwrap())
                .unwrap(),
            status
        );
        assert!(!status.installed && !status.active && !status.pending);
        assert!(status.profile.is_none());
    }

    #[test]
    fn status_rejects_unknown_fields_malformed_json_and_oversized_input() {
        for json in [
            r#"{"installed":true,"active":true,"pending":false,"profile":"Public","message":"OK","command":"nft"}"#,
            r#"{"installed":true,"active":true,"pending":false,"profile":"Unknown","message":"OK"}"#,
            r#"{"active":true}"#,
            "not json",
        ] {
            assert!(parse_status(Cursor::new(json.as_bytes()), true).is_err());
        }
        let input = vec![b' '; MAX_STATUS_JSON_BYTES + 1];
        assert!(parse_status(Cursor::new(input), true).is_err());
    }

    #[test]
    fn status_messages_remove_controls_and_are_bounded() {
        let status = FirewallStatus {
            installed: true,
            message: format!("\0\u{1b}\n\u{202e}{}", "é".repeat(MAX_MESSAGE_CHARS + 10)),
            ..FirewallStatus::default()
        };
        let input = serde_json::to_vec(&status).unwrap();
        let parsed = parse_status(Cursor::new(input), true).unwrap();
        assert_eq!(parsed.message, "é".repeat(MAX_MESSAGE_CHARS));
    }

    #[test]
    fn helper_symlinks_directories_and_writable_files_are_untrusted() {
        let directory = tempdir().unwrap();
        let helper = directory.path().join("helper");
        fs::write(&helper, "not an executable").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!trusted_helper(&helper).unwrap());
        assert!(!trusted_helper(directory.path()).unwrap());
        let link = directory.path().join("helper-link");
        symlink(&helper, &link).unwrap();
        assert!(!trusted_helper(&link).unwrap());
    }

    #[test]
    fn runtime_status_rejects_symlinks_and_non_regular_files() {
        let directory = tempdir().unwrap();
        let helper = directory.path().join("missing-helper");
        assert!(status_at(&helper, directory.path()).is_err());
        let status_file = directory.path().join("status.json");
        fs::write(&status_file, "{}").unwrap();
        let link = directory.path().join("status-link.json");
        symlink(&status_file, &link).unwrap();
        assert!(status_at(&helper, &link).is_err());
    }

    #[test]
    fn only_fixed_pkexec_helper_and_verbs_are_command_arguments() {
        for (mutation, verb) in [
            (Mutation::Apply, "apply"),
            (Mutation::Confirm, "confirm"),
            (Mutation::Rollback, "rollback"),
            (Mutation::Disable, "disable"),
        ] {
            let command = mutation_command(mutation);
            assert_eq!(command.get_program(), PKEXEC_PATH);
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                vec![HELPER_PATH, verb]
            );
            let environment = command
                .get_envs()
                .map(|(key, value)| (key.to_str().unwrap(), value.unwrap().to_str().unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(
                environment,
                vec![("LANG", "C"), ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")]
            );
        }
    }

    #[test]
    fn policy_is_validated_and_encoded_only_as_bounded_json_stdin() {
        let mut policy = FirewallPolicy::new(FirewallProfile::Private);
        policy.inbound.push(InboundRule {
            name: "SSH LAN".into(),
            protocol: Protocol::Tcp,
            port: 22,
            source: Some("192.168.0.0/24".into()),
        });
        let input = policy_json(&policy).unwrap();
        assert!(input.len() <= MAX_POLICY_JSON_BYTES);
        assert_eq!(
            serde_json::from_slice::<FirewallPolicy>(&input).unwrap(),
            policy
        );
        policy.inbound[0].port = 0;
        assert!(policy_json(&policy).is_err());
        // This public call must return before inspecting/spawning any helper.
        assert!(FirewallClient::new().apply(&policy).is_err());
        policy.inbound[0].port = 22;
        policy.inbound[0].name = "$(id)".into();
        assert!(FirewallClient::new().apply(&policy).is_err());
    }

    #[test]
    fn fake_command_receives_stdin_and_errors_are_reported() {
        // These are ordinary unprivileged fake commands. No pkexec or nft runs.
        let mut echo = Command::new("/bin/sh");
        echo.arg("-c")
            .arg("IFS= read -r request; printf '%s' \"$request\"");
        let input = policy_json(&FirewallPolicy::new(FirewallProfile::Public)).unwrap();
        assert_eq!(
            run_command(echo, &input).unwrap(),
            String::from_utf8(input).unwrap()
        );
        let mut denied = Command::new("/bin/sh");
        denied
            .arg("-c")
            .arg("printf 'authorization denied\\n' >&2; exit 126");
        assert!(run_command(denied, &[])
            .unwrap_err()
            .to_string()
            .contains("authorization denied"));
    }

    #[test]
    fn oversized_requests_are_rejected_before_starting_commands() {
        let command = Command::new("/this-command-must-not-be-started");
        let error = run_command(command, &vec![b'a'; MAX_POLICY_JSON_BYTES + 1]).unwrap_err();
        assert!(error.to_string().contains("too large"));
    }
}
