use super::*;
use crate::commands::Output;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use tempfile::TempDir;

const ROOT: Identity = Identity {
    real_uid: 0,
    effective_uid: 0,
};
const PRIOR: &str = "table inet epimetheus_blue {\n chain input { type filter hook input priority 0; policy accept; }\n}\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    List,
    Save,
    Check,
    Replace,
    TimerState,
    Stop,
    Arm,
    EnableBoot,
    DisableBoot,
}

#[derive(Clone, Copy)]
enum Failure {
    Exit,
    Spawn,
    AfterMutation,
}

struct FakeCommands {
    own: Option<String>,
    foreign: BTreeMap<String, String>,
    timer: bool,
    service: bool,
    boot_enabled: bool,
    confirmed_path: std::path::PathBuf,
    pending_path: std::path::PathBuf,
    events: Vec<(Kind, String)>,
    failures: VecDeque<(Kind, Failure)>,
}

impl FakeCommands {
    fn new(own: Option<&str>, state: &State) -> Self {
        Self {
            own: own.map(str::to_owned),
            foreign: BTreeMap::from([
                (
                    "docker".into(),
                    "table ip docker { chain forward { policy accept; } }".into(),
                ),
                (
                    "vpn".into(),
                    "table inet vpn { chain output { policy accept; } }".into(),
                ),
            ]),
            timer: false,
            service: false,
            boot_enabled: false,
            confirmed_path: state.config.join("policy.json"),
            pending_path: state.private().join("pending.json"),
            events: Vec::new(),
            failures: VecDeque::new(),
        }
    }

    fn fail(&mut self, kind: Kind, failure: Failure) {
        self.failures.push_back((kind, failure));
    }

    fn mutations(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter(|(kind, _)| *kind == Kind::Replace)
            .map(|(_, script)| script.as_str())
            .collect()
    }
}

impl CommandRunner for FakeCommands {
    fn run(&mut self, command: Command<'_>) -> Result<Output> {
        let (kind, text) = match &command {
            Command::ListTables => (Kind::List, ""),
            Command::SaveTable => (Kind::Save, ""),
            Command::Check(script) => (Kind::Check, *script),
            Command::Replace(script) => (Kind::Replace, *script),
            Command::TimerState { .. } => (Kind::TimerState, ""),
            Command::StopTimer { .. } => (Kind::Stop, ""),
            Command::ArmTimer => (Kind::Arm, ""),
            Command::EnableBootService => (Kind::EnableBoot, ""),
            Command::DisableBootService => (Kind::DisableBoot, ""),
        };
        self.events.push((kind, text.to_owned()));
        if kind == Kind::EnableBoot {
            // Assert at invocation time, even if the simulated command fails.
            // Neither mere staging nor a failed persistence may enable boot.
            let confirmed =
                fs::read(&self.confirmed_path).expect("enable requires durable confirmed policy");
            let _: FirewallPolicy = serde_json::from_slice(&confirmed).unwrap();
            assert!(
                !self.pending_path.exists(),
                "enable must follow pending-state commit"
            );
        }
        let failure = if self
            .failures
            .front()
            .is_some_and(|(expected, _)| *expected == kind)
        {
            Some(self.failures.pop_front().unwrap().1)
        } else {
            None
        };
        match failure {
            Some(Failure::Spawn) => bail!("SECRET raw command error 192.0.2.123"),
            Some(Failure::Exit) => {
                return Ok(Output {
                    success: false,
                    stdout: b"SECRET raw command output".to_vec(),
                })
            }
            _ => {}
        }
        let stdout = match command {
            Command::ListTables => {
                let mut tables = vec![serde_json::json!({"metainfo": {"json_schema_version": 1}})];
                for (name, table) in &self.foreign {
                    let family = if table.starts_with("table ip ") {
                        "ip"
                    } else {
                        "inet"
                    };
                    tables.push(serde_json::json!({"table": {"family": family, "name": name}}));
                }
                if self.own.is_some() {
                    tables.push(
                        serde_json::json!({"table": {"family": "inet", "name": "epimetheus_blue"}}),
                    );
                }
                serde_json::to_vec(&serde_json::json!({"nftables": tables})).unwrap()
            }
            Command::SaveTable => self.own.as_ref().unwrap().as_bytes().to_vec(),
            Command::Check(script) => {
                let table = script.strip_prefix(DELETE_TABLE).unwrap_or(script).trim();
                if !table.is_empty() {
                    owned_table(table)?;
                }
                Vec::new()
            }
            Command::Replace(script) => {
                let table = script.strip_prefix(DELETE_TABLE).unwrap_or(script).trim();
                if table.is_empty() {
                    self.own = None;
                } else {
                    owned_table(table)?;
                    self.own = Some(format!("{table}\n"));
                }
                Vec::new()
            }
            Command::TimerState { with_service } => {
                let mut states = if self.timer {
                    "loaded\n".to_owned()
                } else {
                    "not-found\n".to_owned()
                };
                if with_service {
                    states.push_str(if self.service {
                        "loaded\n"
                    } else {
                        "not-found\n"
                    });
                }
                states.into_bytes()
            }
            Command::StopTimer { timer, service } => {
                if timer {
                    self.timer = false;
                }
                if service {
                    self.service = false;
                }
                Vec::new()
            }
            Command::ArmTimer => {
                assert!(
                    !self.timer && !self.service,
                    "stale rollback units must be cancelled first"
                );
                self.timer = true;
                self.service = true;
                Vec::new()
            }
            Command::EnableBootService => {
                self.boot_enabled = true;
                Vec::new()
            }
            Command::DisableBootService => {
                self.boot_enabled = false;
                Vec::new()
            }
        };
        Ok(Output {
            success: !matches!(failure, Some(Failure::AfterMutation)),
            stdout,
        })
    }
}

fn setup(own: Option<&str>) -> (TempDir, Helper<FakeCommands>) {
    let root = tempfile::tempdir().unwrap();
    let state = State::temporary(root.path());
    let commands = FakeCommands::new(own, &state);
    let helper = Helper::new(state, commands);
    (root, helper)
}

fn policy() -> FirewallPolicy {
    FirewallPolicy::new(FirewallProfile::Public)
}

fn apply(helper: &mut Helper<FakeCommands>) {
    helper.execute(ROOT, Verb::Apply, Some(policy())).unwrap();
}

fn status(helper: &Helper<FakeCommands>) -> serde_json::Value {
    let bytes = fs::read(helper.state.runtime.join("firewall-status.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 5);
    assert_eq!(value["installed"], true);
    for key in ["active", "pending"] {
        assert!(value[key].is_boolean());
    }
    assert!(value["message"].is_string());
    assert!(!String::from_utf8(bytes).unwrap().contains("SECRET"));
    value
}

fn confirmed_bytes(helper: &Helper<FakeCommands>) -> Option<Vec<u8>> {
    fs::read(helper.state.config.join("policy.json")).ok()
}

#[test]
fn first_apply_arms_before_check_then_atomically_installs_without_persistence() {
    let (_root, mut helper) = setup(None);
    let foreign = helper.runner.foreign.clone();
    apply(&mut helper);
    let kinds: Vec<_> = helper.runner.events.iter().map(|(kind, _)| *kind).collect();
    assert!(
        kinds.iter().position(|kind| *kind == Kind::Arm).unwrap()
            < kinds.iter().position(|kind| *kind == Kind::Check).unwrap()
    );
    assert!(
        kinds.iter().position(|kind| *kind == Kind::Check).unwrap()
            < kinds
                .iter()
                .position(|kind| *kind == Kind::Replace)
                .unwrap()
    );
    assert_eq!(helper.runner.mutations().len(), 1);
    assert!(!helper.runner.mutations()[0].contains(DELETE_TABLE));
    assert!(helper.runner.timer);
    let pending = helper.state.pending().unwrap().unwrap();
    assert!(pending.applied);
    assert!(pending.previous_table.is_none());
    assert!(pending.expires_at >= now().unwrap() + 59);
    assert!(confirmed_bytes(&helper).is_none());
    assert!(!helper.runner.boot_enabled);
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| matches!(kind, Kind::EnableBoot | Kind::DisableBoot)));
    assert_eq!(helper.runner.foreign, foreign);
    assert_eq!(status(&helper)["active"], true);
    assert_eq!(status(&helper)["pending"], true);
}

#[test]
fn existing_table_is_the_only_snapshot_and_replacement_is_one_transaction() {
    let (_root, mut helper) = setup(Some(PRIOR));
    let foreign = helper.runner.foreign.clone();
    apply(&mut helper);
    assert_eq!(
        helper
            .state
            .pending()
            .unwrap()
            .unwrap()
            .previous_table
            .as_deref(),
        Some(PRIOR)
    );
    let mutations = helper.runner.mutations();
    assert_eq!(mutations.len(), 1);
    assert!(mutations[0].starts_with(DELETE_TABLE));
    assert!(!mutations[0].contains("docker"));
    assert!(!mutations[0].contains("vpn"));
    assert!(!mutations[0].contains("hook forward"));
    assert!(!mutations[0].contains("hook output"));
    assert_eq!(helper.runner.foreign, foreign);
}

#[test]
fn rollback_restores_existing_or_absent_table_and_preserves_confirmed_policy() {
    for previous in [Some(PRIOR), None] {
        let (_root, mut helper) = setup(previous);
        helper.state.initialize().unwrap();
        helper
            .state
            .save_policy(&FirewallPolicy::new(FirewallProfile::Private))
            .unwrap();
        let boot_policy = confirmed_bytes(&helper);
        let foreign = helper.runner.foreign.clone();
        apply(&mut helper);
        helper.execute(ROOT, Verb::Rollback, None).unwrap();
        assert_eq!(helper.runner.own.as_deref(), previous);
        assert!(helper.state.pending().unwrap().is_none());
        assert!(!helper.runner.timer);
        assert_eq!(confirmed_bytes(&helper), boot_policy);
        assert_eq!(helper.runner.foreign, foreign);
        assert_eq!(status(&helper)["active"], previous.is_some());
        assert_eq!(status(&helper)["pending"], false);
    }
}

#[test]
fn rollback_without_pending_never_removes_confirmed_table() {
    let (_root, mut helper) = setup(Some(PRIOR));
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
    assert!(helper.runner.mutations().is_empty());
    assert_eq!(status(&helper)["active"], true);
}

#[test]
fn another_pending_apply_is_rejected_without_commands_or_state_changes() {
    let (_root, mut helper) = setup(None);
    apply(&mut helper);
    let pending = fs::read(helper.state.private().join("pending.json")).unwrap();
    helper.runner.events.clear();
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert!(helper.runner.events.is_empty());
    assert_eq!(
        fs::read(helper.state.private().join("pending.json")).unwrap(),
        pending
    );
}

#[test]
fn non_root_and_setuid_callers_cannot_create_state_or_run_commands() {
    for identity in [
        Identity {
            real_uid: 1000,
            effective_uid: 1000,
        },
        Identity {
            real_uid: 1000,
            effective_uid: 0,
        },
        Identity {
            real_uid: 0,
            effective_uid: 1000,
        },
    ] {
        for verb in [
            Verb::Apply,
            Verb::Confirm,
            Verb::Rollback,
            Verb::Disable,
            Verb::Boot,
        ] {
            let (_root, mut helper) = setup(None);
            let input = if verb == Verb::Apply {
                Some(policy())
            } else {
                None
            };
            assert!(helper.execute(identity, verb, input).is_err());
            assert!(!helper.state.runtime.exists());
            assert!(!helper.state.config.exists());
            assert!(helper.runner.events.is_empty());
        }
    }
}

#[test]
fn process_lock_rejects_concurrent_mutation_and_is_not_deleted() {
    let (_root, mut helper) = setup(None);
    helper.state.initialize().unwrap();
    let lock = helper.state.lock(false).unwrap();
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert!(helper.runner.events.is_empty());
    drop(lock);
    apply(&mut helper);
    assert!(helper.state.private().join("operation.lock").is_file());
}

#[test]
fn timed_rollback_waits_for_the_process_lock_instead_of_losing_recovery() {
    let (_root, mut helper) = setup(None);
    apply(&mut helper);
    let lock = helper.state.lock(false).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        send.send(helper.execute(ROOT, Verb::Rollback, None).is_ok())
            .unwrap();
        helper
    });
    assert!(receive
        .recv_timeout(std::time::Duration::from_millis(30))
        .is_err());
    drop(lock);
    assert!(receive
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap());
    let helper = thread.join().unwrap();
    assert!(helper.state.pending().unwrap().is_none());
    assert!(helper.runner.own.is_none());
}

#[test]
fn only_exact_fixed_verbs_and_no_extra_arguments_are_accepted() {
    for (text, verb) in [
        ("apply", Verb::Apply),
        ("confirm", Verb::Confirm),
        ("rollback", Verb::Rollback),
        ("disable", Verb::Disable),
        ("boot", Verb::Boot),
    ] {
        assert_eq!(Verb::parse(&[text.into()]).unwrap(), verb);
    }
    for args in [
        vec![],
        vec!["status".into()],
        vec!["apply; nft flush ruleset".into()],
        vec!["apply".into(), "/tmp/policy".into()],
        vec![OsString::from_vec(vec![0xff])],
    ] {
        assert!(Verb::parse(&args).is_err());
    }
}

#[test]
fn policy_json_is_bounded_strict_and_never_interpreted_as_commands() {
    let valid = serde_json::to_vec(&policy()).unwrap();
    assert!(read_input(Verb::Apply, &mut valid.as_slice())
        .unwrap()
        .is_some());
    for mut input in [
        b"".as_slice(),
        b"null",
        b"{}",
        b"nft flush ruleset",
        b"{",
        b"[]",
        b"{} {}",
    ] {
        assert!(read_input(Verb::Apply, &mut input).is_err());
    }
    let mut unknown = serde_json::to_value(policy()).unwrap();
    unknown["command"] = "nft flush ruleset".into();
    assert!(read_input(
        Verb::Apply,
        &mut serde_json::to_vec(&unknown).unwrap().as_slice()
    )
    .is_err());
    let mut with_rule = policy();
    with_rule.inbound.push(InboundRule {
        name: "test".into(),
        protocol: Protocol::Tcp,
        port: 443,
        source: None,
    });
    let mut unknown = serde_json::to_value(&with_rule).unwrap();
    unknown["inbound"][0]["path"] = "/tmp/script.nft".into();
    assert!(read_input(
        Verb::Apply,
        &mut serde_json::to_vec(&unknown).unwrap().as_slice()
    )
    .is_err());
    with_rule.inbound[0].source = Some("192.0.2.0/24; flush ruleset".into());
    assert!(read_input(
        Verb::Apply,
        &mut serde_json::to_vec(&with_rule).unwrap().as_slice()
    )
    .is_err());
    assert!(read_input(Verb::Apply, &mut vec![b' '; MAX_POLICY + 1].as_slice()).is_err());
    for verb in [Verb::Confirm, Verb::Rollback, Verb::Disable, Verb::Boot] {
        assert!(read_input(verb, &mut valid.as_slice()).is_err());
        assert!(read_input(verb, &mut b" \n\t".as_slice())
            .unwrap()
            .is_none());
    }
}

#[test]
fn unbounded_input_stream_is_read_only_to_the_limit() {
    struct Endless(usize);
    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer.fill(b'x');
            self.0 += buffer.len();
            Ok(buffer.len())
        }
    }
    let mut input = Endless(0);
    assert!(read_input(Verb::Apply, &mut input).is_err());
    assert_eq!(input.0, MAX_POLICY + 1);
}

#[test]
fn direct_dispatch_also_rejects_missing_or_unexpected_policy() {
    let (_root, mut helper) = setup(None);
    assert!(helper.execute(ROOT, Verb::Apply, None).is_err());
    for verb in [Verb::Confirm, Verb::Rollback, Verb::Disable, Verb::Boot] {
        assert!(helper.execute(ROOT, verb, Some(policy())).is_err());
    }
    assert!(!helper.state.runtime.exists());
    assert!(helper.runner.events.is_empty());
}

#[test]
fn confirmation_alone_persists_policy_with_protected_state_and_public_sanitized_status() {
    let (_root, mut helper) = setup(None);
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    apply(&mut helper);
    assert!(confirmed_bytes(&helper).is_none());
    helper.execute(ROOT, Verb::Confirm, None).unwrap();
    assert!(helper.runner.boot_enabled);
    assert_eq!(
        confirmed_bytes(&helper).unwrap(),
        serde_json::to_vec(&policy()).unwrap()
    );
    assert!(helper.state.pending().unwrap().is_none());
    assert!(!helper.runner.timer && !helper.runner.service);
    for (path, mode) in [
        (helper.state.runtime.clone(), 0o755),
        (helper.state.private(), 0o700),
        (helper.state.config.clone(), 0o700),
        (helper.state.config.join("policy.json"), 0o600),
        (helper.state.private().join("operation.lock"), 0o600),
        (helper.state.runtime.join("firewall-status.json"), 0o644),
    ] {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o777, mode);
        assert_eq!(metadata.uid(), Identity::current().effective_uid);
    }
    assert_eq!(status(&helper)["active"], true);
    assert_eq!(status(&helper)["pending"], false);
    assert_eq!(
        status(&helper)["profile"],
        serde_json::to_value(FirewallProfile::Public).unwrap()
    );
}

#[test]
fn expired_or_absent_applied_table_cannot_be_confirmed_or_persisted() {
    for expired in [true, false] {
        let (_root, mut helper) = setup(None);
        apply(&mut helper);
        if expired {
            let mut pending = helper.state.pending().unwrap().unwrap();
            pending.expires_at = 0;
            helper.state.save_pending(&pending).unwrap();
        } else {
            helper.runner.own = None;
        }
        assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
        assert!(confirmed_bytes(&helper).is_none());
        assert!(helper.runner.own.is_none());
        assert!(helper.state.pending().unwrap().is_none());
        assert!(!helper.runner.timer);
    }
}

#[test]
fn timer_arm_failure_never_runs_an_nft_mutation_even_with_an_existing_table() {
    for failure in [Failure::Exit, Failure::AfterMutation] {
        let (_root, mut helper) = setup(Some(PRIOR));
        helper.runner.fail(Kind::Arm, failure);
        assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
        assert!(helper.runner.mutations().is_empty());
        assert!(!helper
            .runner
            .events
            .iter()
            .any(|(kind, _)| *kind == Kind::Check));
        assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
        assert!(helper.state.pending().unwrap().is_none());
        assert!(!helper.runner.timer);
    }
}

#[test]
fn failed_check_or_apply_immediately_restores_existing_and_absent_tables() {
    for previous in [Some(PRIOR), None] {
        for (kind, failure) in [
            (Kind::Check, Failure::Exit),
            (Kind::Replace, Failure::Exit),
            (Kind::Replace, Failure::AfterMutation),
            (Kind::Replace, Failure::Spawn),
        ] {
            let (_root, mut helper) = setup(previous);
            let foreign = helper.runner.foreign.clone();
            helper.runner.fail(kind, failure);
            let error = helper
                .execute(ROOT, Verb::Apply, Some(policy()))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("SECRET"));
            assert_eq!(helper.runner.own.as_deref(), previous);
            assert!(helper.state.pending().unwrap().is_none());
            assert!(!helper.runner.timer);
            assert!(confirmed_bytes(&helper).is_none());
            assert_eq!(helper.runner.foreign, foreign);
            assert_eq!(status(&helper)["active"], previous.is_some());
            assert_eq!(status(&helper)["pending"], false);
        }
    }
}

#[test]
fn rollback_command_failures_retain_snapshot_and_independent_timer_for_retry() {
    for kind in [Kind::List, Kind::Check, Kind::Replace] {
        let (_root, mut helper) = setup(Some(PRIOR));
        apply(&mut helper);
        helper.runner.fail(kind, Failure::Exit);
        assert!(helper.execute(ROOT, Verb::Rollback, None).is_err());
        assert!(helper.state.pending().unwrap().is_some());
        assert!(helper.runner.timer);
        assert_eq!(status(&helper)["pending"], true);
        helper.execute(ROOT, Verb::Rollback, None).unwrap();
        assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
        assert!(helper.state.pending().unwrap().is_none());
    }
}

#[test]
fn apply_and_recovery_failure_keeps_only_owned_backup_and_rearms_retry() {
    let (_root, mut helper) = setup(Some(PRIOR));
    helper.runner.fail(Kind::Replace, Failure::AfterMutation);
    helper.runner.fail(Kind::Replace, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert_eq!(
        helper
            .state
            .pending()
            .unwrap()
            .unwrap()
            .previous_table
            .as_deref(),
        Some(PRIOR)
    );
    assert!(helper.runner.timer);
    assert_eq!(status(&helper)["pending"], true);
    assert!(confirmed_bytes(&helper).is_none());
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
}

#[test]
fn early_command_failures_and_unsafe_snapshot_never_mutate_firewall() {
    for kind in [Kind::TimerState, Kind::List, Kind::Save] {
        let (_root, mut helper) = setup(Some(PRIOR));
        helper.runner.fail(kind, Failure::Spawn);
        let error = helper
            .execute(ROOT, Verb::Apply, Some(policy()))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SECRET"));
        assert!(helper.runner.mutations().is_empty());
        assert!(helper.state.pending().unwrap().is_none());
        assert!(!helper.runner.timer);
    }
    for unsafe_snapshot in [
        "table inet docker {}",
        "table inet epimetheus_blue {}\nflush ruleset",
        "table inet epimetheus_blue {}\ntable ip vpn {}",
    ] {
        let (_root, mut helper) = setup(Some(unsafe_snapshot));
        assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
        assert!(helper.runner.mutations().is_empty());
        assert!(helper.state.pending().unwrap().is_none());
        assert!(!helper.runner.timer);
    }
}

#[test]
fn timer_cancellation_failure_rolls_back_before_persisting_confirmation() {
    let (_root, mut helper) = setup(Some(PRIOR));
    helper.state.initialize().unwrap();
    helper
        .state
        .save_policy(&FirewallPolicy::new(FirewallProfile::Private))
        .unwrap();
    let before = confirmed_bytes(&helper);
    apply(&mut helper);
    helper.runner.fail(Kind::Stop, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert_eq!(confirmed_bytes(&helper), before);
    assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
    assert!(helper.state.pending().unwrap().is_none());
}

#[test]
fn confirmation_inspection_failure_keeps_pending_and_never_persists() {
    let (_root, mut helper) = setup(None);
    apply(&mut helper);
    helper.runner.fail(Kind::List, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert!(helper.state.pending().unwrap().is_some());
    assert!(helper.runner.timer);
    assert!(confirmed_bytes(&helper).is_none());
}

#[test]
fn disable_removes_only_owned_table_and_boot_policy_in_all_states() {
    for previous in [Some(PRIOR), None] {
        for pending in [false, true] {
            let (_root, mut helper) = setup(previous);
            let foreign = helper.runner.foreign.clone();
            helper.state.initialize().unwrap();
            helper.state.save_policy(&policy()).unwrap();
            helper.runner.boot_enabled = true;
            if pending {
                apply(&mut helper);
            }
            helper.execute(ROOT, Verb::Disable, None).unwrap();
            assert!(helper.runner.own.is_none());
            assert!(helper.state.pending().unwrap().is_none());
            assert!(confirmed_bytes(&helper).is_none());
            assert!(!helper.runner.timer && !helper.runner.service);
            assert!(!helper.runner.boot_enabled);
            assert_eq!(helper.runner.foreign, foreign);
            assert_eq!(status(&helper)["active"], false);
            assert_eq!(status(&helper)["pending"], false);
            assert!(status(&helper)["profile"].is_null());
        }
    }
}

#[test]
fn disable_failure_does_not_discard_confirmed_policy_or_foreign_tables() {
    for kind in [Kind::Check, Kind::Replace] {
        let (_root, mut helper) = setup(Some(PRIOR));
        helper.state.initialize().unwrap();
        helper.state.save_policy(&policy()).unwrap();
        let before = confirmed_bytes(&helper);
        let foreign = helper.runner.foreign.clone();
        helper.runner.fail(kind, Failure::Exit);
        assert!(helper.execute(ROOT, Verb::Disable, None).is_err());
        assert_eq!(confirmed_bytes(&helper), before);
        assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
        assert_eq!(helper.runner.foreign, foreign);
    }
}

#[test]
fn boot_only_replays_explicitly_confirmed_policy_and_leaves_no_pending_change() {
    let (_root, mut helper) = setup(None);
    helper.execute(ROOT, Verb::Boot, None).unwrap();
    assert!(helper.runner.mutations().is_empty());
    assert!(!helper.runner.timer);
    apply(&mut helper);
    helper.execute(ROOT, Verb::Confirm, None).unwrap();
    let before = confirmed_bytes(&helper);
    helper.runner.own = None; // Simulate a reboot, not a host firewall operation.
    helper.runner.events.clear();
    helper.execute(ROOT, Verb::Boot, None).unwrap();
    assert_eq!(confirmed_bytes(&helper), before);
    assert!(helper.runner.own.is_some());
    assert!(helper.state.pending().unwrap().is_none());
    assert!(!helper.runner.timer && !helper.runner.service);
    assert_eq!(helper.runner.mutations().len(), 1);
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| *kind == Kind::EnableBoot));
    assert_eq!(status(&helper)["pending"], false);
}

#[test]
fn boot_never_overrides_a_pending_apply() {
    let (_root, mut helper) = setup(None);
    apply(&mut helper);
    helper.runner.events.clear();
    assert!(helper.execute(ROOT, Verb::Boot, None).is_err());
    assert!(helper.runner.events.is_empty());
    assert!(confirmed_bytes(&helper).is_none());
}

#[test]
fn root_state_rejects_symlinks_world_writable_files_and_hardlinks() {
    for attack in 0..3 {
        let (root, mut helper) = setup(None);
        helper.state.initialize().unwrap();
        let path = helper.state.private().join("pending.json");
        let target = root.path().join("foreign.json");
        fs::write(&target, b"SECRET foreign state").unwrap();
        match attack {
            0 => symlink(&target, &path).unwrap(),
            1 => {
                fs::write(&path, b"{}").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
            }
            _ => fs::hard_link(&target, &path).unwrap(),
        }
        assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
        assert!(helper.runner.events.is_empty());
        assert_eq!(fs::read(&target).unwrap(), b"SECRET foreign state");
    }
}

#[test]
fn insecure_or_symlink_state_directories_are_refused() {
    let (root, mut helper) = setup(None);
    let target = root.path().join("foreign");
    fs::create_dir(&target).unwrap();
    symlink(&target, &helper.state.runtime).unwrap();
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert!(helper.runner.events.is_empty());
    assert!(fs::read_dir(&target).unwrap().next().is_none());
    let (_root, mut helper) = setup(None);
    helper.state.initialize().unwrap();
    fs::set_permissions(helper.state.private(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert!(helper.runner.events.is_empty());
}

#[test]
fn table_scope_guard_handles_quoted_braces_and_rejects_escape_commands() {
    for table in [
        PRIOR,
        "table inet epimetheus_blue { chain input { comment \"} \\\" {\"; } } # }\n",
        "table inet epimetheus_blue { # }\n chain input {} };",
    ] {
        owned_table(table).unwrap();
    }
    for table in [
        "flush ruleset",
        "table inet foreign {}",
        "table ip epimetheus_blue {}",
        "table inet epimetheus_blue {",
        "table inet epimetheus_blue {} }",
        "table inet epimetheus_blue {} include \"/tmp/rules\"",
        "table inet epimetheus_blue {}\ndelete table inet vpn",
    ] {
        assert!(owned_table(table).is_err(), "{table}");
    }
    assert!(owned_table(&format!(
        "table inet epimetheus_blue {{{}}}",
        " ".repeat(MAX_TABLE)
    ))
    .is_err());
}

#[test]
fn matching_table_name_in_a_foreign_family_is_preserved_and_never_saved() {
    let (_root, mut helper) = setup(None);
    helper.runner.foreign.insert(
        "epimetheus_blue".into(),
        "table ip epimetheus_blue { chain forward {} }".into(),
    );
    let foreign = helper.runner.foreign.clone();
    apply(&mut helper);
    assert!(helper
        .state
        .pending()
        .unwrap()
        .unwrap()
        .previous_table
        .is_none());
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| *kind == Kind::Save));
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    helper.execute(ROOT, Verb::Disable, None).unwrap();
    assert_eq!(helper.runner.foreign, foreign);
}

#[test]
fn stale_timer_and_service_are_cancelled_before_staging_a_new_apply() {
    let (_root, mut helper) = setup(None);
    helper.runner.timer = true;
    helper.runner.service = true;
    apply(&mut helper);
    let kinds: Vec<_> = helper.runner.events.iter().map(|(kind, _)| *kind).collect();
    assert!(
        kinds.iter().position(|kind| *kind == Kind::Stop).unwrap()
            < kinds.iter().position(|kind| *kind == Kind::Arm).unwrap()
    );
    assert!(helper.runner.timer);
    assert!(helper.state.pending().unwrap().unwrap().applied);
}

#[test]
fn incomplete_failed_apply_can_never_be_confirmed_despite_a_partially_committed_command() {
    let (_root, mut helper) = setup(None);
    helper.runner.fail(Kind::Replace, Failure::AfterMutation);
    helper.runner.fail(Kind::Replace, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert!(!helper.state.pending().unwrap().unwrap().applied);
    assert_eq!(status(&helper)["active"], true);
    assert!(status(&helper)["profile"].is_null());
    helper.runner.events.clear();
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert!(helper.runner.events.is_empty());
    assert!(confirmed_bytes(&helper).is_none());
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    assert!(helper.runner.own.is_none());
}

#[test]
fn unsuccessful_arm_and_cleanup_leave_rejectable_pending_state_but_never_mutate_nft() {
    let (_root, mut helper) = setup(Some(PRIOR));
    helper.runner.fail(Kind::Arm, Failure::Exit);
    helper.runner.fail(Kind::TimerState, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    assert!(helper.runner.mutations().is_empty());
    assert_eq!(helper.runner.own.as_deref(), Some(PRIOR));
    assert!(!helper.state.pending().unwrap().unwrap().applied);
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert!(helper.execute(ROOT, Verb::Apply, Some(policy())).is_err());
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    assert!(helper.state.pending().unwrap().is_none());
}

#[test]
fn confirmation_persistence_failure_restores_table_and_never_deletes_a_foreign_target() {
    for previous in [None, Some(PRIOR)] {
        let (root, mut helper) = setup(previous);
        helper.state.initialize().unwrap();
        helper
            .state
            .save_policy(&FirewallPolicy::new(FirewallProfile::Private))
            .unwrap();
        let before = confirmed_bytes(&helper);
        apply(&mut helper);
        let target = root.path().join("foreign.txt");
        fs::write(&target, b"SECRET unrelated file").unwrap();
        symlink(&target, helper.state.config.join("policy.next")).unwrap();
        assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
        assert!(!helper
            .runner
            .events
            .iter()
            .any(|(kind, _)| *kind == Kind::EnableBoot));
        assert_eq!(confirmed_bytes(&helper), before);
        assert_eq!(helper.runner.own.as_deref(), previous);
        assert!(helper.state.pending().unwrap().is_none());
        assert_eq!(fs::read(&target).unwrap(), b"SECRET unrelated file");
    }
}

#[test]
fn rollback_cleanup_failure_preserves_snapshot_without_claiming_new_policy_is_active() {
    let (_root, mut helper) = setup(None);
    apply(&mut helper);
    helper.runner.fail(Kind::Stop, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Rollback, None).is_err());
    assert!(helper.runner.own.is_none());
    assert!(helper.runner.timer);
    assert!(!helper.state.pending().unwrap().unwrap().applied);
    assert_eq!(status(&helper)["active"], false);
    assert_eq!(status(&helper)["pending"], true);
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    assert!(helper.state.pending().unwrap().is_none());
}

#[test]
fn apply_and_rollback_never_change_boot_enablement_even_with_a_confirmed_policy() {
    let (_root, mut helper) = setup(None);
    apply(&mut helper);
    helper.execute(ROOT, Verb::Confirm, None).unwrap();
    let confirmed = confirmed_bytes(&helper);
    assert!(helper.runner.boot_enabled);
    helper.runner.events.clear();
    helper
        .execute(
            ROOT,
            Verb::Apply,
            Some(FirewallPolicy::new(FirewallProfile::Private)),
        )
        .unwrap();
    assert_eq!(confirmed_bytes(&helper), confirmed);
    assert!(helper.runner.boot_enabled);
    assert!(helper.state.pending().unwrap().is_some());
    helper.execute(ROOT, Verb::Rollback, None).unwrap();
    assert_eq!(confirmed_bytes(&helper), confirmed);
    assert!(helper.runner.boot_enabled);
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| matches!(kind, Kind::EnableBoot | Kind::DisableBoot)));
}

#[test]
fn expired_confirmation_cannot_enable_boot_even_when_an_older_policy_is_persisted() {
    let (_root, mut helper) = setup(Some(PRIOR));
    helper.state.initialize().unwrap();
    helper
        .state
        .save_policy(&FirewallPolicy::new(FirewallProfile::Private))
        .unwrap();
    let confirmed = confirmed_bytes(&helper);
    apply(&mut helper);
    let mut pending = helper.state.pending().unwrap().unwrap();
    pending.expires_at = 0;
    helper.state.save_pending(&pending).unwrap();
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert_eq!(confirmed_bytes(&helper), confirmed);
    assert!(!helper.runner.boot_enabled);
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| *kind == Kind::EnableBoot));
}

#[test]
fn enable_failures_are_visible_after_commit_and_explicit_confirm_can_retry_without_applying() {
    for failure in [Failure::Exit, Failure::Spawn, Failure::AfterMutation] {
        let (_root, mut helper) = setup(None);
        apply(&mut helper);
        let own = helper.runner.own.clone();
        let foreign = helper.runner.foreign.clone();
        helper.runner.fail(Kind::EnableBoot, failure);
        let error = helper
            .execute(ROOT, Verb::Confirm, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("confirmed and saved"));
        assert!(error.contains("boot service enable failed"));
        assert!(!error.contains("SECRET"));
        assert_eq!(helper.runner.own, own);
        assert_eq!(helper.runner.foreign, foreign);
        assert_eq!(
            confirmed_bytes(&helper).unwrap(),
            serde_json::to_vec(&policy()).unwrap()
        );
        assert!(helper.state.pending().unwrap().is_none());
        assert!(!helper.runner.timer && !helper.runner.service);
        assert_eq!(status(&helper)["active"], true);
        assert_eq!(status(&helper)["pending"], false);
        assert_eq!(status(&helper)["message"], ENABLE_FAILED);
        helper.runner.events.clear();
        helper.execute(ROOT, Verb::Confirm, None).unwrap();
        assert!(helper.runner.boot_enabled);
        assert_eq!(helper.runner.own, own);
        assert!(helper.runner.mutations().is_empty());
        assert_eq!(status(&helper)["message"], CONFIRMED);
    }
}

#[test]
fn confirm_without_live_or_confirmed_policy_never_enables_boot() {
    let (_root, mut helper) = setup(Some(PRIOR));
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert!(!helper.runner.boot_enabled);
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| *kind == Kind::EnableBoot));
    helper.state.save_policy(&policy()).unwrap();
    helper.runner.own = None;
    assert!(helper.execute(ROOT, Verb::Confirm, None).is_err());
    assert!(!helper.runner.boot_enabled);
    assert!(!helper
        .runner
        .events
        .iter()
        .any(|(kind, _)| *kind == Kind::EnableBoot));
}

#[test]
fn disable_boot_failures_do_not_skip_owned_cleanup_and_are_retryable_and_visible() {
    for failure in [Failure::Exit, Failure::Spawn, Failure::AfterMutation] {
        let (_root, mut helper) = setup(None);
        apply(&mut helper);
        helper.execute(ROOT, Verb::Confirm, None).unwrap();
        let foreign = helper.runner.foreign.clone();
        helper.runner.fail(Kind::DisableBoot, failure);
        let error = helper
            .execute(ROOT, Verb::Disable, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("boot service disable failed"));
        assert!(!error.contains("SECRET"));
        assert!(helper.runner.own.is_none());
        assert_eq!(helper.runner.foreign, foreign);
        assert!(confirmed_bytes(&helper).is_none());
        assert!(helper.state.pending().unwrap().is_none());
        assert_eq!(status(&helper)["active"], false);
        assert_eq!(status(&helper)["pending"], false);
        assert_eq!(status(&helper)["message"], DISABLE_BOOT_FAILED);
        helper.runner.events.clear();
        helper.execute(ROOT, Verb::Disable, None).unwrap();
        assert!(!helper.runner.boot_enabled);
        assert!(helper.runner.mutations().is_empty());
        assert_eq!(status(&helper)["message"], DISABLED);
    }
}

#[test]
fn boot_disable_and_owned_cleanup_failures_are_both_reported() {
    for fail_boot in [false, true] {
        let (_root, mut helper) = setup(None);
        apply(&mut helper);
        helper.execute(ROOT, Verb::Confirm, None).unwrap();
        let own = helper.runner.own.clone();
        let confirmed = confirmed_bytes(&helper);
        let foreign = helper.runner.foreign.clone();
        if fail_boot {
            helper.runner.fail(Kind::DisableBoot, Failure::Exit);
        }
        helper.runner.fail(Kind::Replace, Failure::Exit);
        let error = helper
            .execute(ROOT, Verb::Disable, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owned firewall cleanup failed"));
        assert!(!error.contains("SECRET"));
        assert_eq!(helper.runner.boot_enabled, fail_boot);
        assert_eq!(helper.runner.own, own);
        assert_eq!(confirmed_bytes(&helper), confirmed);
        assert_eq!(helper.runner.foreign, foreign);
        assert_eq!(status(&helper)["active"], true);
        assert_eq!(status(&helper)["pending"], false);
        assert_eq!(status(&helper)["message"], error);
        helper.execute(ROOT, Verb::Disable, None).unwrap();
        assert!(!helper.runner.boot_enabled);
        assert!(helper.runner.own.is_none());
        assert!(confirmed_bytes(&helper).is_none());
    }
}

#[test]
fn disable_turns_off_boot_even_when_pending_rollback_cleanup_fails() {
    let (_root, mut helper) = setup(Some(PRIOR));
    helper.state.initialize().unwrap();
    helper
        .state
        .save_policy(&FirewallPolicy::new(FirewallProfile::Private))
        .unwrap();
    helper.runner.boot_enabled = true;
    apply(&mut helper);
    helper.runner.fail(Kind::Replace, Failure::Exit);
    assert!(helper.execute(ROOT, Verb::Disable, None).is_err());
    assert!(!helper.runner.boot_enabled);
    assert!(helper.runner.timer);
    assert!(helper.state.pending().unwrap().is_some());
    assert_eq!(status(&helper)["pending"], true);
    assert!(status(&helper)["message"]
        .as_str()
        .unwrap()
        .contains("Boot service disabled"));
    helper.execute(ROOT, Verb::Disable, None).unwrap();
    assert!(!helper.runner.boot_enabled);
    assert!(helper.runner.own.is_none());
    assert!(confirmed_bytes(&helper).is_none());
}
