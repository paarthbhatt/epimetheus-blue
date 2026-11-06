use anyhow::{bail, Result};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command as Process, Stdio};
use std::time::{Duration, Instant};

pub const HELPER_PATH: &str = "/usr/lib/epimetheus-blue/blue-firewall-helper";
pub const TIMER: &str = "epimetheus-blue-firewall-rollback.timer";
pub const SERVICE: &str = "epimetheus-blue-firewall-rollback.service";
pub const BOOT_SERVICE: &str = "blue-firewall.service";
pub const MAX_OUTPUT: usize = 1024 * 1024;

#[derive(Debug)]
pub enum Command<'a> {
    ListTables,
    SaveTable,
    Check(&'a str),
    Replace(&'a str),
    TimerState { with_service: bool },
    StopTimer { timer: bool, service: bool },
    ArmTimer,
    EnableBootService,
    DisableBootService,
}

impl Command<'_> {
    fn invocation(&self) -> (&'static str, Vec<&'static str>, &[u8]) {
        match self {
            Self::ListTables => ("/usr/bin/nft", vec!["--json", "list", "tables"], &[]),
            Self::SaveTable => (
                "/usr/bin/nft",
                vec![
                    "--stateless",
                    "--numeric",
                    "list",
                    "table",
                    "inet",
                    "epimetheus_blue",
                ],
                &[],
            ),
            Self::Check(script) => (
                "/usr/bin/nft",
                vec!["--check", "--file", "-"],
                script.as_bytes(),
            ),
            Self::Replace(script) => ("/usr/bin/nft", vec!["--file", "-"], script.as_bytes()),
            Self::TimerState { with_service } => {
                let mut args = vec!["show", "--property=LoadState", "--value", TIMER];
                if *with_service {
                    args.push(SERVICE);
                }
                ("/usr/bin/systemctl", args, &[])
            }
            Self::StopTimer { timer, service } => {
                let mut args = vec!["stop"];
                if *timer {
                    args.push(TIMER);
                }
                if *service {
                    args.push(SERVICE);
                }
                ("/usr/bin/systemctl", args, &[])
            }
            Self::ArmTimer => (
                "/usr/bin/systemd-run",
                vec![
                    "--quiet",
                    "--collect",
                    "--unit=epimetheus-blue-firewall-rollback",
                    "--on-active=60s",
                    "--timer-property=AccuracySec=1s",
                    "--timer-property=RandomizedDelaySec=0",
                    "--property=Type=oneshot",
                    "--property=User=root",
                    "--property=Group=root",
                    "--property=UMask=0077",
                    "--property=Restart=on-failure",
                    "--property=RestartSec=5s",
                    HELPER_PATH,
                    "rollback",
                ],
                &[],
            ),
            // Deliberately no --now: confirmation changes boot enablement only.
            Self::EnableBootService => ("/usr/bin/systemctl", vec!["enable", BOOT_SERVICE], &[]),
            Self::DisableBootService => ("/usr/bin/systemctl", vec!["disable", BOOT_SERVICE], &[]),
        }
    }
}

pub struct Output {
    pub success: bool,
    pub stdout: Vec<u8>,
}

pub trait CommandRunner {
    fn run(&mut self, command: Command<'_>) -> Result<Output>;
}

pub struct SystemRunner;

fn trusted_executable(path: &Path) -> Result<()> {
    // Check every ancestor, not just the executable: no user-writable search path.
    let mut current = Some(path);
    while let Some(entry) = current {
        let metadata = fs::symlink_metadata(entry)
            .map_err(|_| anyhow::anyhow!("Required root-owned executable is unavailable."))?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.file_type().is_symlink()
        {
            bail!("Required executable or its parent is not root-owned and protected.");
        }
        if entry == path {
            if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0
            {
                bail!("Required executable has unsafe permissions.");
            }
        } else if !metadata.is_dir() {
            bail!("Required executable has an invalid parent.");
        }
        current = entry.parent();
    }
    Ok(())
}

pub fn verify_installed_helper() -> Result<()> {
    let path = Path::new(HELPER_PATH);
    if std::env::current_exe().map_err(|_| anyhow::anyhow!("Cannot verify installed helper."))?
        != path
    {
        bail!("Use the root-owned installed firewall helper; development binaries cannot mutate rules.");
    }
    trusted_executable(path)
}

fn bounded_output(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl CommandRunner for SystemRunner {
    fn run(&mut self, command: Command<'_>) -> Result<Output> {
        let (program, args, input) = command.invocation();
        trusted_executable(Path::new(program))?;
        let mut child = Process::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .env("LC_ALL", "C")
            .current_dir("/")
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| anyhow::anyhow!("Cannot start required firewall command."))?;
        let result = std::thread::scope(|scope| {
            let stdin = child.stdin.take();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let writer = scope.spawn(move || match stdin {
                Some(mut pipe) => pipe.write_all(input),
                None => Err(std::io::Error::other("Missing command input")),
            });
            let output = scope.spawn(move || match stdout {
                Some(pipe) => bounded_output(pipe),
                None => Err(std::io::Error::other("Missing command output")),
            });
            let errors = scope.spawn(move || match stderr {
                Some(pipe) => bounded_output(pipe),
                None => Err(std::io::Error::other("Missing command errors")),
            });
            let start = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) if start.elapsed() < Duration::from_secs(15) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => {
                        // SAFETY: this child was put in its own process group above.
                        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
            };
            let written = writer.join();
            let output = output.join();
            let errors = errors.join();
            match (status, written, output, errors) {
                (Some(status), Ok(Ok(())), Ok(Ok(stdout)), Ok(Ok(stderr)))
                    if stdout.len() <= MAX_OUTPUT && stderr.len() <= MAX_OUTPUT =>
                {
                    Ok(Output {
                        success: status.success(),
                        stdout,
                    })
                }
                _ => bail!("Firewall command failed, timed out, or exceeded its output limit."),
            }
        });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_is_fixed_root_owned_and_sixty_seconds() {
        let (program, args, input) = Command::ArmTimer.invocation();
        assert_eq!(program, "/usr/bin/systemd-run");
        assert!(args.contains(&"--on-active=60s"));
        assert!(args.contains(&"--property=User=root"));
        assert!(args.contains(&"--property=Restart=on-failure"));
        assert_eq!(&args[args.len() - 2..], &[HELPER_PATH, "rollback"]);
        assert!(input.is_empty());
    }

    #[test]
    fn commands_never_list_or_flush_the_global_ruleset() {
        for command in [
            Command::ListTables,
            Command::SaveTable,
            Command::Check("safe"),
            Command::Replace("safe"),
        ] {
            let (program, args, _) = command.invocation();
            assert_eq!(program, "/usr/bin/nft");
            assert!(!args.contains(&"ruleset"));
            assert!(!args.contains(&"flush"));
        }
    }

    #[test]
    fn development_binary_is_not_an_installed_privileged_helper() {
        assert!(verify_installed_helper().is_err());
    }

    #[test]
    fn command_output_reader_stops_at_the_fixed_limit() {
        let bytes = vec![b'x'; MAX_OUTPUT * 2];
        assert_eq!(
            bounded_output(bytes.as_slice()).unwrap().len(),
            MAX_OUTPUT + 1
        );
    }

    #[test]
    fn boot_enablement_commands_are_fixed_and_never_start_or_restart_service() {
        for (command, verb) in [
            (Command::EnableBootService, "enable"),
            (Command::DisableBootService, "disable"),
        ] {
            let (program, args, input) = command.invocation();
            assert_eq!(program, "/usr/bin/systemctl");
            assert_eq!(args, [verb, "blue-firewall.service"]);
            assert!(input.is_empty());
            assert!(!args.contains(&"--now"));
            assert!(!args.contains(&"start"));
            assert!(!args.contains(&"restart"));
        }
    }
}
