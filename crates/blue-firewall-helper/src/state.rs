use crate::invalid_state;
use anyhow::{bail, Result};
use blue_firewall::{FirewallPolicy, FirewallProfile, FirewallStatus};
use serde::{Deserialize, Serialize};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const MAX_POLICY: usize = 64 * 1024;
pub const MAX_TABLE: usize = 1024 * 1024;
const MAX_PENDING: usize = 6 * MAX_TABLE + 6 * MAX_POLICY + 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub policy: FirewallPolicy,
    pub previous_table: Option<String>,
    pub previous_profile: Option<FirewallProfile>,
    pub expires_at: u64,
    pub applied: bool,
}

pub struct State {
    pub runtime: PathBuf,
    pub config: PathBuf,
    owner: u32,
    trusted_ancestors: bool,
}

impl State {
    pub fn system() -> Self {
        Self {
            runtime: PathBuf::from("/run/epimetheus-blue"),
            config: PathBuf::from("/etc/epimetheus-blue/firewall"),
            owner: 0,
            trusted_ancestors: true,
        }
    }

    #[cfg(test)]
    pub fn temporary(root: &Path) -> Self {
        Self {
            runtime: root.join("run"),
            config: root.join("etc").join("firewall"),
            // SAFETY: geteuid has no arguments or preconditions.
            owner: unsafe { libc::geteuid() },
            trusted_ancestors: false,
        }
    }

    pub fn private(&self) -> PathBuf {
        self.runtime.join("firewall")
    }

    fn directory(&self, path: &Path, mode: u32) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.uid() != self.owner
                    || metadata.mode() & 0o777 != mode
                {
                    return invalid_state();
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new().mode(mode).create(path).map_err(|_| {
                    anyhow::anyhow!("Cannot create protected firewall state directory.")
                })?;
                fs::set_permissions(path, Permissions::from_mode(mode))
                    .map_err(|_| anyhow::anyhow!("Cannot protect firewall state directory."))?;
            }
            Err(_) => return invalid_state(),
        }
        Ok(())
    }

    fn check_ancestors(&self, path: &Path) -> Result<()> {
        if !self.trusted_ancestors {
            return Ok(());
        }
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|_| anyhow::anyhow!("Invalid firewall state parent."))?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return invalid_state();
            }
        }
        Ok(())
    }

    pub fn initialize(&self) -> Result<()> {
        let run_parent = self
            .runtime
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid runtime root."))?;
        let config_parent = self
            .config
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid configuration root."))?;
        let etc_parent = config_parent
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid configuration parent."))?;
        self.check_ancestors(run_parent)?;
        self.check_ancestors(etc_parent)?;
        self.directory(&self.runtime, 0o755)?;
        self.directory(config_parent, 0o755)?;
        self.directory(&self.config, 0o700)?;
        self.directory(&self.private(), 0o700)
    }

    fn validate_file(&self, file: &File, public: bool) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|_| anyhow::anyhow!("Cannot verify firewall state."))?;
        let forbidden = if public { 0o022 } else { 0o077 };
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.nlink() != 1
            || metadata.mode() & forbidden != 0
        {
            return invalid_state();
        }
        Ok(())
    }

    fn read(&self, path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return invalid_state(),
        };
        self.validate_file(&file, false)?;
        let mut bytes = Vec::new();
        file.take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("Cannot read protected firewall state."))?;
        if bytes.len() > limit {
            return invalid_state();
        }
        Ok(Some(bytes))
    }

    fn sync_parent(path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid firewall state path."))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
            .map_err(|_| anyhow::anyhow!("Cannot open protected firewall state directory."))?;
        directory
            .sync_all()
            .map_err(|_| anyhow::anyhow!("Cannot synchronize firewall state."))
    }

    fn write(&self, path: &Path, bytes: &[u8], public: bool) -> Result<()> {
        // The operation lock serializes these fixed, helper-owned temporary names.
        let temporary = path.with_extension("next");
        self.remove_state_file(&temporary, public)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return invalid_state();
                }
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(path)
                    .map_err(|_| anyhow::anyhow!("Cannot verify firewall state destination."))?;
                self.validate_file(&file, public)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return invalid_state(),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| anyhow::anyhow!("Cannot stage protected firewall state."))?;
        self.validate_file(&file, false)?;
        file.write_all(bytes)
            .map_err(|_| anyhow::anyhow!("Cannot write protected firewall state."))?;
        file.set_permissions(Permissions::from_mode(if public { 0o644 } else { 0o600 }))
            .map_err(|_| anyhow::anyhow!("Cannot protect firewall state file."))?;
        file.sync_all()
            .map_err(|_| anyhow::anyhow!("Cannot synchronize firewall state file."))?;
        fs::rename(&temporary, path)
            .map_err(|_| anyhow::anyhow!("Cannot commit protected firewall state."))?;
        Self::sync_parent(path)
    }

    fn remove_state_file(&self, path: &Path, public: bool) -> Result<()> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return invalid_state(),
        };
        self.validate_file(&file, public)?;
        // allowed-delete: firewall-owned runtime state
        fs::remove_file(path) // allowed-delete: firewall-owned runtime state
            .map_err(|_| anyhow::anyhow!("Cannot remove protected firewall state."))?;
        Self::sync_parent(path)
    }

    pub fn lock(&self, wait: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.private().join("operation.lock"))
            .map_err(|_| anyhow::anyhow!("Cannot open firewall operation lock."))?;
        self.validate_file(&file, false)?;
        use std::os::fd::AsRawFd;
        let flags = libc::LOCK_EX | if wait { 0 } else { libc::LOCK_NB };
        loop {
            // SAFETY: file owns a live descriptor; the lock is released by closing it.
            if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
                return Ok(file);
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                bail!("Another firewall operation is in progress.");
            }
        }
    }

    pub fn pending(&self) -> Result<Option<Pending>> {
        match self.read(&self.private().join("pending.json"), MAX_PENDING)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| anyhow::anyhow!("Invalid pending firewall state.")),
            None => Ok(None),
        }
    }

    pub fn save_pending(&self, pending: &Pending) -> Result<()> {
        let bytes = serde_json::to_vec(pending)
            .map_err(|_| anyhow::anyhow!("Cannot encode pending firewall state."))?;
        if bytes.len() > MAX_PENDING {
            return invalid_state();
        }
        self.write(&self.private().join("pending.json"), &bytes, false)
    }

    pub fn clear_pending(&self) -> Result<()> {
        self.remove_state_file(&self.private().join("pending.json"), false)
    }

    pub fn policy(&self) -> Result<Option<FirewallPolicy>> {
        match self.read(&self.config.join("policy.json"), MAX_POLICY)? {
            Some(bytes) => {
                let policy: FirewallPolicy = serde_json::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("Invalid confirmed firewall policy."))?;
                policy
                    .validate()
                    .map_err(|_| anyhow::anyhow!("Invalid confirmed firewall policy."))?;
                Ok(Some(policy))
            }
            None => Ok(None),
        }
    }

    pub fn save_policy(&self, policy: &FirewallPolicy) -> Result<()> {
        let bytes = serde_json::to_vec(policy)
            .map_err(|_| anyhow::anyhow!("Cannot encode confirmed firewall policy."))?;
        if bytes.len() > MAX_POLICY {
            return invalid_state();
        }
        self.write(&self.config.join("policy.json"), &bytes, false)
    }

    pub fn clear_policy(&self) -> Result<()> {
        self.remove_state_file(&self.config.join("policy.json"), false)
    }

    pub fn status(&self, status: &FirewallStatus) -> Result<()> {
        let bytes = serde_json::to_vec(status)
            .map_err(|_| anyhow::anyhow!("Cannot encode sanitized firewall status."))?;
        self.write(&self.runtime.join("firewall-status.json"), &bytes, true)
    }
}
