//! Quarantine: the only component allowed to move user data.
//!
//! Move in, record everything, move back on request. There is deliberately no
//! delete verb. A file that cannot be stored safely is left where it is.

use crate::db::Db;
use crate::model::Tier;
use crate::now_ms;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Quarantine {
    root: PathBuf,
    db: Arc<Db>,
}

pub struct StoredItem {
    pub id: i64,
    pub blob: PathBuf,
    pub sha256: String,
}

impl Quarantine {
    pub fn new(root: PathBuf, db: Arc<Db>) -> Result<Quarantine> {
        std::fs::create_dir_all(root.join("items"))
            .with_context(|| format!("creating quarantine root {}", root.display()))?;
        Ok(Quarantine { root, db })
    }

    /// Move `path` into quarantine. Returns the record id.
    pub fn store(
        &self,
        path: &Path,
        artifact_id: i64,
        tier: Tier,
        reason: &str,
    ) -> Result<StoredItem> {
        if !tier.may_quarantine() {
            bail!(
                "refusing to quarantine at {}: tier gate is T2",
                tier.label()
            );
        }
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !meta.is_file() {
            bail!("{} is not a regular file", path.display());
        }
        let sha256 = crate::sha256_file(path)?;
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());

        let staging = self
            .root
            .join("items")
            .join(format!(".staging-{}", unique_suffix()));
        std::fs::create_dir_all(&staging)?;
        let payload = staging.join("payload");

        // First move to staging. If this fails, nothing has been recorded and the
        // original file is untouched.
        move_file(path, &payload)?;

        // Record, then promote staging to its final id-named directory.
        let id = match self.db.insert_quarantine(
            artifact_id,
            &sha256,
            &path.to_string_lossy(),
            "items/.staging/payload",
            Some(mode),
            reason,
            tier,
            now_ms(),
        ) {
            Ok(id) => id,
            Err(e) => {
                let _ = move_file(&payload, path);
                let _ = std::fs::remove_dir_all(&staging);
                return Err(e);
            }
        };

        let final_dir = self.root.join("items").join(id.to_string());
        let final_payload = final_dir.join("payload");
        if let Err(e) = std::fs::rename(&staging, &final_dir) {
            // Roll back: put the file back and drop the dangling row.
            let _ = move_file(&payload, path);
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e).context("promoting quarantined object");
        }

        let _ = set_mode(&final_payload, 0o000);
        self.db
            .set_blob_path(id, &final_payload.to_string_lossy())?;
        let _ = self.db.set_state(artifact_id, "quarantined");
        let _ = self.db.event(
            "quarantine",
            "warn",
            Some(&path.to_string_lossy()),
            &format!(
                r#"{{"id":{id},"sha256":"{sha256}","reason":"{}"}}"#,
                escape(reason)
            ),
            now_ms(),
        );

        Ok(StoredItem {
            id,
            blob: final_payload,
            sha256,
        })
    }

    /// Move a quarantined file back to where it came from.
    pub fn restore(&self, id: i64) -> Result<PathBuf> {
        let item = self
            .db
            .quarantine_item(id)?
            .with_context(|| format!("no quarantine record {id}"))?;
        if item.restored_at_ms.is_some() {
            bail!("quarantine record {id} already restored");
        }
        let blob = self
            .db
            .blob_path(id)?
            .map(PathBuf::from)
            .with_context(|| format!("no blob path for {id}"))?;
        if !blob.exists() {
            bail!("quarantined object missing: {}", blob.display());
        }

        let dest = PathBuf::from(&item.original_path);
        if dest.exists() {
            bail!(
                "refusing to overwrite {}: it exists again. Move it aside first.",
                dest.display()
            );
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A quarantined object is mode 000; make it movable first.
        let _ = set_mode(&blob, 0o600);
        move_file(&blob, &dest)?;
        if let Ok(Some(mode)) = self.db.original_mode(id) {
            let _ = set_mode(&dest, mode);
        }
        self.db.mark_restored(id, now_ms())?;
        let _ = self.db.event(
            "quarantine",
            "info",
            Some(&item.original_path),
            r#"{"restored":true}"#,
            now_ms(),
        );
        Ok(dest)
    }

    pub fn list(&self, include_restored: bool) -> Result<Vec<crate::model::Quarantined>> {
        self.db.list_quarantine(include_restored)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// rename(2) when possible, copy+unlink across filesystems.
fn move_file(from: &Path, to: &Path) -> Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)?;
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("moving {} -> {}", from.display(), to.display())),
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture() -> (tempfile::TempDir, Arc<Db>, Quarantine) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open_memory().unwrap());
        let q = Quarantine::new(dir.path().join("q"), db.clone()).unwrap();
        (dir, db, q)
    }

    #[test]
    fn store_then_restore_is_byte_identical() {
        let (dir, db, q) = fixture();
        let src = dir.path().join("bad.bin");
        let payload = b"EICAR-test-payload-0123456789";
        std::fs::write(&src, payload).unwrap();
        let art = db
            .record_artifact(&src.to_string_lossy(), "h", payload.len() as i64, 1, 1)
            .unwrap();

        let stored = q.store(&src, art, Tier::Corroborated, "test").unwrap();
        assert!(!src.exists(), "original should have moved");
        assert!(stored.blob.exists());
        assert_eq!(q.list(false).unwrap().len(), 1);

        let back = q.restore(stored.id).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), payload);
        assert_eq!(q.list(false).unwrap().len(), 0);
    }

    #[test]
    fn refuses_below_t2() {
        let (dir, db, q) = fixture();
        let src = dir.path().join("maybe.bin");
        std::fs::write(&src, b"x").unwrap();
        let art = db
            .record_artifact(&src.to_string_lossy(), "h", 1, 1, 1)
            .unwrap();
        assert!(q.store(&src, art, Tier::Candidate, "weak").is_err());
        assert!(src.exists());
    }

    #[test]
    fn refuses_to_overwrite_on_restore() {
        let (dir, db, q) = fixture();
        let src = dir.path().join("dup.bin");
        std::fs::write(&src, b"one").unwrap();
        let art = db
            .record_artifact(&src.to_string_lossy(), "h", 3, 1, 1)
            .unwrap();
        let stored = q.store(&src, art, Tier::Corroborated, "t").unwrap();
        std::fs::write(&src, b"new file at same path").unwrap();
        assert!(q.restore(stored.id).is_err());
        assert_eq!(std::fs::read(&src).unwrap(), b"new file at same path");
    }

    #[test]
    fn write_through_api() {
        let (dir, _db, _q) = fixture();
        let mut f = std::fs::File::create(dir.path().join("z")).unwrap();
        f.write_all(b"z").unwrap();
    }
}
