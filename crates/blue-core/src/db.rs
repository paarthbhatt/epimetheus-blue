//! SQLite state. One writer, WAL, no ORM.

use crate::model::{
    Artifact, Counts, Dataset, DetectorResult, Event, Finding, Quarantined, ReputationRecord, Tier,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS artifacts (
  id            INTEGER PRIMARY KEY,
  path          TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  size          INTEGER NOT NULL,
  mtime_ms      INTEGER NOT NULL,
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL,
  tier          INTEGER NOT NULL DEFAULT 0,
  state         TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_artifacts_path ON artifacts(path);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha  ON artifacts(sha256);

CREATE TABLE IF NOT EXISTS evidence (
  id          INTEGER PRIMARY KEY,
  artifact_id INTEGER REFERENCES artifacts(id),
  detector    TEXT NOT NULL,
  signature   TEXT,
  confidence  TEXT NOT NULL,
  detail      TEXT,
  created_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id       INTEGER PRIMARY KEY,
  ts_ms    INTEGER NOT NULL,
  kind     TEXT NOT NULL,
  level    TEXT NOT NULL,
  subject  TEXT,
  payload  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ms DESC);

CREATE TABLE IF NOT EXISTS quarantine (
  id              INTEGER PRIMARY KEY,
  artifact_id     INTEGER REFERENCES artifacts(id),
  sha256          TEXT NOT NULL,
  original_path   TEXT NOT NULL,
  blob_path       TEXT NOT NULL,
  original_mode   INTEGER,
  reason          TEXT NOT NULL,
  tier            INTEGER NOT NULL,
  created_ms      INTEGER NOT NULL,
  restored_ms     INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
  id              INTEGER PRIMARY KEY,
  ts_ms           INTEGER NOT NULL,
  kind            TEXT NOT NULL,
  tier            INTEGER NOT NULL,
  subject         TEXT NOT NULL,
  detail          TEXT NOT NULL,
  acknowledged_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts_ms DESC);

CREATE TABLE IF NOT EXISTS datasets (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  source_url   TEXT,
  sha256       TEXT,
  size         INTEGER,
  activated_ms INTEGER NOT NULL,
  active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS reputation_cache (
  sha256       TEXT NOT NULL,
  source       TEXT NOT NULL,
  verdict      TEXT NOT NULL,
  malicious    INTEGER NOT NULL DEFAULT 0,
  suspicious   INTEGER NOT NULL DEFAULT 0,
  harmless     INTEGER NOT NULL DEFAULT 0,
  checked_ms   INTEGER NOT NULL,
  detail       TEXT NOT NULL,
  PRIMARY KEY (sha256, source)
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"#;

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init()?;
        Ok(db)
    }

    pub fn open_memory() -> Result<Db> {
        let conn = Connection::open_in_memory()?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        let c = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.execute_batch(SCHEMA)?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Upsert an observation and return the artifact id.
    pub fn record_artifact(
        &self,
        path: &str,
        sha256: &str,
        size: i64,
        mtime_ms: i64,
        now_ms: i64,
    ) -> Result<i64> {
        let c = self.lock();
        if let Some(id) = c
            .query_row(
                "SELECT id FROM artifacts WHERE path = ?1 AND sha256 = ?2 AND mtime_ms = ?3",
                params![path, sha256, mtime_ms],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            c.execute(
                "UPDATE artifacts SET last_seen_ms = ?1 WHERE id = ?2",
                params![now_ms, id],
            )?;
            return Ok(id);
        }
        c.execute(
            "INSERT INTO artifacts (path, sha256, size, mtime_ms, first_seen_ms, last_seen_ms, tier, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0, 'open')",
            params![path, sha256, size, mtime_ms, now_ms],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn add_evidence(&self, artifact_id: i64, r: &DetectorResult, now_ms: i64) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO evidence (artifact_id, detector, signature, confidence, detail, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                artifact_id,
                r.detector.as_str(),
                r.signature,
                format!("{:?}", r.confidence).to_lowercase(),
                r.detail,
                now_ms
            ],
        )?;
        Ok(())
    }

    pub fn set_tier(&self, artifact_id: i64, tier: Tier) -> Result<()> {
        let c = self.lock();
        c.execute(
            "UPDATE artifacts SET tier = ?1 WHERE id = ?2",
            params![tier.as_i64(), artifact_id],
        )?;
        Ok(())
    }

    pub fn set_state(&self, artifact_id: i64, state: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "UPDATE artifacts SET state = ?1 WHERE id = ?2",
            params![state, artifact_id],
        )?;
        Ok(())
    }

    pub fn event(
        &self,
        kind: &str,
        level: &str,
        subject: Option<&str>,
        payload: &str,
        now_ms: i64,
    ) -> Result<i64> {
        let c = self.lock();
        c.execute(
            "INSERT INTO events (ts_ms, kind, level, subject, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now_ms, kind, level, subject, payload],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn recent_events(&self, limit: usize) -> Result<Vec<Event>> {
        let c = self.lock();
        let mut stmt = c.prepare(
            "SELECT id, ts_ms, kind, level, subject, payload FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(Event {
                id: row.get(0)?,
                ts_ms: row.get(1)?,
                kind: row.get(2)?,
                level: row.get(3)?,
                subject: row.get(4)?,
                payload: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn recent_artifacts(&self, limit: usize) -> Result<Vec<Artifact>> {
        let c = self.lock();
        let mut stmt = c.prepare(
            "SELECT id, path, sha256, size, mtime_ms, tier, state
             FROM artifacts ORDER BY last_seen_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(Artifact {
                id: row.get(0)?,
                path: row.get(1)?,
                sha256: row.get(2)?,
                size: row.get(3)?,
                mtime_ms: row.get(4)?,
                tier: Tier::from_i64(row.get(5)?),
                state: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_quarantine(
        &self,
        artifact_id: i64,
        sha256: &str,
        original_path: &str,
        blob_path: &str,
        original_mode: Option<u32>,
        reason: &str,
        tier: Tier,
        now_ms: i64,
    ) -> Result<i64> {
        let c = self.lock();
        c.execute(
            "INSERT INTO quarantine
               (artifact_id, sha256, original_path, blob_path, original_mode, reason, tier, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact_id,
                sha256,
                original_path,
                blob_path,
                original_mode.map(|m| m as i64),
                reason,
                tier.as_i64(),
                now_ms
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn quarantine_item(&self, id: i64) -> Result<Option<Quarantined>> {
        let c = self.lock();
        let row = c
            .query_row(
                "SELECT id, original_path, sha256, reason, tier, created_ms, restored_ms
                 FROM quarantine WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        Quarantined {
                            id: row.get(0)?,
                            original_path: row.get(1)?,
                            sha256: row.get(2)?,
                            reason: row.get(3)?,
                            tier: Tier::from_i64(row.get(4)?),
                            created_at_ms: row.get(5)?,
                            restored_at_ms: row.get(6)?,
                        },
                        (),
                    ))
                },
            )
            .optional()?;
        Ok(row.map(|(q, _)| q))
    }

    pub fn original_mode(&self, id: i64) -> Result<Option<u32>> {
        let c = self.lock();
        let m: Option<Option<i64>> = c
            .query_row(
                "SELECT original_mode FROM quarantine WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(m.flatten().map(|v| v as u32))
    }

    pub fn blob_path(&self, id: i64) -> Result<Option<String>> {
        let c = self.lock();
        Ok(c.query_row(
            "SELECT blob_path FROM quarantine WHERE id = ?1",
            params![id],
            |row| row.get::<_, String>(0),
        )
        .optional()?)
    }

    pub fn set_blob_path(&self, id: i64, blob_path: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "UPDATE quarantine SET blob_path = ?1 WHERE id = ?2",
            params![blob_path, id],
        )?;
        Ok(())
    }

    pub fn mark_restored(&self, id: i64, now_ms: i64) -> Result<()> {
        let c = self.lock();
        c.execute(
            "UPDATE quarantine SET restored_ms = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        Ok(())
    }

    pub fn list_quarantine(&self, include_restored: bool) -> Result<Vec<Quarantined>> {
        let c = self.lock();
        let sql = if include_restored {
            "SELECT id, original_path, sha256, reason, tier, created_ms, restored_ms
             FROM quarantine ORDER BY id DESC"
        } else {
            "SELECT id, original_path, sha256, reason, tier, created_ms, restored_ms
             FROM quarantine WHERE restored_ms IS NULL ORDER BY id DESC"
        };
        let mut stmt = c.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(Quarantined {
                id: row.get(0)?,
                original_path: row.get(1)?,
                sha256: row.get(2)?,
                reason: row.get(3)?,
                tier: Tier::from_i64(row.get(4)?),
                created_at_ms: row.get(5)?,
                restored_at_ms: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn add_finding(
        &self,
        kind: &str,
        tier: Tier,
        subject: &str,
        detail: &str,
        now_ms: i64,
    ) -> Result<i64> {
        let c = self.lock();
        c.execute(
            "INSERT INTO findings (ts_ms, kind, tier, subject, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now_ms, kind, tier.as_i64(), subject, detail],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn list_findings(&self, limit: usize, include_acknowledged: bool) -> Result<Vec<Finding>> {
        let c = self.lock();
        let sql = if include_acknowledged {
            "SELECT id, ts_ms, kind, tier, subject, detail, acknowledged_ms
             FROM findings ORDER BY id DESC LIMIT ?1"
        } else {
            "SELECT id, ts_ms, kind, tier, subject, detail, acknowledged_ms
             FROM findings WHERE acknowledged_ms IS NULL ORDER BY id DESC LIMIT ?1"
        };
        let mut stmt = c.prepare(sql)?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(Finding {
                id: row.get(0)?,
                ts_ms: row.get(1)?,
                kind: row.get(2)?,
                tier: Tier::from_i64(row.get(3)?),
                subject: row.get(4)?,
                detail: row.get(5)?,
                acknowledged_at_ms: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn acknowledge_finding(&self, id: i64, now_ms: i64) -> Result<()> {
        let c = self.lock();
        c.execute(
            "UPDATE findings SET acknowledged_ms = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        Ok(())
    }

    pub fn add_dataset(
        &self,
        name: &str,
        version: &str,
        source_url: Option<&str>,
        sha256: &str,
        size: i64,
        now_ms: i64,
    ) -> Result<i64> {
        let mut c = self.lock();
        let tx = c.transaction()?;
        tx.execute(
            "UPDATE datasets SET active = 0 WHERE name = ?1",
            params![name],
        )?;
        tx.execute(
            "INSERT INTO datasets (name, version, source_url, sha256, size, activated_ms, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![name, version, source_url, sha256, size, now_ms],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>> {
        let c = self.lock();
        let mut stmt = c.prepare(
            "SELECT id, name, version, source_url, sha256, size, activated_ms, active
             FROM datasets ORDER BY id DESC LIMIT 100",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Dataset {
                id: row.get(0)?,
                name: row.get(1)?,
                version: row.get(2)?,
                source_url: row.get(3)?,
                sha256: row.get(4)?,
                size: row.get(5)?,
                activated_at_ms: row.get(6)?,
                active: row.get::<_, i64>(7)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Cheap counters for the UI. One lock, four queries.
    pub fn counts(&self) -> Result<Counts> {
        let c = self.lock();
        let artifacts: i64 = c.query_row("SELECT COUNT(*) FROM artifacts", [], |r| r.get(0))?;
        let quarantined: i64 = c.query_row(
            "SELECT COUNT(*) FROM quarantine WHERE restored_ms IS NULL",
            [],
            |r| r.get(0),
        )?;
        let findings: i64 = c.query_row(
            "SELECT COUNT(*) FROM findings WHERE acknowledged_ms IS NULL",
            [],
            |r| r.get(0),
        )?;
        let blocked: i64 = c.query_row(
            "SELECT COUNT(*) FROM events WHERE kind = 'dns' AND level = 'notice'",
            [],
            |r| r.get(0),
        )?;
        Ok(Counts {
            artifacts,
            quarantined,
            findings,
            blocked,
        })
    }

    pub fn reputation(&self, sha256: &str, source: &str) -> Result<Option<ReputationRecord>> {
        let c = self.lock();
        Ok(c.query_row(
            "SELECT sha256, source, verdict, malicious, suspicious, harmless, checked_ms, detail
                 FROM reputation_cache WHERE sha256 = ?1 AND source = ?2",
            params![sha256, source],
            |row| {
                Ok(ReputationRecord {
                    sha256: row.get(0)?,
                    source: row.get(1)?,
                    verdict: row.get(2)?,
                    malicious: row.get(3)?,
                    suspicious: row.get(4)?,
                    harmless: row.get(5)?,
                    checked_at_ms: row.get(6)?,
                    detail: row.get(7)?,
                })
            },
        )
        .optional()?)
    }

    pub fn upsert_reputation(&self, record: &ReputationRecord) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO reputation_cache
               (sha256, source, verdict, malicious, suspicious, harmless, checked_ms, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(sha256, source) DO UPDATE SET
               verdict = excluded.verdict,
               malicious = excluded.malicious,
               suspicious = excluded.suspicious,
               harmless = excluded.harmless,
               checked_ms = excluded.checked_ms,
               detail = excluded.detail",
            params![
                record.sha256,
                record.source,
                record.verdict,
                record.malicious,
                record.suspicious,
                record.harmless,
                record.checked_at_ms,
                record.detail
            ],
        )?;
        Ok(())
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let c = self.lock();
        Ok(
            c.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
            .optional()?,
        )
    }

    pub fn kill_switch(&self) -> bool {
        matches!(
            self.get_meta("kill_switch").ok().flatten().as_deref(),
            Some("1" | "true")
        )
    }

    pub fn set_kill_switch(&self, on: bool) -> Result<()> {
        self.set_meta("kill_switch", if on { "1" } else { "0" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_roundtrip() {
        let db = Db::open_memory().unwrap();
        let a = db.record_artifact("/tmp/x", "abc", 10, 5, 100).unwrap();
        let b = db.record_artifact("/tmp/x", "abc", 10, 5, 101).unwrap();
        assert_eq!(a, b);
        db.set_tier(a, Tier::Corroborated).unwrap();
        let rows = db.recent_artifacts(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tier, Tier::Corroborated);
    }

    #[test]
    fn events_are_ordered() {
        let db = Db::open_memory().unwrap();
        db.event("scan", "info", None, "{}", 1).unwrap();
        db.event("scan", "info", None, "{}", 2).unwrap();
        let ev = db.recent_events(10).unwrap();
        assert_eq!(ev[0].ts_ms, 2);
    }

    #[test]
    fn kill_switch_defaults_off() {
        let db = Db::open_memory().unwrap();
        assert!(!db.kill_switch());
        db.set_kill_switch(true).unwrap();
        assert!(db.kill_switch());
    }

    #[test]
    fn reputation_cache_roundtrip() {
        let db = Db::open_memory().unwrap();
        let record = ReputationRecord {
            sha256: "a".repeat(64),
            source: "test".into(),
            verdict: "malicious".into(),
            malicious: 7,
            suspicious: 1,
            harmless: 0,
            checked_at_ms: 42,
            detail: "{}".into(),
        };
        db.upsert_reputation(&record).unwrap();
        let loaded = db
            .reputation(&record.sha256, &record.source)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.verdict, "malicious");
        assert_eq!(loaded.malicious, 7);
        assert_eq!(loaded.checked_at_ms, 42);
    }
}
