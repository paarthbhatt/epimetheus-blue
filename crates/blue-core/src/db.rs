//! SQLite state. One writer, WAL, no ORM.

use crate::model::{
    Artifact, Counts, Dataset, DetectorResult, Event, Finding, Quarantined, ReputationRecord, Tier,
};
use crate::triage::{
    assess_finding, FindingGroup, FindingReview, ReviewClassification, ReviewedFinding,
    TriageSummary, TRIAGE_POLICY_VERSION,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;
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

-- Additive migration: legacy findings and their acknowledgement state stay intact.
-- Opening a database creates the review store, but never assesses the backlog.
CREATE TABLE IF NOT EXISTS finding_reviews (
  finding_id      INTEGER PRIMARY KEY REFERENCES findings(id),
  classification  TEXT NOT NULL CHECK (classification IN ('informational', 'needs_investigation', 'actionable')),
  reason_code     TEXT NOT NULL,
  reason          TEXT NOT NULL,
  group_key       TEXT NOT NULL,
  dedup_key       TEXT NOT NULL,
  policy_version  INTEGER NOT NULL,
  assessed_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_group ON finding_reviews(group_key);

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

// Every read uses the same pending predicate. Missing/outdated reviews fail
// closed; even an incorrectly persisted informational review cannot hide T2+.
// Parameter ?1 is always the current review policy version.
const REVIEWED_FINDINGS_CTE: &str = r#"
WITH reviewed AS (
  SELECT f.id, f.ts_ms, f.kind, f.tier, f.subject, f.detail, f.acknowledged_ms,
         r.finding_id AS review_id, r.classification, r.reason_code, r.reason,
         r.group_key, r.dedup_key, r.policy_version, r.assessed_ms,
         COALESCE(r.group_key, 'unreviewed:' || f.id) AS effective_group_key,
         COALESCE(r.dedup_key, 'unreviewed:' || f.id) AS effective_dedup_key,
         CASE WHEN f.acknowledged_ms IS NULL AND (
           f.tier NOT IN (0, 1) OR r.finding_id IS NULL OR
           r.classification <> 'informational' OR r.policy_version <> ?1
         ) THEN 1 ELSE 0 END AS is_pending,
         CASE WHEN f.tier NOT IN (0, 1) THEN 3
              WHEN r.finding_id IS NULL OR r.policy_version <> ?1 OR
                   r.classification NOT IN ('informational', 'needs_investigation', 'actionable') THEN 2
              WHEN r.classification = 'actionable' THEN 3
              WHEN r.classification = 'needs_investigation' THEN 2
              ELSE 1 END AS attention_rank
  FROM findings f LEFT JOIN finding_reviews r ON r.finding_id = f.id
)
"#;

const REVIEWED_FINDING_COLUMNS: &str = "id, ts_ms, kind, tier, subject, detail, acknowledged_ms,
    review_id, classification, reason_code, reason, group_key, dedup_key, policy_version, assessed_ms";

fn reviewed_finding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReviewedFinding> {
    let finding = Finding {
        id: row.get(0)?,
        ts_ms: row.get(1)?,
        kind: row.get(2)?,
        tier: Tier::from_i64(row.get(3)?),
        subject: row.get(4)?,
        detail: row.get(5)?,
        acknowledged_at_ms: row.get(6)?,
    };
    let review = if row.get::<_, Option<i64>>(7)?.is_some() {
        let name: String = row.get(8)?;
        FindingReview {
            classification: ReviewClassification::from_name(&name),
            reason_code: row.get(9)?,
            reason: row.get(10)?,
            group_key: row.get(11)?,
            dedup_key: row.get(12)?,
            policy_version: u32::try_from(row.get::<_, i64>(13)?).unwrap_or(0),
            assessed_at_ms: row.get(14)?,
        }
        .read_safe(finding.tier)
    } else {
        FindingReview::unreviewed(&finding)
    };
    Ok(ReviewedFinding { finding, review })
}

fn persist_finding_review(c: &Connection, id: i64, review: &FindingReview) -> Result<usize> {
    Ok(c.execute(
        "INSERT INTO finding_reviews
           (finding_id, classification, reason_code, reason, group_key, dedup_key, policy_version, assessed_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(finding_id) DO UPDATE SET
           classification = excluded.classification,
           reason_code = excluded.reason_code,
           reason = excluded.reason,
           group_key = excluded.group_key,
           dedup_key = excluded.dedup_key,
           policy_version = excluded.policy_version,
           assessed_ms = excluded.assessed_ms
         WHERE finding_reviews.classification <> excluded.classification
            OR finding_reviews.reason_code <> excluded.reason_code
            OR finding_reviews.reason <> excluded.reason
            OR finding_reviews.group_key <> excluded.group_key
            OR finding_reviews.dedup_key <> excluded.dedup_key
            OR finding_reviews.policy_version <> excluded.policy_version",
        params![
            id,
            review.classification.as_str(),
            review.reason_code,
            review.reason,
            review.group_key,
            review.dedup_key,
            review.policy_version as i64,
            review.assessed_at_ms,
        ],
    )?)
}

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

    /// Retain every observation and atomically persist its conservative review.
    /// Deduplication never discards source rows or carries an acknowledgement
    /// forward to a new occurrence of the same observation.
    pub fn add_finding(
        &self,
        kind: &str,
        tier: Tier,
        subject: &str,
        detail: &str,
        now_ms: i64,
    ) -> Result<i64> {
        let mut c = self.lock();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO findings (ts_ms, kind, tier, subject, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now_ms, kind, tier.as_i64(), subject, detail],
        )?;
        let id = tx.last_insert_rowid();
        let finding = Finding {
            id,
            ts_ms: now_ms,
            kind: kind.into(),
            tier,
            subject: subject.into(),
            detail: detail.into(),
            acknowledged_at_ms: None,
        };
        persist_finding_review(&tx, id, &assess_finding(&finding, now_ms))?;
        tx.commit()?;
        Ok(id)
    }

    /// History (`true`) retains the original complete, unmodified wire records.
    /// Pending (`false`) returns one unacknowledged representative per group
    /// requiring action/investigation, matching `counts().findings`.
    pub fn list_findings(&self, limit: usize, include_acknowledged: bool) -> Result<Vec<Finding>> {
        Ok(self
            .list_reviewed_findings(limit, include_acknowledged)?
            .into_iter()
            .map(|row| row.finding)
            .collect())
    }

    /// Read-only review/history view. `false` selects pending representatives,
    /// not informational observations. No read triggers assessment or auto-ack.
    pub fn list_reviewed_findings(
        &self,
        limit: usize,
        include_acknowledged: bool,
    ) -> Result<Vec<ReviewedFinding>> {
        let c = self.lock();
        let sql = if include_acknowledged {
            format!(
                "{REVIEWED_FINDINGS_CTE}
                 SELECT {REVIEWED_FINDING_COLUMNS} FROM reviewed ORDER BY id DESC LIMIT ?2"
            )
        } else {
            format!(
                "{REVIEWED_FINDINGS_CTE}, ranked AS (
                   SELECT *, ROW_NUMBER() OVER (
                     PARTITION BY effective_group_key ORDER BY attention_rank DESC, tier DESC, id DESC
                   ) AS group_rank
                   FROM reviewed WHERE is_pending = 1
                 )
                 SELECT {REVIEWED_FINDING_COLUMNS} FROM ranked
                 WHERE group_rank = 1 ORDER BY id DESC LIMIT ?2"
            )
        };
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt.query_map(
            params![TRIAGE_POLICY_VERSION as i64, limit as i64],
            reviewed_finding_from_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Returns `Unreviewed` for a legacy row without a current assessment, or
    /// `None` only when the finding does not exist. T2+ always reads actionable.
    pub fn finding_review(&self, id: i64) -> Result<Option<FindingReview>> {
        let c = self.lock();
        let sql = format!(
            "{REVIEWED_FINDINGS_CTE}
             SELECT {REVIEWED_FINDING_COLUMNS} FROM reviewed WHERE id = ?2"
        );
        Ok(c.query_row(
            &sql,
            params![TRIAGE_POLICY_VERSION as i64, id],
            reviewed_finding_from_row,
        )
        .optional()?
        .map(|row| row.review))
    }

    /// Read-only grouped history. `pending_only` hides groups with no pending
    /// members, but group occurrence totals still include their retained history.
    /// Representatives prefer pending members and the strongest review/tier.
    pub fn list_finding_groups(
        &self,
        limit: usize,
        pending_only: bool,
    ) -> Result<Vec<FindingGroup>> {
        let c = self.lock();
        let sql = format!(
            "{REVIEWED_FINDINGS_CTE}, ranked AS (
               SELECT *, ROW_NUMBER() OVER (
                 PARTITION BY effective_group_key
                 ORDER BY CASE WHEN ?3 <> 0 THEN is_pending ELSE 1 END DESC,
                          attention_rank DESC, tier DESC, id DESC
               ) AS group_rank FROM reviewed
             ), grouped AS (
               SELECT effective_group_key AS grouped_key,
                      MIN(ts_ms) AS first_seen_ms, MAX(ts_ms) AS last_seen_ms,
                      COUNT(*) AS occurrences,
                      COUNT(DISTINCT effective_dedup_key) AS unique_observations,
                      SUM(CASE WHEN acknowledged_ms IS NULL THEN 1 ELSE 0 END) AS unacknowledged,
                      SUM(is_pending) AS pending
               FROM reviewed GROUP BY effective_group_key
               HAVING ?3 = 0 OR SUM(is_pending) > 0
             )
             SELECT {REVIEWED_FINDING_COLUMNS}, g.grouped_key, g.first_seen_ms, g.last_seen_ms,
                    g.occurrences, g.unique_observations, g.unacknowledged, g.pending
             FROM grouped g JOIN ranked ON ranked.effective_group_key = g.grouped_key
             WHERE ranked.group_rank = 1
             ORDER BY g.last_seen_ms DESC, ranked.id DESC LIMIT ?2"
        );
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt.query_map(
            params![TRIAGE_POLICY_VERSION as i64, limit as i64, pending_only],
            |row| {
                let representative = reviewed_finding_from_row(row)?;
                Ok(FindingGroup {
                    group_key: row.get(15)?,
                    classification: representative.review.classification,
                    reason_code: representative.review.reason_code.clone(),
                    reason: representative.review.reason.clone(),
                    kind: representative.finding.kind.clone(),
                    first_seen_ms: row.get(16)?,
                    last_seen_ms: row.get(17)?,
                    occurrences: row.get(18)?,
                    unique_observations: row.get(19)?,
                    unacknowledged: row.get(20)?,
                    pending: row.get(21)?,
                    representative,
                })
            },
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Explicitly assess/reassess the entire retained backlog, including acked
    /// history. Only review records change: verdicts, trust, evidence and manual
    /// acknowledgement timestamps are untouched. Opening/reading never runs this.
    pub fn assess_findings(&self, now_ms: i64) -> Result<TriageSummary> {
        let mut c = self.lock();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let findings = {
            let mut stmt = tx.prepare(
                "SELECT id, ts_ms, kind, tier, subject, detail, acknowledged_ms
                 FROM findings ORDER BY id",
            )?;
            let rows = stmt.query_map([], |row| {
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
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut summary = TriageSummary::default();
        let mut groups = BTreeSet::new();
        let mut pending_groups = BTreeSet::new();
        for finding in findings {
            let review = assess_finding(&finding, now_ms);
            if persist_finding_review(&tx, finding.id, &review)? == 0 {
                summary.unchanged += 1;
            } else {
                summary.assessed += 1;
            }
            match review.classification {
                ReviewClassification::Informational => summary.informational += 1,
                ReviewClassification::NeedsInvestigation => summary.needs_investigation += 1,
                ReviewClassification::Actionable => summary.actionable += 1,
                ReviewClassification::Unreviewed => unreachable!("assessment always classifies"),
            }
            if finding.acknowledged_at_ms.is_none() && review.classification.needs_attention() {
                pending_groups.insert(review.group_key.clone());
            }
            groups.insert(review.group_key);
        }
        summary.groups = groups.len();
        summary.pending_groups = pending_groups.len();
        tx.commit()?;
        Ok(summary)
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

    /// Cheap counters for the UI. Findings counts pending review groups, not
    /// informational novelty, duplicate occurrences, or acknowledged history.
    /// Source rows are still available through `list_findings(_, true)`.
    pub fn counts(&self) -> Result<Counts> {
        let c = self.lock();
        let artifacts: i64 = c.query_row("SELECT COUNT(*) FROM artifacts", [], |r| r.get(0))?;
        let quarantined: i64 = c.query_row(
            "SELECT COUNT(*) FROM quarantine WHERE restored_ms IS NULL",
            [],
            |r| r.get(0),
        )?;
        let findings_sql = format!(
            "{REVIEWED_FINDINGS_CTE}
             SELECT COUNT(DISTINCT effective_group_key) FROM reviewed WHERE is_pending = 1"
        );
        let findings: i64 =
            c.query_row(&findings_sql, params![TRIAGE_POLICY_VERSION as i64], |r| {
                r.get(0)
            })?;
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

    /// Shared nonblocking budget: at most one uncached VT lookup per 16 seconds.
    pub fn reserve_virustotal_slot(&self, now: i64) -> Result<bool> {
        let mut c = self.lock();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = 'vt:last-request-ms'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if previous
            .and_then(|v| v.parse::<i64>().ok())
            .is_some_and(|v| now.saturating_sub(v) < 16_000)
        {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('vt:last-request-ms',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![now.to_string()],
        )?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn network_detail(remote: &str, process: &str, pid: Value) -> (String, String) {
        let endpoint: std::net::SocketAddr = remote.parse().unwrap();
        (
            format!("new egress destination: {endpoint}"),
            json!({
                "observation": "new egress destination",
                "key": format!("v2/tcp/{}/{}", endpoint.ip(), endpoint.port()),
                "protocol": "tcp", "remote": endpoint, "process": process, "pid": pid,
            })
            .to_string(),
        )
    }

    fn path_detail(path: &str, old: Value, new: Value) -> String {
        json!({"path": path, "change": "modified", "old_sha256": old, "new_sha256": new})
            .to_string()
    }

    fn legacy_connection() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE findings (
               id INTEGER PRIMARY KEY, ts_ms INTEGER NOT NULL, kind TEXT NOT NULL,
               tier INTEGER NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL,
               acknowledged_ms INTEGER
             );",
        )
        .unwrap();
        c
    }

    #[test]
    fn new_findings_are_assessed_without_changing_trust_ack_or_evidence() {
        let db = Db::open_memory().unwrap();
        let artifact = db.record_artifact("/fixture/file", "abc", 1, 1, 1).unwrap();
        db.set_meta("trust:fixture", "untouched").unwrap();
        let (subject, detail) = network_detail("203.0.113.8:443", "firefox", json!(123));
        let id = db
            .add_finding("network", Tier::Candidate, &subject, &detail, 42)
            .unwrap();
        let review = db.finding_review(id).unwrap().unwrap();
        assert_eq!(review.classification, ReviewClassification::Informational);
        assert_eq!(review.reason_code, "routine_endpoint_novelty");
        assert_eq!(review.assessed_at_ms, Some(42));
        assert_eq!(review.policy_version, TRIAGE_POLICY_VERSION);
        assert!(review
            .reason
            .contains("not benign, trusted, or acknowledged"));
        assert_eq!(db.counts().unwrap().findings, 0);
        assert!(db.list_findings(10, false).unwrap().is_empty());
        let history = db.list_findings(10, true).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, id);
        assert_eq!(history[0].detail, detail);
        assert_eq!(history[0].tier, Tier::Candidate);
        assert_eq!(history[0].ts_ms, 42);
        assert_eq!(history[0].acknowledged_at_ms, None);
        let artifacts = db.recent_artifacts(10).unwrap();
        assert_eq!(artifacts[0].id, artifact);
        assert_eq!(artifacts[0].state, "open");
        assert_eq!(artifacts[0].tier, Tier::Observed);
        assert_eq!(
            db.get_meta("trust:fixture").unwrap().as_deref(),
            Some("untouched")
        );
    }

    #[test]
    fn t2_plus_is_actionable_and_pending_groups_keep_all_history() {
        let db = Db::open_memory().unwrap();
        let (subject, detail) = network_detail("203.0.113.8:443", "firefox", json!(123));
        let t2 = db
            .add_finding("network", Tier::Corroborated, &subject, &detail, 1)
            .unwrap();
        let t3 = db
            .add_finding("network", Tier::Confirmed, &subject, &detail, 2)
            .unwrap();
        assert_eq!(db.counts().unwrap().findings, 1);
        let pending = db.list_reviewed_findings(10, false).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].finding.id, t3);
        assert_eq!(
            pending[0].review.classification,
            ReviewClassification::Actionable
        );
        assert_eq!(db.list_findings(10, true).unwrap().len(), 2);

        db.acknowledge_finding(t3, 3).unwrap();
        assert_eq!(db.counts().unwrap().findings, 1);
        let groups = db.list_finding_groups(10, true).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].classification, ReviewClassification::Actionable);
        assert_eq!(groups[0].representative.finding.id, t2);
        assert_eq!(groups[0].occurrences, 2);
        assert_eq!(groups[0].unique_observations, 2);
        assert_eq!(groups[0].unacknowledged, 1);
        assert_eq!(groups[0].pending, 1);
        db.acknowledge_finding(t2, 4).unwrap();
        assert_eq!(db.counts().unwrap().findings, 0);
        assert!(db.list_finding_groups(10, true).unwrap().is_empty());
        let history = db.list_finding_groups(10, false).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].classification, ReviewClassification::Actionable);
        assert_eq!(history[0].occurrences, 2);
        assert_eq!(history[0].pending, 0);
    }

    #[test]
    fn novelty_cohorts_dedup_endpoints_without_discarding_attribution() {
        let db = Db::open_memory().unwrap();
        for (remote, process, pid, now) in [
            ("203.0.113.8:443", "firefox", json!(123), 1),
            ("203.0.113.8:443", "unknown", Value::Null, 2),
            ("203.0.113.9:443", "firefox", json!(456), 3),
        ] {
            let (subject, detail) = network_detail(remote, process, pid);
            db.add_finding("network", Tier::Candidate, &subject, &detail, now)
                .unwrap();
        }
        let groups = db.list_finding_groups(10, false).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].classification,
            ReviewClassification::Informational
        );
        assert_eq!(groups[0].occurrences, 3);
        assert_eq!(groups[0].unique_observations, 2);
        assert_eq!(groups[0].unacknowledged, 3);
        assert_eq!(groups[0].pending, 0);
        assert_eq!(groups[0].first_seen_ms, 1);
        assert_eq!(groups[0].last_seen_ms, 3);
        assert_eq!(db.list_findings(10, true).unwrap().len(), 3);
        assert!(db.list_finding_groups(10, true).unwrap().is_empty());
    }

    #[test]
    fn pending_dedup_does_not_transfer_ack_or_merge_distinct_path_evidence() {
        let db = Db::open_memory().unwrap();
        let path = "/home/fixture/.config/systemd/user/example.service";
        let detail = path_detail(path, json!("a".repeat(64)), json!("a".repeat(64)));
        let first = db
            .add_finding("persistence", Tier::Candidate, path, &detail, 1)
            .unwrap();
        db.acknowledge_finding(first, 2).unwrap();
        let reordered =
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(&detail).unwrap()).unwrap();
        let second = db
            .add_finding("persistence", Tier::Candidate, path, &reordered, 3)
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(db.counts().unwrap().findings, 1);
        assert_eq!(db.list_findings(10, false).unwrap()[0].id, second);
        let groups = db.list_finding_groups(10, true).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].classification,
            ReviewClassification::NeedsInvestigation
        );
        assert_eq!(groups[0].reason_code, "path_unchanged_content_unresolved");
        assert_eq!(groups[0].occurrences, 2);
        assert_eq!(groups[0].unique_observations, 1);
        assert_eq!(groups[0].unacknowledged, 1);
        assert_eq!(groups[0].pending, 1);
        let history = db.list_findings(10, true).unwrap();
        assert_eq!(history[0].acknowledged_at_ms, None);
        assert_eq!(history[1].acknowledged_at_ms, Some(2));
        assert_eq!(history[0].detail, reordered);
        assert_eq!(history[1].detail, detail);

        let changed = path_detail(path, json!("a".repeat(64)), json!("b".repeat(64)));
        db.add_finding("persistence", Tier::Candidate, path, &changed, 4)
            .unwrap();
        db.add_finding("integrity", Tier::Candidate, path, &changed, 5)
            .unwrap();
        assert_eq!(db.counts().unwrap().findings, 3);
        assert_eq!(db.list_findings(10, false).unwrap().len(), 3);
        assert_eq!(db.list_findings(10, true).unwrap().len(), 4);
    }

    #[test]
    fn legacy_migration_is_additive_idempotent_and_never_assesses_on_open() {
        let c = legacy_connection();
        let (subject, detail) = network_detail("203.0.113.8:443", "unknown", Value::Null);
        c.execute(
            "INSERT INTO findings VALUES(7, 10, 'network', 1, ?1, ?2, NULL)",
            params![subject, detail],
        )
        .unwrap();
        let path = "/home/fixture/.config/systemd/user/example.service";
        c.execute(
            "INSERT INTO findings VALUES(8, 11, 'persistence', 1, ?1, ?2, 90)",
            params![path, path_detail(path, Value::Null, Value::Null)],
        )
        .unwrap();
        let db = Db {
            conn: Mutex::new(c),
        };
        db.init().unwrap();
        db.init().unwrap();
        let history = db.list_findings(10, true).unwrap();
        let before = serde_json::to_value(&history).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, 8);
        assert_eq!(history[0].acknowledged_at_ms, Some(90));
        assert_eq!(history[1].id, 7);
        assert_eq!(db.counts().unwrap().findings, 1);
        assert_eq!(
            db.finding_review(7).unwrap().unwrap().classification,
            ReviewClassification::Unreviewed
        );
        let persisted: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM finding_reviews", [], |row| row.get(0))
            .unwrap();
        assert_eq!(persisted, 0);

        let summary = db.assess_findings(100).unwrap();
        assert_eq!(summary.assessed, 2);
        assert_eq!(summary.unchanged, 0);
        assert_eq!(summary.informational, 1);
        assert_eq!(summary.needs_investigation, 1);
        assert_eq!(summary.actionable, 0);
        assert_eq!(summary.groups, 2);
        assert_eq!(summary.pending_groups, 0);
        assert_eq!(db.counts().unwrap().findings, 0);
        assert_eq!(
            serde_json::to_value(db.list_findings(10, true).unwrap()).unwrap(),
            before
        );
        assert_eq!(
            db.finding_review(8).unwrap().unwrap().classification,
            ReviewClassification::NeedsInvestigation
        );
    }

    #[test]
    fn explicitly_assessed_suspicious_backlog_stays_pending_with_reasons() {
        let c = legacy_connection();
        let path = "/home/fixture/.profile";
        for (id, old, new) in [
            (1, json!("a".repeat(64)), json!("a".repeat(64))),
            (2, Value::Null, Value::Null),
            (3, json!("a".repeat(64)), json!("b".repeat(64))),
        ] {
            c.execute(
                "INSERT INTO findings VALUES(?1, ?1, 'persistence', 1, ?2, ?3, NULL)",
                params![id, path, path_detail(path, old, new)],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO findings VALUES(4, 4, 'network', 2, 'subject', '{}', NULL)",
            [],
        )
        .unwrap();
        let db = Db {
            conn: Mutex::new(c),
        };
        db.init().unwrap();
        let summary = db.assess_findings(50).unwrap();
        assert_eq!(summary.assessed, 4);
        assert_eq!(summary.needs_investigation, 3);
        assert_eq!(summary.actionable, 1);
        assert_eq!(summary.informational, 0);
        assert_eq!(summary.pending_groups, 4);
        assert_eq!(db.counts().unwrap().findings, 4);
        let pending = db.list_reviewed_findings(10, false).unwrap();
        assert_eq!(pending.len(), 4);
        assert!(pending
            .iter()
            .all(|row| row.finding.acknowledged_at_ms.is_none()));
        assert!(pending.iter().all(|row| !row.review.reason.is_empty()));
    }

    #[test]
    fn reassessment_is_idempotent_and_only_updates_outdated_reviews() {
        let db = Db::open_memory().unwrap();
        let (subject, detail) = network_detail("203.0.113.8:443", "unknown", Value::Null);
        let id = db
            .add_finding("network", Tier::Candidate, &subject, &detail, 1)
            .unwrap();
        let original = db.finding_review(id).unwrap().unwrap();
        let summary = db.assess_findings(100).unwrap();
        assert_eq!(summary.assessed, 0);
        assert_eq!(summary.unchanged, 1);
        assert_eq!(db.finding_review(id).unwrap().unwrap(), original);
        db.lock()
            .execute("UPDATE finding_reviews SET policy_version = 0", [])
            .unwrap();
        let summary = db.assess_findings(200).unwrap();
        assert_eq!(summary.assessed, 1);
        assert_eq!(summary.unchanged, 0);
        let current = db.finding_review(id).unwrap().unwrap();
        assert_eq!(current.group_key, original.group_key);
        assert_eq!(current.dedup_key, original.dedup_key);
        assert_eq!(current.assessed_at_ms, Some(200));
        assert_eq!(current.policy_version, TRIAGE_POLICY_VERSION);
        assert_eq!(
            db.list_findings(10, true).unwrap()[0].acknowledged_at_ms,
            None
        );
        assert_eq!(db.assess_findings(300).unwrap().unchanged, 1);
        assert_eq!(
            db.finding_review(id).unwrap().unwrap().assessed_at_ms,
            Some(200)
        );
    }

    #[test]
    fn stale_info_and_misclassified_t2_cannot_hide_evidence_or_write_on_read() {
        let db = Db::open_memory().unwrap();
        let (subject, detail) = network_detail("203.0.113.8:443", "unknown", Value::Null);
        let t1 = db
            .add_finding("network", Tier::Candidate, &subject, &detail, 1)
            .unwrap();
        let t2 = db
            .add_finding("network", Tier::Corroborated, &subject, &detail, 2)
            .unwrap();
        db.lock()
            .execute(
                "UPDATE finding_reviews SET policy_version = 0 WHERE finding_id = ?1",
                params![t1],
            )
            .unwrap();
        db.lock()
            .execute(
                "UPDATE finding_reviews SET classification = 'informational' WHERE finding_id = ?1",
                params![t2],
            )
            .unwrap();
        let changes = db.lock().total_changes();
        assert_eq!(db.counts().unwrap().findings, 2);
        assert_eq!(db.list_findings(10, false).unwrap().len(), 2);
        assert_eq!(db.list_reviewed_findings(10, true).unwrap().len(), 2);
        assert_eq!(db.list_finding_groups(10, true).unwrap().len(), 2);
        assert_eq!(db.list_finding_groups(10, false).unwrap().len(), 2);
        assert_eq!(
            db.finding_review(t1).unwrap().unwrap().classification,
            ReviewClassification::Unreviewed
        );
        assert_eq!(
            db.finding_review(t2).unwrap().unwrap().classification,
            ReviewClassification::Actionable
        );
        assert_eq!(db.finding_review(999).unwrap(), None);
        assert_eq!(db.lock().total_changes(), changes);
        let persisted: String = db
            .lock()
            .query_row(
                "SELECT classification FROM finding_reviews WHERE finding_id = ?1",
                params![t2],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, "informational");
    }

    #[test]
    fn finding_and_review_insert_are_atomic() {
        let db = Db::open_memory().unwrap();
        db.lock()
            .execute_batch(
                "CREATE TRIGGER fixture_reject_review BEFORE INSERT ON finding_reviews
                 BEGIN SELECT RAISE(ABORT, 'fixture review failure'); END;",
            )
            .unwrap();
        let (subject, detail) = network_detail("203.0.113.8:443", "unknown", Value::Null);
        assert!(db
            .add_finding("network", Tier::Candidate, &subject, &detail, 1)
            .is_err());
        assert!(db.list_findings(10, true).unwrap().is_empty());
        let reviews: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM finding_reviews", [], |row| row.get(0))
            .unwrap();
        assert_eq!(reviews, 0);
    }

    #[test]
    fn native_host_history_keeps_original_finding_wire_shape() {
        let db = Db::open_memory().unwrap();
        let (subject, detail) = network_detail("203.0.113.8:443", "unknown", Value::Null);
        db.add_finding("network", Tier::Candidate, &subject, &detail, 1)
            .unwrap();
        let history = serde_json::to_value(db.list_findings(10, true).unwrap()).unwrap();
        let object = history[0].as_object().unwrap();
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "acknowledged_at_ms",
                "detail",
                "id",
                "kind",
                "subject",
                "tier",
                "ts_ms"
            ]
        );
        assert_eq!(object["detail"], detail);
        assert_eq!(object["tier"], "candidate");
        assert!(object["acknowledged_at_ms"].is_null());
        assert!(!object.contains_key("review"));
    }

    #[test]
    fn reviews_survive_fixture_database_reopen_without_reassessment() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("fixture.db");
        let (subject, detail) = network_detail("203.0.113.8:443", "unknown", Value::Null);
        let (id, review) = {
            let db = Db::open(&path).unwrap();
            let id = db
                .add_finding("network", Tier::Candidate, &subject, &detail, 1)
                .unwrap();
            (id, db.finding_review(id).unwrap().unwrap())
        };
        let reopened = Db::open(&path).unwrap();
        assert_eq!(reopened.finding_review(id).unwrap().unwrap(), review);
        assert_eq!(reopened.list_findings(10, true).unwrap()[0].detail, detail);
        assert_eq!(reopened.counts().unwrap().findings, 0);
    }

    #[test]
    fn empty_backlog_assessment_has_no_side_effects() {
        let db = Db::open_memory().unwrap();
        assert_eq!(db.assess_findings(1).unwrap(), TriageSummary::default());
        assert!(db.list_findings(10, true).unwrap().is_empty());
        assert!(db.list_finding_groups(10, false).unwrap().is_empty());
    }

    #[test]
    fn virustotal_budget_is_shared_and_nonblocking() {
        let db = Db::open_memory().unwrap();
        assert!(db.reserve_virustotal_slot(100_000).unwrap());
        assert!(!db.reserve_virustotal_slot(100_001).unwrap());
        assert!(!db.reserve_virustotal_slot(115_999).unwrap());
        assert!(db.reserve_virustotal_slot(116_000).unwrap());
    }

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
