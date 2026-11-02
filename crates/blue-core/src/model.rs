//! Shared vocabulary: detectors, confidence, verdict tiers.
//!
//! A detector result is an *observation*, not a conclusion. Tiering lives in
//! [`crate::verdict`] and is the only place allowed to promote an observation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Observed = 0,
    Candidate = 1,
    Corroborated = 2,
    Confirmed = 3,
}

impl Tier {
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    pub fn from_i64(v: i64) -> Tier {
        match v {
            0 => Tier::Observed,
            1 => Tier::Candidate,
            2 => Tier::Corroborated,
            _ => Tier::Confirmed,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tier::Observed => "T0 observed",
            Tier::Candidate => "T1 candidate",
            Tier::Corroborated => "T2 corroborated",
            Tier::Confirmed => "T3 confirmed",
        }
    }

    /// A file may only be moved into quarantine at T2 or above.
    pub fn may_quarantine(self) -> bool {
        self >= Tier::Corroborated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detector {
    ClamAv,
    Yara,
    HashRep,
    Integrity,
    Persistence,
}

impl Detector {
    pub fn as_str(self) -> &'static str {
        match self {
            Detector::ClamAv => "clamav",
            Detector::Yara => "yara",
            Detector::HashRep => "hashrep",
            Detector::Integrity => "integrity",
            Detector::Persistence => "persistence",
        }
    }

    pub fn parse_name(s: &str) -> Option<Detector> {
        Some(match s {
            "clamav" => Detector::ClamAv,
            "yara" => Detector::Yara,
            "hashrep" => Detector::HashRep,
            "integrity" => Detector::Integrity,
            "persistence" => Detector::Persistence,
            _ => return None,
        })
    }
}

/// How much a single detector's word is worth on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// One detector's output about one artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorResult {
    pub detector: Detector,
    /// Signature or rule name, when the detector can name what matched.
    pub signature: Option<String>,
    pub confidence: Confidence,
    /// Free-form evidence: byte offset, matched snippet hash, upstream verdict.
    pub detail: Option<String>,
}

impl DetectorResult {
    pub fn new(detector: Detector, signature: impl Into<String>, confidence: Confidence) -> Self {
        Self {
            detector,
            signature: Some(signature.into()),
            confidence,
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Durable record of a file we have looked at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: i64,
    pub path: String,
    pub sha256: String,
    pub size: i64,
    pub mtime_ms: i64,
    pub tier: Tier,
    pub state: String,
}

/// A quarantined item, as shown by `blue quarantine ls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quarantined {
    pub id: i64,
    pub original_path: String,
    pub sha256: String,
    pub reason: String,
    pub tier: Tier,
    pub created_at_ms: i64,
    pub restored_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub ts_ms: i64,
    pub kind: String,
    pub level: String,
    pub subject: Option<String>,
    pub payload: String,
}
