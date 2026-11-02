//! `blue-core` — shared vocabulary, state, policy and the quarantine store.
//!
//! Everything a component needs to agree on lives here. Detection lives in
//! `blue-scan`, resolution in `blue-dns`, exposure in `blue-http`.

pub mod config;
pub mod db;
pub mod model;
pub mod quarantine;
pub mod verdict;

pub use config::Config;
pub use db::Db;
pub use model::{Artifact, Confidence, Detector, DetectorResult, Event, Quarantined, Tier};
pub use quarantine::{Quarantine, StoredItem};
pub use verdict::{classify, escalate_if_confirmed, reason};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Milliseconds since the Unix epoch. One clock for the whole suite.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Streaming SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 of an in-memory buffer.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"hello").unwrap();
        assert_eq!(sha256_file(&p).unwrap(), sha256_bytes(b"hello"));
    }
}
