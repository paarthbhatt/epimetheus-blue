//! Conservative review of observations, separate from verdicts, trust and acknowledgement.
//!
//! Informational means that a narrowly recognized observation does not itself
//! call for action. It never means that its subject is trusted or benign. All
//! source findings are retained; grouping and deduplication are presentation only.

use crate::{sha256_bytes, Finding, Tier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;

pub const TRIAGE_POLICY_VERSION: u32 = 1;

const ACTIONABLE_REASON: &str = "T2+ evidence remains actionable. Automatic review does not lower the verdict, establish trust, acknowledge the finding, or authorize remediation.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewClassification {
    Unreviewed,
    Informational,
    NeedsInvestigation,
    Actionable,
}

impl ReviewClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Informational => "informational",
            Self::NeedsInvestigation => "needs_investigation",
            Self::Actionable => "actionable",
        }
    }

    pub fn needs_attention(self) -> bool {
        self != Self::Informational
    }

    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "informational" => Self::Informational,
            "needs_investigation" => Self::NeedsInvestigation,
            "actionable" => Self::Actionable,
            _ => Self::Unreviewed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingReview {
    pub classification: ReviewClassification,
    /// Stable machine-readable policy reason; `reason` explains its limits.
    pub reason_code: String,
    pub reason: String,
    pub group_key: String,
    /// Observation identity, not a claim that all recorded evidence is identical.
    pub dedup_key: String,
    pub policy_version: u32,
    pub assessed_at_ms: Option<i64>,
}

impl FindingReview {
    pub(crate) fn unreviewed(finding: &Finding) -> Self {
        Self {
            classification: ReviewClassification::Unreviewed,
            reason_code: "not_assessed".into(),
            reason: "Not assessed under the current review policy. Retained for investigation; no trust or acknowledgement has been assigned.".into(),
            group_key: format!("unreviewed:{}", finding.id),
            dedup_key: format!("unreviewed:{}", finding.id),
            policy_version: 0,
            assessed_at_ms: None,
        }
        .read_safe(finding.tier)
    }

    /// Reads fail closed on unsupported assessments, and never suppress T2+.
    /// This only changes the returned view; it does not write to the database.
    pub(crate) fn read_safe(mut self, tier: Tier) -> Self {
        if tier >= Tier::Corroborated {
            self.classification = ReviewClassification::Actionable;
            self.reason_code = "tier_requires_action".into();
            self.reason = ACTIONABLE_REASON.into();
        } else if self.policy_version != TRIAGE_POLICY_VERSION
            || self.classification == ReviewClassification::Unreviewed
        {
            self.classification = ReviewClassification::Unreviewed;
            self.reason_code = "not_assessed".into();
            self.reason = "No supported current-policy assessment is available. Retained for investigation until explicit reassessment; no trust or acknowledgement has been assigned.".into();
        }
        self
    }
}

/// An additive API: the original `Finding` and its native-host wire shape stay unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewedFinding {
    pub finding: Finding,
    pub review: FindingReview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroup {
    pub group_key: String,
    pub classification: ReviewClassification,
    pub reason_code: String,
    pub reason: String,
    pub kind: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// All retained source rows, including acknowledged observations.
    pub occurrences: i64,
    pub unique_observations: i64,
    pub unacknowledged: i64,
    /// Unacknowledged rows requiring action/investigation (including unreviewed).
    pub pending: i64,
    pub representative: ReviewedFinding,
}

/// Classification totals cover all source rows, including acknowledged history.
/// `assessed` counts changed/new persisted reviews; repeat assessment is idempotent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageSummary {
    pub assessed: usize,
    pub unchanged: usize,
    pub informational: usize,
    pub needs_investigation: usize,
    pub actionable: usize,
    pub groups: usize,
    pub pending_groups: usize,
}

/// Assess only the supplied evidence. No filesystem, network, trust, or ack writes.
pub fn assess_finding(finding: &Finding, now_ms: i64) -> FindingReview {
    let detail = serde_json::from_str::<Value>(&finding.detail).ok();
    let canonical = detail
        .as_ref()
        .map(canonical_json)
        .unwrap_or_else(|| finding.detail.clone());
    let tier = finding.tier.as_i64().to_string();
    let dedup_key = fingerprint(
        "observation",
        &[&finding.kind, &tier, &finding.subject, &canonical],
    );

    if finding.tier >= Tier::Corroborated {
        return review(
            finding,
            ReviewClassification::Actionable,
            "tier_requires_action",
            ACTIONABLE_REASON,
            &dedup_key,
            now_ms,
        );
    }

    let Some(object) = detail.as_ref().and_then(Value::as_object) else {
        return investigate(
            finding,
            "detail_not_structured",
            "The observation lacks a structured evidence object recognized by this policy. Retained for investigation; free-form text is not a benign or trust verdict.",
            &dedup_key,
            now_ms,
        );
    };

    // Exact kinds and exact observation schemas only. A similar name or a
    // benign-looking process label cannot opt an observation into a quiet rule.
    match finding.kind.as_str() {
        "network" => assess_network(finding, object, &dedup_key, now_ms),
        "persistence" | "integrity" => assess_path(finding, object, &dedup_key, now_ms),
        "package" => investigate(
            finding,
            "package_integrity_unresolved",
            "A package-integrity observation requires provenance and expected-change review. Automatic triage cannot establish that a package or its changed files are trusted.",
            &dedup_key,
            now_ms,
        ),
        _ => investigate(
            finding,
            "kind_not_recognized",
            "This exact finding kind has no automatic review rule. Retained for investigation; a similar name, path, or process label does not establish trust.",
            &dedup_key,
            now_ms,
        ),
    }
}

fn assess_network(
    finding: &Finding,
    object: &Map<String, Value>,
    dedup_key: &str,
    now_ms: i64,
) -> FindingReview {
    if object.get("observation").and_then(Value::as_str)
        == Some("network connection list truncated")
    {
        return investigate(
            finding,
            "network_visibility_gap",
            "The network observation was truncated. Missing visibility is not evidence of safety; retain this coverage gap for investigation.",
            dedup_key,
            now_ms,
        );
    }

    let allowed = ["observation", "key", "protocol", "remote", "process", "pid"];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return investigate(
            finding,
            "network_unmodeled_evidence",
            "The network record includes evidence outside the endpoint-novelty schema. Retained for investigation rather than suppressing potentially suspicious evidence.",
            dedup_key,
            now_ms,
        );
    }

    let Some((protocol, remote)) = novelty_endpoint(finding, object) else {
        return investigate(
            finding,
            "network_evidence_incomplete",
            "This is not a complete, consistent endpoint-novelty observation. Missing or contradictory attribution/endpoint evidence remains for investigation; no trust is inferred.",
            dedup_key,
            now_ms,
        );
    };

    if remote.port() != 443 {
        return investigate(
            finding,
            "network_endpoint_unresolved",
            "A new destination outside the narrow port-443 novelty rule requires investigation. Endpoint novelty alone neither establishes maliciousness nor authorizes trust.",
            dedup_key,
            now_ms,
        );
    }

    let mut assessment = review(
        finding,
        ReviewClassification::Informational,
        "routine_endpoint_novelty",
        "Only a new, consistently recorded port-443 egress endpoint is evidenced. Domain/reputation, executable identity and TLS have not been verified; process labels are not proof. Informational is not benign, trusted, or acknowledged.",
        dedup_key,
        now_ms,
    );
    // Cohort many routine endpoints without relying on browser/process names.
    // The exact endpoints and all attribution changes remain in source history.
    assessment.group_key = fingerprint("network-novelty-group", &[protocol, "443"]);
    assessment.dedup_key = fingerprint("network-endpoint", &[protocol, &remote.to_string()]);
    assessment
}

fn novelty_endpoint<'a>(
    finding: &Finding,
    object: &'a Map<String, Value>,
) -> Option<(&'a str, SocketAddr)> {
    if object.get("observation")?.as_str()? != "new egress destination" {
        return None;
    }
    let protocol = object.get("protocol")?.as_str()?;
    if !matches!(protocol, "tcp" | "tcp6" | "udp" | "udp6") {
        return None;
    }
    let remote = object.get("remote")?.as_str()?.parse::<SocketAddr>().ok()?;
    if remote.port() == 0
        || remote.ip().is_unspecified()
        || remote.ip().is_loopback()
        || remote.ip().is_multicast()
        || matches!(remote.ip(), std::net::IpAddr::V4(address) if address.is_broadcast())
        || remote.is_ipv6() != protocol.ends_with('6')
    {
        return None;
    }
    if finding.subject != format!("new egress destination: {remote}") {
        return None;
    }
    let process = object.get("process")?.as_str()?;
    if process.is_empty() {
        return None;
    }
    let pid = object.get("pid")?;
    if !pid.is_null()
        && !pid
            .as_u64()
            .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok())
    {
        return None;
    }

    let key = object.get("key")?.as_str()?;
    let current = format!("v2/{protocol}/{}/{}", remote.ip(), remote.port());
    // Older findings included the process in their baseline key. Recognize the
    // exact old format but remove that volatile attribution from dedup identity.
    let legacy = format!("{protocol}/{process}/{}/{}", remote.ip(), remote.port());
    if key != current && key != legacy {
        return None;
    }
    Some((protocol, remote))
}

fn assess_path(
    finding: &Finding,
    object: &Map<String, Value>,
    dedup_key: &str,
    now_ms: i64,
) -> FindingReview {
    if finding.kind == "integrity"
        && object.get("change").and_then(Value::as_str) == Some("inventory_truncated")
    {
        return investigate(
            finding,
            "integrity_visibility_gap",
            "The integrity inventory was truncated. A partial inventory cannot establish safety; retain the coverage gap for investigation.",
            dedup_key,
            now_ms,
        );
    }

    let allowed = ["path", "change", "old_sha256", "new_sha256"];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return investigate(
            finding,
            "path_unmodeled_evidence",
            "The path-change record includes evidence not modeled by this review policy. Preserve it for investigation; automatic triage cannot establish authorization.",
            dedup_key,
            now_ms,
        );
    }
    let change = object.get("change").and_then(Value::as_str);
    if object.get("path").and_then(Value::as_str) != Some(finding.subject.as_str())
        || finding.subject.is_empty()
        || !matches!(change, Some("added" | "removed" | "modified"))
    {
        return investigate(
            finding,
            "path_evidence_incomplete",
            "The path/change evidence is incomplete or inconsistent. Persistence and integrity observations remain for investigation; no benign or trust conclusion is available.",
            dedup_key,
            now_ms,
        );
    }
    let Some(old) = hash_field(object, "old_sha256") else {
        return incomplete_hashes(finding, dedup_key, now_ms);
    };
    let Some(new) = hash_field(object, "new_sha256") else {
        return incomplete_hashes(finding, dedup_key, now_ms);
    };

    let (code, reason) = match (change, old, new) {
        (_, None, None) => (
            "path_unhashed_change",
            "No before/after content hashes were recorded. Symlink targets, large-file contents or other metadata may have changed without usable hash evidence. Retain for investigation; missing hashes do not establish trust.",
        ),
        (Some("modified"), Some(old), Some(new)) if old.eq_ignore_ascii_case(new) => (
            "path_unchanged_content_unresolved",
            "Content hashes match, but a change was observed. Permission/mode, metadata and startup-target evidence is not recorded here; content equality does not establish authorization or trust. Retain for investigation.",
        ),
        (Some("modified"), Some(_), Some(_)) => (
            "path_content_changed",
            "Recorded path contents changed without evidence that the change was authorized. Retain persistence/integrity evidence for investigation; automatic review does not promote the verdict or establish trust.",
        ),
        (Some("added"), None, Some(_)) => (
            "path_added_unresolved",
            "A new path was observed without provenance or authorization evidence. Retain persistence/integrity evidence for investigation; a path name or content hash does not establish trust.",
        ),
        (Some("removed"), Some(_), None) => (
            "path_removed_unresolved",
            "A previously observed path disappeared without authorization evidence. Retain the change for investigation; removal is not automatically benign or proof of remediation.",
        ),
        _ => return incomplete_hashes(finding, dedup_key, now_ms),
    };
    investigate(finding, code, reason, dedup_key, now_ms)
}

fn hash_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<Option<&'a str>> {
    match object.get(key)? {
        Value::Null => Some(None),
        Value::String(hash)
            if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Some(Some(hash))
        }
        _ => None,
    }
}

fn incomplete_hashes(finding: &Finding, dedup_key: &str, now_ms: i64) -> FindingReview {
    investigate(
        finding,
        "path_hash_evidence_incomplete",
        "Before/after hash evidence is missing, invalid or inconsistent with the recorded change. Retain for investigation; insufficient persistence/integrity evidence is never automatically certified benign.",
        dedup_key,
        now_ms,
    )
}

fn investigate(
    finding: &Finding,
    code: &str,
    reason: &str,
    dedup_key: &str,
    now_ms: i64,
) -> FindingReview {
    review(
        finding,
        ReviewClassification::NeedsInvestigation,
        code,
        reason,
        dedup_key,
        now_ms,
    )
}

fn review(
    finding: &Finding,
    classification: ReviewClassification,
    code: &str,
    reason: &str,
    dedup_key: &str,
    now_ms: i64,
) -> FindingReview {
    FindingReview {
        classification,
        reason_code: code.into(),
        reason: reason.into(),
        group_key: fingerprint(
            "review-group",
            &[
                &finding.kind,
                classification.as_str(),
                code,
                &finding.subject,
            ],
        ),
        dedup_key: dedup_key.into(),
        policy_version: TRIAGE_POLICY_VERSION,
        assessed_at_ms: Some(now_ms),
    }
}

fn fingerprint(namespace: &str, parts: &[&str]) -> String {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    format!("v1:{namespace}:{}", sha256_bytes(&bytes))
}

/// Stable even if another crate enables serde_json's `preserve_order` feature.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<_, _> = object.iter().collect();
            let pairs: Vec<_> = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!("{}:{}", Value::String(key.clone()), canonical_json(value))
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        Value::Array(values) => {
            let values: Vec<_> = values.iter().map(canonical_json).collect();
            format!("[{}]", values.join(","))
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(kind: &str, tier: Tier, subject: &str, detail: Value) -> Finding {
        Finding {
            id: 1,
            ts_ms: 1,
            kind: kind.into(),
            tier,
            subject: subject.into(),
            detail: detail.to_string(),
            acknowledged_at_ms: None,
        }
    }

    fn network(remote: &str, protocol: &str, process: &str, pid: Value) -> Finding {
        let endpoint: SocketAddr = remote.parse().unwrap();
        finding(
            "network",
            Tier::Candidate,
            &format!("new egress destination: {endpoint}"),
            json!({
                "observation": "new egress destination",
                "key": format!("v2/{protocol}/{}/{}", endpoint.ip(), endpoint.port()),
                "protocol": protocol,
                "remote": endpoint,
                "process": process,
                "pid": pid,
            }),
        )
    }

    #[test]
    fn novelty_is_information_not_trust_and_does_not_need_a_browser_label() {
        for (protocol, remote) in [
            ("tcp", "203.0.113.8:443"),
            ("udp", "203.0.113.8:443"),
            ("tcp6", "[2001:db8::8]:443"),
            ("udp6", "[2001:db8::8]:443"),
        ] {
            let original = network(remote, protocol, "unknown", Value::Null);
            let result = assess_finding(&original, 42);
            assert_eq!(result.classification, ReviewClassification::Informational);
            assert_eq!(result.reason_code, "routine_endpoint_novelty");
            assert!(result
                .reason
                .contains("not benign, trusted, or acknowledged"));
            assert_eq!(original.tier, Tier::Candidate);
            assert_eq!(original.acknowledged_at_ms, None);
            assert_eq!(result.assessed_at_ms, Some(42));
        }
    }

    #[test]
    fn t2_and_t3_are_always_actionable_even_with_missing_evidence() {
        for kind in ["network", "persistence", "unknown"] {
            for tier in [Tier::Corroborated, Tier::Confirmed] {
                let original = finding(kind, tier, "subject", Value::Null);
                let result = assess_finding(&original, 42);
                assert_eq!(result.classification, ReviewClassification::Actionable);
                assert_eq!(result.reason_code, "tier_requires_action");
            }
        }
    }

    #[test]
    fn exact_kind_and_evidence_are_required_for_quiet_review() {
        let valid = network("203.0.113.8:443", "tcp", "firefox", json!(123));
        for detail in [
            json!({"observation": "new egress destination", "remote": "203.0.113.8:443"}),
            json!({"observation": "malicious connection", "process": "firefox"}),
            json!("new egress destination: 203.0.113.8:443 browser"),
        ] {
            let mut original = valid.clone();
            original.detail = detail.to_string();
            assert!(assess_finding(&original, 1)
                .classification
                .needs_attention());
        }
        for kind in ["network_suspicious", "Network", "browser"] {
            let mut original = valid.clone();
            original.kind = kind.into();
            assert_eq!(
                assess_finding(&original, 1).classification,
                ReviewClassification::NeedsInvestigation
            );
        }
    }

    #[test]
    fn extra_suspicious_evidence_and_contradictions_cannot_be_suppressed() {
        let valid = network("203.0.113.8:443", "tcp", "firefox", json!(123));
        for (key, value) in [
            ("reputation", json!("malicious")),
            ("remote", json!("203.0.113.9:443")),
            ("key", json!("v2/tcp/203.0.113.9/443")),
            ("pid", json!(-1)),
            ("protocol", json!("tcp6")),
        ] {
            let mut original = valid.clone();
            let mut detail: Value = serde_json::from_str(&original.detail).unwrap();
            detail[key] = value;
            original.detail = detail.to_string();
            assert_eq!(
                assess_finding(&original, 1).classification,
                ReviewClassification::NeedsInvestigation
            );
        }
        let mut original = valid;
        original.subject = "unrelated subject".into();
        assert!(assess_finding(&original, 1)
            .classification
            .needs_attention());
    }

    #[test]
    fn nonroutine_ports_and_visibility_gaps_remain_for_investigation() {
        let original = network("203.0.113.8:4444", "tcp", "firefox", json!(123));
        assert_eq!(
            assess_finding(&original, 1).reason_code,
            "network_endpoint_unresolved"
        );
        let original = finding(
            "network",
            Tier::Candidate,
            "network observation truncated",
            json!({"observation": "network connection list truncated", "max_connections": 100}),
        );
        assert_eq!(
            assess_finding(&original, 1).reason_code,
            "network_visibility_gap"
        );
    }

    #[test]
    fn non_egress_addresses_cannot_match_the_quiet_rule() {
        for remote in [
            "0.0.0.0:443",
            "127.0.0.1:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
        ] {
            let original = network(remote, "tcp", "firefox", json!(123));
            assert_eq!(
                assess_finding(&original, 1).classification,
                ReviewClassification::NeedsInvestigation
            );
        }
    }

    #[test]
    fn legacy_keys_and_volatile_attribution_do_not_split_novelty_identity() {
        let original = network("203.0.113.8:443", "tcp", "firefox", json!(123));
        let mut repeated = original.clone();
        repeated.id = 2;
        repeated.ts_ms = 99;
        repeated.detail = json!({
            "observation": "new egress destination",
            "key": "tcp/unknown/203.0.113.8/443",
            "protocol": "tcp", "remote": "203.0.113.8:443", "process": "unknown", "pid": null,
        })
        .to_string();
        let first = assess_finding(&original, 1);
        let second = assess_finding(&repeated, 99);
        assert_eq!(first.group_key, second.group_key);
        assert_eq!(first.dedup_key, second.dedup_key);
        assert_ne!(original.detail, repeated.detail);

        let other = assess_finding(&network("203.0.113.9:443", "tcp", "firefox", json!(123)), 1);
        assert_eq!(first.group_key, other.group_key);
        assert_ne!(first.dedup_key, other.dedup_key);
    }

    #[test]
    fn same_hashes_and_unhashed_symlink_or_metadata_changes_are_not_benign() {
        let hash = "a".repeat(64);
        for kind in ["persistence", "integrity"] {
            for (old, new, code) in [
                (
                    json!(hash),
                    json!(hash),
                    "path_unchanged_content_unresolved",
                ),
                (Value::Null, Value::Null, "path_unhashed_change"),
                (json!(hash), json!("b".repeat(64)), "path_content_changed"),
            ] {
                let original = finding(
                    kind,
                    Tier::Candidate,
                    "/home/test/.config/systemd/user/example.service",
                    json!({
                        "path": "/home/test/.config/systemd/user/example.service",
                        "change": "modified", "old_sha256": old, "new_sha256": new,
                    }),
                );
                let result = assess_finding(&original, 1);
                assert_eq!(
                    result.classification,
                    ReviewClassification::NeedsInvestigation
                );
                assert_eq!(result.reason_code, code);
            }
        }
    }

    #[test]
    fn absent_invalid_or_contradictory_path_hashes_stay_investigation() {
        let path = "/home/test/.profile";
        for detail in [
            json!({"path": path, "change": "modified"}),
            json!({"path": path, "change": "modified", "old_sha256": "abc", "new_sha256": "abc"}),
            json!({"path": path, "change": "modified", "old_sha256": null, "new_sha256": "a".repeat(64)}),
            json!({"path": "/wrong/path", "change": "modified", "old_sha256": null, "new_sha256": null}),
            json!({"path": path, "change": "modified", "old_sha256": null, "new_sha256": null, "target": "/tmp/suspicious"}),
        ] {
            let original = finding("persistence", Tier::Candidate, path, detail);
            assert_eq!(
                assess_finding(&original, 1).classification,
                ReviewClassification::NeedsInvestigation
            );
        }
    }

    #[test]
    fn canonical_dedup_preserves_distinct_evidence_and_exact_kind() {
        let mut original = finding("persistence", Tier::Candidate, "subject", Value::Null);
        original.detail = r#"{"change":"modified","nested":{"b":2,"a":1}}"#.into();
        let first = assess_finding(&original, 1);
        original.detail = r#"{ "nested": {"a":1,"b":2}, "change":"modified" }"#.into();
        assert_eq!(first.dedup_key, assess_finding(&original, 2).dedup_key);
        original.detail = r#"{"change":"modified","nested":{"b":3,"a":1}}"#.into();
        assert_ne!(first.dedup_key, assess_finding(&original, 2).dedup_key);
        original.kind = "integrity".into();
        assert_ne!(first.group_key, assess_finding(&original, 2).group_key);
    }

    #[test]
    fn stale_reviews_fail_closed_and_t2_never_becomes_information() {
        let mut review = assess_finding(
            &network("203.0.113.8:443", "tcp", "unknown", Value::Null),
            1,
        );
        review.policy_version = 0;
        assert_eq!(
            review.clone().read_safe(Tier::Candidate).classification,
            ReviewClassification::Unreviewed
        );
        assert_eq!(
            review.read_safe(Tier::Corroborated).classification,
            ReviewClassification::Actionable
        );
    }
}
