//! Verdict policy: the single place that turns observations into a tier.
//!
//! Pure. No I/O, no clock, no database. If this function is wrong, everything
//! downstream is wrong, so it stays small enough to read in one sitting.

use crate::model::{Confidence, Detector, DetectorResult, Tier};

/// Classify a set of detector results for one artifact.
///
/// Rules, in order:
/// - no results                      -> T0 observed
/// - an AV signature match           -> T2 (a named signature is strong on its own)
/// - two independent detectors agree -> T2 (corroboration)
/// - one high-confidence result      -> T2 (rule author asserted confidence)
/// - anything else                   -> T1 candidate
///
/// T3 is never produced here. Confirmation requires re-scanning the stored
/// object and getting the same verdict; see [`escalate_if_confirmed`].
pub fn classify(results: &[DetectorResult]) -> Tier {
    if results.is_empty() {
        return Tier::Observed;
    }

    if results.iter().any(|r| r.detector == Detector::ClamAv) {
        return Tier::Corroborated;
    }

    let independent = distinct_detectors(results);
    if independent >= 2 {
        return Tier::Corroborated;
    }

    if results.iter().any(|r| r.confidence >= Confidence::High) {
        return Tier::Corroborated;
    }

    Tier::Candidate
}

/// Count how many different detectors reported, ignoring duplicates from one.
pub fn distinct_detectors(results: &[DetectorResult]) -> usize {
    let mut seen: Vec<Detector> = Vec::new();
    for r in results {
        if !seen.contains(&r.detector) {
            seen.push(r.detector);
        }
    }
    seen.len()
}

/// Promote a corroborated verdict to confirmed after a clean re-scan of the
/// quarantined object produced the same classification.
pub fn escalate_if_confirmed(tier: Tier, rescanned: Tier) -> Tier {
    if tier >= Tier::Corroborated && rescanned >= Tier::Corroborated {
        Tier::Confirmed
    } else {
        tier
    }
}

/// Human-readable reason stored on the quarantine record.
pub fn reason(results: &[DetectorResult], tier: Tier) -> String {
    let names: Vec<String> = results
        .iter()
        .filter_map(|r| {
            r.signature
                .as_ref()
                .map(|s| format!("{}:{}", r.detector.as_str(), s))
        })
        .collect();
    if names.is_empty() {
        format!("{} (no named signature)", tier.label())
    } else {
        format!("{} via {}", tier.label(), names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(d: Detector, c: Confidence) -> DetectorResult {
        DetectorResult::new(d, "sig", c)
    }

    #[test]
    fn empty_is_observed() {
        assert_eq!(classify(&[]), Tier::Observed);
    }

    #[test]
    fn single_weak_is_candidate() {
        assert_eq!(
            classify(&[r(Detector::Yara, Confidence::Low)]),
            Tier::Candidate
        );
    }

    #[test]
    fn single_high_is_corroborated() {
        assert_eq!(
            classify(&[r(Detector::Yara, Confidence::High)]),
            Tier::Corroborated
        );
    }

    #[test]
    fn two_detectors_corroborate() {
        let set = [
            r(Detector::Yara, Confidence::Low),
            r(Detector::HashRep, Confidence::Low),
        ];
        assert_eq!(classify(&set), Tier::Corroborated);
    }

    #[test]
    fn same_detector_twice_does_not_corroborate() {
        let set = [
            r(Detector::Yara, Confidence::Low),
            r(Detector::Yara, Confidence::Low),
        ];
        assert_eq!(classify(&set), Tier::Candidate);
    }

    #[test]
    fn av_signature_is_corroborated() {
        assert_eq!(
            classify(&[r(Detector::ClamAv, Confidence::Low)]),
            Tier::Corroborated
        );
    }

    #[test]
    fn confirmation_requires_agreement() {
        assert_eq!(
            escalate_if_confirmed(Tier::Corroborated, Tier::Corroborated),
            Tier::Confirmed
        );
        assert_eq!(
            escalate_if_confirmed(Tier::Candidate, Tier::Corroborated),
            Tier::Candidate
        );
    }

    #[test]
    fn quarantine_gate() {
        assert!(!Tier::Candidate.may_quarantine());
        assert!(Tier::Corroborated.may_quarantine());
    }
}
