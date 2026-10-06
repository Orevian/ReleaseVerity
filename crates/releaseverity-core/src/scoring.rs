//! Release score and verdict, computed purely from check results.

use crate::model::{CheckResult, Status, Verdict};

/// Relative weight of a check. Trust-critical checks weigh more.
pub fn weight(check_id: &str) -> u32 {
    match check_id {
        "source.integrity" | "source.tag" | "artifact.checksum" => 15,
        "artifact.signature" | "repro.rebuild" | "install.install" | "runtime.launch" => 12,
        "provenance" | "runtime.smoke" => 10,
        "sbom" | "install.uninstall" => 6,
        _ => 5,
    }
}

/// Checks whose failure fails the release regardless of score.
pub fn is_critical(check_id: &str) -> bool {
    matches!(check_id, "source.integrity" | "source.tag" | "artifact.checksum" | "install.install" | "runtime.launch" | "runtime.smoke")
}

fn factor(s: Status) -> Option<f64> {
    match s {
        Status::Pass => Some(1.0),
        Status::Warn => Some(0.6),
        Status::Fail | Status::Error => Some(0.0),
        Status::Skipped => None,
    }
}

/// Weighted score in 0..=100, or `None` when nothing was scored.
pub fn score(results: &[CheckResult]) -> Option<u8> {
    let (mut got, mut total) = (0.0, 0.0);
    for r in results {
        if let Some(f) = factor(r.status) {
            let w = weight(&r.id) as f64;
            got += w * f;
            total += w;
        }
    }
    if total == 0.0 {
        None
    } else {
        Some((got / total * 100.0).round() as u8)
    }
}

pub fn verdict(results: &[CheckResult]) -> Verdict {
    let scored = results.iter().any(|r| r.status != Status::Skipped);
    if !scored {
        return Verdict::Inconclusive;
    }
    let critical_fail = results.iter().any(|r| r.status == Status::Fail && is_critical(&r.id));
    let any_fail = results.iter().any(|r| r.status == Status::Fail);
    let any_error = results.iter().any(|r| r.status == Status::Error);
    let any_warn = results.iter().any(|r| r.status == Status::Warn);
    let s = score(results).unwrap_or(0);
    // Errors mean "could not measure", not "measured bad": a low score caused only by
    // errors must not read as a failed release.
    if critical_fail || (s < 60 && any_fail) {
        Verdict::Failed
    } else if any_error {
        Verdict::Inconclusive
    } else if any_fail || any_warn {
        Verdict::VerifiedWithWarnings
    } else {
        Verdict::Verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;

    fn r(id: &str, s: Status) -> CheckResult {
        CheckResult::new(id, Category::Trust, s, "")
    }

    #[test]
    fn all_pass_is_verified_100() {
        let v = vec![r("source.integrity", Status::Pass), r("sbom", Status::Pass)];
        assert_eq!(score(&v), Some(100));
        assert_eq!(verdict(&v), Verdict::Verified);
    }

    #[test]
    fn warning_lowers_score_but_verifies() {
        let v = vec![r("source.integrity", Status::Pass), r("sbom", Status::Warn)];
        assert_eq!(score(&v), Some(89));
        assert_eq!(verdict(&v), Verdict::VerifiedWithWarnings);
    }

    #[test]
    fn critical_failure_fails_even_with_high_score() {
        let v = vec![
            r("source.tag", Status::Fail),
            r("sbom", Status::Pass),
            r("provenance", Status::Pass),
            r("artifact.signature", Status::Pass),
            r("runtime.smoke", Status::Pass),
            r("install.uninstall", Status::Pass),
        ];
        assert_eq!(verdict(&v), Verdict::Failed);
    }

    #[test]
    fn all_errors_is_inconclusive_not_failed() {
        let v = vec![r("install.install", Status::Error), r("runtime.launch", Status::Error)];
        assert_eq!(score(&v), Some(0));
        assert_eq!(verdict(&v), Verdict::Inconclusive);
    }

    #[test]
    fn skipped_is_excluded_and_error_is_inconclusive() {
        let v = vec![r("sbom", Status::Skipped), r("provenance", Status::Pass)];
        assert_eq!(score(&v), Some(100));
        let e = vec![r("provenance", Status::Pass), r("sbom", Status::Error)];
        assert_eq!(verdict(&e), Verdict::Inconclusive);
        assert_eq!(verdict(&[r("sbom", Status::Skipped)]), Verdict::Inconclusive);
        assert_eq!(score(&[]), None);
    }
}
