//! ReleaseVerity Repro Engine: source, artifact, provenance, SBOM and reproducibility verification.

pub mod assets;
pub mod checks;
pub mod diff;
pub mod git;
pub mod inspect;
pub mod provenance;
pub mod sbom;
pub mod signature;

use releaseverity_core::check::Check;

/// The Repro Engine's checks in execution order.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(checks::SourceIntegrity),
        Box::new(checks::SourceTag),
        Box::new(checks::ArtifactChecksum),
        Box::new(checks::ArtifactSignature),
        Box::new(checks::Provenance),
        Box::new(checks::Sbom),
        Box::new(checks::Reproducibility),
    ]
}
