//! Backend that runs Apple's `codesign` tool, so it works on macOS only.
//!
//! `codesign` ships with macOS in `/usr/bin` and is looked up on `PATH` each time an action runs.
//! Start at [`Codesign`].

mod action;
mod actions;
#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "blocking")]
pub mod blocking;
mod runner;
mod types;

pub use action::Action;
pub use actions::{
    Display, ExtractCertificates, InternalRequirements, RemoveSignature, Sign, ValidateConstraint,
    Verify,
};
#[cfg(feature = "async")]
pub use asynchronous::Codesign;
pub use runner::Runner;
pub use types::{
    Authority, CdHash, Certificate, CmsDigest, CodeDirectory, CodeHashes, Constraints,
    ExecutableSegment, Format, HashType, InfoPlist, Location, OsVersion, Platform,
    PreserveMetadata, Requirement, RequirementKind, RequirementsSummary, SealedResources,
    Signature, SignatureKind, SignatureSlot, SigningFlags, Strict, Timestamp,
};
