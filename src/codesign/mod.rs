//! Backend that runs Apple's `codesign` tool, so it works on macOS only.
//!
//! `codesign` ships with macOS in `/usr/bin` and is looked up on `PATH` each time an action runs.
//! Start at [`Codesign`], or at
#![cfg_attr(feature = "blocking", doc = "[`blocking::Codesign`]")]
#![cfg_attr(not(feature = "blocking"), doc = "`blocking::Codesign`")]
//! for the blocking API, from the `blocking` feature.

mod action;
mod actions;
#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "blocking")]
pub mod blocking;
mod core;
mod runner;
mod types;

pub use action::Action;
pub use actions::{
    Display, ExtractCertificates, RemoveSignature, Requirements, Sign, ValidateConstraint, Verify,
};
#[cfg(feature = "async")]
pub use asynchronous::{
    Codesign, extract_certificates, remove_signature, requirements, validate_constraint,
};
pub use runner::Runner;
pub use types::{
    Authority, CdHash, Certificate, CmsDigest, CodeDirectory, CodeHashes, Constraints,
    ExecutableSegment, Format, HashType, InfoPlist, Location, OsVersion, Platform,
    PreserveMetadata, Requirement, RequirementKind, RequirementsSummary, SealedResources,
    Signature, SignatureKind, SignatureSlot, SigningFlags, Strict, Timestamp,
};
