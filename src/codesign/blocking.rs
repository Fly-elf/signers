//! The actions of [`codesign`](super), run by blocking the calling thread.
//!
//! Each function here takes the same arguments as its async twin and returns a builder with the
//! same options, the same output shapes and the same errors. Only the start differs: `.run()`
//! instead of `.await`. The examples in [`codesign`](super) use `.await`; here, read it as
//! `.run()`.
//!
//! `.run()` builds a single-threaded Tokio runtime for the call and drops it before returning, so
//! it needs no runtime of yours and leaves no threads behind. It panics inside a Tokio runtime:
//! async code uses the functions of [`codesign`](super) instead.
//!
//! The option and output types of [`codesign`](super) are re-exported here too, so this module
//! can stand in for it under the same name:
//!
//! ```no_run
//! # fn main() -> signers::Result<()> {
//! use signers::codesign::blocking as codesign;
//!
//! codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
//!     .entitlements("MyApp.entitlements")
//!     .options(codesign::SigningFlags::RUNTIME | codesign::SigningFlags::LIBRARY)
//!     .run()?;
//! codesign::verify("MyApp.app").deep(true).run()?;
//! # Ok(()) }
//! ```

use super::actions::sign;
use super::asynchronous::Async;
use super::core::Core;
use crate::codesign::action::sealed::ToArgs;
use crate::errors::{CodesignError, Result};
use crate::target::{IntoTargets, One, Shape};

// Private so the marker stays unnameable: a `pub(crate)` type in the public alias is a privacy error.
mod marker {
    #[derive(Debug, Clone, Copy)]
    pub struct Blocking;
}

pub(crate) use marker::Blocking;

#[doc(no_inline)]
pub use super::{
    Authority, CdHash, Certificate, CmsDigest, CodeDirectory, CodeHashes, Constraints,
    ExecutableSegment, Format, HashType, InfoPlist, Location, OsVersion, Platform,
    PreserveMetadata, Requirement, RequirementKind, RequirementsSummary, SealedResources,
    Signature, SignatureKind, SignatureSlot, SigningFlags, Strict, Timestamp,
};

impl<S> Core<S, Blocking>
where
    S: Shape,
{
    pub(super) fn run<O>(self, options: O) -> Result<S::Out<O::Output>>
    where
        O: ToArgs + Send + 'static,
    {
        // A runtime per call costs microseconds against the milliseconds of each `codesign`
        // process, and leaves no global state or threads behind.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(CodesignError::Spawn)?;
        runtime.block_on(self.into_runtime::<Async>().run(options))
    }
}

/// A blocking [`RemoveSignature`](super::RemoveSignature), started by `.run()`.
pub type RemoveSignature<S = One> = super::RemoveSignature<S, Blocking>;

/// Removes the signature from `target` (`--remove-signature`).
///
/// Blocking form of [`codesign::remove_signature`](super::remove_signature), which has the details.
pub fn remove_signature<T: IntoTargets>(target: T) -> RemoveSignature<T::Shape> {
    super::RemoveSignature::new(target, Default::default())
}

/// A blocking [`ValidateConstraint`](super::ValidateConstraint), started by `.run()`.
pub type ValidateConstraint<S = One> = super::ValidateConstraint<S, Blocking>;

/// Checks that each plist is a valid launch or library constraint (`--validate-constraint`).
///
/// Blocking form of [`codesign::validate_constraint`](super::validate_constraint), which
/// has the details.
pub fn validate_constraint<T: IntoTargets>(plist: T) -> ValidateConstraint<T::Shape> {
    super::ValidateConstraint::new(plist, Default::default())
}

/// A blocking [`Requirements`](super::Requirements), started by `.run()`.
pub type Requirements<S = One> = super::Requirements<S, Blocking>;

/// Reads the requirements of the signature of `target` (`--display -r-`).
///
/// Blocking form of [`codesign::requirements`](super::requirements), which has the details.
pub fn requirements<T: IntoTargets>(target: T) -> Requirements<T::Shape> {
    super::Requirements::new(target, Default::default())
}

/// A blocking [`ExtractCertificates`](super::ExtractCertificates), started by `.run()`.
pub type ExtractCertificates<S = One> = super::ExtractCertificates<S, Blocking>;

/// Reads the certificate chain that signed `target`, leaf first (`--extract-certificates`).
///
/// Blocking form of [`codesign::extract_certificates`](super::extract_certificates), which
/// has the details.
pub fn extract_certificates<T: IntoTargets>(target: T) -> ExtractCertificates<T::Shape> {
    super::ExtractCertificates::new(target, Default::default())
}

/// A blocking [`Sign`](super::Sign), started by `.run()`.
pub type Sign<S = One> = super::Sign<S, Blocking>;

/// Signs `target` with the identity that `identity` names (`--sign`).
///
/// Blocking form of [`codesign::sign`](super::sign), which has the details.
pub fn sign<T: IntoTargets>(target: T, identity: impl Into<String>) -> Sign<T::Shape> {
    super::Sign::new(target, sign::Options::new(identity))
}

/// Signs `target` ad hoc, with no certificate (`--sign -`).
///
/// Blocking form of [`codesign::sign_adhoc`](super::sign_adhoc), which has the details.
pub fn sign_adhoc<T: IntoTargets>(target: T) -> Sign<T::Shape> {
    super::Sign::new(target, sign::Options::adhoc())
}

/// Signs `target` for notarization: hardened runtime and timestamp
/// (`--options runtime --timestamp`).
///
/// Blocking form of [`codesign::sign_for_distribution`](super::sign_for_distribution), which
/// has the details.
pub fn sign_for_distribution<T: IntoTargets>(
    target: T,
    identity: impl Into<String>,
) -> Sign<T::Shape> {
    super::Sign::new(target, sign::Options::for_distribution(identity))
}

/// A blocking [`Verify`](super::Verify), started by `.run()`.
pub type Verify<S = One> = super::Verify<S, Blocking>;

/// Checks the signature of `target` (`--verify`), changing nothing.
///
/// Blocking form of [`codesign::verify`](super::verify), which has the details.
pub fn verify<T: IntoTargets>(target: T) -> Verify<T::Shape> {
    super::Verify::new(target, Default::default())
}

/// A blocking [`Display`](super::Display), started by `.run()`.
pub type Display<S = One> = super::Display<S, Blocking>;

/// Reads the signature of `target` (`--display`), changing nothing.
///
/// Blocking form of [`codesign::display`](super::display), which has the details.
pub fn display<T: IntoTargets>(target: T) -> Display<T::Shape> {
    super::Display::new(target, Default::default())
}
