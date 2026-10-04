//! Sign, re-sign and strip code signatures on macOS, from async Rust.
//!
//! [`Codesign`] runs Apple's `codesign` tool, which ships with macOS. Pick an action with a
//! constructor, chain its options, then `.await` it inside a Tokio runtime:
//!
//! ```no_run
//! # async fn run() -> signers::Result<()> {
//! use signers::Codesign;
//!
//! // Re-sign a binary after patching it: `force` replaces the signature the patch broke.
//! Codesign::sign_adhoc("patched.dylib").force(true).await?;
//!
//! // Sign an app for notarization: hardened runtime and a secure timestamp.
//! Codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
//!     .entitlements("MyApp.entitlements")
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! Where to go next:
//!
//! - [`Codesign`]: the actions, what `.await` checks before running anything, and running one
//!   `codesign` per target of a collection.
//! - [`codesign`]: everything `Codesign` takes and returns. The action types ([`Sign`](codesign::Sign),
//!   [`RemoveSignature`](codesign::RemoveSignature), [`Verify`](codesign::Verify),
//!   [`Display`](codesign::Display), [`ValidateConstraint`](codesign::ValidateConstraint),
//!   [`ExtractCertificates`](codesign::ExtractCertificates),
//!   [`InternalRequirements`](codesign::InternalRequirements)) carry more examples for each action.
//! - [`IntoTargets`]: what you can pass as targets. One path yields one result; a `Vec`, slice
//!   or array yields one per target, in a `Vec` or an array.
//! - [`Error`]: what can fail.

pub mod codesign;
pub mod errors;
mod target;

pub use codesign::Codesign;
pub use errors::{CodesignError, Error, Result};
pub use target::IntoTargets;
