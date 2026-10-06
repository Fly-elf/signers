//! Sign, re-sign and strip code signatures on macOS, from async or blocking Rust.
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
//! For code that isn't async, the `blocking` feature adds
#![cfg_attr(feature = "blocking", doc = "[`blocking::Codesign`]")]
#![cfg_attr(not(feature = "blocking"), doc = "`blocking::Codesign`")]
//! with the same actions and options, where `.run()` takes the place of `.await`:
//!
//! ```no_run
//! # fn main() -> signers::Result<()> {
//! use signers::blocking::Codesign;
//!
//! Codesign::sign_adhoc("patched.dylib").force(true).run()?;
//! # Ok(()) }
//! ```
//!
//! The Cargo features pick the API: `async`, on by default, provides [`Codesign`]; `blocking`
//! adds `blocking::Codesign` and turns `async` on too, since `.run()` drives the same async
//! code on a runtime of its own. At least one of them must be enabled.
//!
//! Where to go next:
//!
//! - [`Codesign`]: the actions, what `.await` checks before running anything, and running one
//!   `codesign` per target of a collection. `blocking::Codesign` behaves the same.
//! - [`codesign`]: everything `Codesign` takes and returns. The action types
//!   ([`Sign`](codesign::Sign), [`RemoveSignature`](codesign::RemoveSignature),
//!   [`Verify`](codesign::Verify), [`Display`](codesign::Display),
//!   [`ValidateConstraint`](codesign::ValidateConstraint),
//!   [`ExtractCertificates`](codesign::ExtractCertificates),
//!   [`InternalRequirements`](codesign::InternalRequirements)) carry more examples for each action.
//! - [`IntoTargets`]: what you can pass as targets. One path yields one result; a `Vec`, slice
//!   or array yields one per target, in a `Vec` or an array.
//! - [`Error`]: what can fail.
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(feature = "async"))]
compile_error!("signers needs the `async` or the `blocking` feature");

pub mod codesign;
pub mod errors;
mod target;

pub use errors::{CodesignError, Error, Result};
pub use target::IntoTargets;
