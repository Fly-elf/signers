//! Sign, re-sign and strip code signatures on macOS, from async or blocking Rust.
//!
//! [`codesign`] runs Apple's `codesign` tool, which ships with macOS. Call the function of an
//! action, chain its options, then `.await` it inside a Tokio runtime:
//!
//! ```no_run
//! # async fn run() -> signers::Result<()> {
//! use signers::codesign;
//!
//! // Re-sign a binary after patching it: `force` replaces the signature the patch broke.
//! codesign::sign_adhoc("patched.dylib").force(true).await?;
//!
//! // Sign an app for notarization: hardened runtime and a secure timestamp.
//! codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
//!     .entitlements("MyApp.entitlements")
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! For code that isn't async, the `blocking` feature adds
#![cfg_attr(feature = "blocking", doc = "[`codesign::blocking`]")]
#![cfg_attr(not(feature = "blocking"), doc = "`codesign::blocking`")]
//! with the same functions and options, where `.run()` takes the place of `.await`:
//!
//! ```no_run
//! # fn main() -> signers::Result<()> {
//! use signers::codesign::blocking;
//!
//! blocking::sign_adhoc("patched.dylib").force(true).run()?;
//! # Ok(()) }
//! ```
//!
//! The Cargo features pick the API: `async`, on by default, provides the functions of
//! [`codesign`]; `blocking` adds `codesign::blocking` and turns `async` on too, since `.run()`
//! drives the same async code on a runtime of its own. At least one of them must be enabled.
//!
//! Where to go next:
//!
//! - [`codesign`]: the actions, what `.await` checks before running anything, and running one
//!   `codesign` per target of a collection. Each action's builder type
//!   ([`Sign`](codesign::Sign), [`Verify`](codesign::Verify), [`Display`](codesign::Display),
//!   [`RemoveSignature`](codesign::RemoveSignature),
//!   [`ValidateConstraint`](codesign::ValidateConstraint),
//!   [`Requirements`](codesign::Requirements),
//!   [`ExtractCertificates`](codesign::ExtractCertificates)) lists its options.
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
