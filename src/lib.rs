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
//! Outside async code, [`blocking::Codesign`] has the same actions and options, and `.run()`
//! takes the place of `.await`:
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
//! adds [`blocking::Codesign`] and turns `async` on too, since `.run()` drives the same async
//! code on a runtime of its own. At least one of them must be enabled.
//!
//! Where to go next:
//!
//! - [`Codesign`]: the actions, what `.await` checks before running anything, and running one
//!   `codesign` per target of a collection. [`blocking::Codesign`] behaves the same.
//! - [`codesign`]: everything `Codesign` takes and returns. The action types
//!   ([`Sign`](codesign::Sign), [`RemoveSignature`](codesign::RemoveSignature),
//!   [`Verify`](codesign::Verify), [`Display`](codesign::Display),
//!   [`ValidateConstraint`](codesign::ValidateConstraint),
//!   [`ExtractCertificates`](codesign::ExtractCertificates),
//!   [`InternalRequirements`](codesign::InternalRequirements)) carry more examples for each action.
//! - [`IntoTargets`]: what you can pass as targets. One path yields one result; a `Vec`, slice
//!   or array yields one per target, in a `Vec` or an array.
//! - [`Error`]: what can fail.
//!
#![cfg_attr(
    feature = "blocking",
    doc = "[`blocking::Codesign`]: blocking::Codesign"
)]
#![cfg_attr(
    not(feature = "blocking"),
    doc = "[`blocking::Codesign`]: https://docs.rs/signers/latest/signers/blocking/type.Codesign.html"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(feature = "async"))]
compile_error!("signers needs the `async` or the `blocking` feature");

pub mod codesign;
pub mod errors;
mod target;

#[cfg(feature = "async")]
pub use codesign::Codesign;
/// The blocking API: the same actions, run with `.run()` on the calling thread.
///
/// Each `.run()` starts a single-threaded Tokio runtime of its own and drops it before
/// returning, so the caller needs no runtime. Inside one it panics: async code uses
/// [`signers::Codesign`](crate::Codesign) instead.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> signers::Result<()> {
/// use signers::blocking::Codesign;
///
/// Codesign::sign_adhoc(vec!["mytool", "libfoo.dylib"]).force(true).run()?;
/// let signature = Codesign::display("mytool").run()?;
/// println!("{}", signature.identifier);
/// # Ok(()) }
/// ```
#[cfg(feature = "blocking")]
pub mod blocking {
    pub use crate::codesign::blocking::Codesign;
}

pub use errors::{CodesignError, Error, Result};
pub use target::IntoTargets;
