//! Manage macOS binary code-signing with a simple builder API.
//! Built on top of two backends:
//!
//! |                | [`codesign`]                                                                          | `rcodesign`                     |
//! |----------------|----------------------------------------------------------------------------------------|----------------------------------|
//! | Platforms      | macOS only                                                                            | macOS, Linux, Windows            |
//! | Requires       | Xcode Command Line Tools                                                              | nothing extra                    |
//! | Implementation | subprocess — the macOS [`codesign`](https://keith.github.io/xcode-man-pages/codesign.1.html) binary | native — the [`apple-codesign`](https://crates.io/crates/apple-codesign) crate |
//!
//! > 🚧 **Early development.** Signing and removing signatures work through [`codesign`];
//! > `rcodesign`, verifying, and the blocking API are still on the way.
//!
//! - `async` first, with an optional `blocking` API
//! - Multiplatform with no external dependency, via `rcodesign`
//! - Each backend exposes a common subset of actions (`sign`, `verify`, ...)
//! - Each action is configurable through its own builder options
//! - Every backend also exposes its own specific actions and options
//! - Every action needs at least one target (see [`IntoTargets`])
//!
//! # Codesign
//!
//! Wraps the macOS `codesign` utility one-to-one.
//! See the [`codesign`] module for the full list of actions and options.
//!
//! ```no_run
//! # async fn run() -> Result<(), signers::Error> {
//! # use signers::Codesign;
//! // Ad-hoc signature, replacing whatever was there before.
//! Codesign::sign(vec!["MyApp.app", "MyLib.dylib"], "-")
//!     .force(true)
//!     .await?;
//! # Ok(()) }
//! ```
//! ```no_run
//! # async fn run() -> Result<(), signers::Error> {
//! # use signers::Codesign;
//! # use signers::codesign::sign::{SigningFlags, Timestamp};
//! // Signing for distribution.
//! Codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
//!     .entitlements("MyApp.entitlements")
//!     .options(SigningFlags::RUNTIME) // the hardened runtime, needed to notarize
//!     .timestamp(Timestamp::Enabled)
//!     .force(true)
//!     .await?;
//! # Ok(()) }
//! ```
//! ```no_run
//! # async fn run() -> Result<(), signers::Error> {
//! # use signers::Codesign;
//! // Strip a signature, e.g. before patching the Mach-O it no longer matches.
//! Codesign::remove_signature("MyApp.app").await?;
//! # Ok(()) }
//! ```
//!
//! # Rcodesign
//!
//! Exposes the `apple-codesign` crate with an API in the same style as `codesign`'s.
//!
//! > 🚧 Not implemented yet — once it lands, the `rcodesign` module
//! > will document its own actions and options the same way.
//!

pub mod codesign;
pub mod errors;
pub mod target;

pub use codesign::Codesign;
pub use errors::{CodesignError, Error, Result};
pub use target::IntoTargets;
