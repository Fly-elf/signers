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
//! # Logging
//!
//! Every `codesign` run is reported as [`tracing`](https://docs.rs/tracing) events with the target
//! `signers`; the field `program` names the tool (`codesign`). At `debug` level the events say
//! that the tool is being spawned, with its arguments, and that it exited, with its status and
//! the time it took; a run over several targets adds one event with the number of runs and how
//! many go at once. At `trace` level the tool's standard output and error follow. Nothing is
//! emitted at `info` or above, and failures are not logged: they come back as an [`Error`].
//!
//! The crate sets no level cap; what gets recorded is up to the subscriber you install.
//! For example, with `tracing-subscriber` and its `env-filter` feature:
//!
//! ```ignore
//! tracing_subscriber::fmt()
//!     .with_env_filter("warn,signers=debug")
//!     .init();
//! ```
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

#[cfg(not(target_os = "macos"))]
compile_error!("signers currently supports only macOS");

#[cfg(target_os = "macos")]
pub mod codesign;
#[cfg(target_os = "macos")]
mod engine;
#[cfg(target_os = "macos")]
pub mod errors;
#[cfg(target_os = "macos")]
mod target;

#[cfg(target_os = "macos")]
pub use errors::{CodesignError, Error, ProcessError, Result};
#[cfg(target_os = "macos")]
pub use target::IntoTargets;
