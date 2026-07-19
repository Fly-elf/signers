//! Ergonomic, hard-to-misuse Rust API for macOS code signing.
//!
//! Signing actions are built with a fluent [`codesign::Codesign`] builder and
//! executed by `.await`ing them:
//!
//! ```no_run
//! # async fn run() -> Result<(), signers::Error> {
//! use signers::codesign::Codesign;
//!
//! Codesign::sign("MyApp.app").force(true).identity("-").await?;
//! # Ok(()) }
//! ```

pub mod codesign;
pub mod errors;
pub mod target;

pub use errors::{Error, Result};
pub use target::IntoTargets;
