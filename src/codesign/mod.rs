//! Backend that runs Apple's `codesign` tool, so it works on macOS only.
//!
//! Each action is a function that takes the targets and returns a builder: chain the action's
//! options, then `.await` it inside a Tokio runtime. `codesign` ships with macOS in `/usr/bin` and
//! is looked up on `PATH` each time an action runs.
//!
//! ```no_run
//! # async fn run() -> signers::Result<()> {
//! use signers::codesign;
//!
//! codesign::sign_adhoc("patched.dylib").force(true).await?;
//! let [ls, cat] = codesign::display(["/bin/ls", "/bin/cat"]).await?;
//! println!("{} {}", ls.identifier, cat.identifier);
//! # Ok(()) }
//! ```
//!
//! For code that isn't async,
#![cfg_attr(feature = "blocking", doc = "[`blocking`]")]
#![cfg_attr(not(feature = "blocking"), doc = "`blocking`")]
//! has the same functions, where `.run()` takes the place of `.await`. It needs the `blocking`
//! feature.
//!
//! Nothing runs until `.await`. Until then a builder is a plain value that you can build over
//! several statements, clone or drop. The future it turns into is `Send + 'static`, so you can
//! spawn it.
//!
//! ```no_run
//! # async fn run(hardened: bool) -> signers::Result<()> {
//! use signers::codesign::{self, SigningFlags};
//!
//! let mut signing = codesign::sign_adhoc("mytool").identifier("com.example.mytool");
//! if hardened {
//!     signing = signing.options(SigningFlags::RUNTIME);
//! }
//! signing.await?;
//! # Ok(()) }
//! ```
//!
//! What `.await` yields follows the targets (see [`IntoTargets`](crate::IntoTargets)): the
//! action's output for a single path, a `Vec` of outputs for a `Vec` or slice, an array of them
//! for an array. The builders' type parameters stand for that shape and for how the run starts.
//! They are internal, so name a builder as `codesign::Sign<_>` and let type inference fill them
//! in. They can't be imported:
//!
//! ```compile_fail,E0603
//! use signers::target::One;
//! ```
//!
//! # Errors
//!
//! `.await` stops at the first failure. Before starting `codesign` it checks, in this order:
//!
//! 1. that the options can be honoured, else e.g. [`Error::StdioPath`](crate::Error::StdioPath),
//!    or [`Error::Io`](crate::Error::Io) if [`extract_certificates`] can't use the system's
//!    temporary directory;
//! 2. with `per_target(true)`, that no option writes one shared file, else
//!    [`Error::SharedOutputPerTarget`](crate::Error::SharedOutputPerTarget);
//! 3. that there is a target at all, else [`Error::NoTargets`](crate::Error::NoTargets);
//! 4. that no target is an empty path, else [`Error::EmptyTarget`](crate::Error::EmptyTarget);
//! 5. that every target exists, else [`Error::TargetNotFound`](crate::Error::TargetNotFound) or
//!    [`Error::TargetAccess`](crate::Error::TargetAccess).
//!
//! So far no target has been touched. Then `codesign` runs:
//!
//! - once over all the targets, for a single target and by default for the actions that change
//!   them ([`sign`] and its presets, [`remove_signature`]). Its failure comes as
//!   [`Error::Codesign`](crate::Error::Codesign). It stops at the first target it rejects: the
//!   targets before that one have already been changed, the ones after it haven't.
//! - once per target, with [`per_target(true)`](Sign::per_target), which is the default for the
//!   actions that only read them. Every target runs, and the failures come together as
//!   [`Error::Batch`](crate::Error::Batch). If `codesign` can't start at all
//!   ([`CodesignError::NotFound`](crate::CodesignError::NotFound),
//!   [`CodesignError::Spawn`](crate::CodesignError::Spawn)), that error comes alone instead.
//!
//! # Panics
//!
//! `.await` panics outside a Tokio runtime, and in one built without I/O
//! ([`enable_io`](https://docs.rs/tokio/1/tokio/runtime/struct.Builder.html#method.enable_io)).
//! `#[tokio::main]` enables I/O.

mod action;
mod actions;
#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "blocking")]
pub mod blocking;
mod core;
mod types;

pub use actions::{
    Display, ExtractCertificates, RemoveSignature, Requirements, Sign, ValidateConstraint, Verify,
};
#[cfg(feature = "async")]
pub use asynchronous::{
    display, extract_certificates, remove_signature, requirements, sign, sign_adhoc,
    sign_for_distribution, validate_constraint, verify,
};
pub use types::{
    Authority, CdHash, Certificate, CmsDigest, CodeDirectory, CodeHashes, Constraints,
    ExecutableSegment, Format, HashType, InfoPlist, Location, OsVersion, Platform,
    PreserveMetadata, Requirement, RequirementKind, RequirementsSummary, SealedResources,
    Signature, SignatureKind, SignatureSlot, SigningFlags, Strict, Timestamp,
};
