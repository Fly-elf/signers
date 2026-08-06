//! Signing through the macOS `codesign` binary.
//!
//! This backend spawns `codesign` as a subprocess, so it runs on macOS only and
//! needs the Xcode Command Line Tools installed — without them every action
//! fails with [`CodesignError::NotFound`], which names the fix.
//!
//! # Building an invocation
//!
//! [`Codesign`] *is* the invocation, put together in three steps:
//!
//! 1. **Pick the action.** A constructor — [`Codesign::sign`] and, in time, its
//!    siblings — takes the targets plus whatever that action cannot run
//!    without, and hands back a builder specific to it.
//! 2. **Configure it.** One setter per `codesign` option, each returning the
//!    builder so they chain. Which setters exist follows from the action, so a
//!    builder never offers an option its action doesn't support.
//! 3. **Run it.** `.await` is what spawns `codesign`; everything before it only
//!    fills in a value.
//!
//! ```no_run
//! # async fn run() -> Result<(), signers::Error> {
//! use signers::codesign::Codesign;
//!
//! Codesign::sign("MyApp.app", "-") // 1. the action, and what it runs on
//!     .force(true)                 // 2. its options
//!     .await?;                     // 3. the run
//! # Ok(()) }
//! ```
//!
//! # Actions
//!
//! An action is a type holding the options that action was configured with:
//! [`Sign`] for [`Codesign::sign`]. You never build one yourself, but its page
//! is where that action's options are documented and where the worked examples
//! live.

mod actions;

use std::future::{Future, IntoFuture};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use crate::errors::{CodesignError, Error, Result};
use crate::target::IntoTargets;

pub use actions::{Action, PreserveMetadata, Sign, SigningFlags, Timestamp};

/// A `codesign` invocation: an action, the options it will run with, and the
/// targets it will run on.
///
/// `A` is the action, and it's what makes a builder specific.
/// [`Codesign::sign`] returns a `Codesign<Sign>`, whose setters are `codesign`'s
/// signing options and nothing else — an option some *other* action takes isn't
/// rejected at runtime, it isn't there to call.
///
/// This page holds both halves of the API:
///
/// - **Constructors**, on `Codesign<()>` — one per action, each naming its
///   targets and whatever that action cannot run without. For now
///   [`sign`](Codesign::sign).
/// - **Options**, one `impl` block per action — one setter per `codesign` flag,
///   taking `self` and returning it so they chain.
///
/// The action types are where those options are documented in context, with the
/// examples that show them working together: [`Sign`].
///
/// Nothing happens before the `.await`, which yields `Result<(), Error>` — see
/// [`Error`] for what can go wrong on the way. Until then this is an ordinary
/// value: build it across several statements, clone it, drop it unrun.
#[derive(Debug, Clone)]
pub struct Codesign<A> {
    targets: Vec<PathBuf>,
    action: A,
}

impl Codesign<()> {
    /// Signs `target` with `identity` (`codesign --sign`).
    ///
    /// `target` is anything [`IntoTargets`] accepts: a path, or a collection of
    /// them to sign as one batch. `identity` picks the signing certificate — a
    /// keychain identity name, an identity preference, a 40-digit certificate
    /// SHA-1 hash, or `-` for an ad-hoc signature.
    ///
    /// Every option starts at `codesign`'s own default, so re-signing something
    /// that's already signed needs [`force`](Codesign::force), just like on the
    /// command line. See [`Sign`] for the rest of them, and for examples.
    pub fn sign(target: impl IntoTargets, identity: impl Into<String>) -> Codesign<Sign> {
        Codesign {
            targets: target.into_targets(),
            action: Sign::new(identity),
        }
    }
}

/// Runs the action: checks the options, checks every target exists, then spawns
/// `codesign` and waits for it. The future is `Send + 'static`, so it can be
/// `tokio::spawn`ed as-is.
impl<A: Action + Send + 'static> IntoFuture for Codesign<A> {
    type Output = Result<()>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            self.action.validate()?;

            if self.targets.is_empty() {
                return Err(Error::NoTargets);
            }
            for target in &self.targets {
                match tokio::fs::try_exists(target).await {
                    Ok(true) => {}
                    Ok(false) => return Err(Error::TargetNotFound(target.clone())),
                    Err(source) => {
                        return Err(Error::TargetAccess {
                            path: target.clone(),
                            source,
                        });
                    }
                }
            }

            let args = self.action.to_args(&self.targets);
            tracing::trace!(
                "running codesign {}",
                args.iter()
                    .map(|a| a.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            );

            // Spawning and waiting are kept apart so that a failure to *start*
            // `codesign` is never reported as one of its results. That means
            // configuring the streams by hand, which `Command::output` would
            // otherwise do: no inherited stdin for `codesign` to block on, and
            // both of its streams captured rather than leaking into the
            // caller's terminal.
            let child = tokio::process::Command::new("codesign")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|source| match source.kind() {
                    ErrorKind::NotFound => CodesignError::NotFound,
                    _ => CodesignError::Spawn(source),
                })?;

            let output = child.wait_with_output().await.map_err(CodesignError::Run)?;
            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(Error::Codesign(match output.status.code() {
                Some(code) => CodesignError::Failed { code, stderr },
                // No exit code at all: the process was killed before it could
                // exit, so this is not `codesign` rejecting anything.
                None => CodesignError::Terminated {
                    status: output.status,
                    stderr,
                },
            }))
        })
    }
}
