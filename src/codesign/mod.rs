//! Signing through the macOS `codesign` binary.
//!
//! This backend spawns `codesign` as a subprocess, so it runs on macOS only and
//! needs the Xcode Command Line Tools installed — without them every action
//! fails with [`CodesignError::NotFound`](crate::errors::CodesignError::NotFound),
//! which names the fix.
//!
//! Everything starts at [`Codesign::sign`].

mod actions;

use std::future::{Future, IntoFuture};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use crate::errors::{CodesignError, Error, Result};
use crate::target::IntoTargets;

pub use actions::{Action, PreserveMetadata, Sign, SigningFlags, Timestamp};

/// A `codesign` action, and the options it will run with.
///
/// You get one from a constructor ([`Codesign::sign`]), configure it by
/// chaining setters, and run it by `.await`ing it. The action type is what
/// decides which setters exist, so a builder only ever offers options its
/// action actually supports.
///
/// Nothing happens before the `.await`. Until then it's an ordinary value you
/// can keep building, clone, or drop:
///
/// ```no_run
/// # async fn run(hardened: bool) -> Result<(), signers::Error> {
/// use signers::codesign::{Codesign, SigningFlags};
///
/// let mut signing = Codesign::sign("MyApp.app", "-").force(true);
/// if hardened {
///     signing = signing.options(SigningFlags::RUNTIME);
/// }
/// signing.await?;
/// # Ok(()) }
/// ```
///
/// Awaiting gives back `Result<(), Error>`; see [`Error`] for what can go
/// wrong on the way.
#[derive(Debug, Clone)]
pub struct Codesign<A> {
    targets: Vec<PathBuf>,
    action: A,
}

impl Codesign<()> {
    /// Signs `target` with `identity`.
    ///
    /// `target` is anything [`IntoTargets`] accepts: a path, or a collection of
    /// them to sign as one batch. `identity` picks the signing certificate — a
    /// keychain identity name, an identity preference, a 40-digit certificate
    /// SHA-1 hash, or `-` for an ad-hoc signature.
    ///
    /// Every option starts at `codesign`'s own default, so re-signing something
    /// that's already signed needs [`force`](Codesign::force), just like on the
    /// command line.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// use signers::codesign::Codesign;
    ///
    /// Codesign::sign("MyApp.app", "-").force(true).await?;
    /// # Ok(()) }
    /// ```
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
