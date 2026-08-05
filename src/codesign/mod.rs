//! Async signing API backed by the macOS `codesign` binary (subprocess).

mod actions;

use std::future::{Future, IntoFuture};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use crate::errors::{Error, Result};
use crate::target::IntoTargets;

pub use actions::{Action, PreserveMetadata, Sign, SigningFlags, Timestamp};

/// Fluent builder over a signing action, parameterized by the action type.
///
/// Create one with a constructor ([`Codesign::sign`], ...), chain the options
/// that action supports, then `.await` it to run `codesign`.
///
/// Every action fails with an [`Error`], which separates a target this crate
/// rejects before running anything from what `codesign` itself reported. Watch
/// for [`Error::CodesignNotFound`] in particular: it means the Xcode Command
/// Line Tools are missing, the one failure the native backend cannot have.
#[derive(Debug, Clone)]
pub struct Codesign<A> {
    targets: Vec<PathBuf>,
    action: A,
}

impl Codesign<()> {
    /// Signs one or more targets with `codesign`, using `identity`.
    ///
    /// `identity` is a keychain identity name, an identity preference, a
    /// 40-digit certificate SHA-1 hash, or `-` for ad-hoc signing. Every option
    /// keeps `codesign`'s own default, so re-signing a patched binary in place
    /// needs [`force`](Codesign::force) just like on the command line.
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
                    ErrorKind::NotFound => Error::CodesignNotFound,
                    _ => Error::Spawn(source),
                })?;

            let output = child.wait_with_output().await.map_err(Error::Run)?;
            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(match output.status.code() {
                Some(code) => Error::Codesign { code, stderr },
                // No exit code at all: the process was killed before it could
                // exit, so this is not `codesign` rejecting anything.
                None => Error::Terminated {
                    status: output.status,
                    stderr,
                },
            })
        })
    }
}
