//! Backend that runs Apple's `codesign` tool, so it works on macOS only.
//!
//! `codesign` ships with macOS in `/usr/bin` and is looked up on `PATH` each time an action runs.
//! Start at [`Codesign`].

mod actions;
pub mod remove_signature;
pub mod sign;

use std::future::{Future, IntoFuture};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use remove_signature::RemoveSignature;
use sign::Sign;

use crate::errors::{CodesignError, Error, Result};
use crate::target::IntoTargets;

pub use actions::Action;

/// A `codesign` run: an action and its targets, started by `.await`.
///
/// A constructor on `Codesign<()>` picks the action and takes what it can't run without. The
/// setters for that action's options follow. `A` is the action type, so each builder offers
/// only the options `codesign` honours for its action: a `Codesign<RemoveSignature>` has no
/// signing options to misuse.
///
/// Nothing runs until `.await`. Until then this is a plain value that you can build over several
/// statements, clone or drop. To run several at once, spawn
/// [`into_future`](Codesign::into_future): the future is `Send + 'static`.
///
/// # Examples
///
/// Build the run over several statements:
///
/// ```no_run
/// # async fn run(hardened: bool) -> signers::Result<()> {
/// use signers::Codesign;
/// use signers::codesign::sign::SigningFlags;
///
/// let mut signing = Codesign::sign_adhoc("mytool").identifier("com.example.mytool");
/// if hardened {
///     signing = signing.options(SigningFlags::RUNTIME);
/// }
/// signing.await?;
/// # Ok(()) }
/// ```
///
/// Sign several files concurrently, each with its own `codesign` process:
///
/// ```no_run
/// # async fn run(paths: Vec<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
/// use std::future::IntoFuture;
///
/// use signers::Codesign;
///
/// let runs: Vec<_> = paths
///     .into_iter()
///     .map(|path| tokio::spawn(Codesign::sign_adhoc(path).force(true).into_future()))
///     .collect();
/// for run in runs {
///     run.await??;
/// }
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// `.await` stops at the first failure. Before starting `codesign` it checks:
///
/// 1. that the options can be honoured, e.g. [`Error::FileListToStdout`];
/// 2. that there is a target at all, else [`Error::NoTargets`];
/// 3. that every target exists, else [`Error::TargetNotFound`] or [`Error::TargetAccess`].
///
/// So far no target has been touched. Then `codesign` runs once for all targets, and its failures
/// come as [`Error::Codesign`]. It stops at the first target it rejects: the targets before that
/// one have already been changed, the ones after it haven't.
///
/// # Panics
///
/// `.await` panics outside a Tokio runtime, and in one built without I/O
/// ([`enable_io`](https://docs.rs/tokio/1/tokio/runtime/struct.Builder.html#method.enable_io)).
/// `#[tokio::main]` enables I/O.
#[derive(Debug, Clone)]
pub struct Codesign<A> {
    targets: Vec<PathBuf>,
    action: A,
}

/// Constructors, one per action.
impl Codesign<()> {
    /// Signs `target` with the identity that `identity` names (`--sign`).
    ///
    /// `identity` is `-` for an ad hoc signature (see [`sign_adhoc`](Codesign::sign_adhoc)).
    /// Otherwise it selects a certificate, with its private key, from the keychain search list:
    ///
    /// - the name of an identity preference;
    /// - part of the certificate's common name, matching only one certificate (an exact match
    ///   wins), case-sensitive;
    /// - the certificate's SHA-1 hash, as 40 hex digits.
    ///
    /// Signing an already signed target fails with "is already signed" unless you set
    /// [`force`](Codesign::force). A signature added by the linker doesn't need `force`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::sign("MyApp.app", "Apple Development: Jane Doe (A1B2C3D4E5)")
    ///     .force(true)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn sign(target: impl IntoTargets, identity: impl Into<String>) -> Codesign<Sign> {
        Codesign {
            targets: target.into_targets(),
            action: Sign::new(identity),
        }
    }

    /// Signs `target` ad hoc, with no certificate (`--sign -`).
    ///
    /// An ad hoc signature names no signer. That suits local use, including re-signing patched
    /// binaries, but not distribution. It never gets a timestamp.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// // The patch broke the old signature; `force` replaces it.
    /// Codesign::sign_adhoc("patched.dylib").force(true).await?;
    /// # Ok(()) }
    /// ```
    pub fn sign_adhoc(target: impl IntoTargets) -> Codesign<Sign> {
        Codesign {
            targets: target.into_targets(),
            action: Sign::adhoc(),
        }
    }

    /// Signs `target` for notarization: hardened runtime and timestamp
    /// (`--options runtime --timestamp`).
    ///
    /// This is [`sign`](Codesign::sign) with `.options(SigningFlags::RUNTIME)` and
    /// `.timestamp(Timestamp::Enabled)` already set. Later setters override both.
    /// [`options`](Codesign::options) replaces the whole set, so keep `RUNTIME` in it.
    ///
    /// `.await` fetches the timestamp from Apple's server, so without network access the signing
    /// fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    /// use signers::codesign::sign::SigningFlags;
    ///
    /// Codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    ///     .entitlements("MyApp.entitlements")
    ///     .options(SigningFlags::RUNTIME | SigningFlags::LIBRARY)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn sign_for_distribution(
        target: impl IntoTargets,
        identity: impl Into<String>,
    ) -> Codesign<Sign> {
        Codesign {
            targets: target.into_targets(),
            action: Sign::for_distribution(identity),
        }
    }

    /// Removes the signature from `target` (`--remove-signature`).
    ///
    /// On a bundle, `codesign` removes the main executable's signature and the resource seal. It
    /// leaves nested code signed and an empty `_CodeSignature` directory behind. It accepts
    /// unsigned targets, and files that aren't code, without changing them.
    ///
    /// You don't need to remove a signature before re-signing: [`sign`](Codesign::sign) with
    /// [`force`](Codesign::force) replaces it in one step.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::remove_signature(vec!["mytool", "libfoo.dylib"]).await?;
    /// # Ok(()) }
    /// ```
    pub fn remove_signature(target: impl IntoTargets) -> Codesign<RemoveSignature> {
        Codesign {
            targets: target.into_targets(),
            action: RemoveSignature::default(),
        }
    }
}

/// Runs the action when awaited. See [`Codesign`] for its errors and panics.
impl<A: Action + Send + 'static> IntoFuture for Codesign<A> {
    type Output = Result<()>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    /// Returns the future that runs the action. Nothing happens until it's polled.
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
