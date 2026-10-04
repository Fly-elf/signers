//! Backend that runs Apple's `codesign` tool, so it works on macOS only.
//!
//! `codesign` ships with macOS in `/usr/bin` and is looked up on `PATH` each time an action runs.
//! Start at [`Codesign`].

mod actions;
pub mod display;
pub mod extract_certificates;
pub mod remove_signature;
pub mod sign;
pub mod verify;

use std::future::{Future, IntoFuture};
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use display::Display;
use extract_certificates::ExtractCertificates;
use futures_util::StreamExt;
use remove_signature::RemoveSignature;
use sign::Sign;
use verify::Verify;

use crate::errors::{CodesignError, Error, Result};
use crate::target::{IntoTargets, Multi, One, Shape, sealed};

pub use actions::Action;
pub use actions::SignatureSlot;

/// A `codesign` run: an action and its targets, started by `.await`.
///
/// A constructor on `Codesign<()>` picks the action and takes what it can't run without. The
/// setters for that action's options follow. `A` is the action type, so each builder offers
/// only the options `codesign` honours for its action: a `Codesign<RemoveSignature>` has no
/// signing options to misuse.
///
/// `S` is the shape of the targets, fixed by their type (see [`IntoTargets`]): `.await` yields
/// one [`Output`](Action) for a single path, a `Vec` of them for a `Vec` or slice, an array of
/// them for an array. For [`sign`](Codesign::sign), [`remove_signature`](Codesign::remove_signature)
/// and [`verify`](Codesign::verify) the output is `()`; for [`display`](Codesign::display) it is
/// a [`Signature`](display::Signature); for
/// [`extract_certificates`](Codesign::extract_certificates) it is a `Vec` of
/// [`Certificate`](extract_certificates::Certificate).
///
/// In the signatures, `S`, its default `One` and `S::Out` stand for that shape. They are
/// internal, so let type inference fill them in; `Codesign<Sign>` is the builder for a single
/// target. They can't be imported:
///
/// ```compile_fail,E0603
/// use signers::target::One;
/// ```
///
/// Nothing runs until `.await`. Until then this is a plain value that you can build over several
/// statements, clone or drop. The future from [`into_future`](Codesign::into_future) is
/// `Send + 'static`, so you can spawn it.
///
/// `codesign` runs once over all the targets, unless [`per_target`](Codesign::per_target) runs it
/// once per target. That is the default for [`verify`](Codesign::verify) and
/// [`display`](Codesign::display) on a collection.
/// [`extract_certificates`](Codesign::extract_certificates) always runs one per target.
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
/// # Errors
///
/// `.await` stops at the first failure. Before starting `codesign` it checks, in this order:
///
/// 1. that the options can be honoured, else e.g. [`Error::FileListToStdout`], or
///    [`Error::Io`] if [`extract_certificates`](Codesign::extract_certificates) can't use the
///    system's temporary directory;
/// 2. with `per_target(true)`, that no option writes one shared file, else
///    [`Error::SharedOutputPerTarget`];
/// 3. that there is a target at all, else [`Error::NoTargets`];
/// 4. that no target is an empty path, else [`Error::EmptyTarget`];
/// 5. that every target exists, else [`Error::TargetNotFound`] or [`Error::TargetAccess`].
///
/// So far no target has been touched. Then `codesign` runs:
///
/// - once over all the targets, by default (except for [`verify`](Codesign::verify) and
///   [`display`](Codesign::display)) and always
///   for a single target. Its failure comes as [`Error::Codesign`]. It stops at the first target
///   it rejects: the targets before that one have already been changed, the ones after it
///   haven't.
/// - once per target, with `per_target(true)`, which is the default for
///   [`verify`](Codesign::verify) and [`display`](Codesign::display). Every target runs, and the
///   failures come together as [`Error::Batch`]. If `codesign` can't start at all
///   ([`CodesignError::NotFound`], [`CodesignError::Spawn`]), that error comes alone instead.
///
/// # Panics
///
/// `.await` panics outside a Tokio runtime, and in one built without I/O
/// ([`enable_io`](https://docs.rs/tokio/1/tokio/runtime/struct.Builder.html#method.enable_io)).
/// `#[tokio::main]` enables I/O.
#[derive(Debug, Clone)]
pub struct Codesign<A, S = One> {
    targets: Vec<PathBuf>,
    action: A,
    per_target: bool,
    shape: PhantomData<fn() -> S>,
}

fn new<A: Action, T: IntoTargets>(target: T, action: A) -> Codesign<A, T::Shape> {
    Codesign {
        targets: target.into_targets(),
        action,
        per_target: A::PER_TARGET && !<T::Shape as sealed::Shape>::SINGLE,
        shape: PhantomData,
    }
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
    pub fn sign<T: IntoTargets>(
        target: T,
        identity: impl Into<String>,
    ) -> Codesign<Sign, T::Shape> {
        new(target, Sign::new(identity))
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
    pub fn sign_adhoc<T: IntoTargets>(target: T) -> Codesign<Sign, T::Shape> {
        new(target, Sign::adhoc())
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
    pub fn sign_for_distribution<T: IntoTargets>(
        target: T,
        identity: impl Into<String>,
    ) -> Codesign<Sign, T::Shape> {
        new(target, Sign::for_distribution(identity))
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
    pub fn remove_signature<T: IntoTargets>(target: T) -> Codesign<RemoveSignature, T::Shape> {
        new(target, RemoveSignature::default())
    }

    /// Checks the signature of `target` (`--verify`), changing nothing.
    ///
    /// `.await` yields `()` per target when every one verifies. Without options it checks that
    /// the signature is intact and covers the code. Whether the system would run the code is a
    /// different question: verified code can still be refused by Gatekeeper.
    ///
    /// Given several targets, each is verified on its own by default, so one `.await` reports
    /// every target that failed, as [`Error::Batch`]. [`per_target(false)`](Codesign::per_target)
    /// runs one `codesign` instead, which stops at the first target it rejects.
    ///
    /// # Errors
    ///
    /// A target that doesn't verify fails with [`CodesignError::VerificationFailed`]: the
    /// signature is invalid or modified, the target is unsigned, or the requirement text doesn't
    /// compile. A valid signature that doesn't meet a requirement fails with
    /// [`CodesignError::RequirementUnsatisfied`]. The checks made before `codesign` starts are
    /// on [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::verify("MyApp.app").deep(true).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Tell a broken signature from a requirement that isn't met:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::{Codesign, CodesignError, Error};
    ///
    /// match Codesign::verify("mytool").test_requirement("anchor apple").await {
    ///     Ok(()) => println!("signed by Apple"),
    ///     Err(Error::Codesign(CodesignError::RequirementUnsatisfied { .. })) => {
    ///         println!("validly signed, but not by Apple");
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    pub fn verify<T: IntoTargets>(target: T) -> Codesign<Verify, T::Shape> {
        new(target, Verify::default())
    }

    /// Reads the signature of `target` as a [`Signature`](display::Signature) (`--display`),
    /// changing nothing.
    ///
    /// `.await` yields one [`Signature`](display::Signature) per target: identifier, signing
    /// flags, hashes, the certificate chain, entitlements and more.
    /// [`Signature::raw`](display::Signature::raw) and
    /// [`Signature::field`](display::Signature::field) reach whatever the typed fields don't.
    ///
    /// Given several targets, each is read on its own by default, so one `.await` reports every
    /// target that failed, as [`Error::Batch`]. The signatures of the targets that did read are
    /// dropped with it. [`per_target(false)`](Codesign::per_target) runs one `codesign` instead:
    /// it stops at the first target it rejects, and the entitlements of every target stay
    /// [`None`](display::Signature#structfield.entitlements).
    ///
    /// # Errors
    ///
    /// An unsigned target fails with [`CodesignError::Failed`], exit code 1. With one `codesign`
    /// over several targets, its `stderr` also holds the reports of the targets before the unsigned
    /// one. A report or entitlements that can't be read fails with
    /// [`CodesignError::UnexpectedOutput`]. The checks made before `codesign` starts are on
    /// [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    /// use signers::codesign::display::SignatureKind;
    ///
    /// let signature = Codesign::display("MyApp.app").await?;
    /// if signature.signature == SignatureKind::AdHoc {
    ///     println!("{} is signed ad hoc", signature.identifier);
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Read the entitlements of a binary:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let signature = Codesign::display("mytool").await?;
    /// let debuggable = signature
    ///     .entitlements
    ///     .as_ref()
    ///     .and_then(|entitlements| entitlements.get("com.apple.security.get-task-allow"))
    ///     .and_then(|value| value.as_boolean())
    ///     .unwrap_or(false);
    /// # let _ = debuggable;
    /// # Ok(()) }
    /// ```
    ///
    /// Read two binaries at once:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let [ls, cat] = Codesign::display(["/bin/ls", "/bin/cat"]).await?;
    /// println!("{} {}", ls.cd_hash, cat.cd_hash);
    /// # Ok(()) }
    /// ```
    pub fn display<T: IntoTargets>(target: T) -> Codesign<Display, T::Shape> {
        new(target, Display::default())
    }

    /// Reads the certificate chain that signed `target`, leaf first (`--extract-certificates`).
    ///
    /// `.await` yields one `Vec` of [`Certificate`](extract_certificates::Certificate) per target,
    /// the signing certificate first and the root last. A target signed ad hoc has none, so its
    /// `Vec` is empty. [`save_to`](Codesign::save_to) also writes the chains to PEM files.
    ///
    /// Given several targets, each is read on its own, concurrently, and every one that failed is
    /// reported together as [`Error::Batch`]. One `codesign` over several targets would write
    /// every chain to the same files, so this action always runs one per target and has no
    /// [`per_target`](Codesign::per_target) setter:
    ///
    /// ```compile_fail,E0599
    /// signers::Codesign::extract_certificates(vec!["a"]).per_target(false);
    /// ```
    ///
    /// # Errors
    ///
    /// An unsigned target fails with [`CodesignError::Failed`], exit code 1. A file that can't be
    /// read or written fails with [`Error::Io`], also when the system's temporary directory can't
    /// be used. The checks made before `codesign` starts are on [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let chains = Codesign::extract_certificates(vec!["A.app", "B.app"]).await?;
    /// for chain in &chains {
    ///     println!("{} certificates", chain.len());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn extract_certificates<T: IntoTargets>(
        target: T,
    ) -> Codesign<ExtractCertificates, T::Shape> {
        new(target, ExtractCertificates::default())
    }
}

/// Options for a `Vec`, slice or array of targets.
impl<A: Action + actions::sealed::SharedRun, S: Multi> Codesign<A, S> {
    /// Runs one `codesign` per target, concurrently, instead of one for all of them.
    ///
    /// One process stops at the first target it rejects and reports that one only. Per target,
    /// every target runs, and the failures come together as [`Error::Batch`], in input order. At
    /// most [`available_parallelism`](std::thread::available_parallelism) processes run at a
    /// time. The default is `false` for [`sign`](Codesign::sign) and
    /// [`remove_signature`](Codesign::remove_signature), which change the targets in order, and
    /// `true` for [`verify`](Codesign::verify) and [`display`](Codesign::display), which only
    /// read them.
    ///
    /// Only a `Vec`, slice or array of targets has this setter, even with one element: that is
    /// the `S: Multi` bound. A single target always runs one `codesign`:
    ///
    /// ```compile_fail,E0599
    /// signers::Codesign::sign("a", "-").per_target(true);
    /// ```
    ///
    /// [`extract_certificates`](Codesign::extract_certificates) has no such setter either: it
    /// always runs one `codesign` per target.
    ///
    /// An option that writes one shared file, [`file_list`](Codesign::file_list) or
    /// [`detached`](Codesign::detached), makes `.await` fail with
    /// [`Error::SharedOutputPerTarget`].
    ///
    /// <div class="warning">
    ///
    /// The runs overlap in no fixed order. A bundle in the same batch as the code nested in it
    /// can be sealed before that code is signed, which leaves the bundle's signature invalid.
    /// Sign the nested code in an earlier run.
    ///
    /// </div>
    ///
    /// # Examples
    ///
    /// Sign each library on its own, and report every one that failed:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::{Codesign, Error};
    ///
    /// let libraries = vec!["liba.dylib", "libb.dylib", "libc.dylib"];
    /// match Codesign::sign_adhoc(libraries).force(true).per_target(true).await {
    ///     Ok(_) => {}
    ///     Err(Error::Batch(failures)) => {
    ///         for (path, error) in &failures {
    ///             eprintln!("{}: {error}", path.display());
    ///         }
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    pub fn per_target(mut self, per_target: bool) -> Self {
        self.per_target = per_target;
        self
    }
}

/// Runs the action when awaited. See [`Codesign`] for its errors and panics.
impl<A: Action + Send + 'static, S: Shape> IntoFuture for Codesign<A, S> {
    type Output = Result<S::Out<A::Output>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    /// Returns the future that runs the action. Nothing happens until it's polled.
    ///
    /// Once every `codesign` run has exited 0, it resolves to one [`Output`](Action) per target,
    /// shaped like the targets: `S::Out<A::Output>` is `A::Output` for a single path,
    /// `Vec<A::Output>` for a `Vec` or slice, `[A::Output; N]` for an array of `N`.
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            execute(&self.action, &self.targets, self.per_target)
                .await
                .map(S::wrap)
        })
    }
}

/// Checks the options and targets, then runs `codesign` once over all targets or once per target.
async fn execute<A: Action>(
    action: &A,
    targets: &[PathBuf],
    per_target: bool,
) -> Result<Vec<A::Output>> {
    action.validate()?;
    if per_target && let Some(option) = action.shared_output() {
        return Err(Error::SharedOutputPerTarget(option));
    }

    if targets.is_empty() {
        return Err(Error::NoTargets);
    }
    if let Some(index) = targets.iter().position(|t| t.as_os_str().is_empty()) {
        return Err(Error::EmptyTarget(index));
    }
    for target in targets {
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

    // One run over all targets, and its error stays plain.
    if !per_target {
        return run(action, targets).await;
    }

    let cap = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    // The runs are built before they are buffered: mapping the stream
    // itself doesn't compile inside a `Send` boxed future (higher-ranked
    // lifetime limitation).
    let runs: Vec<_> = targets
        .iter()
        .map(|target| run(action, std::slice::from_ref(target)))
        .collect();
    let results: Vec<Result<Vec<A::Output>>> = futures_util::stream::iter(runs)
        .buffered(cap)
        .collect()
        .await;

    let mut outputs = Vec::with_capacity(targets.len());
    let mut failures = Vec::new();
    for (target, result) in targets.iter().zip(results) {
        match result {
            Ok(output) => outputs.extend(output),
            // `codesign` itself couldn't start: that isn't about this target.
            Err(error @ Error::Codesign(CodesignError::NotFound | CodesignError::Spawn(_))) => {
                return Err(error);
            }
            Err(error) => failures.push((target.clone(), error)),
        }
    }
    if failures.is_empty() {
        Ok(outputs)
    } else {
        Err(Error::Batch(failures))
    }
}

/// Runs one `codesign` over `targets` and turns its exit into outputs or an error.
async fn run<A: Action>(action: &A, targets: &[PathBuf]) -> Result<Vec<A::Output>> {
    let args = action.to_args(targets);
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
        let outputs = action.output_bytes(targets, output.stdout, output.stderr)?;
        if outputs.len() != targets.len() {
            return Err(CodesignError::UnexpectedOutput {
                detail: format!("{} outputs for {} targets", outputs.len(), targets.len()),
            }
            .into());
        }
        return Ok(outputs);
    }

    Err(match output.status.code() {
        Some(code) => action.failure_bytes(code, output.stdout, output.stderr),
        // No exit code at all: the process was killed before it could
        // exit, so this is not `codesign` rejecting anything.
        None => CodesignError::Terminated {
            status: output.status,
            stdout: actions::decode(output.stdout),
            stderr: actions::decode(output.stderr),
        }
        .into(),
    })
}

/// The runner's side of its contract with an action, which no shipped action
/// can show from outside: both yield `()`, keep the default `failure` and
/// always return one output per target.
///
/// A stand-in action fills the gap. It runs the real `codesign`, read-only,
/// so these need macOS like the integration suite does.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::Path;

    use super::actions::sealed::ToArgs;
    use super::*;

    /// Displays its targets, yielding the `Executable=<path>` line `codesign`
    /// prints for each, and answers the runner's hooks as told.
    #[derive(Debug, Clone, Default)]
    struct Probe {
        invalid: bool,
        shared_output: Option<&'static str>,
        drop_last_output: bool,
        unreadable: bool,
        file_list: bool,
    }

    impl super::actions::sealed::SharedRun for Probe {}

    impl ToArgs for Probe {
        type Output = String;
        const PER_TARGET: bool = true;

        fn validate(&self) -> Result<()> {
            if self.invalid {
                Err(Error::StdioPath("probe"))
            } else {
                Ok(())
            }
        }

        fn shared_output(&self) -> Option<&'static str> {
            self.shared_output
        }

        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
            let list: &[&str] = if self.file_list {
                &["--file-list", "-"]
            } else {
                &[]
            };
            ["--display"]
                .into_iter()
                .chain(list.iter().copied())
                .chain(["--"])
                .map(OsStr::new)
                .chain(targets.iter().map(|target| target.as_os_str()))
                .map(Cow::Borrowed)
                .collect()
        }

        fn output(
            &self,
            _targets: &[PathBuf],
            _stdout: String,
            stderr: String,
        ) -> Result<Vec<String>> {
            if self.unreadable {
                return Err(Error::StdioPath("probe"));
            }
            let mut outputs: Vec<String> = stderr.lines().map(str::to_owned).collect();
            if self.drop_last_output {
                outputs.pop();
            }
            Ok(outputs)
        }

        fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
            CodesignError::UnexpectedOutput {
                detail: format!("probe saw exit {code} with stdout {stdout:?}: {stderr}"),
            }
            .into()
        }
    }

    /// Signed binaries every macOS install has, so displaying them succeeds.
    const SIGNED: [&str; 3] = ["/bin/ls", "/bin/cat", "/bin/echo"];
    const REPORTS: [&str; 3] = [
        "Executable=/bin/ls",
        "Executable=/bin/cat",
        "Executable=/bin/echo",
    ];

    /// A directory holding `names` as text files, which `codesign` refuses to
    /// display: there is no signature on them to report.
    fn unsigned(names: &[&str]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().expect("could not create a temporary directory");
        let paths = names
            .iter()
            .map(|name| {
                let path = dir.path().join(name);
                std::fs::write(&path, "not code\n").expect("could not write a target");
                path
            })
            .collect();
        (dir, paths)
    }

    fn unexpected_output(error: Error) -> String {
        match error {
            Error::Codesign(CodesignError::UnexpectedOutput { detail }) => detail,
            other => panic!("expected UnexpectedOutput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn outputs_follow_the_targets_in_order_and_in_shape() {
        let one: String = new(SIGNED[1], Probe::default()).await.unwrap();
        assert_eq!(one, REPORTS[1]);

        for per_target in [true, false] {
            let many: Vec<String> = new(SIGNED.to_vec(), Probe::default())
                .per_target(per_target)
                .await
                .unwrap();
            let array: [String; 3] = new(SIGNED, Probe::default())
                .per_target(per_target)
                .await
                .unwrap();

            assert_eq!(many, REPORTS, "per_target({per_target})");
            assert_eq!(array, REPORTS, "per_target({per_target})");
        }
    }

    #[tokio::test]
    async fn an_action_starts_from_its_own_per_target_default() {
        let (_dir, unsigned) = unsigned(&["notes.txt"]);
        let batch = vec![PathBuf::from(SIGNED[0]), unsigned[0].clone()];

        let builder = new(batch, Probe::default());
        assert!(builder.per_target);

        // One process per target without being asked: the failure is collected.
        let error = builder.await.unwrap_err();
        assert!(
            matches!(&error, Error::Batch(failures) if failures.len() == 1 && failures[0].0 == unsigned[0]),
            "got {error:?}",
        );
    }

    #[tokio::test]
    async fn a_failed_run_hands_the_hook_both_streams_trimmed() {
        let (_dir, unsigned) = unsigned(&["a.txt"]);
        let batch = vec![PathBuf::from(SIGNED[0]), unsigned[0].clone()];
        let probe = Probe {
            file_list: true,
            ..Probe::default()
        };

        let error = new(batch, probe).per_target(false).await.unwrap_err();

        assert_eq!(
            unexpected_output(error),
            format!(
                "probe saw exit 1 with stdout \"{0}\": Executable={0}\n{1}: code object is not signed at all",
                SIGNED[0],
                unsigned[0].display()
            )
        );
    }

    #[tokio::test]
    async fn a_failed_run_becomes_whatever_the_action_makes_of_it() {
        let (_dir, unsigned) = unsigned(&["a.txt", "b.txt"]);
        let expected = |path: &PathBuf| {
            format!(
                "probe saw exit 1 with stdout \"\": {}: code object is not signed at all",
                path.display()
            )
        };

        let error = new(&unsigned[0], Probe::default()).await.unwrap_err();
        assert_eq!(unexpected_output(error), expected(&unsigned[0]));

        // A one-element collection keeps the setter and, per target, collects.
        let error = new(vec![unsigned[0].clone()], Probe::default())
            .await
            .unwrap_err();
        let Error::Batch(failures) = error else {
            panic!("expected Batch, got {error:?}");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, unsigned[0]);

        let error = new(vec![unsigned[0].clone()], Probe::default())
            .per_target(false)
            .await
            .unwrap_err();
        assert_eq!(unexpected_output(error), expected(&unsigned[0]));

        // `codesign` stops at the first target it refuses, so one process for
        // both has only the first to complain about.
        let error = new(unsigned.clone(), Probe::default())
            .per_target(false)
            .await
            .unwrap_err();
        assert_eq!(unexpected_output(error), expected(&unsigned[0]));

        let error = new(unsigned.clone(), Probe::default()).await.unwrap_err();
        let Error::Batch(failures) = error else {
            panic!("expected Batch, got {error:?}");
        };
        let failures: Vec<(PathBuf, String)> = failures
            .into_iter()
            .map(|(path, error)| (path, unexpected_output(error)))
            .collect();
        assert_eq!(
            failures,
            [
                (unsigned[0].clone(), expected(&unsigned[0])),
                (unsigned[1].clone(), expected(&unsigned[1])),
            ]
        );
    }

    #[tokio::test]
    async fn an_output_count_other_than_the_target_count_is_unexpected_output() {
        let short = Probe {
            drop_last_output: true,
            ..Probe::default()
        };

        let one_process = new(SIGNED.to_vec(), short.clone())
            .per_target(false)
            .await
            .unwrap_err();
        let detail = unexpected_output(one_process);
        assert!(
            detail.contains('2') && detail.contains('3'),
            "the detail does not name both counts: {detail}"
        );

        let single = new(SIGNED[0], short.clone()).await.unwrap_err();
        let detail = unexpected_output(single);
        assert!(
            detail.contains('0') && detail.contains('1'),
            "the detail does not name both counts: {detail}"
        );

        // Per target, the mismatch is that target's failure like any other.
        let per_target = new(SIGNED, short).await.unwrap_err();
        let Error::Batch(failures) = per_target else {
            panic!("expected Batch, got {per_target:?}");
        };
        let failed: Vec<PathBuf> = failures
            .into_iter()
            .map(|(path, error)| {
                unexpected_output(error);
                path
            })
            .collect();
        assert_eq!(failed, SIGNED.map(PathBuf::from));
    }

    /// What `codesign` printed on a successful exit is the action's to read,
    /// and so is the verdict that it cannot be read.
    #[tokio::test]
    async fn an_error_from_the_output_hook_fails_the_run() {
        let unreadable = Probe {
            unreadable: true,
            ..Probe::default()
        };

        let single = new(SIGNED[0], unreadable.clone()).await.unwrap_err();
        assert!(
            matches!(single, Error::StdioPath("probe")),
            "got {single:?}"
        );

        let one_process = new(SIGNED.to_vec(), unreadable.clone())
            .per_target(false)
            .await
            .unwrap_err();
        assert!(
            matches!(one_process, Error::StdioPath("probe")),
            "got {one_process:?}"
        );

        let per_target = new(SIGNED.to_vec(), unreadable).await.unwrap_err();
        let Error::Batch(failures) = per_target else {
            panic!("expected Batch, got {per_target:?}");
        };
        let failed: Vec<PathBuf> = failures
            .into_iter()
            .map(|(path, error)| {
                assert!(matches!(error, Error::StdioPath("probe")), "got {error:?}");
                path
            })
            .collect();
        assert_eq!(failed, SIGNED.map(PathBuf::from));
    }

    #[tokio::test]
    async fn a_shared_output_is_refused_per_target_for_any_action() {
        let sharing = Probe {
            shared_output: Some("probe_file"),
            ..Probe::default()
        };

        let refused = new(SIGNED.to_vec(), sharing.clone()).await.unwrap_err();
        assert!(
            matches!(refused, Error::SharedOutputPerTarget("probe_file")),
            "got {refused:?}"
        );

        let refused = new(SIGNED, sharing.clone()).await.unwrap_err();
        assert!(
            matches!(refused, Error::SharedOutputPerTarget("probe_file")),
            "got {refused:?}"
        );

        let allowed = new(SIGNED.to_vec(), sharing.clone())
            .per_target(false)
            .await;
        assert_eq!(allowed.unwrap(), REPORTS);

        // `validate` still comes first.
        let invalid = Probe {
            invalid: true,
            ..sharing
        };
        let error = new(SIGNED.to_vec(), invalid).await.unwrap_err();
        assert!(matches!(error, Error::StdioPath("probe")), "got {error:?}");
    }

    /// One target is one process, so there is no second process to
    /// share an output with, even for an action that defaults to per target.
    #[tokio::test]
    async fn a_shared_output_is_not_refused_for_a_single_target() {
        let sharing = Probe {
            shared_output: Some("probe_file"),
            ..Probe::default()
        };

        let report = new(SIGNED[0], sharing.clone()).await.unwrap();
        assert_eq!(report, REPORTS[0]);

        let invalid = Probe {
            invalid: true,
            ..sharing
        };
        let error = new(SIGNED[0], invalid).await.unwrap_err();
        assert!(matches!(error, Error::StdioPath("probe")), "got {error:?}");
    }

    /// `A::PER_TARGET` is true for the probe, yet a single target never
    /// starts per target; the other shapes do.
    #[test]
    fn the_constructor_default_is_false_for_a_single_target_whatever_the_action() {
        const { assert!(Probe::PER_TARGET) };

        assert!(!new("a", Probe::default()).per_target);
        assert!(!new(String::from("a"), Probe::default()).per_target);
        assert!(!new(Path::new("a"), Probe::default()).per_target);
        assert!(!new(PathBuf::from("a"), Probe::default()).per_target);

        assert!(new(vec!["a"], Probe::default()).per_target);
        assert!(new(vec!["a", "b"], Probe::default()).per_target);
        assert!(new(&["a", "b"][..], Probe::default()).per_target);
        assert!(new(["a"], Probe::default()).per_target);
        assert!(new(["a", "b"], Probe::default()).per_target);
    }

    /// The setter is typed on the shape, not on the length.
    #[test]
    fn a_one_element_collection_keeps_the_per_target_setter() {
        let from_vec = new(vec!["a"], Probe::default()).per_target(false);
        assert!(!from_vec.per_target);
        let from_array = new(["a"], Probe::default()).per_target(false);
        assert!(!from_array.per_target);

        assert!(
            new(vec!["a"], Probe::default())
                .per_target(false)
                .per_target(true)
                .per_target
        );
    }
}
