use std::future::{Future, IntoFuture};
use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;

use futures_util::StreamExt;

use super::runner::{Runner, Runtime};
use crate::codesign::Action;
use crate::codesign::action;
use crate::errors::{CodesignError, Error, Result};
use crate::target::{One, Shape};

#[derive(Debug, Clone, Copy)]
pub struct Async;

impl Runtime for Async {}

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
/// a [`Signature`]; for
/// [`extract_certificates`](Codesign::extract_certificates) it is a `Vec` of
/// [`Certificate`]; for
/// [`internal_requirements`](Codesign::internal_requirements) it is a `Vec` of
/// [`Requirement`].
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
/// [`extract_certificates`](Codesign::extract_certificates) and
/// [`internal_requirements`](Codesign::internal_requirements) always run one per target.
///
/// # Examples
///
/// Build the run over several statements:
///
/// ```no_run
/// # async fn run(hardened: bool) -> signers::Result<()> {
/// use signers::Codesign;
/// use signers::codesign::SigningFlags;
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
/// 1. that the options can be honoured, else e.g. [`Error::StdioPath`], or
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
pub type Codesign<A, S = One> = Runner<A, S, Async>;

/// Runs the action when awaited. See [`Codesign`] for its errors and panics.
impl<A: Action + Send + 'static, S: Shape> IntoFuture for Runner<A, S, Async> {
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
            stdout: action::decode(output.stdout),
            stderr: action::decode(output.stderr),
        }
        .into(),
    })
}
