use std::future::{Future, IntoFuture};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::Pin;

use futures_util::StreamExt;

use super::runner::{Async, Runner, collect, command, existence, finish, preflight, spawn_error};
use crate::codesign::Action;
use crate::errors::{CodesignError, Result};
use crate::target::{One, Shape};

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
    preflight(action, targets, per_target)?;
    for target in targets {
        existence(target, tokio::fs::try_exists(target).await)?;
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

    collect(targets, results)
}

/// Runs one `codesign` over `targets` and turns its exit into outputs or an error.
async fn run<A: Action>(action: &A, targets: &[PathBuf]) -> Result<Vec<A::Output>> {
    let child = tokio::process::Command::from(command(action, targets))
        .spawn()
        .map_err(spawn_error)?;
    let output = child.wait_with_output().await.map_err(CodesignError::Run)?;
    finish(action, targets, output)
}
