//! The blocking [`Codesign`], also at [`signers::blocking`](crate::blocking).

use std::future::IntoFuture;

use super::actions::sign;
use super::asynchronous::Async;
use super::core::Core;
use super::runner::{Runner, Runtime};
use crate::codesign::Action;
use crate::codesign::action::sealed::ToArgs;
use crate::errors::{CodesignError, Result};
use crate::target::{IntoTargets, One, Shape};

// Private so the marker stays unnameable: a `pub(crate)` type in the public alias is a privacy error.
mod marker {
    #[derive(Debug, Clone, Copy)]
    pub struct Blocking;
}

pub(crate) use marker::Blocking;

impl Runtime for Blocking {}

impl<S> Core<S, Blocking>
where
    S: Shape,
{
    pub(super) fn run<O>(self, options: O) -> Result<S::Out<O::Output>>
    where
        O: ToArgs + Send + 'static,
    {
        // A runtime per call costs microseconds against the milliseconds of each `codesign`
        // process, and leaves no global state or threads behind.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(CodesignError::Spawn)?;
        runtime.block_on(self.into_runtime::<Async>().run(options))
    }
}

/// A `codesign` run that blocks the calling thread, started by [`run`](Codesign#method.run).
///
/// The blocking twin of [`signers::Codesign`](crate::Codesign), with the same constructors and
/// setters, listed below, the same output shapes and the same errors. Only the start differs:
/// `.run()` instead of `.await`. The examples on the shared methods use `.await`; here, read it
/// as `.run()`.
///
/// Nothing runs until `.run()`. Until then this is a plain value that you can build over
/// several statements, clone or drop.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> signers::Result<()> {
/// use signers::blocking::Codesign;
/// use signers::codesign::SigningFlags;
///
/// Codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
///     .entitlements("MyApp.entitlements")
///     .options(SigningFlags::RUNTIME | SigningFlags::LIBRARY)
///     .run()?;
/// Codesign::verify("MyApp.app").deep(true).run()?;
/// # Ok(()) }
/// ```
pub type Codesign<A, S = One> = Runner<A, S, Blocking>;

impl<A: Action + Send + 'static, S: Shape> Runner<A, S, Blocking> {
    /// Runs the action, blocking the calling thread until every `codesign` has finished.
    ///
    /// It checks, runs and returns exactly like `.await` on
    /// [`signers::Codesign`](crate::Codesign): the same output shape, the same errors, and the
    /// same concurrent processes with [`per_target`](Codesign#method.per_target). It builds a
    /// single-threaded Tokio runtime for the call and drops it before returning.
    ///
    /// # Errors
    ///
    /// Those listed on [`signers::Codesign`](crate::Codesign#errors). A runtime that can't be
    /// created fails with [`CodesignError::Spawn`].
    ///
    /// # Panics
    ///
    /// Panics when called inside a Tokio runtime, such as from an `async fn` it runs. There,
    /// `.await` [`signers::Codesign`](crate::Codesign) instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> signers::Result<()> {
    /// use signers::blocking::Codesign;
    ///
    /// let [ls, cat] = Codesign::display(["/bin/ls", "/bin/cat"]).run()?;
    /// println!("{} {}", ls.identifier, cat.identifier);
    /// # Ok(()) }
    /// ```
    pub fn run(self) -> Result<S::Out<A::Output>> {
        // A runtime per call costs microseconds against the milliseconds of each `codesign`
        // process, and leaves no global state or threads behind.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(CodesignError::Spawn)?;
        runtime.block_on(self.with_runtime::<Async>().into_future())
    }
}

pub type RemoveSignature<S = One> = super::RemoveSignature<S, Blocking>;

pub fn remove_signature<T: IntoTargets>(target: T) -> RemoveSignature<T::Shape> {
    super::RemoveSignature::new(target, Default::default())
}

pub type ValidateConstraint<S = One> = super::ValidateConstraint<S, Blocking>;

pub fn validate_constraint<T: IntoTargets>(plist: T) -> ValidateConstraint<T::Shape> {
    super::ValidateConstraint::new(plist, Default::default())
}

pub type Requirements<S = One> = super::Requirements<S, Blocking>;

pub fn requirements<T: IntoTargets>(target: T) -> Requirements<T::Shape> {
    super::Requirements::new(target, Default::default())
}

pub type ExtractCertificates<S = One> = super::ExtractCertificates<S, Blocking>;

pub fn extract_certificates<T: IntoTargets>(target: T) -> ExtractCertificates<T::Shape> {
    super::ExtractCertificates::new(target, Default::default())
}

pub type Sign<S = One> = super::Sign<S, Blocking>;

pub fn sign<T: IntoTargets>(target: T, identity: impl Into<String>) -> Sign<T::Shape> {
    super::Sign::new(target, sign::Options::new(identity))
}

pub fn sign_adhoc<T: IntoTargets>(target: T) -> Sign<T::Shape> {
    super::Sign::new(target, sign::Options::adhoc())
}

pub fn sign_for_distribution<T: IntoTargets>(
    target: T,
    identity: impl Into<String>,
) -> Sign<T::Shape> {
    super::Sign::new(target, sign::Options::for_distribution(identity))
}

pub type Verify<S = One> = super::Verify<S, Blocking>;

pub fn verify<T: IntoTargets>(target: T) -> Verify<T::Shape> {
    super::Verify::new(target, Default::default())
}
