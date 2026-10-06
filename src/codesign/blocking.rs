//! The blocking [`Codesign`], also at [`signers::blocking`](crate::blocking).

use super::actions::sign;
use super::asynchronous::Async;
use super::core::Core;
use crate::codesign::action::sealed::ToArgs;
use crate::errors::{CodesignError, Result};
use crate::target::{IntoTargets, One, Shape};

// Private so the marker stays unnameable: a `pub(crate)` type in the public alias is a privacy error.
mod marker {
    #[derive(Debug, Clone, Copy)]
    pub struct Blocking;
}

pub(crate) use marker::Blocking;

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

pub type Display<S = One> = super::Display<S, Blocking>;

pub fn display<T: IntoTargets>(target: T) -> Display<T::Shape> {
    super::Display::new(target, Default::default())
}
