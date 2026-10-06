use std::marker::PhantomData;
use std::path::PathBuf;

use crate::codesign::action::sealed::ToArgs;
use crate::target::{self, IntoTargets, Shape};

#[derive(Debug, Clone)]
pub struct Core<S, R> {
    pub(super) targets: Vec<PathBuf>,
    pub(super) per_target: bool,
    marker: PhantomData<fn() -> (S, R)>,
}

impl<S: Shape, R> Core<S, R> {
    pub(super) fn new<O: ToArgs, T: IntoTargets<Shape = S>>(target: T) -> Self {
        Self {
            targets: target.into_targets(),
            per_target: O::PER_TARGET && !<S as target::sealed::Shape>::SINGLE,
            marker: PhantomData,
        }
    }
}

#[cfg(feature = "blocking")]
impl<S, R> Core<S, R> {
    pub(super) fn into_runtime<R2>(self) -> Core<S, R2> {
        Core {
            targets: self.targets,
            per_target: self.per_target,
            marker: PhantomData,
        }
    }
}
