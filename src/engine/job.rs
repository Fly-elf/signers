//! The state every action builder carries: its targets, and whether to run per target.

use std::marker::PhantomData;
use std::path::PathBuf;

use super::execute::execute;
use super::operation::Operation;
use super::runtime::Runtime;
use crate::target::{self, IntoTargets, Shape};

/// The targets of an action and how they are run, over target shape `S` and runtime `R`.
///
/// `S` fixes what a run yields; `R` how it is driven.
#[derive(Debug, Clone)]
pub struct Job<S, R> {
    pub(crate) targets: Vec<PathBuf>,
    pub(crate) batch: bool,
    marker: PhantomData<fn() -> (S, R)>,
}

impl<S, R> Job<S, R>
where
    S: Shape,
{
    /// Starts with the operation's batching default, except for a single target, which runs once.
    pub(crate) fn new<O, T>(target: T) -> Self
    where
        O: Operation,
        T: IntoTargets<Shape = S>,
    {
        Self {
            targets: target.into_targets(),
            batch: O::BATCH && !<S as target::sealed::Shape>::SINGLE,
            marker: PhantomData,
        }
    }
}

impl<S, R> Job<S, R>
where
    S: Shape,
    R: Runtime,
{
    /// Runs `op` over the targets and wraps the outputs in the shape `S`.
    pub(crate) fn run<O>(self, op: O) -> R::Output<S::Out<O::Output>>
    where
        O: Operation + Send + 'static,
    {
        R::drive::<O::Tool, _>(
            async move { execute(&op, &self.targets, self.batch).await.map(S::wrap) },
        )
    }
}

#[cfg(test)]
#[path = "unit_tests/job.rs"]
mod tests;
