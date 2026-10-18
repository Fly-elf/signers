use std::marker::PhantomData;
use std::path::PathBuf;

use super::execute::execute;
use super::operation::Operation;
use super::runtime::Runtime;
use crate::target::{self, IntoTargets, Shape};

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
    pub(crate) fn run<O>(self, op: O) -> R::Output<S::Out<O::Output>>
    where
        O: Operation + Send + 'static,
    {
        R::drive::<O::Tool, _>(
            async move { execute(&op, &self.targets, self.batch).await.map(S::wrap) },
        )
    }
}
