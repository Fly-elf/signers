use std::future::IntoFuture;

use super::asynchronous::Async;
use super::runner::{Runner, Runtime};
use crate::codesign::Action;
use crate::errors::{CodesignError, Result};
use crate::target::{One, Shape};

// Private so the marker stays unnameable: a `pub(crate)` type in the public alias is a privacy error.
mod marker {
    #[derive(Debug, Clone, Copy)]
    pub struct Blocking;
}

use marker::Blocking;

impl Runtime for Blocking {}

pub type Codesign<A, S = One> = Runner<A, S, Blocking>;

impl<A: Action + Send + 'static, S: Shape> Runner<A, S, Blocking> {
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
