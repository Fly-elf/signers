//! How a run is driven: as a boxed future (async) or to completion on the calling thread
//! (blocking).

use std::future::Future;
use std::pin::Pin;

use super::tool::Tool;
#[cfg(feature = "blocking")]
use crate::errors::ProcessError;
use crate::errors::Result;

/// The future an async run turns into.
pub type RunFuture<V> = Pin<Box<dyn Future<Output = Result<V>> + Send>>;

/// Drives the future of a run to what the action's caller receives.
pub trait Runtime {
    /// A future for async runs, the result itself for blocking ones.
    type Output<V: Send + 'static>;

    /// Starts `run`. `T` names the tool that reports a failure to set the runtime up.
    fn drive<T: Tool, V: Send + 'static>(
        run: impl Future<Output = Result<V>> + Send + 'static,
    ) -> Self::Output<V>;
}

/// Hands the run back as a future for the caller's own runtime.
#[cfg(feature = "async")]
#[derive(Debug, Clone, Copy)]
pub struct Async;

#[cfg(feature = "async")]
impl Runtime for Async {
    type Output<V: Send + 'static> = RunFuture<V>;

    fn drive<T: Tool, V: Send + 'static>(
        run: impl Future<Output = Result<V>> + Send + 'static,
    ) -> RunFuture<V> {
        Box::pin(run)
    }
}

/// Runs to completion on a current-thread runtime built for the call.
///
/// A build failure is reported as [`ProcessError::Spawn`] of the tool.
#[cfg(feature = "blocking")]
#[derive(Debug, Clone, Copy)]
pub struct Blocking;

#[cfg(feature = "blocking")]
impl Runtime for Blocking {
    type Output<V: Send + 'static> = Result<V>;

    fn drive<T: Tool, V: Send + 'static>(
        run: impl Future<Output = Result<V>> + Send + 'static,
    ) -> Result<V> {
        // A runtime per call costs microseconds against the milliseconds of each `codesign`
        // process, and leaves no global state or threads behind.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|source| {
                T::error(ProcessError::Spawn {
                    program: T::PROGRAM,
                    source,
                })
            })?;
        runtime.block_on(run)
    }
}

#[cfg(test)]
#[path = "unit_tests/runtime.rs"]
mod tests;
