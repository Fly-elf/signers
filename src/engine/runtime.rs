use std::future::Future;
use std::pin::Pin;

use super::tool::Tool;
#[cfg(feature = "blocking")]
use crate::errors::ProcessError;
use crate::errors::Result;

pub type RunFuture<V> = Pin<Box<dyn Future<Output = Result<V>> + Send>>;

pub trait Runtime {
    type Output<V: Send + 'static>;

    fn drive<T: Tool, V: Send + 'static>(
        run: impl Future<Output = Result<V>> + Send + 'static,
    ) -> Self::Output<V>;
}

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
