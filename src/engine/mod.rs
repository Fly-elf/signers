//! The tool-agnostic machinery behind every tool module: the contract between an action and the
//! tool it runs, the process run, the checks and the batching, and the sync or async driver.
//!
//! A tool module supplies a [`Tool`] (which program, how its failures map to errors) and an
//! [`Operation`] per action (arguments in, outputs out). A [`Job`] holds the targets and runs the
//! operation on an [`Async`] or [`Blocking`] runtime, yielding the shape the targets ask for.

mod execute;
mod job;
mod operation;
mod process;
mod runtime;
mod tool;

pub use job::Job;
pub use operation::{Operation, PushArgs, Rejection, SharedRun};
#[cfg(feature = "async")]
pub use runtime::Async;
#[cfg(feature = "blocking")]
pub use runtime::Blocking;
pub use tool::Tool;
