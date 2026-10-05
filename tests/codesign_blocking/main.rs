//! End-to-end tests for the blocking `codesign` API.
//!
//! `.run()` is the async run on a runtime of its own, and the builder is the
//! async one, options included. So this suite covers only the run path: each
//! action once, the checks made before anything runs, every error a run can
//! end in, the target shapes and both ways of splitting a batch. The options
//! are tested once, in the async suite. Failures that need `PATH` pointed at a
//! stand-in `codesign` live in `tests/codesign_process_state/`.

#![cfg(all(target_os = "macos", feature = "blocking"))]

#[path = "../support/mod.rs"]
mod support;

mod actions;
mod errors;
mod per_target;
mod preflight;
mod runtime;
mod shapes;
