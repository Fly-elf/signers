//! The `tracing` events a `codesign` run reports: what they are called, at which level, with which
//! fields and in which order, under the single target `signers`.
//!
//! Subscribers are thread-local, so every test drives its run on its own thread: a current-thread
//! runtime for the async API, the calling thread for the blocking one. Failures that need `PATH`
//! pointed at a stand-in `codesign` live in `tests/codesign_process_state/`.

#![cfg(target_os = "macos")]

#[path = "../support/mod.rs"]
mod support;

mod batch;
mod run;
