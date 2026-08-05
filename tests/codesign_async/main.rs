//! End-to-end tests for the async `codesign` backend — the public builder
//! driven against a real Mach-O fixture, with the macOS `codesign` CLI checking
//! the result.
//!
//! One module per action; `verify` and `remove` join `sign` here as they land.
//! Anything that mutates process-global state (the working directory, `PATH`)
//! lives in `tests/codesign_process_state.rs` instead, so this binary stays
//! parallel-safe.

#![cfg(target_os = "macos")]

#[path = "../support/mod.rs"]
mod support;

mod sign;
