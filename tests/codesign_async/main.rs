//! End-to-end tests for the async `codesign` backend — the public builder
//! driven against a real Mach-O fixture, with the macOS `codesign` CLI checking
//! the result.
//!
//! One module per action; `verify` joins `sign` and `remove_signature` here as
//! it lands. Anything that mutates process-global state (the working directory,
//! `PATH`) lives in `tests/codesign_process_state.rs` instead, so this binary
//! stays parallel-safe.

#![cfg(target_os = "macos")]

#[path = "../support/mod.rs"]
mod support;

mod remove_signature;
mod sign;

use signers::{CodesignError, Error};

/// Unwraps the `Error::Codesign` a failed run must produce, returning the
/// diagnostics it captured.
///
/// Shared by every action's suite: what a failing run has to look like from
/// outside is a property of the backend, not of the action that triggered it.
fn codesign_error(error: Error) -> String {
    match error {
        Error::Codesign(CodesignError::Failed { stderr, .. }) => {
            assert!(
                !stderr.is_empty(),
                "the failure was reported with no diagnostics"
            );
            stderr
        }
        other => panic!("expected the `codesign` run to fail, got {other:?}"),
    }
}
