//! End-to-end tests for the async `codesign` backend — the public builder
//! driven against a real Mach-O fixture, with the macOS `codesign` CLI checking
//! the result.
//!
//! One module per action (`sign`, `remove_signature`, `verify`, `display`,
//! `extract_certificates`), plus the pre-flight checks they share. Anything
//! that mutates process-global state (the working directory, `PATH`, `TMPDIR`)
//! lives in `tests/codesign_process_state/` instead, so this binary stays
//! parallel-safe.

#![cfg(target_os = "macos")]

#[path = "../support/mod.rs"]
mod support;

mod display;
mod extract_certificates;
mod preflight;
mod remove_signature;
mod sign;
mod verify;

use std::path::PathBuf;

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

/// Unwraps the `Error::Batch` a per-target run over a collection must produce
/// as soon as one target fails, returning the failing targets with their errors.
fn batch_failures(error: Error) -> Vec<(PathBuf, Error)> {
    match error {
        Error::Batch(failures) => failures,
        other => panic!("expected the failures of a batch, got {other:?}"),
    }
}
