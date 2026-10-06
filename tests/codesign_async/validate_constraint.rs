//! `validate_constraint`, end to end — one submodule per test
//! category, named for what it covers.
//!
//! Every plist is also handed to the `codesign` CLI, and what it printed is
//! checked against what the action decided, so no test passes because the
//! library and the test agree on a mistake.
//!
//! The quirk this action exists to work around: `codesign` exits 0 and prints
//! "Constraint validation failed" for every plist it could read, valid ones
//! included. Only an `error:` line tells a rejected constraint apart.

mod per_target;
mod preflight;
mod unreadable;
mod validating;

use std::path::Path;

use signers::{CodesignError, Error};

use crate::support::inspect;

/// The diagnostics `codesign` prints for a plist that it read but whose
/// constraint it rejects, or `None` if it accepted it.
///
/// The CLI is the judge: a line starting `error:` on stderr is a rejection,
/// and the run still exits 0.
fn cli_rejection(plist: &Path) -> Option<String> {
    let run = inspect::codesign(&["--validate-constraint".as_ref(), plist.as_ref()]);
    assert!(
        run.success,
        "the test harness could not read {}: {}",
        plist.display(),
        run.stderr.trim()
    );
    run.stderr
        .lines()
        .any(|line| line.starts_with("error:"))
        .then_some(run.stderr)
}

/// Unwraps the `ConstraintInvalid` a rejected constraint must produce,
/// returning its stderr.
fn constraint_invalid(error: Error) -> String {
    match error {
        Error::Codesign(CodesignError::ConstraintInvalid { stdout, stderr }) => {
            assert!(stdout.is_empty(), "unexpected stdout: {stdout}");
            assert!(!stderr.is_empty(), "the rejection carried no diagnostics");
            stderr
        }
        other => panic!("expected ConstraintInvalid, got {other:?}"),
    }
}

/// Unwraps the `Failed` a plist `codesign` cannot read must produce,
/// returning its exit code and stderr.
fn unreadable(error: Error) -> (i32, String) {
    match error {
        Error::Codesign(CodesignError::Failed { code, stderr, .. }) => (code, stderr),
        other => panic!("expected Failed, got {other:?}"),
    }
}
