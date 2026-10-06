//! A batch with a target `codesign` refuses, run as one process and as one
//! process per target.

use std::path::PathBuf;

use signers::codesign::blocking::{sign_adhoc, verify};
use signers::{CodesignError, Error};

use crate::support::fixture::Workspace;
use crate::support::inspect;

/// One process stops at the refused target and leaves the ones after it alone.
#[test]
fn one_process_fails_as_a_whole_at_the_first_refused_target() {
    let workspace = Workspace::new();
    let refused = workspace.adhoc_signed("signed");
    let after = workspace.unsigned("after");

    let error = sign_adhoc(vec![refused, after.clone()])
        .per_target(false)
        .run()
        .unwrap_err();

    assert!(
        matches!(error, Error::Codesign(CodesignError::Failed { .. })),
        "got {error:?}"
    );
    assert!(!inspect::is_signed(&after), "the run went past the failure");
}

#[test]
fn per_target_runs_every_target_and_collects_the_failures() {
    let workspace = Workspace::new();
    let before = workspace.unsigned("before");
    let refused = workspace.adhoc_signed("signed");
    let after = workspace.unsigned("after");

    let error = sign_adhoc(vec![before.clone(), refused.clone(), after.clone()])
        .per_target(true)
        .run()
        .unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected Batch, got {error:?}");
    };
    let [(path, error)] = &failures[..] else {
        panic!("expected one failure, got {failures:?}");
    };
    assert_eq!(*path, refused);
    assert!(
        matches!(error, Error::Codesign(CodesignError::Failed { .. })),
        "got {error:?}"
    );
    inspect::assert_valid(&before);
    inspect::assert_valid(&after);
}

/// Every failure is listed, in input order.
#[test]
fn per_target_failures_come_in_input_order() {
    let workspace = Workspace::new();
    let targets: Vec<PathBuf> = ["c", "a", "b"]
        .into_iter()
        .map(|name| workspace.unsigned(name))
        .collect();

    let error = verify(targets.clone()).run().unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected Batch, got {error:?}");
    };
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, targets.iter().collect::<Vec<_>>());
    for (_, error) in &failures {
        assert!(
            matches!(
                error,
                Error::Codesign(CodesignError::VerificationFailed { .. })
            ),
            "got {error:?}"
        );
    }
}
