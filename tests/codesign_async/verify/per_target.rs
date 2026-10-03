//! `per_target`: one `codesign` per target (the default for a verification,
//! so every target is judged) against one for all of them, which stops at the
//! first target that does not verify.

use std::path::PathBuf;

use signers::{Codesign, CodesignError, Error};

use super::{break_signature, requirement_unsatisfied, verification_failed};
use crate::support::fixture::Workspace;

#[tokio::test]
async fn every_valid_target_verifies() {
    let workspace = Workspace::new();
    let targets: Vec<_> = ["first", "second", "third"]
        .map(|name| workspace.adhoc_signed(name))
        .into();

    let outputs: Vec<()> = Codesign::verify(targets.clone()).await.unwrap();
    let explicit: Vec<()> = Codesign::verify(targets.clone())
        .per_target(true)
        .await
        .unwrap();
    let together: Vec<()> = Codesign::verify(targets.clone())
        .per_target(false)
        .await
        .unwrap();

    assert_eq!(outputs.len(), 3);
    assert_eq!(explicit.len(), 3);
    assert_eq!(together.len(), 3);
}

#[tokio::test]
async fn an_array_of_targets_yields_an_array_of_the_same_length() {
    let workspace = Workspace::new();
    let targets = ["first", "second"].map(|name| workspace.adhoc_signed(name));

    let [(), ()] = Codesign::verify(targets.clone()).await.unwrap();
    let [(), ()] = Codesign::verify(targets).per_target(false).await.unwrap();
}

#[tokio::test]
async fn a_slice_of_targets_yields_a_vec() {
    let workspace = Workspace::new();
    let targets = ["first", "second", "third"].map(|name| workspace.adhoc_signed(name));

    let outputs: Vec<()> = Codesign::verify(&targets[..2]).await.unwrap();

    assert_eq!(outputs.len(), 2);
}

/// Every target is judged: the ones that fail are all reported, in input
/// order, and the ones that pass don't hide them.
#[tokio::test]
async fn every_failing_target_is_collected_in_input_order() {
    let workspace = Workspace::new();
    let unsigned = workspace.unsigned("unsigned");
    let good = workspace.adhoc_signed("good");
    let broken = workspace.adhoc_signed("broken");
    break_signature(&broken);
    let missing_signature = workspace.unsigned("also-unsigned");
    let batch = vec![
        unsigned.clone(),
        good.clone(),
        broken.clone(),
        missing_signature.clone(),
    ];

    let error = Codesign::verify(batch).await.unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected a batch, got {error:?}");
    };
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, [&unsigned, &broken, &missing_signature]);
    for (path, error) in failures {
        let stderr = verification_failed(error);
        assert!(
            stderr.contains(&path.display().to_string()),
            "the diagnostics are not about {}: {stderr}",
            path.display()
        );
    }
}

/// With one process per target, each failure is attributed to its own target.
#[tokio::test]
async fn failures_are_not_mixed_up_between_targets() {
    let workspace = Workspace::new();
    let unsigned = workspace.unsigned("unsigned");
    let broken = workspace.adhoc_signed("broken");
    break_signature(&broken);

    let error = Codesign::verify(vec![broken.clone(), unsigned.clone()])
        .await
        .unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected a batch, got {error:?}");
    };
    let [(first, first_error), (second, second_error)] = &failures[..] else {
        panic!("expected two failures, got {failures:?}");
    };
    assert_eq!((first, second), (&broken, &unsigned));
    assert!(verification_failed_text(first_error).contains("invalid signature"));
    assert!(verification_failed_text(second_error).contains("not signed at all"));
}

fn verification_failed_text(error: &Error) -> &str {
    match error {
        Error::Codesign(CodesignError::VerificationFailed { stderr, .. }) => stderr,
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

/// Each target keeps the exit code of its own process, so one batch can hold
/// both kinds of failure.
#[tokio::test]
async fn a_batch_can_mix_broken_signatures_and_unsatisfied_requirements() {
    let workspace = Workspace::new();
    let broken = workspace.adhoc_signed("broken");
    break_signature(&broken);
    let valid = workspace.adhoc_signed("valid");

    let error = Codesign::verify(vec![broken.clone(), valid.clone()])
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected a batch, got {error:?}");
    };
    let [(first, first_error), (second, second_error)]: [_; 2] = failures.try_into().unwrap();
    assert_eq!((first, second), (broken, valid));
    verification_failed(first_error);
    requirement_unsatisfied(second_error);
}

#[tokio::test]
async fn a_single_failure_in_a_collection_is_still_a_batch() {
    let workspace = Workspace::new();
    let unsigned = workspace.unsigned("unsigned");

    let in_a_list = Codesign::verify(vec![unsigned.clone()]).await.unwrap_err();
    let in_an_array = Codesign::verify([unsigned.clone()]).await.unwrap_err();

    for error in [in_a_list, in_an_array] {
        let Error::Batch(failures) = error else {
            panic!("expected a batch, got {error:?}");
        };
        let [(path, _)] = &failures[..] else {
            panic!("expected exactly one failure, got {failures:?}");
        };
        assert_eq!(*path, unsigned);
    }
}

/// A single target has no `per_target`: its failure is the plain error.
#[tokio::test]
async fn a_single_target_fails_with_its_plain_error() {
    let workspace = Workspace::new();
    let unsigned = workspace.unsigned("unsigned");

    let error = Codesign::verify(&unsigned).await.unwrap_err();

    verification_failed(error);
}

/// One process for all targets stops at the first one that doesn't verify, as
/// `codesign` does, and the error is the plain one, not a batch.
#[tokio::test]
async fn one_process_stops_at_the_first_failing_target() {
    let workspace = Workspace::new();
    let good = workspace.adhoc_signed("good");
    let first_bad = workspace.unsigned("first-bad");
    let second_bad = workspace.unsigned("second-bad");

    let error = Codesign::verify(vec![good, first_bad.clone(), second_bad.clone()])
        .per_target(false)
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains(&first_bad.display().to_string()),
        "got {stderr}"
    );
    assert!(
        !stderr.contains(&second_bad.display().to_string()),
        "the second failure was reached: {stderr}"
    );
}

#[tokio::test]
async fn one_process_reports_an_unsatisfied_requirement_as_one_plain_error() {
    let workspace = Workspace::new();
    let targets = ["first", "second"].map(|name| workspace.adhoc_signed(name));

    let error = Codesign::verify(targets)
        .per_target(false)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    requirement_unsatisfied(error);
}

#[tokio::test]
async fn per_target_keeps_the_last_value() {
    let workspace = Workspace::new();
    let first = workspace.unsigned("first");
    let second = workspace.unsigned("second");
    let batch = vec![first, second];

    let collected = Codesign::verify(batch.clone())
        .per_target(false)
        .per_target(true)
        .await
        .unwrap_err();
    let stopped = Codesign::verify(batch)
        .per_target(true)
        .per_target(false)
        .await
        .unwrap_err();

    assert!(matches!(collected, Error::Batch(ref failures) if failures.len() == 2));
    verification_failed(stopped);
}

/// Options apply to every target in the batch alike.
#[tokio::test]
async fn options_apply_to_every_target() {
    let workspace = Workspace::new();
    let targets = vec![
        workspace.adhoc_signed("first"),
        workspace.adhoc_signed("second"),
    ];

    Codesign::verify(targets)
        .deep(true)
        .strict(signers::codesign::verify::Strict::All)
        .test_requirement("!anchor apple")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_large_batch_is_fully_judged() {
    let workspace = Workspace::new();
    let mut batch: Vec<PathBuf> = Vec::new();
    let mut unsigned = Vec::new();
    for i in 0..40 {
        if i % 7 == 3 {
            let path = workspace.unsigned(format!("unsigned-{i}"));
            unsigned.push(path.clone());
            batch.push(path);
        } else {
            batch.push(workspace.adhoc_signed(format!("signed-{i}")));
        }
    }

    let error = Codesign::verify(batch).await.unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected a batch, got {error:?}");
    };
    let failed: Vec<PathBuf> = failures.into_iter().map(|(path, _)| path).collect();
    assert_eq!(failed, unsigned);
}
