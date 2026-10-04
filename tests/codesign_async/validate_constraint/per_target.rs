//! `per_target`: one `codesign` per plist (the default, so every plist is
//! judged on its own) against one for all of them, where the `error:` lines
//! cannot be told apart.

use std::path::PathBuf;

use signers::{Codesign, CodesignError, Error};

use super::{constraint_invalid, unreadable};
use crate::support::fixture::{Workspace, fixture};

fn valid() -> PathBuf {
    fixture("constraint-team.plist")
}

fn unknown_key() -> PathBuf {
    fixture("bad-constraint.plist")
}

fn empty_dict() -> PathBuf {
    fixture("constraint-empty.plist")
}

#[tokio::test]
async fn every_valid_plist_is_accepted() {
    let plists = vec![
        valid(),
        fixture("launch-constraint.plist"),
        fixture("constraint-and.plist"),
    ];

    let default: Vec<()> = Codesign::validate_constraint(plists.clone()).await.unwrap();
    let each: Vec<()> = Codesign::validate_constraint(plists.clone())
        .per_target(true)
        .await
        .unwrap();
    let together: Vec<()> = Codesign::validate_constraint(plists.clone())
        .per_target(false)
        .await
        .unwrap();

    assert_eq!(default.len(), 3);
    assert_eq!(each.len(), 3);
    assert_eq!(together.len(), 3);
}

#[tokio::test]
async fn an_array_of_plists_yields_an_array_of_the_same_length() {
    let [(), ()] = Codesign::validate_constraint([valid(), valid()])
        .await
        .unwrap();
    let [(), ()] = Codesign::validate_constraint([valid(), valid()])
        .per_target(false)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_slice_of_plists_yields_a_vec() {
    let plists = [valid(), valid(), valid()];

    let outputs: Vec<()> = Codesign::validate_constraint(&plists[..2]).await.unwrap();

    assert_eq!(outputs.len(), 2);
}

#[tokio::test]
async fn a_single_rejected_plist_fails_with_its_plain_error() {
    let error = Codesign::validate_constraint(unknown_key())
        .await
        .unwrap_err();

    assert!(constraint_invalid(error).contains("bogus-key-xyz"));
}

#[tokio::test]
async fn every_rejected_plist_is_collected_in_input_order() {
    let plists = vec![valid(), unknown_key(), valid(), empty_dict()];

    let error = Codesign::validate_constraint(plists).await.unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected the failures of a batch, got {error:?}");
    };
    let paths: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(paths, [&unknown_key(), &empty_dict()]);
    let [(_, first), (_, second)] = failures.try_into().unwrap_or_else(|_| unreachable!());
    // Each process saw a single plist, so each rejection speaks only about it.
    let first = constraint_invalid(first);
    let second = constraint_invalid(second);
    assert!(first.contains("bogus-key-xyz"), "{first}");
    assert!(
        !first.contains("does not specify any constraints"),
        "{first}"
    );
    assert!(
        second.contains("does not specify any constraints"),
        "{second}"
    );
    assert!(!second.contains("bogus-key-xyz"), "{second}");
}

#[tokio::test]
async fn a_single_rejection_in_a_collection_is_still_a_batch() {
    let in_a_list = Codesign::validate_constraint(vec![unknown_key()])
        .await
        .unwrap_err();
    let in_an_array = Codesign::validate_constraint([unknown_key()])
        .await
        .unwrap_err();

    for error in [in_a_list, in_an_array] {
        let Error::Batch(failures) = error else {
            panic!("expected a Batch, got {error:?}");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, unknown_key());
    }
}

#[tokio::test]
async fn an_unreadable_plist_and_a_rejected_one_fail_separately() {
    let workspace = Workspace::new();
    let garbage = workspace.write("garbage.plist", "garbage\n");
    let plists = vec![valid(), garbage.clone(), unknown_key()];

    let error = Codesign::validate_constraint(plists).await.unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected the failures of a batch, got {error:?}");
    };
    let [(first_path, first), (second_path, second)] = failures
        .try_into()
        .unwrap_or_else(|_| panic!("expected two failures"));
    assert_eq!(first_path, garbage);
    assert_eq!(unreadable(first).0, 1);
    assert_eq!(second_path, unknown_key());
    constraint_invalid(second);
}

/// Without `per_target`, `codesign` prints every `error:` line to one stream:
/// the run fails as a whole, as a plain error, and cannot say which plist.
#[tokio::test]
async fn together_a_rejected_plist_fails_the_whole_run_as_a_plain_error() {
    let plists = vec![valid(), unknown_key(), valid()];

    let error = Codesign::validate_constraint(plists)
        .per_target(false)
        .await
        .unwrap_err();

    assert!(constraint_invalid(error).contains("bogus-key-xyz"));
}

#[tokio::test]
async fn together_every_rejection_shows_in_the_diagnostics() {
    let error = Codesign::validate_constraint([unknown_key(), empty_dict()])
        .per_target(false)
        .await
        .unwrap_err();

    let stderr = constraint_invalid(error);

    assert!(stderr.contains("bogus-key-xyz"), "{stderr}");
    assert!(
        stderr.contains("does not specify any constraints"),
        "{stderr}"
    );
}

#[tokio::test]
async fn together_an_unreadable_plist_fails_the_whole_run_with_exit_one() {
    let workspace = Workspace::new();
    let garbage = workspace.write("garbage.plist", "garbage\n");

    let error = Codesign::validate_constraint(vec![valid(), garbage])
        .per_target(false)
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            Error::Codesign(CodesignError::Failed { code: 1, .. })
        ),
        "{error:?}"
    );
}
