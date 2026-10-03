//! `per_target`: one `codesign` for all targets (the default for a removal)
//! against one per target, and what each does with a target `codesign` refuses.
//!
//! The default mode's side of that is in `rejected_by_codesign.rs`
//! (`a_rejected_target_stops_the_batch_where_it_stands`).

use std::path::PathBuf;

use signers::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn every_target_is_stripped() {
    let workspace = Workspace::new();
    let targets: Vec<_> = ["first", "second", "third"]
        .map(|name| workspace.adhoc_signed(name))
        .into();

    let outputs: Vec<()> = Codesign::remove_signature(targets.clone())
        .per_target(true)
        .await
        .unwrap();

    assert_eq!(outputs.len(), targets.len());
    for target in &targets {
        assert!(
            !inspect::is_signed(target),
            "{} kept its signature",
            target.display()
        );
    }
}

#[tokio::test]
async fn an_array_of_targets_yields_an_array_of_the_same_length() {
    let workspace = Workspace::new();
    let targets = ["first", "second"].map(|name| workspace.adhoc_signed(name));

    let [(), ()] = Codesign::remove_signature(targets.clone())
        .per_target(true)
        .await
        .unwrap();

    for target in &targets {
        assert!(!inspect::is_signed(target));
    }
}

/// A single target has no `per_target` setter and runs once: its failure is
/// the plain error, never a `Batch` (ADR-0015).
#[tokio::test]
async fn a_single_target_fails_with_its_plain_error() {
    let workspace = Workspace::new();
    let target = workspace.dir("not-a-bundle");

    let error = Codesign::remove_signature(&target).await.unwrap_err();

    assert!(crate::codesign_error(error).contains("bundle format unrecognized"));
}

/// Where the default mode stops at the first refused target, this one strips
/// everything it can and reports every target it could not.
#[tokio::test]
async fn refused_targets_are_collected_in_input_order_and_the_rest_are_stripped() {
    let workspace = Workspace::new();
    let first_directory = workspace.dir("not-a-bundle");
    let first = workspace.adhoc_signed("first");
    let second_directory = workspace.dir("not a bündle either");
    let last = workspace.adhoc_signed("last");
    let batch = vec![
        first_directory.clone(),
        first.clone(),
        second_directory.clone(),
        last.clone(),
    ];

    let error = Codesign::remove_signature(batch)
        .per_target(true)
        .await
        .unwrap_err();

    let failures: Vec<(PathBuf, String)> = crate::batch_failures(error)
        .into_iter()
        .map(|(path, error)| (path, crate::codesign_error(error)))
        .collect();
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, [&first_directory, &second_directory]);
    for (path, stderr) in &failures {
        assert!(
            stderr.contains("bundle format unrecognized"),
            "got {stderr}"
        );
        // Each process saw one target, so its diagnostics name that one alone.
        assert!(
            stderr.contains(&path.display().to_string()),
            "the diagnostics are not about {}: {stderr}",
            path.display()
        );
    }
    for target in [&first, &last] {
        assert!(
            !inspect::is_signed(target),
            "{} kept its signature",
            target.display()
        );
    }
}

#[tokio::test]
async fn a_single_failure_in_a_collection_is_still_a_batch() {
    let workspace = Workspace::new();
    let directory = workspace.dir("not-a-bundle");

    let in_a_list = Codesign::remove_signature(vec![directory.clone()])
        .per_target(true)
        .await
        .unwrap_err();
    let in_an_array = Codesign::remove_signature([directory.clone()])
        .per_target(true)
        .await
        .unwrap_err();

    for error in [in_a_list, in_an_array] {
        let failures = crate::batch_failures(error);
        let [(path, _)] = &failures[..] else {
            panic!("expected exactly one failure, got {failures:?}");
        };
        assert_eq!(*path, directory);
    }
}
