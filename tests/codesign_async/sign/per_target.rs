//! `per_target`: one `codesign` for all targets (the default for signing)
//! against one per target, and what each does with a target `codesign` refuses.
//!
//! A plain directory and an already signed binary are the two refused targets
//! used throughout: both exist, so they pass the pre-flight checks, and
//! `codesign` turns each down with a message of its own.

use std::future::IntoFuture;
use std::path::PathBuf;

use signers::Error;
use signers::codesign::sign;

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};

/// A batch stops at the first target `codesign` refuses, so the ones after it
/// stay unsigned, and the error is the one `codesign` produced.
#[tokio::test]
async fn one_process_for_all_targets_is_the_default() {
    let workspace = Workspace::new();
    let bad = workspace.dir("not-a-bundle");
    let after = workspace.unsigned("after");
    let batch = vec![bad, after.clone()];

    let by_default = sign(batch.clone(), "-").await.unwrap_err();
    let on_request = sign(batch, "-")
        .per_target(true)
        .per_target(false)
        .await
        .unwrap_err();

    for error in [by_default, on_request] {
        assert!(crate::codesign_error(error).contains("bundle format unrecognized"));
    }
    assert!(
        !inspect::is_signed(&after),
        "the batch carried on past the target codesign refused"
    );
}

#[tokio::test]
async fn every_target_is_signed_with_the_same_options() {
    let workspace = Workspace::new();
    let targets: Vec<_> = ["first", "second", "third"]
        .map(|name| workspace.unsigned(name))
        .into();

    let outputs: Vec<()> = sign(targets.clone(), "-")
        .identifier("com.example.each")
        .per_target(true)
        .await
        .unwrap();

    assert_eq!(outputs.len(), targets.len());
    for target in &targets {
        inspect::assert_valid(target);
        assert_eq!(Signature::of(target).identifier(), "com.example.each");
    }
}

#[tokio::test]
async fn an_array_of_targets_yields_an_array_of_the_same_length() {
    let workspace = Workspace::new();
    let targets = ["first", "second"].map(|name| workspace.unsigned(name));

    let [(), ()] = sign(targets.clone(), "-").per_target(true).await.unwrap();

    for target in &targets {
        inspect::assert_valid(target);
    }
}

#[tokio::test]
async fn a_single_target_yields_unit() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let result: signers::Result<()> = sign(&target, "-").await;

    assert!(matches!(result, Ok(())), "got {result:?}");
    inspect::assert_valid(&target);
}

/// A single target has no `per_target` setter and runs once: its failure is
/// the plain error, never a `Batch`.
#[tokio::test]
async fn a_single_target_fails_with_its_plain_error() {
    let workspace = Workspace::new();
    let target = workspace.dir("not-a-bundle");

    let error = sign(&target, "-").await.unwrap_err();

    assert!(crate::codesign_error(error).contains("bundle format unrecognized"));
}

/// The point of the mode: a refused target costs the others nothing, and each
/// failure comes back attached to the target it is about.
#[tokio::test]
async fn refused_targets_are_collected_in_input_order_and_the_rest_are_signed() {
    let workspace = Workspace::new();
    let already_signed = workspace.adhoc_signed("already-signed");
    let first = workspace.unsigned("first");
    let directory = workspace.dir("not-a-bundle");
    let last = workspace.unsigned("last");
    let batch = vec![
        already_signed.clone(),
        first.clone(),
        directory.clone(),
        last.clone(),
    ];

    let error = sign(batch, "-")
        .identifier("com.example.survivor")
        .per_target(true)
        .await
        .unwrap_err();

    let failures: Vec<(PathBuf, String)> = crate::batch_failures(error)
        .into_iter()
        .map(|(path, error)| (path, crate::codesign_error(error)))
        .collect();
    let [(first_path, first_stderr), (second_path, second_stderr)] = &failures[..] else {
        panic!("expected exactly the two refused targets, got {failures:?}");
    };
    assert_eq!(*first_path, already_signed);
    assert!(
        first_stderr.contains("is already signed"),
        "got {first_stderr}"
    );
    assert_eq!(*second_path, directory);
    assert!(
        second_stderr.contains("bundle format unrecognized"),
        "got {second_stderr}"
    );

    for target in [&first, &last] {
        inspect::assert_valid(target);
        assert_eq!(Signature::of(target).identifier(), "com.example.survivor");
    }
}

/// A caller matching on `Error::Batch` must not also need a second arm for
/// "only one of them failed": the shape of the error follows the shape of the
/// targets, never the number of failures.
#[tokio::test]
async fn a_single_failure_in_a_collection_is_still_a_batch() {
    let workspace = Workspace::new();
    let directory = workspace.dir("not-a-bundle");
    let good = workspace.unsigned("good");

    let among_others = sign(vec![good.clone(), directory.clone()], "-")
        .per_target(true)
        .await
        .unwrap_err();
    let alone_in_a_list = sign(vec![directory.clone()], "-")
        .per_target(true)
        .await
        .unwrap_err();
    let alone_in_an_array = sign([directory.clone()], "-")
        .per_target(true)
        .await
        .unwrap_err();
    let slice: &[PathBuf] = std::slice::from_ref(&directory);
    let alone_in_a_slice = sign(slice, "-").per_target(true).await.unwrap_err();

    for error in [
        among_others,
        alone_in_a_list,
        alone_in_an_array,
        alone_in_a_slice,
    ] {
        let failures = crate::batch_failures(error);
        let [(path, error)] = &failures[..] else {
            panic!("expected exactly one failure, got {failures:?}");
        };
        assert_eq!(*path, directory);
        assert!(
            matches!(error, Error::Codesign(_)),
            "the failure is not what codesign reported: {error:?}"
        );
    }
    inspect::assert_valid(&good);
}

#[tokio::test]
async fn an_array_of_targets_fails_as_a_batch_too() {
    let workspace = Workspace::new();
    let good = workspace.unsigned("good");
    let directory = workspace.dir("not-a-bundle");
    let already_signed = workspace.adhoc_signed("already-signed");

    let error = sign(
        [directory.clone(), good.clone(), already_signed.clone()],
        "-",
    )
    .per_target(true)
    .await
    .unwrap_err();

    let failed: Vec<PathBuf> = crate::batch_failures(error)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    assert_eq!(failed, [directory, already_signed]);
    inspect::assert_valid(&good);
}

/// More targets than `codesign` processes allowed at once, so some of them
/// have to wait their turn: none may be lost, and the failures at either end
/// still come back in the order the targets were given.
#[tokio::test]
async fn a_batch_larger_than_the_process_cap_is_handled_in_full() {
    let cap = std::thread::available_parallelism().map_or(1, usize::from);
    let workspace = Workspace::new();
    let leading = workspace.dir("leading-directory");
    let trailing = workspace.dir("trailing-directory");
    let good: Vec<_> = (0..2 * cap + 1)
        .map(|i| workspace.unsigned(format!("hello-{i}")))
        .collect();
    let mut batch = vec![leading.clone()];
    batch.extend(good.iter().cloned());
    batch.push(trailing.clone());

    let error = sign(batch, "-").per_target(true).await.unwrap_err();

    let failed: Vec<PathBuf> = crate::batch_failures(error)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    assert_eq!(failed, [leading, trailing]);
    for target in &good {
        inspect::assert_valid(target);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_per_target_batch_can_run_on_another_task() {
    let workspace = Workspace::new();
    let targets = vec![workspace.unsigned("first"), workspace.unsigned("second")];

    // Spawned bare, rather than wrapped in an `async` block, so this only
    // compiles while the future stays `Send + 'static` for a collection too.
    let outputs = tokio::spawn(sign(targets.clone(), "-").per_target(true).into_future())
        .await
        .expect("the signing task panicked")
        .expect("the signing task failed");

    assert_eq!(outputs.len(), 2);
    for target in &targets {
        inspect::assert_valid(target);
    }
}
