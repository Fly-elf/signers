//! The builder and its `IntoFuture` impl as a type, independent of any one
//! option: laziness, `Clone`, and running several signings concurrently.

use std::future::IntoFuture;

use signers::codesign::Sign;
use signers::{Codesign, IntoTargets};

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};

#[tokio::test]
async fn a_builder_that_is_never_awaited_does_nothing() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let _unused = Codesign::sign(&target, "-")
        .force(true)
        .identifier("com.example.never");
    tokio::task::yield_now().await;

    assert!(
        !inspect::is_signed(&target),
        "the builder ran without being awaited"
    );
}

#[tokio::test]
async fn a_cloned_builder_is_independent_of_the_original() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let base = Codesign::sign(&target, "-")
        .force(true)
        .identifier("com.example.base");
    let variant = base.clone().identifier("com.example.variant");

    base.await.unwrap();
    assert_eq!(Signature::of(&target).identifier(), "com.example.base");

    variant.await.unwrap();
    assert_eq!(Signature::of(&target).identifier(), "com.example.variant");
}

/// Cloning has to work for every shape, and carry the mode along with the
/// options: here both runs collect the refused target instead of stopping at it.
#[tokio::test]
async fn a_cloned_collection_builder_keeps_its_targets_and_its_mode() {
    let workspace = Workspace::new();
    let directory = workspace.dir("not-a-bundle");
    let target = workspace.unsigned("hello");

    let base = Codesign::sign([directory.clone(), target.clone()], "-")
        .force(true)
        .per_target(true);
    let copy = base.clone();
    assert_eq!(format!("{base:?}"), format!("{copy:?}"));

    for builder in [base, copy] {
        let failures = crate::batch_failures(builder.await.unwrap_err());
        let failed: Vec<_> = failures.iter().map(|(path, _)| path).collect();
        assert_eq!(failed, [&directory]);
        inspect::assert_valid(&target);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_signings_can_run_at_once() {
    let workspace = Workspace::new();
    let targets: Vec<_> = (0..8)
        .map(|i| workspace.unsigned(format!("hello-{i}")))
        .collect();

    let running: Vec<_> = targets
        .iter()
        .enumerate()
        .map(|(i, target)| {
            // Spawned bare, rather than wrapped in an `async` block, so this
            // only compiles while the future stays `Send + 'static`.
            tokio::spawn(
                Codesign::sign(target.clone(), "-")
                    .identifier(format!("com.example.h{i}"))
                    .into_future(),
            )
        })
        .collect();

    for task in running {
        task.await
            .expect("a signing task panicked")
            .expect("a signing task failed");
    }
    for (i, target) in targets.iter().enumerate() {
        inspect::assert_valid(target);
        assert_eq!(
            Signature::of(target).identifier(),
            format!("com.example.h{i}")
        );
    }
}

/// The action's output type is part of the public contract: callers
/// that match on `Ok(())` must keep compiling.
#[tokio::test]
async fn awaiting_a_signing_yields_unit() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let result: signers::Result<()> = Codesign::sign(&target, "-").await;

    assert!(matches!(result, Ok(())));
}

/// A collection of targets yields one output per target, in a `Vec` whatever
/// the collection's length: a one-element list is still a list.
#[tokio::test]
async fn awaiting_a_list_of_targets_yields_one_unit_per_target() {
    let workspace = Workspace::new();
    let targets: Vec<_> = ["first", "second", "third"]
        .map(|name| workspace.unsigned(name))
        .into();

    let from_a_list: signers::Result<Vec<()>> = Codesign::sign(targets.clone(), "-").await;
    let from_a_slice: signers::Result<Vec<()>> =
        Codesign::sign(&targets[..2], "-").force(true).await;
    let from_a_list_of_one: signers::Result<Vec<()>> =
        Codesign::sign(vec![&targets[0]], "-").force(true).await;

    assert_eq!(from_a_list.unwrap().len(), 3);
    assert_eq!(from_a_slice.unwrap().len(), 2);
    assert_eq!(from_a_list_of_one.unwrap().len(), 1);
    for target in &targets {
        inspect::assert_valid(target);
    }
}

/// An array's length is known at compile time, so its outputs can be
/// destructured without a length check.
#[tokio::test]
async fn awaiting_an_array_of_targets_yields_an_array_of_the_same_length() {
    let workspace = Workspace::new();
    let targets = ["first", "second", "third"].map(|name| workspace.unsigned(name));

    let [(), (), ()] = Codesign::sign(targets.clone(), "-").await.unwrap();
    let [()] = Codesign::sign([&targets[0]], "-")
        .force(true)
        .await
        .unwrap();

    for target in &targets {
        inspect::assert_valid(target);
    }
}

/// A helper generic over `T: IntoTargets` can build and configure a signing for
/// any kind of target: every setter is there whatever the shape, and the
/// output type follows the target type.
#[tokio::test]
async fn a_helper_generic_over_the_target_type_configures_any_builder() {
    fn named<T: IntoTargets>(target: T) -> Codesign<Sign, T::Shape> {
        Codesign::sign(target, "-").identifier("com.example.shaped")
    }

    let workspace = Workspace::new();
    let targets =
        ["one", "many", "slice", "array-0", "array-1"].map(|name| workspace.unsigned(name));

    let one: signers::Result<()> = named(&targets[0]).await;
    let many: signers::Result<Vec<()>> = named(vec![&targets[1]]).await;
    let slice: signers::Result<Vec<()>> = named(&targets[2..3]).force(true).await;
    let array: signers::Result<[(); 2]> = named([&targets[3], &targets[4]]).per_target(true).await;

    one.unwrap();
    assert_eq!(many.unwrap().len(), 1);
    assert_eq!(slice.unwrap().len(), 1);
    array.unwrap();
    for target in &targets {
        assert_eq!(Signature::of(target).identifier(), "com.example.shaped");
    }
}

/// `Codesign<Sign>` keeps naming the single-target builder: the shape
/// parameter defaults to one target.
#[tokio::test]
async fn the_builder_type_without_a_shape_is_the_single_target_one() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let builder: Codesign<Sign> = Codesign::sign(&target, "-");
    builder.await.unwrap();

    inspect::assert_valid(&target);
}
