//! The builder and its `IntoFuture` impl as a type, independent of any one
//! option: laziness, `Clone`, and running several signings concurrently.

use std::future::IntoFuture;

use signers::Codesign;

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

/// The action's output type is part of the public contract (ADR-0011): callers
/// that match on `Ok(())` must keep compiling.
#[tokio::test]
async fn awaiting_a_signing_yields_unit() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let result: signers::Result<()> = Codesign::sign(&target, "-").await;

    assert!(matches!(result, Ok(())));
}
