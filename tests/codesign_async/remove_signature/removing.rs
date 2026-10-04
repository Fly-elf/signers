//! Stripping a bare Mach-O: the happy path, batches, universal binaries, and
//! the two states in which a successful run removes nothing at all.

use signers::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};
use crate::support::skip;

#[tokio::test]
async fn a_signed_binary_loses_its_signature() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    assert!(
        inspect::is_signed(&target),
        "the fixture started out unsigned"
    );

    Codesign::remove_signature(&target).await.unwrap();

    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn a_linker_signature_is_removed_too() {
    // The state a freshly linked binary arrives in on Apple Silicon, and the
    // one a caller most often wants gone before patching the Mach-O.
    let workspace = Workspace::new();
    let target = workspace.linker_signed("hello");
    if !inspect::is_signed(&target) {
        skip!("only the Apple Silicon linker signs what it links");
    }

    Codesign::remove_signature(&target).await.unwrap();

    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn every_slice_of_a_universal_binary_is_stripped() {
    // Each slice carries its own CodeDirectory, and one removal has to cover
    // all of them — leaving a signed slice behind would be a partial strip no
    // caller asked for.
    let workspace = Workspace::new();
    let Some(target) = workspace.unsigned_universal("hello-universal") else {
        skip!("this toolchain has only one architecture's SDK");
    };
    Codesign::sign(&target, "-").await.unwrap();
    for arch in ["arm64", "x86_64"] {
        assert_eq!(
            Signature::of_arch(&target, arch).signature(),
            "adhoc",
            "the {arch} slice started out unsigned"
        );
    }

    Codesign::remove_signature(&target).await.unwrap();

    for arch in ["arm64", "x86_64"] {
        assert!(
            !inspect::is_signed_arch(&target, arch),
            "the {arch} slice kept its signature"
        );
    }
}

#[tokio::test]
async fn every_target_in_a_batch_is_stripped() {
    let workspace = Workspace::new();
    let targets = ["first", "second", "third"].map(|name| workspace.adhoc_signed(name));

    Codesign::remove_signature(targets.to_vec()).await.unwrap();

    for target in &targets {
        assert!(
            !inspect::is_signed(target),
            "{} kept its signature",
            target.display()
        );
    }
}

/// Removal is idempotent, which is what makes it safe to run over a batch whose
/// signing state is unknown — but it also means success is no evidence that
/// anything was there to remove.
#[tokio::test]
async fn stripping_an_unsigned_target_succeeds_and_changes_nothing() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let before = std::fs::read(&target).unwrap();

    Codesign::remove_signature(&target).await.unwrap();

    assert!(!inspect::is_signed(&target));
    assert_eq!(
        std::fs::read(&target).unwrap(),
        before,
        "the unsigned target was rewritten anyway"
    );
}

/// `codesign` sees no code in a plain file, and reports nothing to remove as
/// success rather than as an error.
#[tokio::test]
async fn stripping_a_file_that_is_not_code_succeeds() {
    let workspace = Workspace::new();
    let target = workspace.write("notes.txt", "not a Mach-O file\n");

    Codesign::remove_signature(&target).await.unwrap();

    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn spaces_and_non_ascii_in_a_path_are_passed_through_verbatim() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("héllo wörld ✓.bin");

    Codesign::remove_signature(&target).await.unwrap();

    assert!(!inspect::is_signed(&target));
}

/// The action's output type is part of the public contract: callers
/// that match on `Ok(())` must keep compiling.
#[tokio::test]
async fn awaiting_a_removal_yields_unit() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    Codesign::sign(&target, "-").await.unwrap();

    let result: signers::Result<()> = Codesign::remove_signature(&target).await;

    assert!(matches!(result, Ok(())));
}

/// A collection of targets yields one output per target, in the shape of the
/// collection.
#[tokio::test]
async fn awaiting_a_collection_of_targets_yields_one_unit_per_target() {
    let workspace = Workspace::new();
    let targets = ["first", "second", "third"].map(|name| workspace.adhoc_signed(name));

    let from_a_list: signers::Result<Vec<()>> = Codesign::remove_signature(targets.to_vec()).await;
    let from_a_slice: signers::Result<Vec<()>> = Codesign::remove_signature(&targets[..2]).await;
    let from_an_array: signers::Result<[(); 3]> = Codesign::remove_signature(targets.clone()).await;

    assert_eq!(from_a_list.unwrap().len(), 3);
    assert_eq!(from_a_slice.unwrap().len(), 2);
    assert!(matches!(from_an_array, Ok([(), (), ()])));
    for target in &targets {
        assert!(!inspect::is_signed(target));
    }
}
