//! What the builder rejects before it ever spawns `codesign`: the checks every
//! action shares, and option values this crate cannot honour (`file_list("-")`).

use signers::{Codesign, Error};

use crate::preflight::preflight_tests;
use crate::support::fixture::Workspace;
use crate::support::inspect;

preflight_tests!(Codesign::sign_adhoc);

#[tokio::test]
async fn a_file_list_of_standard_output_is_rejected() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::sign(&target, "-")
        .file_list("-")
        .await
        .unwrap_err();

    assert!(matches!(error, Error::FileListToStdout), "got {error:?}");
    assert!(
        !inspect::is_signed(&target),
        "the target was signed despite the rejected option"
    );
}

/// One `codesign` per target would have each process overwrite the file the
/// others wrote, so the combination is refused instead of honoured badly
/// (ADR-0013).
#[tokio::test]
async fn an_option_writing_one_shared_file_cannot_run_per_target() {
    let workspace = Workspace::new();
    let targets = vec![workspace.unsigned("first"), workspace.unsigned("second")];
    let shared = workspace.join("shared.out");

    let with_file_list = Codesign::sign(targets.clone(), "-")
        .file_list(&shared)
        .per_target(true)
        .await
        .unwrap_err();
    let with_detached = Codesign::sign(targets.clone(), "-")
        .detached(&shared)
        .per_target(true)
        .await
        .unwrap_err();

    assert!(
        matches!(with_file_list, Error::SharedOutputPerTarget("file_list")),
        "got {with_file_list:?}"
    );
    assert!(
        matches!(with_detached, Error::SharedOutputPerTarget("detached")),
        "got {with_detached:?}"
    );
    assert!(!shared.exists(), "the shared file was written anyway");
    for target in &targets {
        assert!(
            !inspect::is_signed(target),
            "{} was signed despite the refusal",
            target.display()
        );
    }
}

/// A single target is one process whatever the option, so there is nothing to
/// share and nothing to refuse (ADR-0015). It has no `per_target` setter to
/// ask for a second mode.
#[tokio::test]
async fn a_shared_file_is_not_refused_for_a_single_target() {
    let workspace = Workspace::new();
    let listed = workspace.unsigned("listed");
    let detached = workspace.unsigned("detached");
    let list = workspace.join("signed.txt");
    let signature = workspace.join("detached.sig");

    Codesign::sign(&listed, "-").file_list(&list).await.unwrap();
    Codesign::sign(&detached, "-")
        .detached(&signature)
        .await
        .unwrap();

    let entries = std::fs::read_to_string(&list).unwrap();
    assert_eq!(
        entries
            .lines()
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>(),
        [listed.canonicalize().unwrap()]
    );
    assert!(signature.exists(), "the detached signature was not written");
}

/// Only the type decides, not the number of targets: a one-element collection
/// keeps the setter, and `per_target(true)` is refused there as for any batch.
#[tokio::test]
async fn a_shared_file_is_refused_per_target_for_a_one_element_collection() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let list = workspace.join("signed.txt");

    let from_a_list = Codesign::sign(vec![&target], "-")
        .file_list(&list)
        .per_target(true)
        .await
        .unwrap_err();
    let from_an_array = Codesign::sign([&target], "-")
        .detached(&list)
        .per_target(true)
        .await
        .unwrap_err();

    assert!(
        matches!(from_a_list, Error::SharedOutputPerTarget("file_list")),
        "got {from_a_list:?}"
    );
    assert!(
        matches!(from_an_array, Error::SharedOutputPerTarget("detached")),
        "got {from_an_array:?}"
    );
    assert!(!list.exists(), "the shared file was written anyway");
    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn a_shared_file_is_accepted_once_per_target_is_switched_back_off() {
    let workspace = Workspace::new();
    let targets = vec![workspace.unsigned("first"), workspace.unsigned("second")];
    let list = workspace.join("signed.txt");

    Codesign::sign(targets.clone(), "-")
        .per_target(true)
        .file_list(&list)
        .per_target(false)
        .await
        .unwrap();

    // One process, one list: every target's entry is there, in order.
    let listed = std::fs::read_to_string(&list).unwrap();
    let listed: Vec<_> = listed.lines().map(std::path::PathBuf::from).collect();
    let signed: Vec<_> = targets.iter().map(|t| t.canonicalize().unwrap()).collect();
    assert_eq!(listed, signed);
}

/// The order is part of the contract (ADR-0012): `validate`, then the
/// shared-output check, then the targets themselves. Each case trips two checks
/// at once and has to report the earlier one.
#[tokio::test]
async fn the_checks_made_before_running_come_in_a_fixed_order() {
    let workspace = Workspace::new();
    let missing = workspace.join("nowhere.bin");
    let list = workspace.join("signed.txt");
    let no_targets = Vec::<std::path::PathBuf>::new;

    let invalid_option_and_shared_output = Codesign::sign_adhoc(vec![workspace.join("hello")])
        .detached(&list)
        .file_list("-")
        .per_target(true)
        .await
        .unwrap_err();
    assert!(
        matches!(invalid_option_and_shared_output, Error::FileListToStdout),
        "got {invalid_option_and_shared_output:?}"
    );

    let invalid_option_and_no_targets = Codesign::sign_adhoc(no_targets())
        .file_list("-")
        .await
        .unwrap_err();
    assert!(
        matches!(invalid_option_and_no_targets, Error::FileListToStdout),
        "got {invalid_option_and_no_targets:?}"
    );

    let shared_output_and_no_targets = Codesign::sign_adhoc(no_targets())
        .file_list(&list)
        .per_target(true)
        .await
        .unwrap_err();
    assert!(
        matches!(
            shared_output_and_no_targets,
            Error::SharedOutputPerTarget("file_list")
        ),
        "got {shared_output_and_no_targets:?}"
    );

    let shared_output_and_bad_targets =
        Codesign::sign_adhoc(vec![std::path::PathBuf::new(), missing.clone()])
            .detached(&list)
            .per_target(true)
            .await
            .unwrap_err();
    assert!(
        matches!(
            shared_output_and_bad_targets,
            Error::SharedOutputPerTarget("detached")
        ),
        "got {shared_output_and_bad_targets:?}"
    );
}
