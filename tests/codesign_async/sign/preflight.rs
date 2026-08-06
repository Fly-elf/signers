//! What the builder rejects before it ever spawns `codesign`: empty targets,
//! missing targets, the access errors found while checking for them, and
//! option values this crate cannot honour (`file_list("-")`).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use signers::Error;
use signers::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect;
use crate::support::running_as_root;

#[tokio::test]
async fn an_empty_target_is_rejected() {
    let error = Codesign::sign("", "-").await.unwrap_err();
    assert!(matches!(error, Error::NoTargets), "got {error:?}");
}

#[tokio::test]
async fn an_empty_target_list_is_rejected() {
    let error = Codesign::sign(Vec::<PathBuf>::new(), "-")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NoTargets), "got {error:?}");
}

#[tokio::test]
async fn a_list_of_nothing_but_empty_targets_is_rejected() {
    let error = Codesign::sign(vec!["", ""], "-").await.unwrap_err();
    assert!(matches!(error, Error::NoTargets), "got {error:?}");
}

#[tokio::test]
async fn a_missing_target_is_reported_with_its_path() {
    let workspace = Workspace::new();
    let missing = workspace.join("nowhere.bin");

    let error = Codesign::sign(missing.clone(), "-").await.unwrap_err();

    match error {
        Error::TargetNotFound(path) => assert_eq!(path, missing),
        other => panic!("expected TargetNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn a_missing_target_aborts_the_whole_batch() {
    // The pre-flight check is the difference: handed the same arguments,
    // `codesign` signs the targets it can and only then fails on the missing
    // one, leaving the caller with a half-applied operation.
    let workspace = Workspace::new();
    let present = workspace.unsigned("present");
    let missing = workspace.join("missing");

    let error = Codesign::sign(vec![present.clone(), missing.clone()], "-")
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::TargetNotFound(path) if *path == missing),
        "got {error:?}",
    );
    assert!(
        !inspect::is_signed(&present),
        "the batch was applied even though one target was missing",
    );
}

#[tokio::test]
async fn an_unreadable_parent_directory_is_an_access_error() {
    if running_as_root() {
        return; // root is exempt from the permission bits this relies on
    }
    let workspace = Workspace::new();
    let locked = workspace.dir("locked");
    let target = workspace.join("locked/hidden.bin");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    let error = Codesign::sign(target.clone(), "-").await.unwrap_err();

    // Reopen before asserting, so a failure still leaves a removable workspace.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    match error {
        Error::TargetAccess { path, source } => {
            assert_eq!(path, target);
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected TargetAccess, got {other:?}"),
    }
}

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

#[tokio::test]
async fn a_failure_says_which_target_it_is_about() {
    let workspace = Workspace::new();
    let missing = workspace.join("ghost.bin");

    let error = Codesign::sign(missing.clone(), "-").await.unwrap_err();

    assert!(
        error.to_string().contains(&missing.display().to_string()),
        "unhelpful message: {error}",
    );
}
