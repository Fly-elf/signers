//! What the builder rejects before it ever spawns `codesign`: empty targets,
//! missing targets, and the access errors found while checking for them.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use signers::{Codesign, Error};

use crate::support::fixture::Workspace;
use crate::support::inspect;
use crate::support::running_as_root;

#[tokio::test]
async fn an_empty_target_is_rejected() {
    let error = Codesign::remove_signature("").await.unwrap_err();
    assert!(matches!(error, Error::NoTargets), "got {error:?}");
}

#[tokio::test]
async fn an_empty_target_list_is_rejected() {
    let error = Codesign::remove_signature(Vec::<PathBuf>::new())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NoTargets), "got {error:?}");
}

#[tokio::test]
async fn a_missing_target_is_reported_with_its_path() {
    let workspace = Workspace::new();
    let missing = workspace.join("nowhere.bin");

    let error = Codesign::remove_signature(missing.clone())
        .await
        .unwrap_err();

    match error {
        Error::TargetNotFound(path) => assert_eq!(path, missing),
        other => panic!("expected TargetNotFound, got {other:?}"),
    }
}

/// The pre-flight check matters more here than anywhere else: removal cannot be
/// undone, so a batch that half-applies leaves the caller with signatures they
/// have no way of putting back.
#[tokio::test]
async fn a_missing_target_aborts_the_whole_batch() {
    let workspace = Workspace::new();
    let present = workspace.adhoc_signed("present");
    let missing = workspace.join("missing");

    let error = Codesign::remove_signature(vec![present.clone(), missing.clone()])
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::TargetNotFound(path) if *path == missing),
        "got {error:?}",
    );
    assert!(
        inspect::is_signed(&present),
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

    let error = Codesign::remove_signature(target.clone())
        .await
        .unwrap_err();

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
