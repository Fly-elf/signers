//! Targets and identities that `codesign` itself refuses, checked as much for
//! the diagnostics surviving the trip as for the failure itself.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use signers::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};
use crate::support::running_as_root;

#[tokio::test]
async fn a_plain_file_is_signed_as_a_generic_target() {
    let workspace = Workspace::new();
    let target = workspace.write("notes.txt", "not a Mach-O file\n");

    Codesign::sign(&target, "-").await.unwrap();

    assert_eq!(Signature::of(&target).format(), "generic");
    inspect::assert_valid(&target);
}

#[tokio::test]
async fn a_plain_directory_is_rejected() {
    let workspace = Workspace::new();
    let target = workspace.dir("not-a-bundle");

    let error = Codesign::sign(&target, "-").await.unwrap_err();

    assert!(super::codesign_error(error).contains("bundle format unrecognized"));
}

#[tokio::test]
async fn an_unknown_identity_is_reported_verbatim() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::sign(&target, "No Such Identity 12345")
        .await
        .unwrap_err();

    let stderr = super::codesign_error(error);
    assert!(stderr.contains("no identity found"), "got {stderr}");
    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn a_failure_inside_codesign_is_surfaced_with_its_diagnostics() {
    if running_as_root() {
        return; // root writes wherever it likes
    }
    let workspace = Workspace::new();
    let locked = workspace.dir("locked");
    let target = workspace.unsigned("locked/hello");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();

    let result = Codesign::sign(&target, "-").await;

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    let stderr = super::codesign_error(result.unwrap_err());
    assert!(
        stderr.contains("hello"),
        "the diagnostics name no target: {stderr}"
    );
}
