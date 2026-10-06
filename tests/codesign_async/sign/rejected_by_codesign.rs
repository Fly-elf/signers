//! Targets and identities that `codesign` itself refuses, checked as much for
//! the diagnostics surviving the trip as for the failure itself.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use signers::codesign::sign;

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};
use crate::support::{running_as_root, skip};

#[tokio::test]
async fn a_plain_file_is_signed_as_a_generic_target() {
    let workspace = Workspace::new();
    let target = workspace.write("notes.txt", "not a Mach-O file\n");

    sign(&target, "-").await.unwrap();

    assert_eq!(Signature::of(&target).format(), "generic");
    inspect::assert_valid(&target);
}

#[tokio::test]
async fn a_plain_directory_is_rejected() {
    let workspace = Workspace::new();
    let target = workspace.dir("not-a-bundle");

    let error = sign(&target, "-").await.unwrap_err();

    assert!(crate::codesign_error(error).contains("bundle format unrecognized"));
}

#[tokio::test]
async fn an_unknown_identity_is_reported_verbatim() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = sign(&target, "No Such Identity 12345").await.unwrap_err();

    let stderr = crate::codesign_error(error);
    assert!(stderr.contains("no identity found"), "got {stderr}");
    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn a_failure_inside_codesign_is_surfaced_with_its_diagnostics() {
    if running_as_root() {
        skip!("root writes wherever it likes");
    }
    let workspace = Workspace::new();
    let locked = workspace.dir("locked");
    let target = workspace.unsigned("locked/hello");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();

    let result = sign(&target, "-").await;

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    let stderr = crate::codesign_error(result.unwrap_err());
    assert!(
        stderr.contains("hello"),
        "the diagnostics name no target: {stderr}"
    );
}

/// Without root `codesign` cannot open the system's signature database, which
/// is how this shows the option reached it at all.
#[tokio::test]
async fn a_detached_database_signature_needs_root() {
    if running_as_root() {
        skip!("as root this would write to the system's signature database");
    }
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = sign(&target, "-")
        .detached_database(true)
        .await
        .unwrap_err();

    assert!(crate::codesign_error(error).contains("cannot access a database"));
    assert!(!inspect::is_signed(&target));
}
