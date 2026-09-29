//! Targets that `codesign` itself refuses, checked as much for the diagnostics
//! surviving the trip as for the failure itself.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use signers::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect;
use crate::support::{running_as_root, skip};

#[tokio::test]
async fn a_plain_directory_is_rejected() {
    let workspace = Workspace::new();
    let target = workspace.dir("not-a-bundle");

    let error = Codesign::remove_signature(&target).await.unwrap_err();

    assert!(crate::codesign_error(error).contains("bundle format unrecognized"));
}

/// A batch stops at the first target `codesign` refuses, so the ones after it
/// keep their signatures — the crate does not pass `--continue`.
#[tokio::test]
async fn a_rejected_target_stops_the_batch_where_it_stands() {
    let workspace = Workspace::new();
    let bad = workspace.dir("not-a-bundle");
    let after = workspace.adhoc_signed("after");

    let error = Codesign::remove_signature(vec![bad, after.clone()])
        .await
        .unwrap_err();

    assert!(crate::codesign_error(error).contains("bundle format unrecognized"));
    assert!(
        inspect::is_signed(&after),
        "the batch carried on past the target codesign refused"
    );
}

#[tokio::test]
async fn a_read_only_directory_is_surfaced_with_its_diagnostics() {
    if running_as_root() {
        skip!("root writes wherever it likes");
    }
    let workspace = Workspace::new();
    let locked = workspace.dir("locked");
    let target = workspace.adhoc_signed("locked/hello");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();

    let result = Codesign::remove_signature(&target).await;

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    let stderr = crate::codesign_error(result.unwrap_err());
    assert!(
        stderr.contains("hello"),
        "the diagnostics name no target: {stderr}"
    );
    assert!(
        inspect::is_signed(&target),
        "the signature went away despite the failure"
    );
}
