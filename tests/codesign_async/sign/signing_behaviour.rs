//! The remaining signing-behaviour and output options: page size, timestamps,
//! xattrs, the keychain hint, dry runs, and the collateral files a signing run
//! can produce.

use std::fs;
use std::path::Path;

use signers::codesign::Timestamp;
use signers::codesign::sign;

use crate::support::fixture::{Workspace, set_xattr};
use crate::support::inspect::{self, Signature};

#[tokio::test]
async fn the_page_size_sets_the_signing_granularity() {
    let workspace = Workspace::new();
    let default = workspace.unsigned("default");
    let fine = workspace.unsigned("fine");
    let single = workspace.unsigned("single");

    sign(&default, "-").await.unwrap();
    sign(&fine, "-").page_size(4096).await.unwrap();
    sign(&single, "-").page_size(0).await.unwrap();

    assert_eq!(Signature::of(&default).page_size(), Some(16384));
    assert_eq!(Signature::of(&fine).page_size(), Some(4096));
    // `0` means "seal the whole thing as one page", which `codesign` reports as
    // no page size at all.
    assert_eq!(Signature::of(&single).page_size(), None);

    // Quarter the page, four times the hashes.
    assert!(Signature::of(&fine).code_hashes() > Signature::of(&default).code_hashes());
    assert_eq!(Signature::of(&single).code_hashes(), 1);
}

#[tokio::test]
async fn timestamping_can_be_turned_off() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    // Renders as `--timestamp=none`: the space-separated form is not accepted
    // for an option whose value is optional.
    sign(&target, "-")
        .timestamp(Timestamp::Disabled)
        .await
        .unwrap();

    inspect::assert_valid(&target);
}

/// Ad hoc signatures are never timestamped, so the server is not contacted.
/// What this settles is the rendering: as `--timestamp <url>` the URL would
/// reach `codesign` as one more target, which does not exist.
#[tokio::test]
async fn a_timestamp_server_is_passed_as_a_single_argument() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    sign(&target, "-")
        .timestamp(Timestamp::ServerUrl("http://127.0.0.1:9".into()))
        .await
        .unwrap();

    inspect::assert_valid(&target);
}

#[tokio::test]
async fn a_dry_run_signs_nothing() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    sign(&target, "-").dry_run(true).await.unwrap();

    assert!(!inspect::is_signed(&target), "a dry run wrote a signature");
}

#[tokio::test]
async fn a_dry_run_writes_no_detached_signature_either() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let detached = workspace.join("hello.sig");

    sign(&target, "-")
        .dry_run(true)
        .detached(&detached)
        .await
        .unwrap();

    assert!(!detached.exists(), "a dry run wrote {}", detached.display());
    assert!(!inspect::is_signed(&target));
}

#[tokio::test]
async fn a_detached_signature_leaves_the_target_untouched() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let detached = workspace.join("hello.sig");

    sign(&target, "-").detached(&detached).await.unwrap();

    assert!(
        !inspect::is_signed(&target),
        "the signature was embedded anyway"
    );
    assert!(detached.is_file(), "no signature was written");
    inspect::verify_detached(&detached, &target).unwrap();
}

#[tokio::test]
async fn the_file_list_records_what_was_signed() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let list = workspace.join("signed.txt");

    sign(&target, "-").file_list(&list).await.unwrap();

    // `codesign` writes resolved paths, and a macOS temporary directory sits
    // under a symlink (`/var` -> `/private/var`).
    let signed = target.canonicalize().unwrap();
    let listed = fs::read_to_string(&list).unwrap();
    assert!(
        listed.lines().any(|line| Path::new(line) == signed),
        "{} is not in the file list:\n{listed}",
        signed.display(),
    );
}

#[tokio::test]
async fn disallowed_xattrs_are_stripped_only_on_request() {
    let workspace = Workspace::new();
    let kept = workspace.unsigned("kept");
    let stripped = workspace.unsigned("stripped");
    for target in [&kept, &stripped] {
        set_xattr(target, "com.apple.ResourceFork", "detritus");
    }

    let error = sign(&kept, "-").await.unwrap_err();
    sign(&stripped, "-")
        .strip_disallowed_xattrs(true)
        .await
        .unwrap();

    assert!(crate::codesign_error(error).contains("detritus not allowed"));
    inspect::assert_valid(&stripped);
    assert!(
        !inspect::xattrs(&stripped).contains(&"com.apple.ResourceFork".to_owned()),
        "the resource fork survived"
    );
}

#[tokio::test]
async fn a_keychain_hint_does_not_get_in_the_way() {
    // `--keychain` only narrows where an identity is looked up, and the ad-hoc
    // identity needs no lookup — so even a nonexistent keychain is no obstacle.
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    sign(&target, "-")
        .keychain("/nonexistent/does-not.keychain")
        .await
        .unwrap();

    inspect::assert_valid(&target);
}
