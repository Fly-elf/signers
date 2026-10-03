//! The options that pick what is verified against what: an architecture
//! slice, a detached signature, notarization.

use std::fs;
use std::path::Path;

use signers::Codesign;

use super::{flip_byte, verification_failed};
use crate::support::fixture::Workspace;
use crate::support::inspect;
use crate::support::skip;

/// Offset of the `x86_64` slice inside a fat file, read from its header.
fn x86_64_slice_offset(path: &Path) -> u64 {
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    let bytes = fs::read(path).unwrap();
    let word = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    assert_eq!(word(0), 0xcafe_babe, "not a 32-bit fat file");
    (0..word(4) as usize)
        .map(|i| 8 + 20 * i)
        .find(|&entry| word(entry) == CPU_TYPE_X86_64)
        .map(|entry| u64::from(word(entry + 8)))
        .expect("no x86_64 slice")
}

/// A universal fixture signed ad hoc, with only its `x86_64` slice broken.
fn universal_with_a_broken_x86_64_slice(workspace: &Workspace) -> Option<std::path::PathBuf> {
    let target = workspace.unsigned_universal("universal")?;
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), target.as_ref()])
        .expect_success("pre-sign the universal fixture");
    flip_byte(&target, x86_64_slice_offset(&target) + 0x800);
    assert!(
        inspect::codesign(&[
            "--verify".as_ref(),
            "--architecture".as_ref(),
            "x86_64".as_ref(),
            target.as_ref()
        ])
        .stderr
        .contains("invalid signature"),
        "the harness did not break the x86_64 slice"
    );
    Some(target)
}

#[tokio::test]
async fn every_slice_is_checked_by_default() {
    let workspace = Workspace::new();
    let Some(target) = universal_with_a_broken_x86_64_slice(&workspace) else {
        skip!("this toolchain can't build a universal binary");
    };

    let error = Codesign::verify(&target).await.unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("x86_64"), "got {stderr}");
}

#[tokio::test]
async fn an_architecture_limits_the_check_to_its_slice() {
    let workspace = Workspace::new();
    let Some(target) = universal_with_a_broken_x86_64_slice(&workspace) else {
        skip!("this toolchain can't build a universal binary");
    };

    Codesign::verify(&target)
        .architecture("arm64")
        .await
        .unwrap();
    let error = Codesign::verify(&target)
        .architecture("x86_64")
        .await
        .unwrap_err();
    verification_failed(error);
}

#[tokio::test]
async fn the_last_architecture_wins() {
    let workspace = Workspace::new();
    let Some(target) = universal_with_a_broken_x86_64_slice(&workspace) else {
        skip!("this toolchain can't build a universal binary");
    };

    Codesign::verify(&target)
        .architecture("x86_64")
        .architecture("arm64")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_slice_the_binary_does_not_have_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("thin");
    let absent = if cfg!(target_arch = "aarch64") {
        "x86_64"
    } else {
        "arm64"
    };

    let error = Codesign::verify(&target)
        .architecture(absent)
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains("object file format unrecognized"),
        "got {stderr}"
    );
}

/// `all` isn't an architecture, and is not special-cased: the default already
/// covers every slice.
#[tokio::test]
async fn all_is_not_an_architecture_name() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .architecture("all")
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("unknown architecture name"), "got {stderr}");
}

#[tokio::test]
async fn an_unsigned_file_verifies_against_its_detached_signature() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let signature = workspace.join("hello.sig");
    Codesign::sign(&target, "-")
        .detached(&signature)
        .await
        .unwrap();
    assert!(!inspect::is_signed(&target));
    inspect::verify_detached(&signature, &target).expect("the harness's detached signature");

    Codesign::verify(&target)
        .detached(&signature)
        .await
        .unwrap();

    let without = Codesign::verify(&target).await.unwrap_err();
    verification_failed(without);
}

#[tokio::test]
async fn a_detached_signature_does_not_cover_a_different_file() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let signature = workspace.join("hello.sig");
    Codesign::sign(&target, "-")
        .detached(&signature)
        .await
        .unwrap();
    let other = workspace.write("other.txt", "something else entirely\n");

    let error = Codesign::verify(&other)
        .detached(&signature)
        .await
        .unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn a_missing_detached_signature_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::verify(&target)
        .detached(workspace.join("nowhere.sig"))
        .await
        .unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn the_last_detached_signature_wins() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let signature = workspace.join("hello.sig");
    Codesign::sign(&target, "-")
        .detached(&signature)
        .await
        .unwrap();

    Codesign::verify(&target)
        .detached(workspace.join("nowhere.sig"))
        .detached(&signature)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_detached_path_with_spaces_is_one_argument() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let signature = workspace.join("my hello ✓.sig");
    Codesign::sign(&target, "-")
        .detached(&signature)
        .await
        .unwrap();

    Codesign::verify(&target)
        .detached(&signature)
        .await
        .unwrap();
}

/// Asking for no notarization check is the same as not asking, so it works
/// offline.
#[tokio::test]
async fn check_notarization_false_is_the_plain_check() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    Codesign::verify(&target)
        .check_notarization(true)
        .check_notarization(false)
        .await
        .unwrap();
}

/// It reaches the network, and a target that is valid but not notarized still
/// verifies: the option is accepted, nothing more is promised.
#[tokio::test]
#[cfg_attr(not(signers_test = "network"), ignore = "test groups: network")]
async fn check_notarization_is_accepted_on_a_valid_target() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    Codesign::verify(&target)
        .check_notarization(true)
        .await
        .unwrap();
}

#[tokio::test]
#[cfg_attr(not(signers_test = "network"), ignore = "test groups: network")]
async fn check_notarization_still_reports_a_broken_signature() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::verify(&target)
        .check_notarization(true)
        .await
        .unwrap_err();

    verification_failed(error);
}
