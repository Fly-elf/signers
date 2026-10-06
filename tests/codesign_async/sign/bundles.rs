//! `.app` bundles and versioned frameworks: identifier derivation from
//! `Info.plist`, resource sealing, `deep`, and `bundle_version`.

use std::fs;

use signers::codesign::sign;

use crate::support::fixture::{Workspace, output_of};
use crate::support::inspect::{self, Signature};

#[tokio::test]
async fn an_app_bundle_is_signed_from_its_info_plist() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Hello");

    sign(&bundle, "-").await.unwrap();

    inspect::assert_valid(&bundle);
    let signature = Signature::of(&bundle);
    assert_eq!(signature.identifier(), "com.example.Hello");
    assert!(
        signature.sealed_resources().starts_with("version="),
        "got {}",
        signature.sealed_resources()
    );
    assert!(
        signature.info_plist().starts_with("entries="),
        "got {}",
        signature.info_plist()
    );
    assert!(
        bundle
            .join("Contents/_CodeSignature/CodeResources")
            .is_file()
    );
    assert_eq!(
        output_of(&bundle.join("Contents/MacOS/Hello")),
        "hello, signers"
    );
}

#[tokio::test]
async fn a_signed_bundle_seals_its_resources() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Sealed");

    sign(&bundle, "-").await.unwrap();
    inspect::assert_valid(&bundle);

    fs::write(bundle.join("Contents/smuggled.txt"), "added after signing").unwrap();

    assert!(
        inspect::verify(&bundle).is_err(),
        "the resource seal did not notice a file added after signing",
    );
}

#[tokio::test]
#[expect(
    deprecated,
    reason = "`deep` is deprecated by Apple but still has to work"
)]
async fn deep_signing_is_still_wired_up() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Deep");

    sign(&bundle, "-")
        .deep(true)
        .identifier("com.example.deep")
        .await
        .unwrap();

    inspect::assert_valid(&bundle);
    assert_eq!(Signature::of(&bundle).identifier(), "com.example.deep");
}

#[tokio::test]
async fn a_bundle_version_selects_which_version_to_sign() {
    let workspace = Workspace::new();
    let bundle = workspace.framework("Hello");

    sign(&bundle, "-")
        .bundle_version("A")
        .identifier("com.example.versioned")
        .await
        .unwrap();

    inspect::assert_valid(&bundle);
    assert_eq!(Signature::of(&bundle).identifier(), "com.example.versioned");
    assert!(
        bundle
            .join("Versions/A/_CodeSignature/CodeResources")
            .is_file()
    );
}
