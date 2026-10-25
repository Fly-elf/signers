//! `preserve_metadata`: which parts of an old signature carry over into a
//! forced re-sign.

use signers::codesign::PreserveMetadata;
use signers::codesign::sign;

use crate::support::fixture::{Workspace, fixture_str};
use crate::support::inspect::{self, Signature};

/// Every name in the token list has to be one `codesign` accepts, or the
/// whole comma-separated argument is rejected.
#[tokio::test]
async fn every_preserve_metadata_token_is_accepted() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.original"]);

    sign(&target, "-")
        .force(true)
        .preserve_metadata(PreserveMetadata::all())
        .await
        .unwrap();

    assert_eq!(Signature::of(&target).identifier(), "com.example.original");
}

#[tokio::test]
async fn preserved_metadata_survives_a_re_sign() {
    let workspace = Workspace::new();
    let entitlements = fixture_str("entitlements.plist");
    let presign = [
        "-i",
        "com.example.original",
        "--entitlements",
        &entitlements,
    ];
    let preserved = workspace.presigned("preserved", &presign);
    let discarded = workspace.presigned("discarded", &presign);

    sign(&preserved, "-")
        .force(true)
        .preserve_metadata(PreserveMetadata::IDENTIFIER | PreserveMetadata::ENTITLEMENTS)
        .await
        .unwrap();

    // Control: the same re-sign without the option keeps neither.
    sign(&discarded, "-").force(true).await.unwrap();

    assert_eq!(
        Signature::of(&preserved).identifier(),
        "com.example.original"
    );
    assert!(inspect::entitlements(&preserved).contains("allow-jit"));

    assert_ne!(
        Signature::of(&discarded).identifier(),
        "com.example.original"
    );
    assert!(inspect::entitlements(&discarded).is_empty());
}

/// A set with only unnamed bits must act as an empty one: rendered as
/// `--preserve-metadata=`, `codesign` would read the empty list as a prefix
/// of its first name and keep the old identifier.
#[tokio::test]
async fn a_preserve_set_with_only_unnamed_bits_preserves_nothing() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.original"]);

    sign(&target, "-")
        .force(true)
        .preserve_metadata(PreserveMetadata::from_bits_retain(0x80))
        .await
        .unwrap();

    assert_ne!(Signature::of(&target).identifier(), "com.example.original");
}
