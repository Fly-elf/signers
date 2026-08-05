//! `preserve_metadata`: which parts of an old signature carry over into a
//! forced re-sign.

use signers::codesign::{Codesign, PreserveMetadata};

use crate::support::fixture::{Workspace, fixture_str};
use crate::support::inspect::{self, Signature};

/// Every name in the token list has to be one `codesign` accepts, or the
/// whole comma-separated argument is rejected.
#[tokio::test]
async fn every_preserve_metadata_token_is_accepted() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.original"]);

    Codesign::sign(&target, "-")
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
    let presign = ["-i", "com.example.original", "--entitlements", &entitlements];
    let preserved = workspace.presigned("preserved", &presign);
    let discarded = workspace.presigned("discarded", &presign);

    Codesign::sign(&preserved, "-")
        .force(true)
        .preserve_metadata(PreserveMetadata::IDENTIFIER | PreserveMetadata::ENTITLEMENTS)
        .await
        .unwrap();

    // Control: the same re-sign without the option keeps neither.
    Codesign::sign(&discarded, "-").force(true).await.unwrap();

    assert_eq!(Signature::of(&preserved).identifier(), "com.example.original");
    assert!(inspect::entitlements(&preserved).contains("allow-jit"));

    assert_ne!(Signature::of(&discarded).identifier(), "com.example.original");
    assert!(inspect::entitlements(&discarded).is_empty());
}
