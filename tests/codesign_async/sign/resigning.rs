//! Re-signing a target that already carries a signature: `force`, and the
//! three starting states — unsigned, linker-signed, properly signed — that
//! determine whether it's needed. Each test checks both the outcome and that
//! the *other* signature was left alone.

use signers::codesign::sign;

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};
use crate::support::skip;

#[tokio::test]
async fn re_signing_without_force_fails_and_changes_nothing() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.original"]);
    let before = Signature::of(&target).cd_hash().to_owned();

    let error = sign(&target, "-")
        .identifier("com.example.replacement")
        .await
        .unwrap_err();

    assert!(crate::codesign_error(error).contains("is already signed"));
    let after = Signature::of(&target);
    assert_eq!(
        after.cd_hash(),
        before,
        "the existing signature was disturbed"
    );
    assert_eq!(after.identifier(), "com.example.original");
}

#[tokio::test]
async fn force_replaces_an_existing_signature() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.original"]);
    let before = Signature::of(&target).cd_hash().to_owned();

    sign(&target, "-")
        .force(true)
        .identifier("com.example.replacement")
        .await
        .unwrap();

    let after = Signature::of(&target);
    assert_eq!(after.identifier(), "com.example.replacement");
    assert_ne!(after.cd_hash(), before, "the signature was not rewritten");
    inspect::assert_valid(&target);
}

#[tokio::test]
async fn a_linker_signature_is_replaced_without_force() {
    let workspace = Workspace::new();
    let target = workspace.linker_signed("hello");
    if !inspect::is_signed(&target) {
        skip!("only the Apple Silicon linker signs what it links");
    }
    assert!(
        Signature::of(&target)
            .flag_names()
            .contains(&"linker-signed")
    );

    sign(&target, "-")
        .identifier("com.example.relinked")
        .await
        .unwrap();

    let signature = Signature::of(&target);
    assert_eq!(signature.identifier(), "com.example.relinked");
    assert!(
        !signature.flag_names().contains(&"linker-signed"),
        "the provisional linker signature survived",
    );
}

#[tokio::test]
async fn force_on_an_unsigned_target_is_harmless() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    sign(&target, "-").force(true).await.unwrap();

    inspect::assert_valid(&target);
}
