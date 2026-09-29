//! Signing with a certificate rather than ad hoc: keychain lookup, timestamps,
//! and the distribution preset.
//!
//! Each test creates a throwaway identity in a keychain of its own and deletes it
//! afterwards, so they sit in the `keychain` test group; the timestamp tests
//! also need Apple's timestamp server, the `network` group. A test is ignored
//! unless every group it needs is set. Run them before a release or after a
//! change to identity or timestamp handling:
//!
//! ```text
//! RUSTFLAGS='--cfg signers_test="keychain" --cfg signers_test="network"' cargo test
//! ```

use signers::Codesign;
use signers::codesign::sign::{SigningFlags, Timestamp};

use crate::support::fixture::Workspace;
use crate::support::identity::Identity;
use crate::support::inspect::{self, Signature};

#[tokio::test]
#[cfg_attr(not(signers_test = "keychain"), ignore = "test group: keychain")]
async fn a_certificate_signature_names_its_signer() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let identity = Identity::new();

    Codesign::sign(&target, identity.name())
        .keychain(identity.keychain())
        .await
        .unwrap();

    inspect::assert_valid(&target);
    let signature = Signature::of(&target);
    assert_eq!(signature.authority(), Some(identity.name()));
    assert_eq!(signature.flags() & super::ADHOC, 0, "signed ad hoc");
}

/// The identity's keychain is not on the search list, so the keychain setter is
/// the only way `codesign` can find it.
#[tokio::test]
#[cfg_attr(not(signers_test = "keychain"), ignore = "test group: keychain")]
async fn the_identity_is_looked_up_in_the_given_keychain() {
    let workspace = Workspace::new();
    let unfound = workspace.unsigned("unfound");
    let found = workspace.unsigned("found");
    let identity = Identity::new();

    let error = Codesign::sign(&unfound, identity.name()).await.unwrap_err();
    Codesign::sign(&found, identity.name())
        .keychain(identity.keychain())
        .await
        .unwrap();

    assert!(crate::codesign_error(error).contains("no identity found"));
    assert!(!inspect::is_signed(&unfound));
    assert_eq!(Signature::of(&found).authority(), Some(identity.name()));
}

#[tokio::test]
#[cfg_attr(
    not(all(signers_test = "keychain", signers_test = "network")),
    ignore = "test groups: keychain, network"
)]
async fn timestamping_can_be_turned_on() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let identity = Identity::new();

    Codesign::sign(&target, identity.name())
        .keychain(identity.keychain())
        .timestamp(Timestamp::Enabled)
        .await
        .unwrap();

    assert!(Signature::of(&target).timestamp().is_some());
}

#[tokio::test]
#[cfg_attr(
    not(all(signers_test = "keychain", signers_test = "network")),
    ignore = "test groups: keychain, network"
)]
async fn a_timestamp_server_url_is_used() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let identity = Identity::new();

    Codesign::sign(&target, identity.name())
        .keychain(identity.keychain())
        .timestamp(Timestamp::ServerUrl(
            "http://timestamp.apple.com/ts01".into(),
        ))
        .await
        .unwrap();

    assert!(Signature::of(&target).timestamp().is_some());
}

#[tokio::test]
#[cfg_attr(
    not(all(signers_test = "keychain", signers_test = "network")),
    ignore = "test groups: keychain, network"
)]
async fn the_distribution_preset_is_timestamped() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let identity = Identity::new();

    Codesign::sign_for_distribution(&target, identity.name())
        .keychain(identity.keychain())
        .await
        .unwrap();

    let signature = Signature::of(&target);
    assert!(signature.timestamp().is_some(), "{}", signature.raw());
    assert_eq!(signature.flags(), SigningFlags::RUNTIME.bits());
}
