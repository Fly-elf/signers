//! Targets signed with a certificate of our own, so chains differ from target
//! to target. The identity is a throwaway in a keychain of its own, hence the
//! `keychain` test group:
//!
//! ```text
//! RUSTFLAGS='--cfg signers_test="keychain"' cargo test
//! ```

use std::path::{Path, PathBuf};

use signers::Codesign;

use super::{PLATFORM_BINARY, ders, expected_pem, file_names, read};
use crate::support::fixture::Workspace;
use crate::support::identity::Identity;
use crate::support::inspect;

fn sign_with(identity: &Identity, target: &Path) {
    inspect::codesign(&[
        "--sign".as_ref(),
        identity.name().as_ref(),
        "--keychain".as_ref(),
        identity.keychain().as_ref(),
        target.as_ref(),
    ])
    .expect_success("sign with the throwaway identity");
}

#[tokio::test]
#[cfg_attr(not(signers_test = "keychain"), ignore = "test group: keychain")]
async fn a_certificate_signature_yields_its_own_chain() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let identity = Identity::new();
    sign_with(&identity, &target);

    let chain = Codesign::extract_certificates(&target).await.unwrap();

    assert_eq!(ders(&chain), inspect::certificates(&target));
    let (subject, _) = inspect::subject_and_issuer(chain[0].der());
    assert!(subject.contains(identity.name()), "leaf: {subject}");
}

/// Two different chains claiming one file name: each chain is matched to its
/// own target in memory, and each lands whole in one of the two files.
#[tokio::test]
#[cfg_attr(not(signers_test = "keychain"), ignore = "test group: keychain")]
async fn different_chains_under_one_file_name_each_get_a_file() {
    let workspace = Workspace::new();
    workspace.dir("own");
    let own = workspace.unsigned("own/ls");
    let identity = Identity::new();
    sign_with(&identity, &own);
    let targets = vec![own.clone(), PathBuf::from(PLATFORM_BINARY), own.clone()];
    let out = workspace.join("out");

    let chains = Codesign::extract_certificates(targets.clone())
        .save_to(&out)
        .await
        .unwrap();

    for (chain, target) in chains.iter().zip(&targets) {
        assert_eq!(
            ders(chain),
            inspect::certificates(target),
            "{}",
            target.display()
        );
    }
    assert_eq!(file_names(&out), ["ls.pem", "ls2.pem", "ls3.pem"]);
    let mut written: Vec<String> = ["ls.pem", "ls2.pem", "ls3.pem"]
        .iter()
        .map(|name| read(&out, name))
        .collect();
    let mut expected: Vec<String> = targets.iter().map(|t| expected_pem(t)).collect();
    written.sort();
    expected.sort();
    assert_eq!(written, expected);
}

#[tokio::test]
#[cfg_attr(not(signers_test = "keychain"), ignore = "test group: keychain")]
async fn a_signed_bundle_is_saved_under_its_bundle_name() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Hello");
    let identity = Identity::new();
    sign_with(&identity, &bundle);
    let out = workspace.join("out");

    Codesign::extract_certificates(&bundle)
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["Hello.app.pem"]);
    assert_eq!(read(&out, "Hello.app.pem"), expected_pem(&bundle));
}
