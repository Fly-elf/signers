//! A target signed with a certificate rather than ad hoc. The identity is a
//! throwaway in a keychain of its own, hence the `keychain` test group:
//!
//! ```text
//! RUSTFLAGS='--cfg signers_test="keychain"' cargo test
//! ```

use signers::Codesign;
use signers::codesign::{Authority, SignatureKind};

use crate::support::fixture::Workspace;
use crate::support::identity::Identity;
use crate::support::inspect;

#[tokio::test]
#[cfg_attr(not(signers_test = "keychain"), ignore = "test group: keychain")]
async fn a_certificate_signature_names_its_signer() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let identity = Identity::new();
    inspect::codesign(&[
        "--sign".as_ref(),
        identity.name().as_ref(),
        "--keychain".as_ref(),
        identity.keychain().as_ref(),
        target.as_ref(),
    ])
    .expect_success("sign with the throwaway identity");

    let signature = Codesign::display(&target).await.unwrap();

    let SignatureKind::Certificate { authorities, .. } = &signature.signature else {
        panic!("not a certificate signature: {:?}", signature.signature);
    };
    assert_eq!(authorities, &[Authority::Name(identity.name().to_owned())]);
    assert_eq!(signature.raw(), inspect::Signature::of(&target).raw());
    assert_eq!(
        signature.code_directory.flags.bits() & 0x2,
        0,
        "signed ad hoc"
    );
}
