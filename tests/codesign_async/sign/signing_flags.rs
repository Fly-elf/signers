//! `SigningFlags` (`--options`) and the hardened-runtime version that rides
//! along with them.

use signers::Codesign;
use signers::codesign::SigningFlags;

use crate::support::fixture::Workspace;
use crate::support::inspect::Signature;

#[tokio::test]
async fn option_flags_are_sealed_into_the_code_directory() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .options(SigningFlags::RUNTIME | SigningFlags::KILL)
        .await
        .unwrap();

    // Both that the tokens are spelled the way `codesign` wants, and that the
    // bit values in `SigningFlags` are the ones it actually seals.
    let signature = Signature::of(&target);
    assert_eq!(signature.flag_names(), ["adhoc", "kill", "runtime"]);
    assert_eq!(
        signature.flags(),
        super::ADHOC | SigningFlags::KILL.bits() | SigningFlags::RUNTIME.bits(),
    );
}

/// The unit tests can only check the tokens against what the crate itself
/// declares. This is what settles them against `codesign`: each flag alone,
/// asserting the bit it actually seals is the bit `SigningFlags` names.
#[tokio::test]
async fn each_signing_flag_seals_the_bit_it_claims() {
    let workspace = Workspace::new();

    for (index, flag) in SigningFlags::all().iter().enumerate() {
        let target = workspace.unsigned(format!("flag-{index}"));

        Codesign::sign(&target, "-")
            .options(flag)
            .await
            .unwrap_or_else(|e| panic!("`codesign` rejected {flag:?}: {e}"));

        assert_eq!(
            Signature::of(&target).flags(),
            super::ADHOC | flag.bits(),
            "{flag:?} did not seal the bit it names",
        );
    }
}

#[tokio::test]
async fn the_last_set_of_option_flags_wins() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .options(SigningFlags::RUNTIME)
        .options(SigningFlags::LIBRARY)
        .await
        .unwrap();

    // `codesign` takes `library` on the way in and prints `library-validation`
    // on the way out, so the bits are what settles it.
    let signature = Signature::of(&target);
    assert_eq!(
        signature.flags(),
        super::ADHOC | SigningFlags::LIBRARY.bits()
    );
    assert_eq!(signature.flag_names(), ["adhoc", "library-validation"]);
}

#[tokio::test]
async fn an_empty_flag_set_seals_nothing() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .options(SigningFlags::empty())
        .await
        .unwrap();

    assert_eq!(Signature::of(&target).flags(), super::ADHOC);
}

#[tokio::test]
async fn the_hardened_runtime_version_is_recorded() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .options(SigningFlags::RUNTIME)
        .runtime_version("12.0")
        .await
        .unwrap();

    assert_eq!(Signature::of(&target).runtime_version(), Some("12.0.0"));
}
