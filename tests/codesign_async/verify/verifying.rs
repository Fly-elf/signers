//! Verifying a bare Mach-O or file: what passes, what fails and how, and that
//! the target is left alone either way.

use std::fs;

use signers::codesign::Strict;
use signers::codesign::remove_signature;
use signers::{Codesign, CodesignError, Error};

use super::{break_signature, requirement_unsatisfied, verification_failed};
use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn an_ad_hoc_signed_binary_verifies() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    Codesign::verify(&target).await.unwrap();
}

/// The state a freshly linked binary arrives in on Apple Silicon.
#[tokio::test]
async fn a_linker_signed_binary_verifies() {
    let workspace = Workspace::new();
    let target = workspace.linker_signed("hello");
    if !inspect::is_signed(&target) {
        crate::support::skip!("this linker leaves binaries unsigned");
    }

    Codesign::verify(&target).await.unwrap();
}

#[tokio::test]
async fn a_signed_dylib_verifies() {
    let workspace = Workspace::new();
    let target = workspace.unsigned_dylib("hello.dylib");
    Codesign::sign(&target, "-").await.unwrap();

    Codesign::verify(&target).await.unwrap();
}

#[tokio::test]
async fn a_signed_plain_file_verifies() {
    let workspace = Workspace::new();
    let target = workspace.write("notes.txt", "not a Mach-O file\n");
    Codesign::sign(&target, "-").await.unwrap();

    Codesign::verify(&target).await.unwrap();
}

/// What a caller re-signing a patched binary checks next.
#[tokio::test]
async fn a_binary_signed_by_the_library_verifies() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    Codesign::sign(&target, "-")
        .identifier("com.example.verified")
        .await
        .unwrap();

    Codesign::verify(&target).await.unwrap();
}

#[tokio::test]
async fn an_unsigned_binary_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::verify(&target).await.unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains("code object is not signed at all"),
        "got {stderr}"
    );
}

/// Verifying is the same question whether the signature was never there or
/// was taken away.
#[tokio::test]
async fn a_binary_stripped_of_its_signature_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    remove_signature(&target).await.unwrap();

    let error = Codesign::verify(&target).await.unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn a_modified_binary_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    break_signature(&target);

    let error = Codesign::verify(&target).await.unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("invalid signature"), "got {stderr}");
}

#[tokio::test]
async fn the_failure_names_the_target_it_is_about() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::verify(&target).await.unwrap_err();

    assert!(
        error.to_string().contains(&target.display().to_string()),
        "unhelpful message: {error}"
    );
}

/// An unsigned plain file is as unsigned as an unsigned executable.
#[tokio::test]
async fn an_unsigned_plain_file_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.write("notes.txt", "not a Mach-O file\n");

    let error = Codesign::verify(&target).await.unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn a_plain_directory_does_not_verify() {
    let workspace = Workspace::new();
    let target = workspace.dir("not-a-bundle");

    let error = Codesign::verify(&target).await.unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains("bundle format unrecognized"),
        "got {stderr}"
    );
}

#[tokio::test]
async fn verifying_leaves_the_target_untouched() {
    let workspace = Workspace::new();
    let valid = workspace.adhoc_signed("valid");
    let unsigned = workspace.unsigned("unsigned");
    let broken = workspace.adhoc_signed("broken");
    break_signature(&broken);
    let targets = [valid, unsigned, broken];
    let before = targets.each_ref().map(|path| fs::read(path).unwrap());

    for target in &targets {
        let _ = Codesign::verify(target).await;
        let _ = Codesign::verify(target)
            .deep(true)
            .strict(Strict::All)
            .await;
    }

    for (target, before) in targets.iter().zip(before) {
        assert_eq!(
            fs::read(target).unwrap(),
            before,
            "{} changed",
            target.display()
        );
    }
}

#[tokio::test]
async fn spaces_and_non_ascii_in_a_path_are_passed_through_verbatim() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("héllo wörld ✓.bin");

    Codesign::verify(&target).await.unwrap();
}

/// A name that looks like an option is still a path: the trailing `--` keeps
/// `codesign` from reading it as one.
#[tokio::test]
async fn a_target_named_like_an_option_is_still_a_path() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("--deep");

    Codesign::verify(&target).await.unwrap();
}

/// The output type is part of the public contract: callers that match on
/// `Ok(())` must keep compiling.
#[tokio::test]
async fn awaiting_a_verification_yields_unit() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let result: signers::Result<()> = Codesign::verify(&target).await;

    assert!(matches!(result, Ok(())));
}

#[tokio::test]
async fn a_verification_failure_is_a_codesign_error_so_the_question_mark_works() {
    async fn check(path: &std::path::Path) -> signers::Result<()> {
        Codesign::verify(path).await?;
        Ok(())
    }
    let workspace = Workspace::new();

    let error = check(&workspace.unsigned("hello")).await.unwrap_err();

    assert!(matches!(
        error,
        Error::Codesign(CodesignError::VerificationFailed { .. })
    ));
    assert!(
        !matches!(
            error,
            Error::Codesign(CodesignError::RequirementUnsatisfied { .. })
        ),
        "an unsigned target is not an unsatisfied requirement"
    );
}

/// Exit 1 and exit 3 are different questions: broken signatures never read as
/// "valid, wrong signer".
#[tokio::test]
async fn a_broken_signature_is_never_reported_as_an_unsatisfied_requirement() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    break_signature(&target);

    let error = Codesign::verify(&target)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn a_valid_signature_that_misses_the_requirement_is_not_a_verification_failure() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    requirement_unsatisfied(error);
}
