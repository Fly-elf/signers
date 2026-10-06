//! `signature_slot`: which of a code object's signatures is verified. Every
//! signature this machine can make is a single one, so the second slot is only
//! ever checked against what `codesign` itself answers.

use signers::Error;
use signers::codesign::SignatureSlot;
use signers::codesign::verify;

use super::{break_signature, requirement_unsatisfied, verification_failed};
use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn the_first_slot_verifies_a_signed_binary() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    verify(&target)
        .signature_slot(SignatureSlot::First)
        .await
        .unwrap();
    verify("/bin/ls")
        .signature_slot(SignatureSlot::First)
        .await
        .unwrap();
}

/// The system binary has one signature, so asking for a second one fails the
/// way `codesign` itself does.
#[tokio::test]
async fn the_second_slot_of_a_single_signature_binary_does_not_verify() {
    let oracle = inspect::codesign(&[
        "--verify".as_ref(),
        "--signature-slot".as_ref(),
        "2".as_ref(),
        "/bin/ls".as_ref(),
    ]);
    assert!(!oracle.success);

    let error = verify("/bin/ls")
        .signature_slot(SignatureSlot::Second)
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("not signed at all"), "got {stderr}");
}

#[tokio::test]
async fn the_second_slot_of_an_ad_hoc_binary_follows_codesign() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let oracle = inspect::codesign(&[
        "--verify".as_ref(),
        "--signature-slot".as_ref(),
        "2".as_ref(),
        target.as_ref(),
    ]);

    let result = verify(&target).signature_slot(SignatureSlot::Second).await;

    assert_eq!(result.is_ok(), oracle.success, "{}", oracle.stderr);
}

#[tokio::test]
async fn an_unsigned_binary_fails_in_either_slot() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    for slot in [SignatureSlot::First, SignatureSlot::Second] {
        let error = verify(&target).signature_slot(slot).await.unwrap_err();
        let stderr = verification_failed(error);
        assert!(
            stderr.contains("not signed at all"),
            "{slot:?}: got {stderr}"
        );
    }
}

#[tokio::test]
async fn a_broken_signature_fails_in_the_first_slot() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    break_signature(&target);

    let error = verify(&target)
        .signature_slot(SignatureSlot::First)
        .await
        .unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn the_last_slot_wins() {
    let result = verify("/bin/ls")
        .signature_slot(SignatureSlot::Second)
        .signature_slot(SignatureSlot::First)
        .await;
    result.unwrap();

    let error = verify("/bin/ls")
        .signature_slot(SignatureSlot::First)
        .signature_slot(SignatureSlot::Second)
        .await
        .unwrap_err();
    verification_failed(error);
}

#[tokio::test]
async fn a_slot_combines_with_a_requirement() {
    let workspace = Workspace::new();
    let requirement = workspace.write("req.txt", "anchor apple\n");

    verify("/bin/ls")
        .signature_slot(SignatureSlot::First)
        .test_requirement("anchor apple")
        .await
        .unwrap();
    verify("/bin/ls")
        .signature_slot(SignatureSlot::First)
        .test_requirement_file(&requirement)
        .await
        .unwrap();

    let error = verify("/bin/ls")
        .signature_slot(SignatureSlot::First)
        .test_requirement("!anchor apple")
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
}

/// With one target per process, each target is judged on its own slot result.
#[tokio::test]
async fn a_slot_applies_to_every_target_of_a_batch() {
    let workspace = Workspace::new();
    let unsigned = workspace.unsigned("unsigned");
    let signed = workspace.adhoc_signed("signed");

    let error = verify(vec![signed.clone(), unsigned.clone()])
        .signature_slot(SignatureSlot::First)
        .await
        .unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected Batch, got {error:?}");
    };
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, unsigned);
}

#[test]
fn slots_compare_and_copy_by_value() {
    let slot = SignatureSlot::First;
    let copy = slot;
    assert_eq!(slot, copy);
    assert_ne!(SignatureSlot::First, SignatureSlot::Second);
    assert_eq!(format!("{:?}", SignatureSlot::Second), "Second");
}
