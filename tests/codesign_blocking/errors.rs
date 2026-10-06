//! Every error the real `codesign` can make a run end in, reaching the caller
//! of `.run()` as it reaches the caller of `.await`.

use std::fs;

use signers::blocking::Codesign;
use signers::codesign::SignatureSlot;
use signers::codesign::blocking::{extract_certificates, validate_constraint};
use signers::{CodesignError, Error};

use crate::support::fixture::{Workspace, fixture};
use crate::support::inspect;

#[test]
fn a_refused_target_is_a_failed_run_with_codesigns_diagnostics() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let before = fs::read(&target).unwrap();

    let error = Codesign::sign_adhoc(&target).run().unwrap_err();

    match error {
        Error::Codesign(CodesignError::Failed { code, stderr, .. }) => {
            assert_eq!(code, 1);
            assert!(stderr.contains("is already signed"), "{stderr}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(fs::read(&target).unwrap(), before);
}

#[test]
fn an_unsigned_target_fails_verification() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::verify(&target).run().unwrap_err();

    match error {
        Error::Codesign(CodesignError::VerificationFailed { stderr, .. }) => {
            assert!(stderr.contains("not signed at all"), "{stderr}");
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

#[test]
fn an_unmet_requirement_is_requirement_unsatisfied() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement("anchor apple")
        .run()
        .unwrap_err();

    assert!(
        matches!(
            error,
            Error::Codesign(CodesignError::RequirementUnsatisfied { .. })
        ),
        "got {error:?}"
    );
    inspect::assert_valid(&target);
}

#[test]
fn an_invalid_constraint_is_constraint_invalid() {
    let error = validate_constraint(fixture("bad-constraint.plist"))
        .run()
        .unwrap_err();

    match error {
        Error::Codesign(CodesignError::ConstraintInvalid { stderr, .. }) => {
            assert!(!stderr.is_empty(), "the rejection carried no diagnostics");
        }
        other => panic!("expected ConstraintInvalid, got {other:?}"),
    }
}

#[test]
fn an_empty_signature_slot_is_no_signature() {
    let error = Codesign::display("/bin/ls")
        .signature_slot(SignatureSlot::Second)
        .run()
        .unwrap_err();

    match error {
        Error::Codesign(CodesignError::NoSignature { stderr, .. }) => {
            assert!(stderr.contains("/bin/ls: no signature"), "{stderr}");
        }
        other => panic!("expected NoSignature, got {other:?}"),
    }
}

#[test]
fn a_certificate_directory_that_is_a_file_is_an_io_error() {
    let workspace = Workspace::new();
    let out = workspace.write("out", "not a directory\n");

    let error = extract_certificates("/bin/ls")
        .save_to(&out)
        .run()
        .unwrap_err();

    match error {
        Error::Io { path, .. } => assert_eq!(path, out),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fs::read_to_string(&out).unwrap(), "not a directory\n");
}
