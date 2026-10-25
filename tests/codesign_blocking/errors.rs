//! Every error the real `codesign` can make a run end in, reaching the caller
//! of `.run()` as it reaches the caller of `.await`.

use std::fs;

use signers::codesign::SignatureSlot;
use signers::codesign::blocking::{display, sign_adhoc, verify};
use signers::codesign::blocking::{extract_certificates, validate_constraint};
use signers::{CodesignError, Error, ProcessError};

use crate::support::fixture::{Workspace, fixture};
use crate::support::inspect;

#[test]
fn a_refused_target_is_a_failed_run_with_codesigns_diagnostics() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let before = fs::read(&target).unwrap();

    let error = sign_adhoc(&target).run().unwrap_err();

    match error {
        Error::Process(ProcessError::Failed { output, .. }) => {
            assert_eq!(output.program, "codesign");
            assert_eq!(output.status.code(), Some(1));
            assert!(
                output.stderr.contains("is already signed"),
                "{}",
                output.stderr
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(fs::read(&target).unwrap(), before);
}

#[test]
fn an_unsigned_target_fails_verification() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = verify(&target).run().unwrap_err();

    match error {
        Error::Codesign(CodesignError::VerificationFailed { output, .. }) => {
            assert!(
                output.stderr.contains("not signed at all"),
                "{}",
                output.stderr
            );
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

#[test]
fn an_unmet_requirement_is_requirement_unsatisfied() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = verify(&target)
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
        Error::Codesign(CodesignError::ConstraintInvalid { output, .. }) => {
            assert!(
                !output.stderr.is_empty(),
                "the rejection carried no diagnostics"
            );
        }
        other => panic!("expected ConstraintInvalid, got {other:?}"),
    }
}

#[test]
#[cfg_attr(not(signers_test = "macos27"), ignore = "test group: macos27")]
fn an_empty_signature_slot_is_no_signature() {
    let error = display("/bin/ls")
        .signature_slot(SignatureSlot::Second)
        .run()
        .unwrap_err();

    match error {
        Error::Codesign(CodesignError::NoSignature { output, .. }) => {
            assert!(
                output.stderr.contains("/bin/ls: no signature"),
                "{}",
                output.stderr
            );
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

#[test]
fn a_failed_run_exposes_what_codesign_printed() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let oracle = inspect::codesign(&["--sign".as_ref(), "-".as_ref(), target.as_ref()]);
    assert!(!oracle.success);

    let error = sign_adhoc(&target).run().unwrap_err();

    let output = error.output().expect("a failed run has an output");
    assert_eq!(output.program, "codesign");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, oracle.stdout.trim());
    assert_eq!(output.stderr, oracle.stderr.trim());
    assert_eq!(error.stdout(), Some(output.stdout.as_str()));
    assert_eq!(error.stderr(), Some(output.stderr.as_str()));
}

#[test]
fn a_verdict_exposes_what_codesign_printed() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let oracle = inspect::codesign(&["--verify".as_ref(), target.as_ref()]);
    assert!(!oracle.success);

    let error = verify(&target).run().unwrap_err();

    let output = error.output().expect("a verdict has an output");
    assert_eq!(output.program, "codesign");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(error.stdout(), Some(oracle.stdout.trim()));
    assert_eq!(error.stderr(), Some(oracle.stderr.trim()));
}

#[test]
fn an_error_from_before_the_run_has_no_output() {
    let error = sign_adhoc("/no/such/target").run().unwrap_err();

    assert!(matches!(error, Error::PathNotFound(_)), "got {error:?}");
    assert!(error.output().is_none());
    assert_eq!((error.stdout(), error.stderr()), (None, None));
}
