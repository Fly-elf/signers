use std::ffi::OsString;

use super::*;
use crate::codesign::validate_constraint;
use crate::errors::testing::{exited, ran};
use crate::errors::{Error, ProcessError};

const BOGUS_FAILED: &str = "Constraint validation failed";
const ERROR_REPORT: &str = "error: Lightweight Code requirement failed validation for category Launch\n\tError Domain=LWCRVerificationError Code=1 \"Error: Unknown Key, Context: bogus-key-xyz\" UserInfo={NSLocalizedDescription=Error: Unknown Key, Context: bogus-key-xyz}";

fn paths(names: &[&str]) -> Vec<PathBuf> {
    names.iter().map(PathBuf::from).collect()
}

fn action() -> Options {
    validate_constraint("a.plist").options
}

fn args_of<S>(builder: &ValidateConstraint<S>) -> Vec<OsString> {
    builder
        .options
        .to_args(&builder.job.targets)
        .into_iter()
        .map(Cow::into_owned)
        .collect()
}

fn invalid(result: Result<Vec<()>, Rejection>) -> (String, String) {
    match result {
        Err(Rejection::Error(Error::Codesign(CodesignError::ConstraintInvalid { output }))) => {
            assert_eq!(output.program, "codesign");
            assert!(output.status.success());
            (output.stdout, output.stderr)
        }
        other => panic!("expected ConstraintInvalid, got {other:?}"),
    }
}

#[test]
fn the_action_only_validates_the_plists() {
    assert_eq!(
        args_of(&validate_constraint("c.plist")),
        ["--validate-constraint", "--", "c.plist"].map(OsString::from)
    );
}

#[test]
fn every_plist_is_passed_in_order() {
    assert_eq!(
        args_of(&validate_constraint(["a.plist", "b.plist", "-c.plist"])),
        [
            "--validate-constraint",
            "--",
            "a.plist",
            "b.plist",
            "-c.plist"
        ]
        .map(OsString::from)
    );
}

#[test]
fn the_bogus_failed_line_alone_is_a_success() {
    let outputs = action()
        .output(&paths(&["a"]), &ran("", BOGUS_FAILED.to_owned()))
        .unwrap();

    assert_eq!(outputs, [()]);
}

#[test]
fn an_empty_stderr_is_a_success() {
    let outputs = action()
        .output(&paths(&["a", "b", "c"]), &ran("", String::new()))
        .unwrap();

    assert_eq!(outputs.len(), 3);
}

#[test]
fn an_error_line_is_a_rejection_that_keeps_both_streams() {
    let stderr = format!("{ERROR_REPORT}\n{BOGUS_FAILED}");

    let (stdout, kept) = invalid(action().output(
        &paths(&["a"]),
        &ran("some output".to_owned(), stderr.clone()),
    ));

    assert_eq!(stdout, "some output");
    assert_eq!(kept, stderr);
}

#[test]
fn an_error_line_after_other_lines_is_still_a_rejection() {
    let stderr = format!("{BOGUS_FAILED}\nwarning: something\n{ERROR_REPORT}");

    invalid(action().output(&paths(&["a", "b"]), &ran("", stderr)));
}

#[test]
fn an_error_line_without_the_bogus_line_is_a_rejection() {
    invalid(action().output(&paths(&["a"]), &ran("", "error: bad constraint".to_owned())));
}

#[test]
fn error_text_inside_a_line_is_not_a_rejection() {
    let stderr = format!("{BOGUS_FAILED}\nwarning: not an error: really");

    let outputs = action().output(&paths(&["a"]), &ran("", stderr)).unwrap();

    assert_eq!(outputs, [()]);
}

#[test]
fn exit_code_one_is_a_plain_failure_with_both_streams() {
    for code in [1, 2] {
        match action().failure(
            code,
            exited(
                "codesign",
                code,
                "out",
                "Error reading constraint from x.plist",
            ),
        ) {
            Error::Process(ProcessError::Failed { output }) => {
                assert_eq!(output.program, "codesign");
                assert_eq!(output.status.code(), Some(code));
                assert_eq!(output.stdout, "out");
                assert_eq!(output.stderr, "Error reading constraint from x.plist");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}

#[test]
fn a_rejection_names_its_diagnostics() {
    let error: Error = CodesignError::ConstraintInvalid {
        output: exited("codesign", 0, "", ERROR_REPORT),
    }
    .into();

    let message = error.to_string();

    assert!(message.starts_with("invalid constraint: "), "{message}");
    assert!(message.contains("Unknown Key"), "{message}");
}
