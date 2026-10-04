//! `test_requirement` and `test_requirement_file`: a requirement the code must
//! satisfy on top of a valid signature, and the exit codes that tell the two
//! failures apart.

use std::path::PathBuf;

use signers::codesign::Strict;
use signers::{Codesign, CodesignError, Error};

use super::{requirement_unsatisfied, verification_failed};
use crate::support::fixture::Workspace;

/// Apple's own binaries are signed by Apple, which is the one requirement the
/// fixture can't satisfy and `/bin/ls` always does.
#[tokio::test]
async fn a_binary_that_satisfies_the_requirement_verifies() {
    Codesign::verify("/bin/ls")
        .test_requirement("anchor apple")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_binary_that_misses_the_requirement_is_an_unsatisfied_requirement() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    let stderr = requirement_unsatisfied(error);
    assert!(
        stderr.contains("failed to satisfy specified code requirement"),
        "got {stderr}"
    );
}

#[tokio::test]
async fn the_requirement_can_name_the_identifier_the_binary_was_signed_with() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    Codesign::sign(&target, "-")
        .identifier("com.example.required")
        .await
        .unwrap();

    Codesign::verify(&target)
        .test_requirement("identifier \"com.example.required\"")
        .await
        .unwrap();

    let error = Codesign::verify(&target)
        .test_requirement("identifier \"com.example.other\"")
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
}

/// The text goes to `codesign` as one argument, so quotes, spaces and
/// operators survive intact.
#[tokio::test]
async fn a_compound_requirement_with_quotes_and_spaces_is_evaluated_whole() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    Codesign::sign(&target, "-")
        .identifier("com.example.compound")
        .await
        .unwrap();

    Codesign::verify(&target)
        .test_requirement("identifier \"com.example.compound\" or anchor apple")
        .await
        .unwrap();

    let error = Codesign::verify(&target)
        .test_requirement("identifier \"com.example.compound\" and anchor apple")
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
}

#[tokio::test]
async fn a_requirement_that_does_not_compile_is_a_verification_failure() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement("this is not a requirement ((")
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("Requirement syntax error"), "got {stderr}");
}

/// `-` is requirement text here, not a request to read standard input: it fails
/// to compile like any other garbage, and never hangs waiting for input.
#[tokio::test]
async fn a_lone_dash_is_requirement_text_not_stdin() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement("-")
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("Requirement syntax error"), "got {stderr}");
}

#[tokio::test]
async fn a_requirement_is_not_checked_when_the_signature_itself_is_broken() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::verify(&target)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn the_last_requirement_wins() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    Codesign::verify(&target)
        .test_requirement("anchor apple")
        .test_requirement("!anchor apple")
        .await
        .unwrap();

    let error = Codesign::verify("/bin/ls")
        .test_requirement("!anchor apple")
        .test_requirement("anchor apple")
        .test_requirement("!anchor apple")
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
}

/// Meeting the requirement doesn't excuse a signature that doesn't verify.
#[tokio::test]
async fn a_satisfied_requirement_does_not_excuse_a_broken_signature() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    super::break_signature(&target);

    let error = Codesign::verify(&target)
        .deep(true)
        .strict(Strict::All)
        .test_requirement("!anchor apple")
        .await
        .unwrap_err();

    verification_failed(error);
}

/// The verdict comes with whatever `codesign` printed on standard output as
/// well, trimmed.
#[tokio::test]
async fn an_unsatisfied_requirement_keeps_what_codesign_printed_on_stdout() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let oracle = crate::support::inspect::codesign(&[
        "--verify".as_ref(),
        "--test-requirement".as_ref(),
        "=anchor apple".as_ref(),
        target.as_ref(),
    ]);
    assert!(!oracle.success);

    let error = Codesign::verify(&target)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();

    match error {
        Error::Codesign(CodesignError::RequirementUnsatisfied { stdout, .. }) => {
            assert_eq!(stdout, oracle.stdout.trim());
        }
        other => panic!("expected RequirementUnsatisfied, got {other:?}"),
    }
}

/// Apple's own binaries satisfy `anchor apple`, an ad hoc one doesn't: the same
/// two verdicts as the text form, read from a file.
#[tokio::test]
async fn a_requirement_file_decides_like_requirement_text() {
    let workspace = Workspace::new();
    let adhoc = workspace.adhoc_signed("hello");
    let apple = workspace.write("apple.txt", "anchor apple\n");
    let not_apple = workspace.write("not-apple.txt", "!anchor apple\n");

    Codesign::verify("/bin/ls")
        .test_requirement_file(&apple)
        .await
        .unwrap();
    Codesign::verify(&adhoc)
        .test_requirement_file(&not_apple)
        .await
        .unwrap();

    let error = Codesign::verify(&adhoc)
        .test_requirement_file(&apple)
        .await
        .unwrap_err();
    let stderr = requirement_unsatisfied(error);
    assert!(
        stderr.contains("failed to satisfy specified code requirement"),
        "got {stderr}"
    );
    let error = Codesign::verify("/bin/ls")
        .test_requirement_file(&not_apple)
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
}

#[tokio::test]
async fn a_requirement_file_agrees_with_the_real_codesign() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let requirement = workspace.write("req.txt", "identifier \"com.example.nowhere\"\n");
    let oracle = crate::support::inspect::codesign(&[
        "--verify".as_ref(),
        "-R".as_ref(),
        requirement.as_ref(),
        target.as_ref(),
    ]);
    assert!(!oracle.success);
    assert!(
        oracle.stderr.contains("failed to satisfy"),
        "got {}",
        oracle.stderr
    );

    let error = Codesign::verify(&target)
        .test_requirement_file(&requirement)
        .await
        .unwrap_err();

    requirement_unsatisfied(error);
}

#[tokio::test]
async fn a_requirement_file_path_with_spaces_is_one_argument() {
    let workspace = Workspace::new();
    let requirement = workspace.write("my requirement.txt", "anchor apple\n");

    Codesign::verify("/bin/ls")
        .test_requirement_file(&requirement)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_requirement_file_that_does_not_compile_is_a_verification_failure() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let garbage = workspace.write("bad.txt", "this is not a requirement ((\n");
    let empty = workspace.write("empty.txt", "");

    for requirement in [garbage, empty] {
        let error = Codesign::verify(&target)
            .test_requirement_file(&requirement)
            .await
            .unwrap_err();

        let stderr = verification_failed(error);
        assert!(stderr.contains("Requirement syntax error"), "got {stderr}");
    }
}

#[tokio::test]
async fn a_requirement_file_that_does_not_exist_is_a_verification_failure() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement_file(workspace.join("missing.txt"))
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(stderr.contains("No such file or directory"), "got {stderr}");
}

#[tokio::test]
async fn a_requirement_file_is_not_checked_when_the_signature_itself_is_broken() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let requirement = workspace.write("req.txt", "anchor apple\n");

    let error = Codesign::verify(&target)
        .test_requirement_file(&requirement)
        .await
        .unwrap_err();

    verification_failed(error);
}

/// Text and file share one slot: whichever was set last decides.
#[tokio::test]
async fn the_last_requirement_wins_between_text_and_file() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let apple = workspace.write("apple.txt", "anchor apple\n");
    let not_apple = workspace.write("not-apple.txt", "!anchor apple\n");

    Codesign::verify(&target)
        .test_requirement_file(&apple)
        .test_requirement("!anchor apple")
        .await
        .unwrap();
    Codesign::verify(&target)
        .test_requirement("anchor apple")
        .test_requirement_file(&not_apple)
        .await
        .unwrap();

    let error = Codesign::verify(&target)
        .test_requirement("!anchor apple")
        .test_requirement_file(&apple)
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
    let error = Codesign::verify(&target)
        .test_requirement_file(&not_apple)
        .test_requirement("anchor apple")
        .await
        .unwrap_err();
    requirement_unsatisfied(error);
}

/// `-R -` would read the caller's standard input, which `codesign` isn't given.
#[tokio::test]
async fn a_requirement_file_of_standard_input_is_rejected_before_anything_runs() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = Codesign::verify(&target)
        .test_requirement_file("-")
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::StdioPath("test_requirement_file")),
        "got {error:?}"
    );

    for per_target in [false, true] {
        let error = Codesign::verify(vec![target.clone(), target.clone()])
            .test_requirement_file("-")
            .per_target(per_target)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::StdioPath("test_requirement_file")),
            "per_target({per_target}): got {error:?}"
        );
    }
}

/// `-` as text is requirement source, so only the file setter refuses it.
#[tokio::test]
async fn a_requirement_file_replaced_by_text_is_no_longer_refused() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    Codesign::verify(&target)
        .test_requirement_file("-")
        .test_requirement("!anchor apple")
        .await
        .unwrap();
}

/// One requirement file, every target judged: the batch lists the ones that miss it.
#[tokio::test]
async fn a_requirement_file_applies_to_every_target_of_a_batch() {
    let workspace = Workspace::new();
    let adhoc = workspace.adhoc_signed("hello");
    let apple = workspace.write("apple.txt", "anchor apple\n");

    let error = Codesign::verify(vec![PathBuf::from("/bin/ls"), adhoc.clone()])
        .test_requirement_file(&apple)
        .await
        .unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected Batch, got {error:?}");
    };
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, adhoc);
    requirement_unsatisfied(failures.into_iter().next().unwrap().1);
}
