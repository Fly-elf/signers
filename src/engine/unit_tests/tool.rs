use super::testing::Sh;
use super::*;
use crate::errors::testing::exited;

#[test]
fn the_default_error_wraps_the_process_error_unchanged() {
    let error = Sh::error(ProcessError::NotFound { program: "sh" });

    assert!(matches!(
        error,
        Error::Process(ProcessError::NotFound { program: "sh" })
    ));
}

#[test]
fn the_default_failure_is_a_failed_process_of_this_program() {
    let error = Sh::failed(exited("sh", 5, "out", "err"));

    match error {
        Error::Process(ProcessError::Failed { output }) => {
            assert_eq!(output.program, "sh");
            assert_eq!(output.status.code(), Some(5));
            assert_eq!(output.stdout, "out");
            assert_eq!(output.stderr, "err");
        }
        other => panic!("expected Process(Failed), got {other:?}"),
    }
    assert_eq!(
        Sh::failed(exited("sh", 5, "", "")).to_string(),
        "`sh` exited with code 5: no diagnostics"
    );
}
