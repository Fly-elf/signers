use super::testing::Sh;
use super::*;

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
    let error = Sh::failed(5, "out".into(), "err".into());

    match error {
        Error::Process(ProcessError::Failed {
            program,
            code,
            stdout,
            stderr,
        }) => {
            assert_eq!(program, "sh");
            assert_eq!(code, 5);
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected Process(Failed), got {other:?}"),
    }
    assert_eq!(
        Sh::failed(5, String::new(), String::new()).to_string(),
        "`sh` exited with code 5: no diagnostics"
    );
}
