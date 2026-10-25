use super::*;
use crate::Error;

/// A status that was killed by `signal`, as `wait` reports it.
#[cfg(unix)]
fn killed_by(signal: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;

    ExitStatus::from_raw(signal)
}

#[test]
fn a_failure_carries_its_diagnostics() {
    let error = ProcessError::Failed {
        program: "codesign",
        stdout: "printed on stdout".into(),
        code: 1,
        stderr: "hello: no identity found".into(),
    };
    assert_eq!(
        error.to_string(),
        "`codesign` exited with code 1: hello: no identity found"
    );
}

/// `codesign` is not required to say anything before it fails, and a
/// message that trails off after its colon reads like truncated output.
#[test]
fn a_failure_with_nothing_to_say_still_reads_as_a_sentence() {
    let silent = ProcessError::Failed {
        program: "codesign",
        stdout: "printed on stdout".into(),
        code: 3,
        stderr: String::new(),
    };
    assert_eq!(
        silent.to_string(),
        "`codesign` exited with code 3: no diagnostics"
    );
}

#[cfg(unix)]
#[test]
fn a_terminated_process_reports_the_signal_that_killed_it() {
    let error = ProcessError::Terminated {
        program: "codesign",
        stdout: "printed on stdout".into(),
        status: killed_by(9),
        stderr: String::new(),
    };
    assert_eq!(
        error.to_string(),
        "the `codesign` process terminated abnormally (signal: 9 (SIGKILL)): no diagnostics",
    );
}

#[test]
fn a_missing_program_is_named_in_the_message() {
    let error = Error::from(ProcessError::NotFound { program: "pkgutil" });
    assert_eq!(error.to_string(), "`pkgutil` was not found on PATH");
}

#[test]
fn a_spawn_failure_names_the_program_and_the_cause() {
    let error = ProcessError::Spawn {
        program: "codesign",
        source: std::io::Error::other("no fork"),
    };
    assert_eq!(
        error.to_string(),
        "failed to spawn the `codesign` process or the Tokio runtime: no fork",
    );
}

#[test]
fn a_run_failure_names_the_program_and_the_cause() {
    let error = ProcessError::Run {
        program: "codesign",
        source: std::io::Error::other("no wait"),
    };
    assert_eq!(
        error.to_string(),
        "failed while running the `codesign` process: no wait",
    );
}

#[test]
fn unreadable_output_says_what_was_wrong_with_it() {
    let error = ProcessError::UnexpectedOutput {
        program: "codesign",
        detail: "2 outputs for 3 targets".into(),
        stdout: "printed on stdout".into(),
        stderr: "printed on stderr".into(),
    };
    assert_eq!(
        error.to_string(),
        "`codesign` produced output this crate can't read: 2 outputs for 3 targets",
    );
}

#[test]
fn a_process_error_names_the_program_in_every_variant() {
    let io = || std::io::Error::other("boom");
    let cases = [
        (
            ProcessError::NotFound { program: "tool" },
            "`tool` was not found on PATH",
        ),
        (
            ProcessError::Spawn {
                program: "tool",
                source: io(),
            },
            "failed to spawn the `tool` process or the Tokio runtime: boom",
        ),
        (
            ProcessError::Run {
                program: "tool",
                source: io(),
            },
            "failed while running the `tool` process: boom",
        ),
        (
            ProcessError::Failed {
                program: "tool",
                code: 2,
                stdout: "printed on stdout".into(),
                stderr: "bad input".into(),
            },
            "`tool` exited with code 2: bad input",
        ),
        (
            ProcessError::UnexpectedOutput {
                program: "tool",
                detail: "2 outputs for 3 targets".into(),
                stdout: "printed on stdout".into(),
                stderr: "printed on stderr".into(),
            },
            "`tool` produced output this crate can't read: 2 outputs for 3 targets",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn a_process_failure_with_nothing_to_say_still_reads_as_a_sentence() {
    let silent = ProcessError::Failed {
        program: "tool",
        code: 3,
        stdout: "printed on stdout".into(),
        stderr: String::new(),
    };
    assert_eq!(
        silent.to_string(),
        "`tool` exited with code 3: no diagnostics"
    );
}

#[cfg(unix)]
#[test]
fn a_terminated_process_error_reports_the_signal_and_its_diagnostics() {
    let with = ProcessError::Terminated {
        program: "tool",
        status: killed_by(9),
        stdout: "printed on stdout".into(),
        stderr: "Killed".into(),
    };
    assert_eq!(
        with.to_string(),
        "the `tool` process terminated abnormally (signal: 9 (SIGKILL)): Killed",
    );

    let silent = ProcessError::Terminated {
        program: "tool",
        status: killed_by(9),
        stdout: String::new(),
        stderr: String::new(),
    };
    assert_eq!(
        silent.to_string(),
        "the `tool` process terminated abnormally (signal: 9 (SIGKILL)): no diagnostics",
    );
}

#[test]
fn a_process_error_keeps_its_io_source() {
    use std::error::Error as _;

    let spawn = ProcessError::Spawn {
        program: "tool",
        source: std::io::Error::other("boom"),
    };
    assert_eq!(spawn.source().unwrap().to_string(), "boom");

    let run = ProcessError::Run {
        program: "tool",
        source: std::io::Error::other("bang"),
    };
    assert_eq!(run.source().unwrap().to_string(), "bang");

    assert!(
        ProcessError::NotFound { program: "tool" }
            .source()
            .is_none()
    );
}

/// `Error::Process` is transparent like `Error::Codesign`, and `?` converts into it.
#[test]
fn the_process_wrapper_forwards_display_unchanged() {
    let inner = ProcessError::Failed {
        program: "tool",
        code: 4,
        stdout: String::new(),
        stderr: "nope".into(),
    };
    let text = inner.to_string();

    let error = Error::from(inner);

    assert!(matches!(
        error,
        Error::Process(ProcessError::Failed { code: 4, .. })
    ));
    assert_eq!(error.to_string(), text);
}

#[test]
fn the_process_wrapper_forwards_the_source_of_the_inner_error() {
    use std::error::Error as _;

    let error = Error::from(ProcessError::Run {
        program: "tool",
        source: std::io::Error::other("bang"),
    });
    // Transparent: the wrapper's source is the inner error's source, not the inner error.
    assert_eq!(error.source().unwrap().to_string(), "bang");
}
