use super::*;
use crate::Error;
use crate::errors::testing::{exited, killed};

#[test]
fn a_failure_carries_its_diagnostics() {
    let error = ProcessError::Failed {
        output: exited(
            "codesign",
            1,
            "printed on stdout",
            "hello: no identity found",
        ),
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
        output: exited("codesign", 3, "printed on stdout", ""),
    };
    assert_eq!(
        silent.to_string(),
        "`codesign` exited with code 3: no diagnostics"
    );
}

#[test]
fn a_killed_process_reports_the_signal_that_killed_it() {
    let with = ProcessError::Failed {
        output: killed("codesign", 9, "printed on stdout", "Killed"),
    };
    assert_eq!(
        with.to_string(),
        "`codesign` was killed (signal: 9 (SIGKILL)): Killed",
    );

    let silent = ProcessError::Failed {
        output: killed("codesign", 9, "", ""),
    };
    assert_eq!(
        silent.to_string(),
        "`codesign` was killed (signal: 9 (SIGKILL)): no diagnostics",
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
        detail: "2 outputs for 3 targets".into(),
        output: exited("codesign", 0, "printed on stdout", "printed on stderr"),
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
                output: exited("tool", 2, "printed on stdout", "bad input"),
            },
            "`tool` exited with code 2: bad input",
        ),
        (
            ProcessError::UnexpectedOutput {
                detail: "2 outputs for 3 targets".into(),
                output: exited("tool", 0, "printed on stdout", "printed on stderr"),
            },
            "`tool` produced output this crate can't read: 2 outputs for 3 targets",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

/// Every variant answers `program()`, whether it holds the name itself or through its `Output`.
#[test]
fn program_names_the_tool_in_every_variant() {
    let io = || std::io::Error::other("boom");
    let cases = [
        ProcessError::NotFound { program: "tool" },
        ProcessError::Spawn {
            program: "tool",
            source: io(),
        },
        ProcessError::Run {
            program: "tool",
            source: io(),
        },
        ProcessError::Failed {
            output: exited("tool", 2, "", ""),
        },
        ProcessError::Failed {
            output: killed("tool", 9, "", ""),
        },
        ProcessError::UnexpectedOutput {
            detail: "d".into(),
            output: exited("tool", 0, "", ""),
        },
    ];
    for error in cases {
        assert_eq!(error.program(), "tool", "{error:?}");
    }
}

/// Only the variants that come after a finished run carry its `Output`, whole.
#[test]
fn the_variants_after_a_finished_run_carry_its_output() {
    let failed = ProcessError::Failed {
        output: exited("tool", 2, "printed", "bad input"),
    };
    let output = failed.output().expect("Failed has an output");
    assert_eq!(output.program, "tool");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, "printed");
    assert_eq!(output.stderr, "bad input");

    let by_signal = ProcessError::Failed {
        output: killed("tool", 9, "", "Killed"),
    };
    assert_eq!(by_signal.output().unwrap().status.code(), None);

    let unreadable = ProcessError::UnexpectedOutput {
        detail: "d".into(),
        output: exited("tool", 0, "o", "e"),
    };
    let output = unreadable.output().expect("UnexpectedOutput has an output");
    assert!(output.status.success());
    assert_eq!((output.stdout.as_str(), output.stderr.as_str()), ("o", "e"));
}

#[test]
fn the_variants_before_or_without_a_finished_run_have_no_output() {
    let io = || std::io::Error::other("boom");
    for error in [
        ProcessError::NotFound { program: "tool" },
        ProcessError::Spawn {
            program: "tool",
            source: io(),
        },
        ProcessError::Run {
            program: "tool",
            source: io(),
        },
    ] {
        assert!(error.output().is_none(), "{error:?}");
        assert_eq!(error.stdout(), None, "{error:?}");
        assert_eq!(error.stderr(), None, "{error:?}");
    }
}

#[test]
fn stdout_and_stderr_read_the_output_of_the_run() {
    let failed = ProcessError::Failed {
        output: exited("tool", 2, "printed", "bad input"),
    };
    assert_eq!(failed.stdout(), Some("printed"));
    assert_eq!(failed.stderr(), Some("bad input"));

    let unreadable = ProcessError::UnexpectedOutput {
        detail: "d".into(),
        output: exited("tool", 0, "", "warning"),
    };
    assert_eq!(unreadable.stdout(), Some(""));
    assert_eq!(unreadable.stderr(), Some("warning"));
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
        output: exited("tool", 4, "", "nope"),
    };
    let text = inner.to_string();

    let error = Error::from(inner);

    assert!(matches!(error, Error::Process(ProcessError::Failed { .. })));
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
