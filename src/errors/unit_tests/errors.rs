use super::*;

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

/// The remedy is the whole point of the variant: `codesign` ships with macOS, so the
/// fix is `PATH`, never the Command Line Tools.
#[test]
fn a_missing_binary_names_the_remedy() {
    let message = CodesignError::NotFound.to_string();
    assert_eq!(
        message,
        "`codesign` was not found on PATH; it ships with macOS in /usr/bin, \
         so check that PATH includes /usr/bin",
    );
    assert!(!message.contains("xcode-select"), "got {message}");
}

/// The outer `Error::Codesign` wrapper must forward `Display` unchanged, so callers who
/// only do `eprintln!("{error}")` see no difference from before the split.
#[test]
fn the_wrapper_variant_forwards_display_unchanged() {
    let error = Error::from(CodesignError::NotFound);
    assert_eq!(error.to_string(), CodesignError::NotFound.to_string());
}

/// A failing run of `code`, as a batch entry holds it.
fn failed(code: i32, stderr: &str) -> Error {
    ProcessError::Failed {
        program: "codesign",
        stdout: "printed on stdout".into(),
        code,
        stderr: stderr.into(),
    }
    .into()
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
fn a_missing_path_is_named_in_the_message() {
    assert_eq!(
        Error::PathNotFound(PathBuf::from("My App.app")).to_string(),
        "path does not exist: My App.app",
    );
}

#[test]
fn an_unreadable_path_carries_the_cause() {
    let error = Error::PathAccess {
        path: PathBuf::from("/locked/a.app"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    };
    assert_eq!(
        error.to_string(),
        "could not access /locked/a.app: permission denied",
    );
}

#[test]
fn an_empty_target_is_named_by_its_position() {
    assert_eq!(
        Error::EmptyTarget(0).to_string(),
        "target 0 is an empty path"
    );
    assert_eq!(
        Error::EmptyTarget(12).to_string(),
        "target 12 is an empty path"
    );
}

#[test]
fn a_shared_output_refusal_names_the_setter() {
    assert_eq!(
        Error::SharedOutputPerTarget("file_list").to_string(),
        "file_list writes one shared file and can't be combined with per_target(true)",
    );
    assert_eq!(
        Error::SharedOutputPerTarget("detached").to_string(),
        "detached writes one shared file and can't be combined with per_target(true)",
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

/// The path prefix stays even where `codesign` repeats it: some of its
/// messages (a `-R` mismatch) name no target at all.
#[test]
fn a_batch_lists_every_failure_in_the_order_given() {
    let error = Error::Batch(vec![
        (PathBuf::from("b.dylib"), failed(1, "b.dylib: nope")),
        (
            PathBuf::from("My App.app"),
            Error::PathNotFound(PathBuf::from("My App.app")),
        ),
        (PathBuf::from("a"), failed(3, "")),
    ]);

    assert_eq!(
        error.to_string(),
        format!(
            "3 target(s) failed: \
             b.dylib: `codesign` exited with code 1: b.dylib: nope; \
             My App.app: {}; \
             a: `codesign` exited with code 3: no diagnostics",
            Error::PathNotFound(PathBuf::from("My App.app")),
        ),
    );
}

#[test]
fn a_batch_of_one_has_no_separator() {
    let error = Error::Batch(vec![(PathBuf::from("a.app"), failed(1, "boom"))]);
    assert_eq!(
        error.to_string(),
        "1 target(s) failed: a.app: `codesign` exited with code 1: boom",
    );
}

#[test]
fn failures_are_joined_with_a_semicolon() {
    assert_eq!(failures(&[]), "");
    assert_eq!(
        failures(&[(PathBuf::from("a"), Error::NoTargets)]),
        format!("a: {}", Error::NoTargets),
    );
    assert_eq!(
        failures(&[
            (PathBuf::from("a"), Error::EmptyTarget(0)),
            (PathBuf::from("dir/b c"), Error::EmptyTarget(1)),
        ]),
        "a: target 0 is an empty path; dir/b c: target 1 is an empty path",
    );
}

/// A path is shown through `Path::display`, so bytes that are not UTF-8
/// cannot make the message itself unprintable.
#[cfg(unix)]
#[test]
fn a_failure_on_a_path_that_is_not_utf8_is_still_printable() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = PathBuf::from(OsString::from_vec(vec![b'a', 0xff, b'b']));
    assert_eq!(
        failures(&[(path.clone(), Error::EmptyTarget(0))]),
        format!("{}: target 0 is an empty path", path.display()),
    );
}

#[test]
fn a_verification_failure_carries_its_diagnostics() {
    let error = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: "app: invalid signature (code or signature have been modified)".into(),
        resources: Vec::new(),
    };
    assert_eq!(
        error.to_string(),
        "verification failed: app: invalid signature (code or signature have been modified)",
    );
}

#[test]
fn a_verification_failure_with_nothing_to_say_still_reads_as_a_sentence() {
    let silent = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: String::new(),
        resources: Vec::new(),
    };
    assert_eq!(silent.to_string(), "verification failed: no diagnostics");
}

fn resource(change: Change, path: &str) -> ResourceChange {
    ResourceChange {
        change,
        path: PathBuf::from(path),
    }
}

#[test]
fn a_verification_failure_lists_the_altered_resources_in_order() {
    let error = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: "A.app: a sealed resource is missing or invalid".into(),
        resources: vec![
            resource(Change::Modified, "/x/A.app/Contents/Resources/r.txt"),
            resource(Change::Added, "/x/A.app/Contents/Resources/new.txt"),
            resource(Change::Missing, "/x/A.app/Contents/Resources/gone.txt"),
        ],
    };
    assert_eq!(
        error.to_string(),
        "verification failed: A.app: a sealed resource is missing or invalid \
         (modified: /x/A.app/Contents/Resources/r.txt; \
         added: /x/A.app/Contents/Resources/new.txt; \
         missing: /x/A.app/Contents/Resources/gone.txt)",
    );
}

#[test]
fn a_single_altered_resource_is_listed_without_a_separator() {
    let error = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: "A.app: bad".into(),
        resources: vec![resource(Change::Missing, "/x/r.txt")],
    };
    assert_eq!(
        error.to_string(),
        "verification failed: A.app: bad (missing: /x/r.txt)"
    );
}

#[test]
fn resources_are_listed_even_without_diagnostics() {
    let error = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: String::new(),
        resources: vec![resource(Change::Added, "/x/r.txt")],
    };
    assert_eq!(
        error.to_string(),
        "verification failed: no diagnostics (added: /x/r.txt)"
    );
}

#[cfg(unix)]
#[test]
fn a_resource_path_that_is_not_utf8_is_still_printable() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = PathBuf::from(OsString::from_vec(vec![b'/', 0xff, b'b']));
    let error = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: "bad".into(),
        resources: vec![ResourceChange {
            change: Change::Modified,
            path: path.clone(),
        }],
    };
    assert_eq!(
        error.to_string(),
        format!("verification failed: bad (modified: {})", path.display())
    );
}

#[test]
fn resource_changes_compare_by_value() {
    assert_eq!(resource(Change::Added, "/a"), resource(Change::Added, "/a"));
    assert_ne!(
        resource(Change::Added, "/a"),
        resource(Change::Modified, "/a")
    );
    assert_ne!(resource(Change::Added, "/a"), resource(Change::Added, "/b"));
}

#[test]
fn an_unsatisfied_requirement_says_the_signature_itself_is_fine() {
    let error = CodesignError::RequirementUnsatisfied {
        stdout: "printed on stdout".into(),
        stderr: "test-requirement: code failed to satisfy specified code requirement(s)".into(),
    };
    assert_eq!(
        error.to_string(),
        "validly signed, but the requirement isn't satisfied: \
         test-requirement: code failed to satisfy specified code requirement(s)",
    );
}

#[test]
fn an_unsatisfied_requirement_with_nothing_to_say_still_reads_as_a_sentence() {
    let silent = CodesignError::RequirementUnsatisfied {
        stdout: "printed on stdout".into(),
        stderr: String::new(),
    };
    assert_eq!(
        silent.to_string(),
        "validly signed, but the requirement isn't satisfied: no diagnostics",
    );
}

#[test]
fn the_verification_variants_forward_display_through_the_wrapper() {
    let failed = CodesignError::VerificationFailed {
        stdout: "printed on stdout".into(),
        stderr: "x".into(),
        resources: Vec::new(),
    };
    let unsatisfied = CodesignError::RequirementUnsatisfied {
        stdout: "printed on stdout".into(),
        stderr: "y".into(),
    };
    for inner in [failed, unsatisfied] {
        let text = inner.to_string();
        assert_eq!(Error::from(inner).to_string(), text);
    }
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
