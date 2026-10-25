use super::*;
use crate::codesign::CodesignError;
use crate::errors::testing::{exited, killed};

/// A failing run of `code`, as a batch entry holds it.
fn failed(code: i32, stderr: &str) -> Error {
    ProcessError::Failed {
        output: exited("codesign", code, "printed on stdout", stderr),
    }
    .into()
}

#[test]
fn a_missing_path_is_named_in_the_message() {
    assert_eq!(
        Error::PathNotFound(PathBuf::from("My App.app")).to_string(),
        "path does not exist: My App.app",
    );
}

/// Each error followed by its sources, as a reporter that walks `source()` prints them.
fn walk(error: &dyn std::error::Error) -> Vec<String> {
    std::iter::successors(Some(error), |e| e.source())
        .map(ToString::to_string)
        .collect()
}

/// The I/O error is the `source()` alone, so a reporter that prints the whole
/// chain shows it once; `Process` is transparent and adds no link of its own.
#[test]
fn a_wrapped_io_error_appears_once_in_the_chain() {
    let cause = || std::io::Error::other("disk on fire");
    let cases = [
        (
            Error::PathAccess {
                path: PathBuf::from("/locked/a.app"),
                source: cause(),
            },
            "could not access /locked/a.app",
        ),
        (
            Error::Io {
                path: PathBuf::from("/tmp/x 1/cert.pem"),
                source: cause(),
            },
            "I/O error on /tmp/x 1/cert.pem",
        ),
        (
            Error::from(ProcessError::Spawn {
                program: "tool",
                source: cause(),
            }),
            "could not start `tool`",
        ),
        (
            Error::from(ProcessError::Run {
                program: "tool",
                source: cause(),
            }),
            "failed while running the `tool` process",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
        let source = std::error::Error::source(&error).expect("the cause is the source");
        assert!(source.is::<std::io::Error>(), "{error:?}");
        assert_eq!(walk(&error), [message, "disk on fire"]);
    }
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

/// Display is all a batch message is built from, so each entry brings the
/// causes its own message leaves to `source()`.
#[test]
fn a_batch_message_carries_the_causes_of_every_failure() {
    let error = Error::Batch(vec![
        (
            PathBuf::from("/locked/a.app"),
            Error::PathAccess {
                path: PathBuf::from("/locked/a.app"),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
        ),
        (
            PathBuf::from("b.dylib"),
            ProcessError::Spawn {
                program: "tool",
                source: std::io::Error::other("no fork"),
            }
            .into(),
        ),
    ]);
    assert_eq!(
        error.to_string(),
        "2 target(s) failed: \
         /locked/a.app: could not access /locked/a.app: permission denied; \
         b.dylib: could not start `tool`: no fork",
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
fn the_process_wrapper_delegates_the_accessors() {
    let failed = Error::from(ProcessError::Failed {
        output: killed("tool", 9, "printed", "Killed"),
    });
    let output = failed.output().expect("a process failure has an output");
    assert_eq!(output.program, "tool");
    assert_eq!(output.status.code(), None);
    assert_eq!(failed.stdout(), Some("printed"));
    assert_eq!(failed.stderr(), Some("Killed"));

    let unreadable = Error::from(ProcessError::UnexpectedOutput {
        detail: "d".into(),
        output: exited("tool", 0, "o", "e"),
    });
    assert_eq!(unreadable.output().unwrap().program, "tool");
    assert_eq!(unreadable.stdout(), Some("o"));
    assert_eq!(unreadable.stderr(), Some("e"));
}

#[test]
fn the_codesign_wrapper_delegates_the_accessors() {
    let error = Error::from(CodesignError::NoSignature {
        output: exited("codesign", 0, "o", "e"),
    });
    assert_eq!(error.output().unwrap().program, "codesign");
    assert_eq!(error.stdout(), Some("o"));
    assert_eq!(error.stderr(), Some("e"));
}

/// A batch holds outputs inside its entries, but no single run is its own.
#[test]
fn errors_without_a_finished_run_have_no_output() {
    let io = || std::io::Error::other("boom");
    for error in [
        Error::NoTargets,
        Error::EmptyTarget(0),
        Error::PathNotFound(PathBuf::from("a")),
        Error::PathAccess {
            path: PathBuf::from("a"),
            source: io(),
        },
        Error::Io {
            path: PathBuf::from("a"),
            source: io(),
        },
        Error::StdioPath("file_list"),
        Error::SharedOutputPerTarget("detached"),
        Error::Batch(vec![(PathBuf::from("a"), failed(1, "boom"))]),
        Error::from(CodesignError::NotFound),
        Error::from(ProcessError::NotFound { program: "tool" }),
        Error::from(ProcessError::Spawn {
            program: "tool",
            source: io(),
        }),
        Error::from(ProcessError::Run {
            program: "tool",
            source: io(),
        }),
    ] {
        assert!(error.output().is_none(), "{error:?}");
        assert_eq!(error.stdout(), None, "{error:?}");
        assert_eq!(error.stderr(), None, "{error:?}");
    }
}
