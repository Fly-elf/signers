use super::*;

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
