//! Why an action failed: [`Error`](enum@Error), and [`CodesignError`] for the `codesign` backend.

use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

/// A `Result` whose error is this crate's [`Error`](enum@Error).
pub type Result<T> = std::result::Result<T, Error>;

/// Why an action failed.
///
/// Every variant except [`Codesign`](Error::Codesign) and [`Batch`](Error::Batch) comes from a
/// check made before `codesign` starts, so no target has been touched. The order of the checks
/// is on [`Codesign`](crate::Codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() {
/// use signers::{Codesign, CodesignError, Error};
///
/// match Codesign::sign_adhoc("mytool").force(true).await {
///     Ok(()) => {}
///     Err(Error::TargetNotFound(path)) => eprintln!("no such file: {}", path.display()),
///     Err(Error::Codesign(CodesignError::Failed { stderr, .. })) => eprintln!("{stderr}"),
///     Err(error) => eprintln!("{error}"),
/// }
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// No target was given: an empty `Vec`, slice or array.
    #[error("no targets to operate on")]
    NoTargets,

    /// The target at this index is an empty path; index 0 for a single target.
    ///
    /// Only the first empty path is reported.
    #[error("target {0} is an empty path")]
    EmptyTarget(usize),

    /// This target doesn't exist.
    #[error("target does not exist: {0}")]
    TargetNotFound(PathBuf),

    /// Whether this target exists couldn't be checked, e.g. because a parent directory denies
    /// access.
    #[error("could not access target {path}: {source}")]
    TargetAccess {
        path: PathBuf,
        source: std::io::Error,
    },

    /// An option was given `-`, which on the command line means standard input or output.
    ///
    /// It holds the setter's name: `"file_list"`, `"requirements"` or `"test_requirement_file"`.
    /// `codesign` gets no standard streams here, so pass a file path instead.
    #[error(
        "{0}(\"-\") is not supported: `codesign` gets no standard streams here, pass a file path"
    )]
    StdioPath(&'static str),

    /// An option that writes one shared file was combined with
    /// [`per_target(true)`](crate::Codesign::per_target).
    ///
    /// It holds the setter's name, `"file_list"` or `"detached"`. One process per target would
    /// make every process write that same file.
    #[error("{0} writes one shared file and can't be combined with per_target(true)")]
    SharedOutputPerTarget(&'static str),

    /// These targets failed in a [`per_target(true)`](crate::Codesign::per_target) run, each with
    /// its own error, in input order.
    ///
    /// Every target ran, so the ones not listed succeeded; their outputs are dropped. One failing
    /// target is enough to get this variant rather than its plain error. See
    /// [`per_target`](crate::Codesign::per_target) for an example.
    #[error("{} target(s) failed: {}", .0.len(), failures(.0))]
    Batch(Vec<(PathBuf, Error)>),

    /// The `codesign` tool couldn't run, or it rejected the job.
    #[error(transparent)]
    Codesign(#[from] CodesignError),
}

/// Why running the `codesign` tool failed.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum CodesignError {
    /// No `codesign` was found on `PATH`.
    ///
    /// `codesign` ships with macOS in `/usr/bin`. This error usually means `PATH` leaves out
    /// `/usr/bin`, or the system isn't macOS.
    #[error(
        "`codesign` was not found on PATH; it ships with macOS in /usr/bin, \
         so check that PATH includes /usr/bin"
    )]
    NotFound,

    /// `codesign` was found but couldn't start, e.g. because it isn't executable.
    #[error("failed to spawn the `codesign` process: {0}")]
    Spawn(#[source] std::io::Error),

    /// Waiting for `codesign` or reading its output failed.
    ///
    /// The outcome is unknown, so the targets may or may not have changed.
    #[error("failed while running the `codesign` process: {0}")]
    Run(#[source] std::io::Error),

    /// `codesign` exited with `code`.
    ///
    /// `stderr` holds its diagnostics and `stdout` what it printed on standard output, both
    /// trimmed. Only `stderr` is part of the message.
    ///
    /// When one `codesign` runs over several targets, the targets before the rejected one have
    /// already changed. See [`Codesign`](crate::Codesign#errors).
    #[error("`codesign` exited with code {code}: {}", diagnostics(.stderr))]
    Failed {
        code: i32,
        stdout: String,
        stderr: String,
    },

    /// `codesign` was killed by a signal before it could exit.
    ///
    /// `status` holds the signal (`ExitStatusExt::signal`). `stderr` is usually empty. `stdout`
    /// holds what `codesign` printed on standard output, trimmed; it isn't part of the message.
    #[error("the `codesign` process terminated abnormally ({status}): {}", diagnostics(.stderr))]
    Terminated {
        status: ExitStatus,
        stdout: String,
        stderr: String,
    },

    /// `codesign` exited 0, but its output couldn't be read as the action's result.
    ///
    /// `detail` says what didn't match, e.g. the number of results against the number of
    /// targets.
    #[error("`codesign` produced output this crate can't read: {detail}")]
    UnexpectedOutput { detail: String },

    /// [`verify`](crate::Codesign::verify) found the target's signature wanting.
    ///
    /// The signature is invalid or modified, the target is unsigned, or the requirement text of
    /// [`test_requirement`](crate::Codesign::test_requirement) doesn't compile. `stderr` holds
    /// the diagnostics `codesign` printed on standard error and `stdout` what it printed on standard
    /// output, both trimmed. Only `stderr` is part of the message.
    ///
    /// `resources` names the sealed resources that were altered, in the order `codesign` printed
    /// them, which can differ from run to run. It is filled only with
    /// [`check_designated_requirement`](crate::Codesign::check_designated_requirement), and stays
    /// empty when the damage is to nested code (see [`deep`](crate::Codesign::deep)) or when
    /// nothing was altered. The message lists them after the diagnostics, as
    /// `(modified: /path; added: /path)`.
    #[error("verification failed: {}{}", diagnostics(.stderr), changes(.resources))]
    VerificationFailed {
        stdout: String,
        stderr: String,
        resources: Vec<ResourceChange>,
    },

    /// [`verify`](crate::Codesign::verify) found a valid signature on code that doesn't meet the
    /// requirement it was given.
    ///
    /// That requirement is the text of
    /// [`test_requirement`](crate::Codesign::test_requirement) or, with
    /// [`check_designated_requirement`](crate::Codesign::check_designated_requirement), the code's
    /// own. `stderr` holds the diagnostics `codesign` printed on standard error and `stdout` what it
    /// printed on standard output, both trimmed. Only `stderr` is part of the message.
    #[error("validly signed, but the requirement isn't satisfied: {}", diagnostics(.stderr))]
    RequirementUnsatisfied { stdout: String, stderr: String },
}

/// A sealed resource that [`verify`](crate::Codesign::verify) found altered.
///
/// It is found in [`CodesignError::VerificationFailed`].
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::errors::Change;
/// use signers::{Codesign, CodesignError, Error};
///
/// let result = Codesign::verify("MyApp.app").check_designated_requirement(true).await;
/// if let Err(Error::Codesign(CodesignError::VerificationFailed { resources, .. })) = result {
///     for resource in resources.iter().filter(|r| r.change == Change::Modified) {
///         println!("tampered: {}", resource.path.display());
///     }
/// }
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceChange {
    /// How the resource differs from what the signature sealed.
    pub change: Change,
    /// Absolute path, canonical: a temporary directory shows as `/private/var/...`.
    ///
    /// Read from `codesign`'s text output, so bytes that aren't valid UTF-8 become `U+FFFD`.
    pub path: PathBuf,
}

/// How a sealed resource differs from what the signature sealed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The bundle holds a file the signature doesn't cover.
    Added,
    /// The file's contents differ from what was sealed.
    Modified,
    /// A sealed file is gone.
    Missing,
}

impl Change {
    fn as_str(self) -> &'static str {
        match self {
            Change::Added => "added",
            Change::Modified => "modified",
            Change::Missing => "missing",
        }
    }
}

/// Renders `resources` as ` (modified: path; added: path)`, or nothing if there are none.
fn changes(resources: &[ResourceChange]) -> String {
    if resources.is_empty() {
        return String::new();
    }
    let list: Vec<String> = resources
        .iter()
        .map(|r| format!("{}: {}", r.change.as_str(), r.path.display()))
        .collect();
    format!(" ({})", list.join("; "))
}

/// Returns `stderr`, or "no diagnostics" if it's empty, so a message never ends with a colon.
fn diagnostics(stderr: &str) -> &str {
    if stderr.is_empty() {
        "no diagnostics"
    } else {
        stderr
    }
}

/// Joins the entries of a [`Batch`](Error::Batch) as `path: error`, separated by `; `.
fn failures(failures: &[(PathBuf, Error)]) -> String {
    failures
        .iter()
        .map(|(path, error)| format!("{}: {error}", path.display()))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A status that was killed by `signal`, as `wait` reports it.
    #[cfg(unix)]
    fn killed_by(signal: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        ExitStatus::from_raw(signal)
    }

    #[test]
    fn a_failure_carries_its_diagnostics() {
        let error = CodesignError::Failed {
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
        let silent = CodesignError::Failed {
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
        let error = CodesignError::Terminated {
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
        CodesignError::Failed {
            stdout: "printed on stdout".into(),
            code,
            stderr: stderr.into(),
        }
        .into()
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
        let error = CodesignError::UnexpectedOutput {
            detail: "2 outputs for 3 targets".into(),
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
                Error::TargetNotFound(PathBuf::from("My App.app")),
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
                Error::TargetNotFound(PathBuf::from("My App.app")),
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
}
