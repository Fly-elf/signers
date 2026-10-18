//! Why an action failed: [`Error`](enum@Error), with [`CodesignError`] for `codesign` and
//! [`ProcessError`] for the other external tools.

use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

/// A `Result` whose error is this crate's [`Error`](enum@Error).
pub type Result<T> = std::result::Result<T, Error>;

/// Why an action failed.
///
/// Every variant except [`Codesign`](Error::Codesign), [`Process`](Error::Process),
/// [`Batch`](Error::Batch) and [`Io`](Error::Io) comes from a check made before `codesign`
/// starts, so no target has been touched. The order of the checks is listed in [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() {
/// use signers::{CodesignError, Error, codesign};
///
/// match codesign::sign_adhoc("mytool").force(true).await {
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

    /// A file or directory couldn't be read, created or written.
    ///
    /// `path` is the one involved.
    /// [`extract_certificates`](crate::codesign::extract_certificates) raises it, for the
    /// system's temporary directory, for the files it reads back and for the ones
    /// [`save_to`](crate::codesign::ExtractCertificates::save_to) writes. It never changes a
    /// target. Raised while a target is read, it is collected in [`Batch`](Error::Batch).
    #[error("I/O error on {path}: {source}")]
    Io {
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
    /// [`per_target(true)`](crate::codesign::Sign::per_target).
    ///
    /// It holds the setter's name, `"file_list"` or `"detached"`. One process per target would
    /// make every process write that same file.
    #[error("{0} writes one shared file and can't be combined with per_target(true)")]
    SharedOutputPerTarget(&'static str),

    /// These targets failed in a [`per_target(true)`](crate::codesign::Sign::per_target) run, each
    /// with its own error, in input order.
    ///
    /// Every target ran, so the ones not listed succeeded; their outputs are dropped. One failing
    /// target is enough to get this variant rather than its plain error. See
    /// [`per_target`](crate::codesign::Sign::per_target) for an example.
    #[error("{} target(s) failed: {}", .0.len(), failures(.0))]
    Batch(Vec<(PathBuf, Error)>),

    /// The `codesign` tool couldn't run, or it rejected the job.
    #[error(transparent)]
    Codesign(#[from] CodesignError),

    /// An external tool couldn't run, or it rejected the job.
    ///
    /// For a tool whose module has no error type of its own. The `codesign` actions never
    /// return it: they report through [`Codesign`](Error::Codesign).
    #[error(transparent)]
    Process(#[from] ProcessError),
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

    /// [`verify`](crate::codesign::verify) found the target's signature wanting.
    ///
    /// The signature is invalid or modified, the target is unsigned, or the requirement text of
    /// [`test_requirement`](crate::codesign::Verify::test_requirement) doesn't compile. `stderr`
    /// holds the diagnostics `codesign` printed on standard error and `stdout` what it printed on
    /// standard output, both trimmed. Only `stderr` is part of the message.
    ///
    /// `resources` names the sealed resources that were altered, in the order `codesign` printed
    /// them, which can differ from run to run. It is filled only with
    /// [`check_designated_requirement`](crate::codesign::Verify::check_designated_requirement), and
    /// stays empty when the damage is to nested code (see
    /// [`deep`](crate::codesign::Verify::deep)) or when nothing was altered. The message lists them
    /// after the diagnostics, as `(modified: /path; added: /path)`.
    #[error("verification failed: {}{}", diagnostics(.stderr), changes(.resources))]
    VerificationFailed {
        stdout: String,
        stderr: String,
        resources: Vec<ResourceChange>,
    },

    /// [`verify`](crate::codesign::verify) found a valid signature on code that doesn't meet
    /// the requirement it was given.
    ///
    /// That requirement is the text of
    /// [`test_requirement`](crate::codesign::Verify::test_requirement) or, with
    /// [`check_designated_requirement`](crate::codesign::Verify::check_designated_requirement), the
    /// code's own. `stderr` holds the diagnostics `codesign` printed on standard error and `stdout`
    /// what it printed on standard output, both trimmed. Only `stderr` is part of the message.
    #[error("validly signed, but the requirement isn't satisfied: {}", diagnostics(.stderr))]
    RequirementUnsatisfied { stdout: String, stderr: String },

    /// [`validate_constraint`](crate::codesign::validate_constraint) found a constraint that
    /// isn't valid.
    ///
    /// The plist has an unknown key or is empty. `stderr` holds the diagnostics `codesign`
    /// printed on standard error and `stdout` what it printed on standard output, both trimmed.
    /// Only `stderr` is part of the message.
    ///
    /// On macOS 27 `codesign` exits 0 and prints "Constraint validation failed" even for a valid
    /// plist, so the exit code says nothing here. A plist is rejected only when `codesign` also
    /// reports an error for it, and that report is what `stderr` keeps.
    #[error("invalid constraint: {}", diagnostics(.stderr))]
    ConstraintInvalid { stdout: String, stderr: String },

    /// [`display`](crate::codesign::display) found no signature in the
    /// [`signature_slot`](crate::codesign::Display::signature_slot) it was asked for.
    ///
    /// Code with one signature has nothing in the second slot. `codesign` exits 0 for it, and
    /// reports `no signature` in place of the signature, so this crate fails instead of returning
    /// one with nothing in it. Unsigned code is a different failure: [`CodesignError::Failed`].
    /// `stderr` and `stdout` hold what `codesign` printed on each stream during the whole run,
    /// trimmed, so with one run over several targets they also cover targets that read fine. Only
    /// `stderr` is part of the message.
    #[error("no signature: {}", diagnostics(.stderr))]
    NoSignature { stdout: String, stderr: String },
}

/// Why running an external tool failed.
///
/// The general form of [`CodesignError`]'s process failures, for tools whose module has no error
/// type of its own. Each variant names the tool in `program`, the executable looked up on `PATH`,
/// e.g. `"codesign"`. No action returns it yet; the `codesign` ones report through
/// [`CodesignError`].
///
/// # Examples
///
/// ```
/// use signers::{Error, ProcessError};
///
/// fn explain(error: &Error) -> String {
///     match error {
///         Error::Process(ProcessError::NotFound { program }) => format!("install `{program}`"),
///         Error::Process(ProcessError::Failed { stderr, .. }) => stderr.clone(),
///         other => other.to_string(),
///     }
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ProcessError {
    /// No executable called `program` was found on `PATH`.
    #[error("`{program}` was not found on PATH")]
    NotFound { program: &'static str },

    /// `program` was found but couldn't start, e.g. because it isn't executable.
    ///
    /// The blocking `.run()` also returns it when it can't create its runtime.
    #[error("failed to spawn the `{program}` process or the Tokio runtime: {source}")]
    Spawn {
        program: &'static str,
        source: std::io::Error,
    },

    /// Waiting for `program` or reading its output failed.
    ///
    /// The outcome is unknown, so the targets may or may not have changed.
    #[error("failed while running the `{program}` process: {source}")]
    Run {
        program: &'static str,
        source: std::io::Error,
    },

    /// `program` exited with `code`.
    ///
    /// `stderr` holds its diagnostics and `stdout` what it printed on standard output, both
    /// trimmed. Only `stderr` is part of the message.
    ///
    /// When one run covers several targets, the targets before the rejected one may already have
    /// changed.
    #[error("`{program}` exited with code {code}: {}", diagnostics(.stderr))]
    Failed {
        program: &'static str,
        code: i32,
        stdout: String,
        stderr: String,
    },

    /// `program` was killed by a signal before it could exit.
    ///
    /// `status` holds the signal (`ExitStatusExt::signal`). `stderr` is usually empty. `stdout`
    /// holds what `program` printed on standard output, trimmed; it isn't part of the message.
    #[error("the `{program}` process terminated abnormally ({status}): {}", diagnostics(.stderr))]
    Terminated {
        program: &'static str,
        status: ExitStatus,
        stdout: String,
        stderr: String,
    },

    /// `program` exited 0, but its output couldn't be read as the action's result.
    ///
    /// `detail` says what didn't match, e.g. the number of results against the number of
    /// targets.
    #[error("`{program}` produced output this crate can't read: {detail}")]
    UnexpectedOutput {
        program: &'static str,
        detail: String,
    },
}

/// A sealed resource that [`verify`](crate::codesign::verify) found altered.
///
/// It is found in [`CodesignError::VerificationFailed`].
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::errors::Change;
/// use signers::{CodesignError, Error, codesign};
///
/// let result = codesign::verify("MyApp.app").check_designated_requirement(true).await;
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
}
