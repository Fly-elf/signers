//! Why an action failed: [`Error`](enum@Error). [`ProcessError`] says what went wrong with the
//! external tool's process, and [`CodesignError`] holds what only `codesign` reports.

use std::path::PathBuf;

use thiserror::Error;

mod process;

pub use process::ProcessError;

/// A `Result` whose error is this crate's [`Error`](enum@Error).
pub type Result<T> = std::result::Result<T, Error>;

/// Why an action failed.
///
/// Every variant except [`Codesign`](Error::Codesign), [`Process`](Error::Process),
/// [`Batch`](Error::Batch) and [`Io`](Error::Io) comes from a check made before the tool
/// starts, so no target has been touched. The order of the checks is listed in
/// [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() {
/// use signers::{Error, ProcessError, codesign};
///
/// match codesign::sign_adhoc("mytool").force(true).await {
///     Ok(()) => {}
///     Err(Error::PathNotFound(path)) => eprintln!("no such file: {}", path.display()),
///     Err(Error::Process(ProcessError::Failed { stderr, .. })) => eprintln!("{stderr}"),
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
    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),

    /// Whether this target exists couldn't be checked, e.g. because a parent directory denies
    /// access.
    #[error("could not access {path}: {source}")]
    #[non_exhaustive]
    PathAccess {
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
    #[non_exhaustive]
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
    /// Every target was tried, so the ones not listed succeeded; their outputs are dropped. A target
    /// for which the tool couldn't start is listed with its spawn error. One failing
    /// target is enough to get this variant rather than its plain error. See
    /// [`per_target`](crate::codesign::Sign::per_target) for an example.
    #[error("{} target(s) failed: {}", .0.len(), failures(.0))]
    Batch(Vec<(PathBuf, Error)>),

    /// `codesign` is missing, or it rejected the job with a verdict.
    ///
    /// Only what is specific to `codesign` comes here: [`NotFound`](CodesignError::NotFound) and
    /// the verdicts of [`verify`](crate::codesign::verify),
    /// [`validate_constraint`](crate::codesign::validate_constraint) and
    /// [`display`](crate::codesign::display). Any other failure of its process is
    /// [`Process`](Error::Process).
    #[error(transparent)]
    Codesign(#[from] CodesignError),

    /// An external tool's process failed: it couldn't run, exited non-zero, or printed what
    /// this crate can't read.
    ///
    /// `program` in the [`ProcessError`] names the tool. For `codesign` it is every such failure
    /// except a missing executable, which is [`Codesign`](Error::Codesign).
    #[error(transparent)]
    Process(#[from] ProcessError),
}

#[cfg(feature = "__test-constructors")]
impl Error {
    #[doc(hidden)]
    pub fn path_access(path: PathBuf, source: std::io::Error) -> Self {
        Self::PathAccess { path, source }
    }

    #[doc(hidden)]
    pub fn io(path: PathBuf, source: std::io::Error) -> Self {
        Self::Io { path, source }
    }
}

/// What only `codesign` reports: a missing executable, and the verdicts of some actions.
///
/// Every other failure of its process is a [`ProcessError`] in [`Error::Process`].
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
    #[non_exhaustive]
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
    #[non_exhaustive]
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
    #[non_exhaustive]
    ConstraintInvalid { stdout: String, stderr: String },

    /// [`display`](crate::codesign::display) found no signature in the
    /// [`signature_slot`](crate::codesign::Display::signature_slot) it was asked for.
    ///
    /// Code with one signature has nothing in the second slot. `codesign` exits 0 for it, and
    /// reports `no signature` in place of the signature, so this crate fails instead of returning
    /// one with nothing in it. Unsigned code is a different failure: [`ProcessError::Failed`].
    /// `stderr` and `stdout` hold what `codesign` printed on each stream during the whole run,
    /// trimmed, so with one run over several targets they also cover targets that read fine. Only
    /// `stderr` is part of the message.
    #[error("no signature: {}", diagnostics(.stderr))]
    #[non_exhaustive]
    NoSignature { stdout: String, stderr: String },
}

#[cfg(feature = "__test-constructors")]
impl CodesignError {
    #[doc(hidden)]
    pub fn verification_failed(
        stdout: String,
        stderr: String,
        resources: Vec<ResourceChange>,
    ) -> Self {
        Self::VerificationFailed {
            stdout,
            stderr,
            resources,
        }
    }

    #[doc(hidden)]
    pub fn requirement_unsatisfied(stdout: String, stderr: String) -> Self {
        Self::RequirementUnsatisfied { stdout, stderr }
    }

    #[doc(hidden)]
    pub fn constraint_invalid(stdout: String, stderr: String) -> Self {
        Self::ConstraintInvalid { stdout, stderr }
    }

    #[doc(hidden)]
    pub fn no_signature(stdout: String, stderr: String) -> Self {
        Self::NoSignature { stdout, stderr }
    }
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
pub(crate) fn diagnostics(stderr: &str) -> &str {
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
#[path = "unit_tests/errors.rs"]
mod tests;
