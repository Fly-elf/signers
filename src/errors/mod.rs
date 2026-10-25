//! Why an action failed: [`Error`](enum@Error). [`ProcessError`] says what went wrong with the
//! external tool's process. `codesign` adds [`CodesignError`](crate::codesign::CodesignError)
//! for what only it reports.

use std::path::PathBuf;

use thiserror::Error;

/// Gives an error type `stdout()` and `stderr()` over its `output()`; the docs are written once here.
macro_rules! streams {
    ($error:ty) => {
        impl $error {
            /// What the tool printed on standard output, trimmed.
            ///
            /// `None` when the error doesn't come from a finished run, see
            /// [`output`](Self::output). Shorthand for `output()` then
            /// [`stdout`](crate::errors::Output::stdout).
            pub fn stdout(&self) -> Option<&str> {
                self.output().map(|output| output.stdout.as_str())
            }

            /// What the tool printed on standard error, trimmed.
            ///
            /// `None` when the error doesn't come from a finished run, see
            /// [`output`](Self::output). Shorthand for `output()` then
            /// [`stderr`](crate::errors::Output::stderr).
            pub fn stderr(&self) -> Option<&str> {
                self.output().map(|output| output.stderr.as_str())
            }
        }
    };
}

pub(crate) use streams;

mod process;

pub use process::{Output, ProcessError};

/// A `Result` whose error is this crate's [`Error`](enum@Error).
pub type Result<T> = std::result::Result<T, Error>;

/// Why an action failed.
///
/// For [`PathAccess`](Error::PathAccess) and [`Io`](Error::Io) the I/O error is
/// [`source()`](std::error::Error::source), not part of the message; the message of
/// [`Batch`](Error::Batch) includes the causes of each failure.
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
/// use signers::{Error, codesign};
///
/// match codesign::sign_adhoc("mytool").force(true).await {
///     Ok(()) => {}
///     Err(Error::PathNotFound(path)) => eprintln!("no such file: {}", path.display()),
///     Err(error) => match error.stderr() {
///         Some(stderr) => eprintln!("codesign said: {stderr}"),
///         None => eprintln!("{error}"),
///     },
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
    #[error("could not access {path}")]
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
    #[error("I/O error on {path}")]
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
    /// Only what is specific to `codesign` comes here: [`NotFound`](crate::codesign::CodesignError::NotFound) and
    /// the verdicts of [`verify`](crate::codesign::verify),
    /// [`validate_constraint`](crate::codesign::validate_constraint) and
    /// [`display`](crate::codesign::display). Any other failure of its process is
    /// [`Process`](Error::Process).
    #[error(transparent)]
    Codesign(#[from] crate::codesign::CodesignError),

    /// An external tool's process failed: it couldn't run, exited non-zero, or printed what
    /// this crate can't read.
    ///
    /// `program` in the [`ProcessError`] names the tool. For `codesign` it is every such failure
    /// except a missing executable, which is [`Codesign`](Error::Codesign).
    #[error(transparent)]
    Process(#[from] ProcessError),
}

impl Error {
    /// The finished run behind this error: its exit status and both output streams.
    ///
    /// `Some` for a [`Process`](Error::Process) error that came after the run, and for a
    /// [`Codesign`](Error::Codesign) verdict. `None` for everything else, including checks made
    /// before the tool starts and [`Batch`](Error::Batch): look at the errors inside it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn run() {
    /// use signers::codesign;
    ///
    /// if let Err(error) = codesign::blocking::verify("MyApp.app").run() {
    ///     if let Some(output) = error.output() {
    ///         eprintln!("{} ended with {}", output.program, output.status);
    ///     }
    /// }
    /// # }
    /// ```
    pub fn output(&self) -> Option<&Output> {
        match self {
            Error::Process(error) => error.output(),
            Error::Codesign(error) => error.output(),
            _ => None,
        }
    }
}

streams!(Error);

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

/// Returns `stderr`, or "no diagnostics" if it's empty, so a message never ends with a colon.
pub(crate) fn diagnostics(stderr: &str) -> &str {
    if stderr.is_empty() {
        "no diagnostics"
    } else {
        stderr
    }
}

/// Joins the entries of a [`Batch`](Error::Batch) as `path: error: cause…`, separated by `; `.
fn failures(failures: &[(PathBuf, Error)]) -> String {
    failures
        .iter()
        .map(|(path, error)| format!("{}: {}", path.display(), chain(error)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Renders an error followed by each of its sources, as `error: cause: …`.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
#[path = "unit_tests/support.rs"]
pub(crate) mod testing;

#[cfg(test)]
#[path = "unit_tests/errors.rs"]
mod tests;
