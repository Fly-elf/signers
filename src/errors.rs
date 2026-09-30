//! Why an action failed: [`Error`](enum@Error), and [`CodesignError`] for the `codesign` backend.

use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

/// A `Result` whose error is this crate's [`Error`](enum@Error).
pub type Result<T> = std::result::Result<T, Error>;

/// Why an action failed.
///
/// Every variant except [`Codesign`](Error::Codesign) comes from a check made before `codesign`
/// starts, so no target has been touched.
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
    /// No target was given, or every target was an empty path.
    #[error("no targets to operate on")]
    NoTargets,

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

    /// [`file_list`](crate::Codesign::file_list) was `-`, but the crate captures standard output,
    /// so the list would be lost.
    #[error("file_list(\"-\") is not supported: pass a path instead of standard output")]
    FileListToStdout,

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
        "the `codesign` binary was not found on PATH; \
         install the Xcode Command Line Tools with `xcode-select --install`"
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

    /// `codesign` exited with `code`. `stderr` holds its diagnostics, trimmed.
    ///
    /// In a batch, the targets before the rejected one have already changed. See
    /// [`Codesign`](crate::Codesign#errors).
    #[error("`codesign` exited with code {code}: {}", diagnostics(.stderr))]
    Failed { code: i32, stderr: String },

    /// `codesign` was killed by a signal before it could exit.
    ///
    /// `status` holds the signal (`ExitStatusExt::signal`). `stderr` is usually empty.
    #[error("the `codesign` process terminated abnormally ({status}): {}", diagnostics(.stderr))]
    Terminated { status: ExitStatus, stderr: String },
}

/// Returns `stderr`, or "no diagnostics" if it's empty, so a message never ends with a colon.
fn diagnostics(stderr: &str) -> &str {
    if stderr.is_empty() {
        "no diagnostics"
    } else {
        stderr
    }
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
            status: killed_by(9),
            stderr: String::new(),
        };
        assert_eq!(
            error.to_string(),
            "the `codesign` process terminated abnormally (signal: 9 (SIGKILL)): no diagnostics",
        );
    }

    /// The remedy is the whole point of the variant: without it the caller is
    /// left to guess that this is a toolchain problem.
    #[test]
    fn a_missing_binary_names_the_remedy() {
        let message = CodesignError::NotFound.to_string();
        assert!(message.contains("xcode-select --install"), "got {message}");
    }

    /// The outer `Error::Codesign` wrapper must forward `Display` unchanged, so callers who
    /// only do `eprintln!("{error}")` see no difference from before the split.
    #[test]
    fn the_wrapper_variant_forwards_display_unchanged() {
        let error = Error::from(CodesignError::NotFound);
        assert_eq!(error.to_string(), CodesignError::NotFound.to_string());
    }
}
