//! What can go wrong while running an action.
//!
//! - [`Error`](enum@Error) — every error this crate can return.
//! - [`CodesignError`] — the errors specific to the `codesign` backend.
//! - [`Result`] — shorthand for `Result<T, Error>`, used everywhere in the crate.

use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

/// Shorthand for a result that fails with this crate's [`Error`](enum@Error).
pub type Result<T> = std::result::Result<T, Error>;

/// Every error this crate can return, from any action.
///
/// - The crate turning a request down before running anything — a target that isn't there, an
///   option it can't honour. Nothing has run yet, so a batch that can't work this way leaves
///   every target untouched.
/// - What a backend reported once it actually ran, e.g. [`Error::Codesign`].
///
/// # Examples
///
/// ```no_run
/// # async fn run() {
/// use signers::{CodesignError, Error, codesign::Codesign};
///
/// match Codesign::sign("MyApp.app", "-").force(true).await {
///     Ok(()) => println!("signed"),
///     Err(Error::Codesign(CodesignError::NotFound)) => {
///         eprintln!("run `xcode-select --install` first")
///     }
///     Err(Error::Codesign(CodesignError::Failed { stderr, .. })) => {
///         eprintln!("codesign said no: {stderr}")
///     }
///     Err(error) => eprintln!("{error}"),
/// }
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// No target was given, or every one given was empty.
    #[error("no targets to operate on")]
    NoTargets,

    /// A target isn't there.
    #[error("target does not exist: {0}")]
    TargetNotFound(PathBuf),

    /// A target couldn't be looked at to find out whether it exists — usually
    /// permission denied somewhere in its parent directories.
    #[error("could not access target {path}: {source}")]
    TargetAccess {
        path: PathBuf,
        source: std::io::Error,
    },

    /// [`file_list`](crate::codesign::Codesign::file_list) was set to `-`,
    /// which is how `codesign` spells "write the list to standard output".
    ///
    /// This crate captures the child's output and has nowhere to hand that list
    /// to you, so it would just be thrown away. Pass a real path instead.
    #[error("file_list(\"-\") is not supported: pass a path instead of standard output")]
    FileListToStdout,

    /// Something went wrong in the `codesign` subprocess backend; see [`CodesignError`].
    #[error(transparent)]
    Codesign(#[from] CodesignError),
}

/// What can go wrong specifically in the `codesign` subprocess backend.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum CodesignError {
    /// The `codesign` binary isn't installed, or isn't on `PATH`.
    ///
    /// Worth matching on if you want to fall back to another backend: it's the
    /// one failure the native `rcodesign` backend can't have.
    #[error(
        "the `codesign` binary was not found on PATH; \
         install the Xcode Command Line Tools with `xcode-select --install`"
    )]
    NotFound,

    /// `codesign` is installed but couldn't be started: not executable, a
    /// failed fork, and so on.
    #[error("failed to spawn the `codesign` process: {0}")]
    Spawn(#[source] std::io::Error),

    /// `codesign` started, but reading its output or reaping it failed, so
    /// there's no result to report either way.
    #[error("failed while running the `codesign` process: {0}")]
    Run(#[source] std::io::Error),

    /// `codesign` ran and refused the job. This is the one that carries its
    /// complaint: `stderr` is what it printed, trimmed.
    #[error("`codesign` exited with code {code}: {}", diagnostics(.stderr))]
    Failed { code: i32, stderr: String },

    /// `codesign` was killed before it could exit — a crash on a malformed
    /// binary, a timeout from outside, the OOM killer.
    ///
    /// No exit code, and usually nothing on `stderr` either. On Unix, the
    /// signal that killed it is in `status`, via `ExitStatusExt::signal`.
    #[error("the `codesign` process terminated abnormally ({status}): {}", diagnostics(.stderr))]
    Terminated { status: ExitStatus, stderr: String },
}

/// Stands in for the diagnostics a failing run didn't produce, so a message
/// never trails off after its colon.
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
