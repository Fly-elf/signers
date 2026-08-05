//! Library error types.

use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

/// Convenience alias for results returned across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while running a signing action.
///
/// Marked `#[non_exhaustive]`: new variants will be added as backends grow, so
/// always keep a wildcard arm when matching.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// No target was supplied, or every supplied target was empty.
    #[error("no targets to operate on")]
    NoTargets,

    /// A target path does not exist on disk.
    #[error("target does not exist: {0}")]
    TargetNotFound(PathBuf),

    /// A target path could not be accessed while checking that it exists (e.g.
    /// permission denied on a parent directory).
    #[error("could not access target {path}: {source}")]
    TargetAccess {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The signing action's [`file_list`](crate::codesign::Codesign::file_list)
    /// was set to `-`, `codesign`'s syntax for writing the list to standard
    /// output.
    ///
    /// This crate captures the child process's stdout internally and has no
    /// path to relay it back to the caller, so that list would otherwise be
    /// silently discarded. Pass a real file path instead.
    #[error("file_list(\"-\") is not supported: pass a path instead of standard output")]
    FileListToStdout,

    /// The `codesign` binary is not installed, or is not on `PATH`.
    ///
    /// Match on this to fall back to another backend: it is the one failure
    /// the native `rcodesign` backend cannot have.
    #[error(
        "the `codesign` binary was not found on PATH; \
         install the Xcode Command Line Tools with `xcode-select --install`"
    )]
    CodesignNotFound,

    /// The `codesign` process could not be spawned for any other reason — the
    /// binary is there but not executable, the fork failed, and so on.
    #[error("failed to spawn the `codesign` process: {0}")]
    Spawn(#[source] std::io::Error),

    /// The `codesign` process started, but its result could not be collected:
    /// reading its output or reaping it failed.
    #[error("failed while running the `codesign` process: {0}")]
    Run(#[source] std::io::Error),

    /// The `codesign` process ran to completion and exited with a failure code;
    /// `stderr` holds its captured (trimmed) diagnostic output.
    #[error("`codesign` exited with code {code}: {}", diagnostics(.stderr))]
    Codesign { code: i32, stderr: String },

    /// The `codesign` process was killed before it could exit — a crash on a
    /// malformed binary, an external timeout, the OOM killer.
    ///
    /// It has no exit code, and usually no diagnostics either. On Unix the
    /// signal that killed it is reachable through `ExitStatusExt::signal`.
    #[error("the `codesign` process terminated abnormally ({status}): {}", diagnostics(.stderr))]
    Terminated { status: ExitStatus, stderr: String },
}

/// Stands in for the diagnostics a failing run did not produce, so that a
/// message never trails off after its colon.
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
        let error = Error::Codesign {
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
        let silent = Error::Codesign {
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
        let error = Error::Terminated {
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
        let message = Error::CodesignNotFound.to_string();
        assert!(message.contains("xcode-select --install"), "got {message}");
    }
}
