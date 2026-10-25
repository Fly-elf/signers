use std::process::ExitStatus;

use thiserror::Error;

use super::diagnostics;

/// Why running an external tool failed.
///
/// Each variant names the tool in `program`, the executable looked up on `PATH`, e.g.
/// `"codesign"`. It comes wrapped in [`Error::Process`]. The `codesign` actions return every
/// variant but [`NotFound`](ProcessError::NotFound), which is
/// [`CodesignError::NotFound`] so that it can hint at `/usr/bin`.
///
/// # Examples
///
/// ```
/// use signers::{Error, ProcessError};
///
/// fn explain(error: &Error) -> String {
///     match error {
///         Error::Process(ProcessError::NotFound { program, .. }) => format!("install `{program}`"),
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
    #[non_exhaustive]
    NotFound { program: &'static str },

    /// `program` was found but couldn't start, e.g. because it isn't executable.
    ///
    /// The blocking `.run()` also returns it when it can't create its runtime.
    #[error("failed to spawn the `{program}` process or the Tokio runtime: {source}")]
    #[non_exhaustive]
    Spawn {
        program: &'static str,
        source: std::io::Error,
    },

    /// Waiting for `program` or reading its output failed.
    ///
    /// The outcome is unknown, so the targets may or may not have changed.
    #[error("failed while running the `{program}` process: {source}")]
    #[non_exhaustive]
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
    #[non_exhaustive]
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
    #[non_exhaustive]
    Terminated {
        program: &'static str,
        status: ExitStatus,
        stdout: String,
        stderr: String,
    },

    /// `program` exited 0, but its output couldn't be read as the action's result.
    ///
    /// `detail` says what didn't match, e.g. the number of results against the number of
    /// targets. `stdout` and `stderr` hold what the run printed, trimmed; with one run over several
    /// targets they cover all of them. Neither is part of the message.
    #[error("`{program}` produced output this crate can't read: {detail}")]
    #[non_exhaustive]
    UnexpectedOutput {
        program: &'static str,
        detail: String,
        stdout: String,
        stderr: String,
    },
}

#[cfg(feature = "__test-constructors")]
impl ProcessError {
    #[doc(hidden)]
    pub fn not_found(program: &'static str) -> Self {
        Self::NotFound { program }
    }

    #[doc(hidden)]
    pub fn spawn(program: &'static str, source: std::io::Error) -> Self {
        Self::Spawn { program, source }
    }

    #[doc(hidden)]
    pub fn run(program: &'static str, source: std::io::Error) -> Self {
        Self::Run { program, source }
    }

    #[doc(hidden)]
    pub fn failed(program: &'static str, code: i32, stdout: String, stderr: String) -> Self {
        Self::Failed {
            program,
            code,
            stdout,
            stderr,
        }
    }

    #[doc(hidden)]
    pub fn terminated(
        program: &'static str,
        status: ExitStatus,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self::Terminated {
            program,
            status,
            stdout,
            stderr,
        }
    }

    #[doc(hidden)]
    pub fn unexpected_output(
        program: &'static str,
        detail: String,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self::UnexpectedOutput {
            program,
            detail,
            stdout,
            stderr,
        }
    }
}
