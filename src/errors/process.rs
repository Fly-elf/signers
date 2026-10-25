use std::fmt;
use std::process::ExitStatus;

use thiserror::Error;

use super::diagnostics;

/// Why running an external tool failed.
///
/// Each variant names the tool in `program`, the executable looked up on `PATH`, e.g.
/// `"codesign"`. It comes wrapped in [`Error::Process`](crate::Error::Process). The `codesign` actions return every
/// variant but [`NotFound`](ProcessError::NotFound), which is
/// [`CodesignError::NotFound`](crate::codesign::CodesignError::NotFound) so that it can hint at `/usr/bin`.
///
/// [`Failed`](ProcessError::Failed) and [`UnexpectedOutput`](ProcessError::UnexpectedOutput) come
/// after a run that ended, and carry its [`Output`].
///
/// # Examples
///
/// ```
/// use signers::{Error, ProcessError};
///
/// fn explain(error: &Error) -> String {
///     match error {
///         Error::Process(ProcessError::NotFound { program, .. }) => format!("install `{program}`"),
///         Error::Process(ProcessError::Failed { output, .. }) => output.stderr.clone(),
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

    /// `program` exited non-zero, or was killed by a signal.
    ///
    /// `output` holds the exit status and what the run printed. The message gives the exit code,
    /// or the signal when there is none (`status.code()` is [`None`]), followed by the `stderr`
    /// diagnostics.
    ///
    /// When one run covers several targets, the targets before the rejected one may already have
    /// changed.
    #[error(fmt = failed)]
    #[non_exhaustive]
    Failed { output: Output },

    /// `program` exited 0, but its output couldn't be read as the action's result.
    ///
    /// `detail` says what didn't match, e.g. the number of results against the number of
    /// targets. `output` holds what the run printed, for all its targets. Only `detail` is part
    /// of the message.
    #[error("`{}` produced output this crate can't read: {detail}", .output.program)]
    #[non_exhaustive]
    UnexpectedOutput { detail: String, output: Output },
}

impl ProcessError {
    /// The tool this error is about, e.g. `"codesign"`.
    pub fn program(&self) -> &'static str {
        match self {
            Self::NotFound { program }
            | Self::Spawn { program, .. }
            | Self::Run { program, .. } => program,
            Self::Failed { output } | Self::UnexpectedOutput { output, .. } => output.program,
        }
    }

    /// The finished run behind this error, for [`Failed`](Self::Failed) and
    /// [`UnexpectedOutput`](Self::UnexpectedOutput); `None` for a process that never ran to the end.
    pub fn output(&self) -> Option<&Output> {
        match self {
            Self::Failed { output } | Self::UnexpectedOutput { output, .. } => Some(output),
            Self::NotFound { .. } | Self::Spawn { .. } | Self::Run { .. } => None,
        }
    }
}

super::streams!(ProcessError);

/// What a run of an external tool produced once it ended.
///
/// Errors that come after the run carry it: [`ProcessError::Failed`],
/// [`ProcessError::UnexpectedOutput`] and the verdicts of
/// [`CodesignError`](crate::CodesignError). Read it with `output()` on any of them, or with
/// `stdout()` and `stderr()` when only the text matters.
///
/// With one run over several targets, the streams cover all of them, including targets that
/// passed before the one that failed.
///
/// # Examples
///
/// ```no_run
/// # fn run() {
/// use signers::{Error, ProcessError, codesign};
///
/// match codesign::blocking::display("MyApp.app").run() {
///     Err(Error::Process(ProcessError::Failed { output, .. })) => {
///         match output.status.code() {
///             Some(code) => eprintln!("{} exited with {code}", output.program),
///             None => eprintln!("{} was killed", output.program),
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Output {
    /// The executable that ran, e.g. `"codesign"`.
    pub program: &'static str,
    /// How the process ended. [`code`](ExitStatus::code) is `None` when a signal killed it.
    pub status: ExitStatus,
    /// What it printed on standard output, decoded lossily as UTF-8 and trimmed.
    pub stdout: String,
    /// What it printed on standard error, decoded and trimmed like `stdout`.
    pub stderr: String,
}

#[cfg(feature = "__test-constructors")]
impl Output {
    #[doc(hidden)]
    pub fn new(program: &'static str, status: ExitStatus, stdout: String, stderr: String) -> Self {
        Self {
            program,
            status,
            stdout,
            stderr,
        }
    }
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
    pub fn failed(output: Output) -> Self {
        Self::Failed { output }
    }

    #[doc(hidden)]
    pub fn unexpected_output(detail: String, output: Output) -> Self {
        Self::UnexpectedOutput { detail, output }
    }
}

fn failed(output: &Output, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Output {
        program,
        status,
        stderr,
        ..
    } = output;
    match status.code() {
        Some(code) => write!(
            f,
            "`{program}` exited with code {code}: {}",
            diagnostics(stderr)
        ),
        None => write!(
            f,
            "`{program}` was killed ({status}): {}",
            diagnostics(stderr)
        ),
    }
}

#[cfg(test)]
#[path = "unit_tests/process.rs"]
mod tests;
