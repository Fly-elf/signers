//! Builders for the finished runs that error tests need.

use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use super::Output;

/// A run of `program` that exited with `code`.
pub(crate) fn exited(program: &'static str, code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        program,
        status: ExitStatus::from_raw(code << 8),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

/// A run of `program` that a signal killed, as `wait` reports it.
pub(crate) fn killed(program: &'static str, signal: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        program,
        status: ExitStatus::from_raw(signal),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

/// A `codesign` run that exited 0 printing `stdout` and `stderr`.
pub(crate) fn ran(stdout: impl Into<String>, stderr: impl Into<String>) -> Output {
    Output {
        program: "codesign",
        status: ExitStatus::from_raw(0),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}
