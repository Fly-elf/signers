//! Starts the tool's process and captures its exit, with each way it can fail to run kept apart.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::process::{ExitStatus, Stdio};

use super::tool::Tool;
use crate::errors::{Error, ProcessError, Result};

/// How a process ended, with both streams decoded.
pub struct Exit {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Exit {
    /// Gives the streams of a run that exited 0.
    ///
    /// A non-zero exit goes through `failure`, which can read it as it likes. A kill by a signal
    /// has no exit code, so it is [`ProcessError::Terminated`] whatever `failure` does.
    pub fn success<T: Tool>(
        self,
        failure: impl FnOnce(i32, String, String) -> Error,
    ) -> Result<(String, String)> {
        if self.status.success() {
            return Ok((self.stdout, self.stderr));
        }
        Err(match self.status.code() {
            Some(code) => failure(code, self.stdout, self.stderr),
            // No exit code at all: the process was killed before it could
            // exit, so this is not the tool rejecting anything.
            None => T::error(ProcessError::Terminated {
                program: T::PROGRAM,
                status: self.status,
                stdout: self.stdout,
                stderr: self.stderr,
            }),
        })
    }
}

/// A failed run, split by whether the tool started at all.
pub(crate) enum RunError {
    /// The tool never ran, so nothing is known about any target; a batch stops on it.
    Unstarted(Error),
    /// The tool ran and failed; a batch collects it against its target.
    Failed(Error),
}

impl RunError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            RunError::Unstarted(error) | RunError::Failed(error) => error,
        }
    }
}

/// Runs the tool with `args` and waits for it, with no standard input.
pub(crate) async fn spawn<T: Tool>(args: &[Cow<'_, OsStr>]) -> std::result::Result<Exit, RunError> {
    tracing::debug!(target: "signers", program = T::PROGRAM, args = ?args, "spawning");

    // Spawning and waiting are kept apart so that a failure to *start*
    // the tool is never reported as one of its results. That means
    // configuring the streams by hand, which `Command::output` would
    // otherwise do: no inherited stdin for the tool to block on, and
    // both of its streams captured rather than leaking into the
    // caller's terminal.
    let started = std::time::Instant::now();
    let child = tokio::process::Command::new(T::PROGRAM)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| {
            RunError::Unstarted(T::error(match source.kind() {
                ErrorKind::NotFound => ProcessError::NotFound {
                    program: T::PROGRAM,
                },
                _ => ProcessError::Spawn {
                    program: T::PROGRAM,
                    source,
                },
            }))
        })?;

    let output = child.wait_with_output().await.map_err(|source| {
        RunError::Failed(T::error(ProcessError::Run {
            program: T::PROGRAM,
            source,
        }))
    })?;
    tracing::debug!(
        target: "signers",
        program = T::PROGRAM,
        status = %output.status,
        elapsed = ?started.elapsed(),
        "exited"
    );
    let stdout = decode(output.stdout);
    let stderr = decode(output.stderr);
    tracing::trace!(target: "signers", program = T::PROGRAM, stdout = %stdout, stderr = %stderr, "output");
    Ok(Exit {
        status: output.status,
        stdout,
        stderr,
    })
}

/// Turns a stream into text: invalid UTF-8 becomes U+FFFD, surrounding whitespace is dropped.
///
/// The only place the crate decodes a tool's output.
fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).trim().to_string()
}

#[cfg(test)]
#[path = "unit_tests/process.rs"]
mod tests;
