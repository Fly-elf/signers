//! Starts the tool's process and captures its [`Output`], with each way it can fail to run kept apart.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::process::Stdio;

use super::tool::Tool;
use crate::errors::{Error, Output, ProcessError, Result};

/// Passes a run that exited 0; otherwise `failure` maps its exit code, and a kill by a signal is
/// the tool's [`ProcessError::Failed`].
pub(crate) fn exit<T: Tool>(
    output: Output,
    failure: impl FnOnce(i32, Output) -> Error,
) -> Result<Output> {
    if output.status.success() {
        return Ok(output);
    }
    Err(match output.status.code() {
        Some(code) => failure(code, output),
        // No exit code at all: the process was killed before it could
        // exit, so this is not the tool rejecting anything.
        None => T::error(ProcessError::Failed { output }),
    })
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
pub(crate) async fn spawn<T: Tool>(
    args: &[Cow<'_, OsStr>],
) -> std::result::Result<Output, RunError> {
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
    Ok(Output {
        program: T::PROGRAM,
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
