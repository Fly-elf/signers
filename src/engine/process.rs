use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::process::{ExitStatus, Stdio};

use super::tool::Tool;
use crate::errors::{Error, ProcessError, Result};

pub struct Exit {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Exit {
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

pub(crate) enum RunError {
    Unstarted(Error),
    Failed(Error),
}

impl RunError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            RunError::Unstarted(error) | RunError::Failed(error) => error,
        }
    }
}

pub(crate) async fn spawn<T: Tool>(args: &[Cow<'_, OsStr>]) -> std::result::Result<Exit, RunError> {
    tracing::trace!(
        "running {} {}",
        T::PROGRAM,
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    // Spawning and waiting are kept apart so that a failure to *start*
    // the tool is never reported as one of its results. That means
    // configuring the streams by hand, which `Command::output` would
    // otherwise do: no inherited stdin for the tool to block on, and
    // both of its streams captured rather than leaking into the
    // caller's terminal.
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
    Ok(Exit {
        status: output.status,
        stdout: decode(output.stdout),
        stderr: decode(output.stderr),
    })
}

/// Turns a stream into text: invalid UTF-8 becomes U+FFFD, surrounding whitespace is dropped.
///
/// The only place the crate decodes `codesign` output.
fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).trim().to_string()
}
