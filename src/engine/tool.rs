//! The external program an action runs, and how its failures reach the caller.

use crate::errors::{Error, Output, ProcessError};

/// An external program that actions run, looked up on `PATH`.
///
/// A tool overrides [`error`](Self::error) to report some failures as an error of its own; the
/// default wraps every [`ProcessError`] as [`Error::Process`].
pub trait Tool: 'static {
    /// The executable name; also what [`ProcessError`] reports as `program`.
    const PROGRAM: &'static str;

    /// Turns a process failure into the error this tool reports.
    ///
    /// An override maps the failures it names and wraps the rest as [`Error::Process`].
    fn error(error: ProcessError) -> Error {
        Error::Process(error)
    }

    /// The error for a run that exited non-zero or was killed, as [`ProcessError::Failed`] of this tool.
    fn failed(output: Output) -> Error {
        Self::error(ProcessError::Failed { output })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::Tool;

    /// Runs shell snippets, with every `Tool` default left as it is.
    pub struct Sh;

    impl Tool for Sh {
        const PROGRAM: &'static str = "sh";
    }

    /// The real `codesign`, for runs that need a tool with signed binaries to read.
    pub struct Real;

    impl Tool for Real {
        const PROGRAM: &'static str = "codesign";
    }

    /// A program no PATH has.
    pub struct Missing;

    impl Tool for Missing {
        const PROGRAM: &'static str = "signers-no-such-program";
    }

    /// A file that exists but isn't executable.
    pub struct NotExecutable;

    impl Tool for NotExecutable {
        const PROGRAM: &'static str = "/etc/hosts";
    }
}

#[cfg(test)]
#[path = "unit_tests/tool.rs"]
mod tests;
