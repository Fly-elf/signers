//! The external program an action runs, and how its failures reach the caller.

use crate::errors::{Error, ProcessError};

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

    /// The error for a non-zero exit, as [`ProcessError::Failed`] of this tool.
    fn failed(code: i32, stdout: String, stderr: String) -> Error {
        Self::error(ProcessError::Failed {
            program: Self::PROGRAM,
            code,
            stdout,
            stderr,
        })
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
mod tests {
    use super::testing::Sh;
    use super::*;

    #[test]
    fn the_default_error_wraps_the_process_error_unchanged() {
        let error = Sh::error(ProcessError::NotFound { program: "sh" });

        assert!(matches!(
            error,
            Error::Process(ProcessError::NotFound { program: "sh" })
        ));
    }

    #[test]
    fn the_default_failure_is_a_failed_process_of_this_program() {
        let error = Sh::failed(5, "out".into(), "err".into());

        match error {
            Error::Process(ProcessError::Failed {
                program,
                code,
                stdout,
                stderr,
            }) => {
                assert_eq!(program, "sh");
                assert_eq!(code, 5);
                assert_eq!(stdout, "out");
                assert_eq!(stderr, "err");
            }
            other => panic!("expected Process(Failed), got {other:?}"),
        }
        assert_eq!(
            Sh::failed(5, String::new(), String::new()).to_string(),
            "`sh` exited with code 5: no diagnostics"
        );
    }
}
