use crate::engine::Tool;
use crate::errors::{CodesignError, Error, ProcessError};

pub(crate) struct Codesign;

impl Tool for Codesign {
    const PROGRAM: &'static str = "codesign";

    fn error(error: ProcessError) -> Error {
        match error {
            ProcessError::NotFound { .. } => CodesignError::NotFound.into(),
            other => Error::Process(other),
        }
    }
}

impl Codesign {
    pub(crate) fn unexpected_output(detail: impl Into<String>) -> Error {
        Self::error(ProcessError::UnexpectedOutput {
            program: Self::PROGRAM,
            detail: detail.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::*;

    #[test]
    fn not_found_maps_to_the_codesign_variant() {
        let error = Codesign::error(ProcessError::NotFound {
            program: "codesign",
        });

        assert!(matches!(error, Error::Codesign(CodesignError::NotFound)));
    }

    #[test]
    fn spawn_and_run_keep_their_io_error() {
        let spawn = Codesign::error(ProcessError::Spawn {
            program: "codesign",
            source: std::io::Error::other("no fork"),
        });
        let run = Codesign::error(ProcessError::Run {
            program: "codesign",
            source: std::io::Error::other("no wait"),
        });

        match spawn {
            Error::Codesign(CodesignError::Spawn(source)) => {
                assert_eq!(source.to_string(), "no fork")
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
        match run {
            Error::Codesign(CodesignError::Run(source)) => {
                assert_eq!(source.to_string(), "no wait")
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn failed_keeps_the_code_and_both_streams() {
        let error = Codesign::failed(3, "out".into(), "err".into());

        match error {
            Error::Codesign(CodesignError::Failed {
                code,
                stdout,
                stderr,
            }) => {
                assert_eq!(code, 3);
                assert_eq!(stdout, "out");
                assert_eq!(stderr, "err");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn terminated_keeps_the_status_and_both_streams() {
        let error = Codesign::error(ProcessError::Terminated {
            program: "codesign",
            status: ExitStatus::from_raw(9),
            stdout: "out".into(),
            stderr: "err".into(),
        });

        match error {
            Error::Codesign(CodesignError::Terminated {
                status,
                stdout,
                stderr,
            }) => {
                assert_eq!(status.signal(), Some(9));
                assert_eq!(stdout, "out");
                assert_eq!(stderr, "err");
            }
            other => panic!("expected Terminated, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_output_keeps_its_detail() {
        let error = Codesign::error(ProcessError::UnexpectedOutput {
            program: "codesign",
            detail: "2 outputs for 3 targets".into(),
        });

        match error {
            Error::Codesign(CodesignError::UnexpectedOutput { detail }) => {
                assert_eq!(detail, "2 outputs for 3 targets");
            }
            other => panic!("expected UnexpectedOutput, got {other:?}"),
        }
    }

    /// Every message a `codesign` user already saw stays the same through the mapping.
    #[test]
    fn the_mapped_errors_read_as_codesign_errors() {
        let error = Codesign::failed(1, String::new(), "A.app: bad".into());

        assert_eq!(
            error.to_string(),
            "`codesign` exited with code 1: A.app: bad"
        );
    }
}
