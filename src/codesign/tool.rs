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
            stdout: String::new(),
            stderr: String::new(),
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
            Error::Process(ProcessError::Spawn { program, source }) => {
                assert_eq!(program, "codesign");
                assert_eq!(source.to_string(), "no fork");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
        match run {
            Error::Process(ProcessError::Run { program, source }) => {
                assert_eq!(program, "codesign");
                assert_eq!(source.to_string(), "no wait");
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn failed_keeps_the_code_and_both_streams() {
        let error = Codesign::failed(3, "out".into(), "err".into());

        match error {
            Error::Process(ProcessError::Failed {
                program,
                code,
                stdout,
                stderr,
            }) => {
                assert_eq!(program, "codesign");
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
            Error::Process(ProcessError::Terminated {
                program,
                status,
                stdout,
                stderr,
            }) => {
                assert_eq!(program, "codesign");
                assert_eq!(status.signal(), Some(9));
                assert_eq!(stdout, "out");
                assert_eq!(stderr, "err");
            }
            other => panic!("expected Terminated, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_output_names_codesign_and_keeps_its_detail() {
        let error = Codesign::unexpected_output("2 outputs for 3 targets");

        match error {
            Error::Process(ProcessError::UnexpectedOutput { program, detail }) => {
                assert_eq!(program, "codesign");
                assert_eq!(detail, "2 outputs for 3 targets");
            }
            other => panic!("expected UnexpectedOutput, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_output_through_the_mapping_is_the_same_error() {
        let error = Codesign::error(ProcessError::UnexpectedOutput {
            program: "codesign",
            detail: "no plist".into(),
        });

        assert!(matches!(
            error,
            Error::Process(ProcessError::UnexpectedOutput { program: "codesign", ref detail })
                if detail == "no plist"
        ));
    }

    #[test]
    fn the_mapped_errors_read_as_codesign_errors() {
        let error = Codesign::failed(1, String::new(), "A.app: bad".into());

        assert_eq!(
            error.to_string(),
            "`codesign` exited with code 1: A.app: bad"
        );
    }

    #[test]
    fn the_not_found_message_keeps_the_usr_bin_hint() {
        let error = Codesign::error(ProcessError::NotFound {
            program: "codesign",
        });

        assert_eq!(
            error.to_string(),
            "`codesign` was not found on PATH; it ships with macOS in /usr/bin, \
             so check that PATH includes /usr/bin"
        );
    }
}
