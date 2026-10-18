use crate::engine::Tool;
use crate::errors::{CodesignError, Error, ProcessError};

pub(crate) struct Codesign;

impl Tool for Codesign {
    const PROGRAM: &'static str = "codesign";

    fn error(error: ProcessError) -> Error {
        match error {
            ProcessError::NotFound { .. } => CodesignError::NotFound,
            ProcessError::Spawn { source, .. } => CodesignError::Spawn(source),
            ProcessError::Run { source, .. } => CodesignError::Run(source),
            ProcessError::Failed {
                code,
                stdout,
                stderr,
                ..
            } => CodesignError::Failed {
                code,
                stdout,
                stderr,
            },
            ProcessError::Terminated {
                status,
                stdout,
                stderr,
                ..
            } => CodesignError::Terminated {
                status,
                stdout,
                stderr,
            },
            ProcessError::UnexpectedOutput { detail, .. } => {
                CodesignError::UnexpectedOutput { detail }
            }
        }
        .into()
    }
}
