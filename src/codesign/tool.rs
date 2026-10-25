use crate::codesign::CodesignError;
use crate::engine::Tool;
use crate::errors::{Error, ProcessError};

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
#[path = "unit_tests/tool.rs"]
mod tests;
