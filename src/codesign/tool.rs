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

#[cfg(test)]
#[path = "unit_tests/tool.rs"]
mod tests;
