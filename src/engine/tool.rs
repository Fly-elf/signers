use crate::errors::{Error, ProcessError};

pub trait Tool: 'static {
    const PROGRAM: &'static str;

    fn error(error: ProcessError) -> Error {
        Error::Process(error)
    }

    fn failed(code: i32, stdout: String, stderr: String) -> Error {
        Self::error(ProcessError::Failed {
            program: Self::PROGRAM,
            code,
            stdout,
            stderr,
        })
    }
}
