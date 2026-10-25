use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use signers::errors::{Change, ResourceChange};
use signers::{CodesignError, Error, ProcessError};

create_exception!(_native, NativeError, PyException);

pub(crate) fn to_py(err: Error) -> PyErr {
    Python::attach(|py| match payload(py, &err) {
        Ok(payload) => NativeError::new_err(payload.unbind()),
        Err(failed) => failed,
    })
}

fn payload<'py>(py: Python<'py>, err: &Error) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("message", err.to_string())?;
    let kind = match err {
        Error::NoTargets => "NoTargets",
        Error::EmptyTarget(index) => {
            d.set_item("index", index)?;
            "EmptyTarget"
        }
        Error::PathNotFound(path) => {
            d.set_item("path", path.as_os_str())?;
            "PathNotFound"
        }
        Error::PathAccess { path, source, .. } => {
            d.set_item("path", path.as_os_str())?;
            d.set_item("errno", source.raw_os_error())?;
            "PathAccess"
        }
        Error::Io { path, source, .. } => {
            d.set_item("path", path.as_os_str())?;
            d.set_item("errno", source.raw_os_error())?;
            "Io"
        }
        Error::StdioPath(option) => {
            d.set_item("option", option)?;
            "StdioPath"
        }
        Error::SharedOutputPerTarget(option) => {
            d.set_item("option", option)?;
            "SharedOutputPerTarget"
        }
        Error::Batch(failures) => {
            let failures = failures
                .iter()
                .map(|(path, failure)| Ok((path.as_os_str(), payload(py, failure)?)))
                .collect::<PyResult<Vec<_>>>()?;
            d.set_item("failures", failures)?;
            "Batch"
        }
        Error::Codesign(err) => {
            d.set_item("codesign", true)?;
            codesign_fields(&d, err)?
        }
        Error::Process(err) => {
            d.set_item("process", true)?;
            process_fields(&d, err)?
        }
        _ => "Other",
    };
    d.set_item("kind", kind)?;
    Ok(d)
}

fn codesign_fields(d: &Bound<'_, PyDict>, err: &CodesignError) -> PyResult<&'static str> {
    let kind = match err {
        CodesignError::NotFound => "NotFound",
        CodesignError::VerificationFailed {
            stdout,
            stderr,
            resources,
            ..
        } => {
            streams(d, stdout, stderr)?;
            let resources = resources
                .iter()
                .filter_map(resource)
                .map(|(change, path)| {
                    let r = PyDict::new(d.py());
                    r.set_item("change", change)?;
                    r.set_item("path", path)?;
                    Ok(r)
                })
                .collect::<PyResult<Vec<_>>>()?;
            d.set_item("resources", resources)?;
            "VerificationFailed"
        }
        CodesignError::RequirementUnsatisfied { stdout, stderr, .. } => {
            streams(d, stdout, stderr)?;
            "RequirementUnsatisfied"
        }
        CodesignError::ConstraintInvalid { stdout, stderr, .. } => {
            streams(d, stdout, stderr)?;
            "ConstraintInvalid"
        }
        CodesignError::NoSignature { stdout, stderr, .. } => {
            streams(d, stdout, stderr)?;
            "NoSignature"
        }
        _ => "Other",
    };
    Ok(kind)
}

fn process_fields(d: &Bound<'_, PyDict>, err: &ProcessError) -> PyResult<&'static str> {
    let kind = match err {
        ProcessError::NotFound { program, .. } => {
            d.set_item("program", program)?;
            "NotFound"
        }
        ProcessError::Spawn {
            program, source, ..
        } => {
            d.set_item("program", program)?;
            d.set_item("errno", source.raw_os_error())?;
            "Spawn"
        }
        ProcessError::Run {
            program, source, ..
        } => {
            d.set_item("program", program)?;
            d.set_item("errno", source.raw_os_error())?;
            "Run"
        }
        ProcessError::Failed {
            program,
            code,
            stdout,
            stderr,
            ..
        } => {
            d.set_item("program", program)?;
            d.set_item("code", code)?;
            streams(d, stdout, stderr)?;
            "Failed"
        }
        ProcessError::Terminated {
            program,
            status,
            stdout,
            stderr,
            ..
        } => {
            #[cfg(unix)]
            let signal = std::os::unix::process::ExitStatusExt::signal(status);
            #[cfg(not(unix))]
            let signal: Option<i32> = None;
            d.set_item("program", program)?;
            d.set_item("signal", signal)?;
            streams(d, stdout, stderr)?;
            "Terminated"
        }
        ProcessError::UnexpectedOutput {
            program,
            detail,
            stdout,
            stderr,
            ..
        } => {
            d.set_item("program", program)?;
            d.set_item("detail", detail)?;
            streams(d, stdout, stderr)?;
            "UnexpectedOutput"
        }
        _ => "Other",
    };
    Ok(kind)
}

fn streams(d: &Bound<'_, PyDict>, stdout: &str, stderr: &str) -> PyResult<()> {
    d.set_item("stdout", stdout)?;
    d.set_item("stderr", stderr)
}

// A change kind this binding doesn't know yet has no Python counterpart, so it is left out.
fn resource(r: &ResourceChange) -> Option<(&'static str, &std::ffi::OsStr)> {
    let change = match r.change {
        Change::Added => "Added",
        Change::Modified => "Modified",
        Change::Missing => "Missing",
        _ => return None,
    };
    Some((change, r.path.as_os_str()))
}

#[cfg(test)]
#[path = "unit_tests/error.rs"]
mod tests;
