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
mod tests {
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::ExitStatus;

    use pyo3::types::PyAnyMethods;

    use super::*;

    fn payload<'py>(py: Python<'py>, err: Error) -> Bound<'py, PyDict> {
        let err = to_py(err);
        assert!(err.is_instance_of::<NativeError>(py));
        err.value(py)
            .getattr("args")
            .and_then(|args| args.get_item(0))
            .and_then(|p| Ok(p.cast_into::<PyDict>()?))
            .expect("the payload is a dict in args[0]")
    }

    /// Every key of `expected` (a Python dict literal) has that value in the
    /// payload, `None` meaning absent or `None`; `message` is the Display text.
    fn assert_payload(err: Error, expected: &str) {
        Python::initialize();
        Python::attach(|py| {
            let message = err.to_string();
            let payload = payload(py, err);
            let expected = CString::new(expected).unwrap();
            let expected = py.eval(&expected, None, None).unwrap();
            for (key, value) in expected.cast::<PyDict>().unwrap().iter() {
                let actual = payload.get_item(&key).unwrap();
                let actual = actual
                    .as_ref()
                    .map_or_else(|| py.None().into_bound(py), |v| v.clone());
                assert!(
                    actual.eq(&value).unwrap(),
                    "{key}: {actual} != {value} in {payload}"
                );
            }
            let actual: String = payload
                .get_item("message")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(actual, message);
        });
    }

    fn codesign(err: CodesignError) -> Error {
        Error::Codesign(err)
    }

    fn process(err: ProcessError) -> Error {
        Error::Process(err)
    }

    #[test]
    fn every_constructible_variant_maps_to_its_kind_and_fields() {
        let cases: Vec<(Error, &str)> = vec![
            (
                Error::NoTargets,
                "{'kind': 'NoTargets', 'codesign': None, 'process': None}",
            ),
            (Error::EmptyTarget(2), "{'kind': 'EmptyTarget', 'index': 2}"),
            (
                Error::PathNotFound("/t/a b".into()),
                "{'kind': 'PathNotFound', 'path': '/t/a b', 'errno': None}",
            ),
            (
                Error::path_access("/t/x".into(), io::Error::from_raw_os_error(13)),
                "{'kind': 'PathAccess', 'path': '/t/x', 'errno': 13}",
            ),
            (
                Error::io("/t/y".into(), io::Error::other("boom")),
                "{'kind': 'Io', 'path': '/t/y', 'errno': None}",
            ),
            (
                Error::StdioPath("file_list"),
                "{'kind': 'StdioPath', 'option': 'file_list'}",
            ),
            (
                Error::SharedOutputPerTarget("detached"),
                "{'kind': 'SharedOutputPerTarget', 'option': 'detached'}",
            ),
            (
                codesign(CodesignError::NotFound),
                "{'kind': 'NotFound', 'codesign': True, 'process': None, 'program': None}",
            ),
            (
                process(ProcessError::not_found("pkgutil")),
                "{'kind': 'NotFound', 'process': True, 'codesign': None, 'program': 'pkgutil'}",
            ),
            (
                process(ProcessError::spawn(
                    "codesign",
                    io::Error::from_raw_os_error(1),
                )),
                "{'kind': 'Spawn', 'process': True, 'codesign': None, 'program': 'codesign', 'errno': 1}",
            ),
            (
                process(ProcessError::run("codesign", io::Error::other("pipe"))),
                "{'kind': 'Run', 'process': True, 'program': 'codesign', 'errno': None}",
            ),
            (
                process(ProcessError::failed("codesign", 3, "o".into(), "e".into())),
                "{'kind': 'Failed', 'process': True, 'codesign': None, 'program': 'codesign', 'code': 3, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                process(ProcessError::terminated(
                    "codesign",
                    ExitStatus::from_raw(9),
                    "o".into(),
                    "e".into(),
                )),
                "{'kind': 'Terminated', 'process': True, 'program': 'codesign', 'signal': 9, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                process(ProcessError::unexpected_output(
                    "codesign",
                    "d".into(),
                    "o".into(),
                    "e".into(),
                )),
                "{'kind': 'UnexpectedOutput', 'process': True, 'program': 'codesign', 'detail': 'd', 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::verification_failed(
                    "o".into(),
                    "e".into(),
                    Vec::new(),
                )),
                "{'kind': 'VerificationFailed', 'codesign': True, 'stdout': 'o', 'stderr': 'e', 'resources': []}",
            ),
            (
                codesign(CodesignError::requirement_unsatisfied(
                    "o".into(),
                    "e".into(),
                )),
                "{'kind': 'RequirementUnsatisfied', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::constraint_invalid("o".into(), "e".into())),
                "{'kind': 'ConstraintInvalid', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::no_signature("o".into(), "e".into())),
                "{'kind': 'NoSignature', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
            ),
        ];
        for (err, expected) in cases {
            assert_payload(err, expected);
        }
    }

    #[test]
    fn a_non_utf8_path_crosses_as_a_surrogate_escaped_str() {
        let path = PathBuf::from(OsStr::from_bytes(b"/t/\xff"));
        assert_payload(Error::PathNotFound(path), r"{'path': '/t/\udcff'}");
    }

    #[test]
    fn batch_failures_are_path_payload_pairs_in_order_and_nest() {
        let inner = Error::Batch(vec![("/t/c".into(), Error::NoTargets)]);
        let failed = process(ProcessError::failed(
            "codesign",
            1,
            String::new(),
            "e".into(),
        ));
        let err = Error::Batch(vec![("/t/a".into(), failed), ("/t/b".into(), inner)]);
        assert_payload(err, "{'kind': 'Batch', 'codesign': None}");

        let err = Error::Batch(vec![
            ("/t/a".into(), process(ProcessError::not_found("codesign"))),
            (
                "/t/b".into(),
                Error::Batch(vec![("/t/c".into(), Error::NoTargets)]),
            ),
        ]);
        Python::initialize();
        Python::attach(|py| {
            let failures = payload(py, err).get_item("failures").unwrap().unwrap();
            let shape = CString::new(
                "[(p, f['kind'], [(q, g['kind']) for q, g in f.get('failures', [])]) for p, f in failures]",
            )
            .unwrap();
            let locals = PyDict::new(py);
            locals.set_item("failures", failures).unwrap();
            let shape = py.eval(&shape, None, Some(&locals)).unwrap();
            let expected = CString::new(
                "[('/t/a', 'NotFound', []), ('/t/b', 'Batch', [('/t/c', 'NoTargets')])]",
            )
            .unwrap();
            let expected = py.eval(&expected, None, None).unwrap();
            assert!(shape.eq(&expected).unwrap(), "{shape}");
        });
    }
}
