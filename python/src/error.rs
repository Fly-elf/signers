use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use signers::errors::{Change, ResourceChange};
use signers::{CodesignError, Error};

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
        Error::TargetNotFound(path) => {
            d.set_item("path", path.as_os_str())?;
            "TargetNotFound"
        }
        Error::TargetAccess { path, source } => {
            d.set_item("path", path.as_os_str())?;
            d.set_item("errno", source.raw_os_error())?;
            "TargetAccess"
        }
        Error::Io { path, source } => {
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
        _ => "Other",
    };
    d.set_item("kind", kind)?;
    Ok(d)
}

fn codesign_fields(d: &Bound<'_, PyDict>, err: &CodesignError) -> PyResult<&'static str> {
    let kind = match err {
        CodesignError::NotFound => "NotFound",
        CodesignError::Spawn(source) => {
            d.set_item("errno", source.raw_os_error())?;
            "Spawn"
        }
        CodesignError::Run(source) => {
            d.set_item("errno", source.raw_os_error())?;
            "Run"
        }
        CodesignError::Failed {
            code,
            stdout,
            stderr,
        } => {
            d.set_item("code", code)?;
            streams(d, stdout, stderr)?;
            "Failed"
        }
        CodesignError::Terminated {
            status,
            stdout,
            stderr,
        } => {
            #[cfg(unix)]
            let signal = std::os::unix::process::ExitStatusExt::signal(status);
            #[cfg(not(unix))]
            let signal: Option<i32> = None;
            d.set_item("signal", signal)?;
            streams(d, stdout, stderr)?;
            "Terminated"
        }
        CodesignError::UnexpectedOutput { detail } => {
            d.set_item("detail", detail)?;
            "UnexpectedOutput"
        }
        CodesignError::VerificationFailed {
            stdout,
            stderr,
            resources,
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
        CodesignError::RequirementUnsatisfied { stdout, stderr } => {
            streams(d, stdout, stderr)?;
            "RequirementUnsatisfied"
        }
        CodesignError::ConstraintInvalid { stdout, stderr } => {
            streams(d, stdout, stderr)?;
            "ConstraintInvalid"
        }
        CodesignError::NoSignature { stdout, stderr } => {
            streams(d, stdout, stderr)?;
            "NoSignature"
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

    #[test]
    fn every_constructible_variant_maps_to_its_kind_and_fields() {
        let cases: Vec<(Error, &str)> = vec![
            (Error::NoTargets, "{'kind': 'NoTargets', 'codesign': None}"),
            (Error::EmptyTarget(2), "{'kind': 'EmptyTarget', 'index': 2}"),
            (
                Error::TargetNotFound("/t/a b".into()),
                "{'kind': 'TargetNotFound', 'path': '/t/a b'}",
            ),
            (
                Error::TargetAccess {
                    path: "/t/x".into(),
                    source: io::Error::from_raw_os_error(13),
                },
                "{'kind': 'TargetAccess', 'path': '/t/x', 'errno': 13}",
            ),
            (
                Error::Io {
                    path: "/t/y".into(),
                    source: io::Error::other("boom"),
                },
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
                "{'kind': 'NotFound', 'codesign': True}",
            ),
            (
                codesign(CodesignError::Spawn(io::Error::from_raw_os_error(1))),
                "{'kind': 'Spawn', 'codesign': True, 'errno': 1}",
            ),
            (
                codesign(CodesignError::Run(io::Error::other("pipe"))),
                "{'kind': 'Run', 'codesign': True, 'errno': None}",
            ),
            (
                codesign(CodesignError::Failed {
                    code: 3,
                    stdout: "o".into(),
                    stderr: "e".into(),
                }),
                "{'kind': 'Failed', 'codesign': True, 'code': 3, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::Terminated {
                    status: ExitStatus::from_raw(9),
                    stdout: "o".into(),
                    stderr: "e".into(),
                }),
                "{'kind': 'Terminated', 'codesign': True, 'signal': 9, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::UnexpectedOutput { detail: "d".into() }),
                "{'kind': 'UnexpectedOutput', 'codesign': True, 'detail': 'd'}",
            ),
            (
                codesign(CodesignError::VerificationFailed {
                    stdout: "o".into(),
                    stderr: "e".into(),
                    resources: Vec::new(),
                }),
                "{'kind': 'VerificationFailed', 'codesign': True, 'stdout': 'o', 'stderr': 'e', 'resources': []}",
            ),
            (
                codesign(CodesignError::RequirementUnsatisfied {
                    stdout: "o".into(),
                    stderr: "e".into(),
                }),
                "{'kind': 'RequirementUnsatisfied', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::ConstraintInvalid {
                    stdout: "o".into(),
                    stderr: "e".into(),
                }),
                "{'kind': 'ConstraintInvalid', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
            ),
            (
                codesign(CodesignError::NoSignature {
                    stdout: "o".into(),
                    stderr: "e".into(),
                }),
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
        assert_payload(Error::TargetNotFound(path), r"{'path': '/t/\udcff'}");
    }

    #[test]
    fn batch_failures_are_path_payload_pairs_in_order_and_nest() {
        let inner = Error::Batch(vec![("/t/c".into(), Error::NoTargets)]);
        let failed = codesign(CodesignError::Failed {
            code: 1,
            stdout: String::new(),
            stderr: "e".into(),
        });
        let err = Error::Batch(vec![("/t/a".into(), failed), ("/t/b".into(), inner)]);
        assert_payload(err, "{'kind': 'Batch', 'codesign': None}");

        let err = Error::Batch(vec![
            ("/t/a".into(), codesign(CodesignError::NotFound)),
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
