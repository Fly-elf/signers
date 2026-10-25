use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;

use pyo3::types::PyAnyMethods;

use super::*;

/// A finished run of `codesign` that exited with `code`.
fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
    Output::new(
        "codesign",
        ExitStatus::from_raw(code << 8),
        stdout.into(),
        stderr.into(),
    )
}

/// A finished run of `codesign` that `signal` killed.
fn killed(signal: i32, stdout: &str, stderr: &str) -> Output {
    Output::new(
        "codesign",
        ExitStatus::from_raw(signal),
        stdout.into(),
        stderr.into(),
    )
}

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
            process(ProcessError::failed(exited(3, "o", "e"))),
            "{'kind': 'Failed', 'process': True, 'codesign': None, 'program': 'codesign', 'returncode': 3, 'stdout': 'o', 'stderr': 'e'}",
        ),
        (
            process(ProcessError::failed(killed(9, "o", "e"))),
            "{'kind': 'Failed', 'process': True, 'codesign': None, 'program': 'codesign', 'returncode': -9, 'stdout': 'o', 'stderr': 'e', 'signal': None, 'code': None}",
        ),
        (
            process(ProcessError::unexpected_output(
                "d".into(),
                exited(0, "o", "e"),
            )),
            "{'kind': 'UnexpectedOutput', 'process': True, 'program': 'codesign', 'detail': 'd', 'stdout': 'o', 'stderr': 'e'}",
        ),
        (
            codesign(CodesignError::verification_failed(
                exited(1, "o", "e"),
                Vec::new(),
            )),
            "{'kind': 'VerificationFailed', 'codesign': True, 'stdout': 'o', 'stderr': 'e', 'resources': []}",
        ),
        (
            codesign(CodesignError::requirement_unsatisfied(exited(3, "o", "e"))),
            "{'kind': 'RequirementUnsatisfied', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
        ),
        (
            codesign(CodesignError::constraint_invalid(exited(0, "o", "e"))),
            "{'kind': 'ConstraintInvalid', 'codesign': True, 'stdout': 'o', 'stderr': 'e'}",
        ),
        (
            codesign(CodesignError::no_signature(exited(0, "o", "e"))),
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
    let failed = process(ProcessError::failed(exited(1, "", "e")));
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
        let expected =
            CString::new("[('/t/a', 'NotFound', []), ('/t/b', 'Batch', [('/t/c', 'NoTargets')])]")
                .unwrap();
        let expected = py.eval(&expected, None, None).unwrap();
        assert!(shape.eq(&expected).unwrap(), "{shape}");
    });
}
