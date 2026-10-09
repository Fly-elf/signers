use std::path::PathBuf;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;
use signers::codesign::{
    self, Display, ExtractCertificates, PreserveMetadata, RemoveSignature, Sign, SignatureSlot,
    SigningFlags, Strict, Timestamp, Verify, blocking,
};

use crate::convert;
use crate::error;
use crate::target::Target;

// One body for the sync and the async native function of an action. `$build` runs at
// call time either way, so a bad option raises before anything is awaited.
macro_rules! run {
    (
        $mode:tt $py:ident, $target:expr, $t:ident => $build:expr
        $(, $per_target:ident)?
        $(; $out:ident => $one:expr, $many:expr)?
    ) => {
        match $target {
            Target::One($t) => {
                let b = $build;
                finish!($mode $py, b $(, $out => $one)?)
            }
            Target::Many($t) => {
                let b = $build;
                $(let b = match $per_target {
                    Some(p) => b.per_target(p),
                    None => b,
                };)?
                finish!($mode $py, b $(, $out => $many)?)
            }
        }
    };
}

macro_rules! finish {
    (sync $py:ident, $b:ident) => {
        $py.detach(|| $b.run()).map(drop).map_err(error::to_py)
    };
    // A `()` result would reach Python as an empty tuple; `None::<()>` reaches it as `None`.
    (async $py:ident, $b:ident) => {
        future_into_py($py, async move {
            $b.await.map(|_| None::<()>).map_err(error::to_py)
        })
    };
    (sync $py:ident, $b:ident, $out:ident => $convert:expr) => {{
        let $out = $py.detach(|| $b.run()).map_err(error::to_py)?;
        $convert
    }};
    (async $py:ident, $b:ident, $out:ident => $convert:expr) => {
        future_into_py($py, async move {
            let $out = $b.await.map_err(error::to_py)?;
            Python::attach(|$py| $convert.map(Bound::unbind))
        })
    };
}

fn configure_remove<S, R>(
    b: RemoveSignature<S, R>,
    bundle_version: Option<String>,
) -> RemoveSignature<S, R> {
    match bundle_version {
        Some(v) => b.bundle_version(v),
        None => b,
    }
}

#[pyfunction]
#[pyo3(signature = (target, *, per_target = None, bundle_version = None))]
pub(crate) fn codesign_remove_signature(
    py: Python<'_>,
    target: Target,
    per_target: Option<bool>,
    bundle_version: Option<String>,
) -> PyResult<()> {
    run!(sync py, target, t => configure_remove(blocking::remove_signature(t), bundle_version),
        per_target)
}

#[pyfunction]
#[pyo3(signature = (target, *, per_target = None, bundle_version = None))]
pub(crate) fn codesign_remove_signature_async<'py>(
    py: Python<'py>,
    target: Target,
    per_target: Option<bool>,
    bundle_version: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => configure_remove(codesign::remove_signature(t), bundle_version),
        per_target)
}

#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub(crate) struct SignArgs {
    identifier: Option<String>,
    requirements: Option<String>,
    prefix: Option<String>,
    keychain: Option<PathBuf>,
    entitlements: Option<PathBuf>,
    force_library_entitlements: bool,
    generate_entitlement_der: bool,
    options: Option<u32>,
    runtime_version: Option<String>,
    launch_constraint_self: Option<PathBuf>,
    launch_constraint_parent: Option<PathBuf>,
    launch_constraint_responsible: Option<PathBuf>,
    library_constraint: Option<PathBuf>,
    enforce_constraint_validity: bool,
    force: bool,
    deep: bool,
    preserve_metadata: Option<u8>,
    page_size: Option<u32>,
    timestamp: Option<String>,
    bundle_version: Option<String>,
    strip_disallowed_xattrs: bool,
    single_threaded_signing: bool,
    dry_run: bool,
    detached: Option<PathBuf>,
    detached_database: bool,
    file_list: Option<PathBuf>,
}

// An unset option or a false flag leaves the setter uncalled, so the presets of
// `sign_for_distribution` survive.
#[allow(deprecated)]
fn configure<S, R>(mut b: Sign<S, R>, a: SignArgs) -> Sign<S, R> {
    macro_rules! set {
        ($($f:ident),*) => {$(if let Some(v) = a.$f { b = b.$f(v); })*};
    }
    macro_rules! flag {
        ($($f:ident),*) => {$(if a.$f { b = b.$f(true); })*};
    }

    set!(
        identifier,
        requirements,
        prefix,
        keychain,
        entitlements,
        runtime_version,
        launch_constraint_self,
        launch_constraint_parent,
        launch_constraint_responsible,
        library_constraint,
        page_size,
        bundle_version,
        detached,
        file_list
    );
    flag!(
        force_library_entitlements,
        generate_entitlement_der,
        enforce_constraint_validity,
        force,
        deep,
        strip_disallowed_xattrs,
        single_threaded_signing,
        dry_run,
        detached_database
    );
    if let Some(bits) = a.options {
        b = b.options(SigningFlags::from_bits_truncate(bits));
    }
    if let Some(bits) = a.preserve_metadata {
        b = b.preserve_metadata(PreserveMetadata::from_bits_truncate(bits));
    }
    if let Some(t) = a.timestamp {
        b = b.timestamp(match t.as_str() {
            "ENABLED" => Timestamp::Enabled,
            "DISABLED" => Timestamp::Disabled,
            _ => Timestamp::ServerUrl(t),
        });
    }
    b
}

#[pyfunction]
#[pyo3(signature = (target, identity, options, *, per_target = None))]
pub(crate) fn codesign_sign(
    py: Python<'_>,
    target: Target,
    identity: String,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<()> {
    run!(sync py, target, t => configure(blocking::sign(t, identity), options), per_target)
}

#[pyfunction]
#[pyo3(signature = (target, identity, options, *, per_target = None))]
pub(crate) fn codesign_sign_async<'py>(
    py: Python<'py>,
    target: Target,
    identity: String,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => configure(codesign::sign(t, identity), options), per_target)
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_sign_adhoc(
    py: Python<'_>,
    target: Target,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<()> {
    run!(sync py, target, t => configure(blocking::sign_adhoc(t), options), per_target)
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_sign_adhoc_async<'py>(
    py: Python<'py>,
    target: Target,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => configure(codesign::sign_adhoc(t), options), per_target)
}

#[pyfunction]
#[pyo3(signature = (target, identity, options, *, per_target = None))]
pub(crate) fn codesign_sign_for_distribution(
    py: Python<'_>,
    target: Target,
    identity: String,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<()> {
    run!(sync py, target,
        t => configure(blocking::sign_for_distribution(t, identity), options), per_target)
}

#[pyfunction]
#[pyo3(signature = (target, identity, options, *, per_target = None))]
pub(crate) fn codesign_sign_for_distribution_async<'py>(
    py: Python<'py>,
    target: Target,
    identity: String,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target,
        t => configure(codesign::sign_for_distribution(t, identity), options), per_target)
}

#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub(crate) struct VerifyArgs {
    deep: bool,
    strict: Option<String>,
    ignore_resources: bool,
    architecture: Option<String>,
    bundle_version: Option<String>,
    check_designated_requirement: bool,
    test_requirement: Option<String>,
    test_requirement_file: Option<PathBuf>,
    detached: Option<PathBuf>,
    check_notarization: bool,
    signature_slot: Option<String>,
}

fn configure_verify<S, R>(mut b: Verify<S, R>, a: VerifyArgs) -> PyResult<Verify<S, R>> {
    macro_rules! set {
        ($($f:ident),*) => {$(if let Some(v) = a.$f { b = b.$f(v); })*};
    }
    macro_rules! flag {
        ($($f:ident),*) => {$(if a.$f { b = b.$f(true); })*};
    }

    set!(
        architecture,
        bundle_version,
        test_requirement,
        test_requirement_file,
        detached
    );
    flag!(
        deep,
        ignore_resources,
        check_designated_requirement,
        check_notarization
    );
    if let Some(name) = a.strict {
        b = b.strict(match name.as_str() {
            "ALL" => Strict::All,
            "SYMLINKS" => Strict::Symlinks,
            "SIDEBAND" => Strict::Sideband,
            _ => return Err(PyValueError::new_err(format!("unknown Strict: {name}"))),
        });
    }
    if let Some(name) = a.signature_slot {
        b = b.signature_slot(signature_slot(&name)?);
    }
    Ok(b)
}

fn signature_slot(name: &str) -> PyResult<SignatureSlot> {
    match name {
        "FIRST" => Ok(SignatureSlot::First),
        "SECOND" => Ok(SignatureSlot::Second),
        _ => Err(PyValueError::new_err(format!(
            "unknown SignatureSlot: {name}"
        ))),
    }
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_verify(
    py: Python<'_>,
    target: Target,
    options: VerifyArgs,
    per_target: Option<bool>,
) -> PyResult<()> {
    run!(sync py, target, t => configure_verify(blocking::verify(t), options)?, per_target)
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_verify_async<'py>(
    py: Python<'py>,
    target: Target,
    options: VerifyArgs,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => configure_verify(codesign::verify(t), options)?, per_target)
}

#[pyfunction]
#[pyo3(signature = (target, *, per_target = None))]
pub(crate) fn codesign_validate_constraint(
    py: Python<'_>,
    target: Target,
    per_target: Option<bool>,
) -> PyResult<()> {
    run!(sync py, target, t => blocking::validate_constraint(t), per_target)
}

#[pyfunction]
#[pyo3(signature = (target, *, per_target = None))]
pub(crate) fn codesign_validate_constraint_async<'py>(
    py: Python<'py>,
    target: Target,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => codesign::validate_constraint(t), per_target)
}

#[derive(FromPyObject)]
#[pyo3(from_item_all)]
pub(crate) struct DisplayArgs {
    architecture: Option<String>,
    bundle_version: Option<String>,
    deep: bool,
    signature_slot: Option<String>,
    detached: Option<PathBuf>,
}

fn configure_display<S, R>(mut b: Display<S, R>, a: DisplayArgs) -> PyResult<Display<S, R>> {
    if let Some(v) = a.architecture {
        b = b.architecture(v);
    }
    if let Some(v) = a.bundle_version {
        b = b.bundle_version(v);
    }
    if let Some(v) = a.detached {
        b = b.detached(v);
    }
    if a.deep {
        b = b.deep(true);
    }
    if let Some(name) = a.signature_slot {
        b = b.signature_slot(signature_slot(&name)?);
    }
    Ok(b)
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_display<'py>(
    py: Python<'py>,
    target: Target,
    options: DisplayArgs,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(sync py, target, t => configure_display(blocking::display(t), options)?, per_target;
        s => convert::signature(py, &s), convert::flat(py, &s, convert::signature))
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_display_async<'py>(
    py: Python<'py>,
    target: Target,
    options: DisplayArgs,
    per_target: Option<bool>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => configure_display(codesign::display(t), options)?, per_target;
        s => convert::signature(py, &s), convert::flat(py, &s, convert::signature))
}

#[pyfunction]
pub(crate) fn codesign_requirements<'py>(
    py: Python<'py>,
    target: Target,
) -> PyResult<Bound<'py, PyAny>> {
    run!(sync py, target, t => blocking::requirements(t);
        r => convert::flat(py, &r, convert::requirement),
        convert::nested(py, &r, convert::requirement))
}

#[pyfunction]
pub(crate) fn codesign_requirements_async<'py>(
    py: Python<'py>,
    target: Target,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => codesign::requirements(t);
        r => convert::flat(py, &r, convert::requirement),
        convert::nested(py, &r, convert::requirement))
}

fn configure_extract<S, R>(
    b: ExtractCertificates<S, R>,
    save_to: Option<PathBuf>,
) -> ExtractCertificates<S, R> {
    match save_to {
        Some(dir) => b.save_to(dir),
        None => b,
    }
}

#[pyfunction]
#[pyo3(signature = (target, *, save_to = None))]
pub(crate) fn codesign_extract_certificates<'py>(
    py: Python<'py>,
    target: Target,
    save_to: Option<PathBuf>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(sync py, target, t => configure_extract(blocking::extract_certificates(t), save_to);
        c => convert::flat(py, &c, convert::certificate),
        convert::nested(py, &c, convert::certificate))
}

#[pyfunction]
#[pyo3(signature = (target, *, save_to = None))]
pub(crate) fn codesign_extract_certificates_async<'py>(
    py: Python<'py>,
    target: Target,
    save_to: Option<PathBuf>,
) -> PyResult<Bound<'py, PyAny>> {
    run!(async py, target, t => configure_extract(codesign::extract_certificates(t), save_to);
        c => convert::flat(py, &c, convert::certificate),
        convert::nested(py, &c, convert::certificate))
}
