use std::path::PathBuf;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use signers::codesign::{
    PreserveMetadata, SignatureSlot, SigningFlags, Strict, Timestamp, blocking,
};

use crate::error;
use crate::target::Target;

#[pyfunction]
#[pyo3(signature = (target, *, per_target = None, bundle_version = None))]
pub(crate) fn codesign_remove_signature(
    py: Python<'_>,
    target: Target,
    per_target: Option<bool>,
    bundle_version: Option<String>,
) -> PyResult<()> {
    fn configure<S>(
        b: blocking::RemoveSignature<S>,
        bundle_version: Option<String>,
    ) -> blocking::RemoveSignature<S> {
        match bundle_version {
            Some(v) => b.bundle_version(v),
            None => b,
        }
    }

    match target {
        Target::One(path) => {
            py.detach(|| configure(blocking::remove_signature(path), bundle_version).run())
        }
        Target::Many(paths) => py.detach(|| {
            let b = configure(blocking::remove_signature(paths), bundle_version);
            match per_target {
                Some(p) => b.per_target(p).run(),
                None => b.run(),
            }
            .map(drop)
        }),
    }
    .map_err(error::to_py)
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
fn configure<S>(mut b: blocking::Sign<S>, a: SignArgs) -> blocking::Sign<S> {
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

macro_rules! run_with {
    ($py:ident, $target:ident, $per_target:ident, $args:ident, $configure:ident, $t:ident => $start:expr) => {
        match $target {
            Target::One($t) => $py.detach(|| $configure($start, $args).run()),
            Target::Many($t) => $py.detach(|| {
                let b = $configure($start, $args);
                match $per_target {
                    Some(p) => b.per_target(p).run(),
                    None => b.run(),
                }
                .map(drop)
            }),
        }
        .map_err(error::to_py)
    };
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
    run_with!(py, target, per_target, options, configure, t => blocking::sign(t, identity))
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_sign_adhoc(
    py: Python<'_>,
    target: Target,
    options: SignArgs,
    per_target: Option<bool>,
) -> PyResult<()> {
    run_with!(py, target, per_target, options, configure, t => blocking::sign_adhoc(t))
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
    run_with!(py, target, per_target, options, configure, t => blocking::sign_for_distribution(t, identity))
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

fn configure_verify<S>(mut b: blocking::Verify<S>, a: VerifyArgs) -> PyResult<blocking::Verify<S>> {
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
        b = b.signature_slot(match name.as_str() {
            "FIRST" => SignatureSlot::First,
            "SECOND" => SignatureSlot::Second,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "unknown SignatureSlot: {name}"
                )));
            }
        });
    }
    Ok(b)
}

#[pyfunction]
#[pyo3(signature = (target, options, *, per_target = None))]
pub(crate) fn codesign_verify(
    py: Python<'_>,
    target: Target,
    options: VerifyArgs,
    per_target: Option<bool>,
) -> PyResult<()> {
    match target {
        Target::One(path) => {
            let b = configure_verify(blocking::verify(path), options)?;
            py.detach(|| b.run())
        }
        Target::Many(paths) => {
            let b = configure_verify(blocking::verify(paths), options)?;
            py.detach(|| match per_target {
                Some(p) => b.per_target(p).run(),
                None => b.run(),
            })
            .map(drop)
        }
    }
    .map_err(error::to_py)
}

#[pyfunction]
#[pyo3(signature = (target, *, per_target = None))]
pub(crate) fn codesign_validate_constraint(
    py: Python<'_>,
    target: Target,
    per_target: Option<bool>,
) -> PyResult<()> {
    match target {
        Target::One(path) => py.detach(|| blocking::validate_constraint(path).run()),
        Target::Many(paths) => py.detach(|| {
            let b = blocking::validate_constraint(paths);
            match per_target {
                Some(p) => b.per_target(p).run(),
                None => b.run(),
            }
            .map(drop)
        }),
    }
    .map_err(error::to_py)
}
