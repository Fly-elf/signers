use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use signers::codesign::blocking;

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
            single(per_target)?;
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

fn single(per_target: Option<bool>) -> PyResult<()> {
    match per_target {
        Some(_) => Err(PyTypeError::new_err(
            "per_target needs a sequence of targets",
        )),
        None => Ok(()),
    }
}
