#[cfg(not(target_os = "macos"))]
compile_error!("signers' Python bindings currently support only macOS");

use pyo3::prelude::*;

mod codesign;
mod convert;
mod error;
mod logging;
mod target;

#[pymodule]
mod _native {
    use pyo3::prelude::*;

    #[pymodule_export]
    use super::codesign::{
        codesign_display, codesign_display_async, codesign_extract_certificates,
        codesign_extract_certificates_async, codesign_remove_signature,
        codesign_remove_signature_async, codesign_requirements, codesign_requirements_async,
        codesign_sign, codesign_sign_adhoc, codesign_sign_adhoc_async, codesign_sign_async,
        codesign_sign_for_distribution, codesign_sign_for_distribution_async,
        codesign_validate_constraint, codesign_validate_constraint_async, codesign_verify,
        codesign_verify_async,
    };
    #[pymodule_export]
    use super::error::NativeError;
    #[pymodule_export]
    use super::logging::refresh_log_levels;

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        super::logging::install(m.py())
    }
}
