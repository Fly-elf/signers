use pyo3::prelude::*;

mod codesign;
mod error;
mod target;

#[pymodule]
mod _native {
    #[pymodule_export]
    use super::codesign::codesign_remove_signature;
    #[pymodule_export]
    use super::error::NativeError;
}
