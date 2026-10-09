use pyo3::prelude::*;

mod codesign;
mod error;
mod target;

#[pymodule]
mod _native {
    #[pymodule_export]
    use super::codesign::{
        codesign_remove_signature, codesign_sign, codesign_sign_adhoc,
        codesign_sign_for_distribution,
    };
    #[pymodule_export]
    use super::error::NativeError;
}
