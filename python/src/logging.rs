use std::sync::OnceLock;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

static RESET: OnceLock<pyo3_log::ResetHandle> = OnceLock::new();

pub(crate) fn install(py: Python<'_>) -> PyResult<()> {
    let handle = pyo3_log::Logger::new(py, pyo3_log::Caching::LoggersAndLevels)?
        .filter(log::LevelFilter::Trace)
        .install()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let _ = RESET.set(handle);
    Ok(())
}

#[pyfunction]
pub(crate) fn refresh_log_levels() {
    if let Some(handle) = RESET.get() {
        handle.reset();
    }
}
