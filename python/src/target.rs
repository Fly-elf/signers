use std::path::PathBuf;

use pyo3::FromPyObject;

#[derive(FromPyObject)]
pub(crate) enum Target {
    One(PathBuf),
    Many(Vec<PathBuf>),
}
