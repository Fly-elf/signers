//! Library error types.

use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

/// Convenience alias for results returned across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while running a signing action.
///
/// Marked `#[non_exhaustive]`: new variants will be added as backends grow, so
/// always keep a wildcard arm when matching.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// No target was supplied, or every supplied target was empty.
    #[error("no targets to operate on")]
    NoTargets,

    /// A target path does not exist on disk.
    #[error("target does not exist: {0}")]
    TargetNotFound(PathBuf),

    /// A target path could not be accessed while checking that it exists (e.g.
    /// permission denied on a parent directory).
    #[error("could not access target {path}: {source}")]
    TargetAccess {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The `codesign` process could not be spawned — typically because the
    /// binary is missing (Xcode Command Line Tools not installed) or not on
    /// `PATH`.
    #[error("failed to spawn the `codesign` process: {0}")]
    Spawn(#[source] std::io::Error),

    /// The `codesign` process ran but exited unsuccessfully; `stderr` holds its
    /// captured (trimmed) diagnostic output.
    #[error("`codesign` exited unsuccessfully ({status}): {stderr}")]
    Codesign { status: ExitStatus, stderr: String },
}
