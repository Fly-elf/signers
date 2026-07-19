//! Concrete `codesign` actions.
//!
//! One action per submodule; each defines its options struct, its [`Default`],
//! its [`Action`] impl, and the option setters on the matching
//! `Codesign<Action>` specialisation.

mod sign;

pub use sign::{DigestAlgorithm, Metadata, Sign, SigningFlag, Timestamp};

/// Marker implemented by every `codesign` action.
///
/// Sealed: it cannot be implemented outside this crate, so the set of actions
/// stays closed and the argument-building behaviour stays a private
/// implementation detail. Use it only as a bound (`Codesign<A: Action>`).
pub trait Action: sealed::Sealed {}

pub(crate) mod sealed {
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// Crate-internal behaviour every action provides: rendering itself, applied
    /// to `targets`, into a `codesign` argument list.
    ///
    /// Living behind a `pub(crate)` module keeps both the trait and `args` off
    /// the public API, while the generic `IntoFuture` runner can still call it.
    pub trait Sealed {
        fn args(&self, targets: &[PathBuf]) -> Vec<OsString>;
    }
}
