//! Concrete `codesign` actions.
//!
//! One action per submodule; each defines its options struct, its [`Default`],
//! its [`Action`] impl, and the option setters on the matching
//! `Codesign<Action>` specialisation.

mod sign;

pub use sign::{PreserveMetadata, Sign, SigningFlags, Timestamp};

/// Marker implemented by every `codesign` action.
///
/// Sealed: it cannot be implemented outside this crate, so the set of actions
/// stays closed and the argument-building behaviour stays a private
/// implementation detail. Use it only as a bound (`Codesign<A: Action>`).
pub trait Action: sealed::Sealed {}

/// Every action is defined by its argument rendering; the marker follows from
/// it, so actions never implement it by hand.
impl<T: sealed::Sealed> Action for T {}

pub(crate) mod sealed {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    /// Crate-internal behaviour every action provides: rendering itself, applied
    /// to `targets`, into a `codesign` argument list.
    ///
    /// Living behind a `pub(crate)` module keeps both the trait and `args` off
    /// the public API, while the generic `IntoFuture` runner can still call it.
    ///
    /// Arguments borrow from the action for as long as `'a`: flag names are
    /// `&'static str` and most option values already live in the action, so
    /// only the few arguments built at render time are owned.
    pub trait Sealed {
        fn args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>>;
    }
}
