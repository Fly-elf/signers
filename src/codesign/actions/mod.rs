//! Concrete `codesign` actions.
//!
//! One action per submodule; each defines its options struct, its [`Default`],
//! its [`Action`] impl, and the option setters on the matching
//! `Codesign<Action>` specialisation.

mod sign;

pub use sign::{PreserveMetadata, Sign, SigningFlags, Timestamp};

/// Marks the types that can be run as a `codesign` action — [`Sign`] and, in
/// time, its siblings.
///
/// Sealed, so only this crate can implement it: the set of actions stays closed
/// and how they turn into arguments stays an implementation detail. There's
/// nothing to call here; it exists to be used as a bound.
pub trait Action: sealed::ToArgs {}

/// Every action is defined by its argument rendering; the marker follows from
/// it, so actions never implement it by hand.
impl<T: sealed::ToArgs> Action for T {}

/// Home of the trait that seals [`Action`]: outside the crate this module
/// cannot be named, so [`ToArgs`](sealed::ToArgs) cannot be implemented and no
/// foreign type can become an action.
pub(crate) mod sealed {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use crate::errors::Result;

    /// Renders an action, applied to `targets`, into a `codesign` argument list.
    ///
    /// This is what every action *is* — the options it holds only matter as the
    /// arguments they turn into. Living behind a `pub(crate)` module keeps both
    /// the trait and the rendering off the public API, while the generic
    /// `IntoFuture` runner can still call it.
    ///
    /// Arguments borrow from the action for as long as `'a`: flag names are
    /// `&'static str` and most option values already live in the action, so
    /// only the few arguments built at render time are owned.
    pub trait ToArgs {
        /// Rejects an option combination this crate cannot honour, before any
        /// target is looked at or `codesign` is ever spawned.
        ///
        /// Most actions have nothing to reject, hence the default no-op.
        fn validate(&self) -> Result<()> {
            Ok(())
        }

        /// Called once [`validate`](Self::validate) has passed, so an action
        /// renders only combinations it has already accepted.
        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>>;
    }
}
