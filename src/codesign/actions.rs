//! Shared machinery every `codesign` action builds on.
//!
//! Each action (`sign`, `remove_signature` and, in time, `verify`) lives in its
//! own sibling module of [`codesign`](crate::codesign) and defines its options
//! struct, [`Default`], [`Action`] impl, and the setters on the matching
//! `Codesign<Action>` specialisation — this module has no submodules of its
//! own. It stays a separate module because [`Action`]/[`ToArgs`](sealed::ToArgs),
//! along with the [`PushArgs`] vocabulary and [`joined`] helper every action
//! renders its arguments with, will also be shared by the future blocking API,
//! not just the async one.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use bitflags::Flags;

/// Marks the types that can be run as a `codesign` action — `Sign`,
/// `RemoveSignature` and, in time, their siblings.
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

/// Argument-list vocabulary, so that each `codesign` option renders on one
/// line and the arguments that have to allocate stay visible as such.
pub(crate) trait PushArgs<'a> {
    /// A standalone argument known at compile time: a bare flag such as
    /// `--force`, or a whole `=`-form argument such as `--timestamp=none`.
    fn flag(&mut self, name: &'static str);

    /// A flag followed by its value, borrowed from the action for `'a`.
    fn option<V: AsRef<OsStr> + ?Sized>(&mut self, name: &'static str, value: &'a V);

    /// An argument that only exists once rendered — a joined token list, a
    /// number, an interpolated `=`-form option — and so must be owned.
    fn built(&mut self, value: impl Into<OsString>);

    /// The paths the action operates on, which `codesign` expects last,
    /// introduced by the `--` end-of-options separator.
    fn targets(&mut self, targets: &'a [PathBuf]);
}

impl<'a> PushArgs<'a> for Vec<Cow<'a, OsStr>> {
    fn flag(&mut self, name: &'static str) {
        self.push(Cow::Borrowed(OsStr::new(name)));
    }

    fn option<V: AsRef<OsStr> + ?Sized>(&mut self, name: &'static str, value: &'a V) {
        self.flag(name);
        self.push(Cow::Borrowed(value.as_ref()));
    }

    fn built(&mut self, value: impl Into<OsString>) {
        self.push(Cow::Owned(value.into()));
    }

    fn targets(&mut self, targets: &'a [PathBuf]) {
        // Without the separator, `codesign`'s getopt reads a target whose name
        // starts with `-` as options: `codesign --sign - -patched` fails with
        // "unknown architecture name", having parsed `-patched` as `-p -a ...`.
        self.flag("--");
        self.extend(targets.iter().map(|t| Cow::Borrowed(t.as_os_str())));
    }
}

/// Comma-joins the tokens of the flags set in `flags`, in declaration order.
///
/// Tokens come from each flag's `#[bitflags(flag_name)]`, so they are declared
/// rather than derived. `bitflags`' own formatter can't be used here: it
/// separates with ` | `, while `codesign` wants a bare comma-separated list.
pub(crate) fn joined<F: Flags + Copy>(flags: F) -> String {
    let mut tokens = String::new();
    for flag in F::FLAGS.iter().filter(|flag| flags.contains(*flag.value())) {
        if !tokens.is_empty() {
            tokens.push(',');
        }
        tokens.push_str(flag.name());
    }
    tokens
}
