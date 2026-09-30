//! What every `codesign` action shares: the sealed [`Action`] trait and argument rendering.
//!
//! It's apart from the async runner so that a blocking runner can share it.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use bitflags::Flags;

/// An action type that [`Codesign`](crate::Codesign) can run, such as
/// [`Sign`](crate::codesign::sign::Sign).
///
/// Use it as a bound to accept any runnable `Codesign<A>`. It's sealed, so only this crate
/// defines actions.
pub trait Action: sealed::ToArgs {}

impl<T: sealed::ToArgs> Action for T {}

/// Holds [`ToArgs`](sealed::ToArgs) where other crates can't name it, which seals [`Action`].
pub(crate) mod sealed {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use crate::errors::Result;

    /// Renders an action into `codesign` arguments.
    pub trait ToArgs {
        /// Rejects options this crate can't honour, before any target is checked or `codesign`
        /// runs.
        fn validate(&self) -> Result<()> {
            Ok(())
        }

        /// Renders the arguments for `targets`, once [`validate`](Self::validate) has passed.
        ///
        /// Flag names are `'static` and most values borrow from the action, so only arguments
        /// built here allocate.
        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>>;
    }
}

/// Appends `codesign` arguments, so that each option renders in one line.
pub(crate) trait PushArgs<'a> {
    /// Appends an argument known at compile time, e.g. `--force` or `--timestamp=none`.
    fn flag(&mut self, name: &'static str);

    /// Appends a flag and its value, borrowed from the action.
    fn option<V: AsRef<OsStr> + ?Sized>(&mut self, name: &'static str, value: &'a V);

    /// Appends an argument built at render time, e.g. a joined flag list or a number.
    fn built(&mut self, value: impl Into<OsString>);

    /// Appends `--`, then the targets, so that no target is read as an option.
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

/// Comma-joins the `flag_name` tokens of the flags set in `flags`, in declaration order.
///
/// Not `bitflags`' `Display`, which separates with ` | `.
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
