//! What every `codesign` action shares: the sealed [`Action`] trait, argument rendering and
//! the result of a successful run.
//!
//! It's apart from the async runner so that a blocking runner can share it.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use bitflags::Flags;

/// Which of the two signatures of a code object to use (`--signature-slot`).
///
/// Without it, `codesign` uses the slot the system prefers. The second slot exists only if the
/// code carries two signatures. Pass it to [`verify`](crate::Codesign::verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSlot {
    /// The first signature (`1`).
    First,
    /// The second signature (`2`).
    Second,
}

impl SignatureSlot {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::First => "1",
            Self::Second => "2",
        }
    }
}

/// An action type that [`Codesign`](crate::Codesign) can run, such as
/// [`Sign`](crate::codesign::sign::Sign).
///
/// Use it as a bound to accept a single-target `Codesign<A>` of any action. `A::Output` is what
/// one target yields on success, `()` for the actions with nothing to return, and a
/// [`Signature`](crate::codesign::display::Signature) for [`display`](crate::Codesign::display);
/// `.await` returns it shaped like the targets (see [`IntoTargets`](crate::IntoTargets)). It's
/// sealed, so only this crate defines actions.
pub trait Action: sealed::ToArgs {}

impl<T: sealed::ToArgs> Action for T {}

/// Holds [`ToArgs`](sealed::ToArgs) where other crates can't name it, which seals [`Action`].
pub(crate) mod sealed {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use crate::errors::{CodesignError, Error, Result};

    /// Renders an action into `codesign` arguments and reads the result of its run.
    ///
    /// `Sync` because per-target runs share one action concurrently.
    pub trait ToArgs: Sync {
        /// What `.await` yields for each target when `codesign` succeeds.
        ///
        /// It depends on the action type only, never on the option values.
        type Output: Send + 'static;

        /// The action's `per_target` default, for a collection of targets.
        ///
        /// `true` suits read-only actions; mutating ones keep `false`, so `codesign` handles their
        /// targets in order. A single target always runs once, whatever this says.
        const PER_TARGET: bool;

        /// Rejects options this crate can't honour, before any target is checked or `codesign`
        /// runs.
        fn validate(&self) -> Result<()> {
            Ok(())
        }

        /// Names the setter of an option set to write one file for all targets, if any.
        ///
        /// With `per_target(true)` the runner refuses it with [`Error::SharedOutputPerTarget`].
        /// [`validate`](Self::validate) can't see `per_target`, hence a hook of its own.
        fn shared_output(&self) -> Option<&'static str> {
            None
        }

        /// Renders the arguments for `targets`, once [`validate`](Self::validate) has passed.
        ///
        /// Flag names are `'static` and most values borrow from the action, so only arguments
        /// built here allocate.
        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>>;

        /// Builds one output per target from the stdout and stderr of a run that exited 0.
        ///
        /// `targets` are the ones this run covered: all of them, or one per run with
        /// `per_target`. The outputs must follow them in order; any other count becomes
        /// [`CodesignError::UnexpectedOutput`]. Both streams are lossy-decoded and trimmed. A
        /// failed run goes to [`failure`](Self::failure) instead.
        fn output(
            &self,
            targets: &[PathBuf],
            stdout: String,
            stderr: String,
        ) -> Result<Vec<Self::Output>>;

        /// Turns a non-zero exit code into this action's error; by default
        /// [`CodesignError::Failed`].
        ///
        /// Both streams are already lossy-decoded and trimmed; the default keeps them as they
        /// are. A process killed by a signal has no exit code and never gets here.
        fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
            CodesignError::Failed {
                code,
                stdout,
                stderr,
            }
            .into()
        }

        /// Decodes both streams with [`decode`](super::decode), then calls [`output`](Self::output).
        ///
        /// The runner calls this, never `output`; actions don't override it.
        fn output_bytes(
            &self,
            targets: &[PathBuf],
            stdout: Vec<u8>,
            stderr: Vec<u8>,
        ) -> Result<Vec<Self::Output>> {
            self.output(targets, super::decode(stdout), super::decode(stderr))
        }

        /// Decodes both streams with [`decode`](super::decode), then calls
        /// [`failure`](Self::failure). The runner calls this; actions don't override it.
        fn failure_bytes(&self, code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Error {
            self.failure(code, super::decode(stdout), super::decode(stderr))
        }
    }
}

/// Turns a stream into text: invalid UTF-8 becomes U+FFFD, surrounding whitespace is dropped.
///
/// The only place the crate decodes `codesign` output.
pub(crate) fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).trim().to_string()
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

#[cfg(test)]
mod tests {
    use super::sealed::ToArgs;
    use super::*;
    use crate::errors::{CodesignError, Error, Result};

    /// Reports the streams it was given, so a test sees what the adapters hand over.
    struct Echo;

    impl ToArgs for Echo {
        type Output = (String, String);
        const PER_TARGET: bool = false;

        fn to_args<'a>(&'a self, _targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
            Vec::new()
        }

        fn output(
            &self,
            _targets: &[PathBuf],
            stdout: String,
            stderr: String,
        ) -> Result<Vec<Self::Output>> {
            Ok(vec![(stdout, stderr)])
        }
    }

    #[test]
    fn decode_trims_surrounding_whitespace() {
        assert_eq!(
            decode(b" \n\tkeep  inner\n space \r\n".to_vec()),
            "keep  inner\n space"
        );
        assert_eq!(decode(b"plain".to_vec()), "plain");
    }

    #[test]
    fn decode_of_nothing_or_only_whitespace_is_empty() {
        assert_eq!(decode(Vec::new()), "");
        assert_eq!(decode(b" \n\t\r\n".to_vec()), "");
    }

    #[test]
    fn decode_replaces_invalid_utf8_with_the_replacement_character() {
        assert_eq!(decode(b"a\xFFb".to_vec()), "a\u{FFFD}b");
        assert_eq!(decode(vec![0xC3]), "\u{FFFD}");
        assert_eq!(decode("caf\u{E9}\n".as_bytes().to_vec()), "caf\u{E9}");
    }

    #[test]
    fn output_bytes_decodes_both_streams() {
        let outputs = Echo
            .output_bytes(&[], b"\nout\xFF\n".to_vec(), b"  err \n".to_vec())
            .unwrap();

        assert_eq!(outputs, [("out\u{FFFD}".to_owned(), "err".to_owned())]);
    }

    #[test]
    fn failure_bytes_decodes_both_streams_for_the_default_failure() {
        match Echo.failure_bytes(7, b"out\n".to_vec(), b"\xFFerr\n".to_vec()) {
            Error::Codesign(CodesignError::Failed {
                code,
                stdout,
                stderr,
            }) => {
                assert_eq!(code, 7);
                assert_eq!(stdout, "out");
                assert_eq!(stderr, "\u{FFFD}err");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn the_default_failure_keeps_stdout_apart_from_the_message() {
        let error = Echo.failure(2, "printed".into(), "bad".into());

        assert_eq!(error.to_string(), "`codesign` exited with code 2: bad");
    }
}
