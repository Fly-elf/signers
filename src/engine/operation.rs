//! What an action tells the engine: its arguments, how to read a run's output, and its hooks.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use super::tool::Tool;
use crate::errors::{Error, Result};

/// Marks the action types whose targets can share one run of the tool; bounds `per_target`.
pub trait SharedRun {}

/// Renders an action into the tool's arguments and reads the result of its run.
///
/// `Sync` because per-target runs share one action concurrently.
pub trait Operation: Sync {
    /// The program this operation runs.
    type Tool: Tool;

    /// What a run yields for each target when the tool succeeds.
    ///
    /// It depends on the action type only, never on the option values.
    type Output: Send + 'static;

    /// The action's `per_target` default, for a collection of targets.
    ///
    /// `true` suits read-only actions; mutating ones keep `false`, so the tool handles their
    /// targets in order. A single target always runs once, whatever this says.
    const BATCH: bool;

    /// Rejects options this crate can't honour, before any target is checked or the tool
    /// runs.
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// Names the setter of an option set to write one file for all targets, if any.
    ///
    /// With `per_target(true)` the engine refuses it with [`Error::SharedOutputPerTarget`].
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
    /// [`ProcessError::UnexpectedOutput`](crate::errors::ProcessError::UnexpectedOutput). Both streams are lossy-decoded and trimmed. A
    /// failed run goes to [`failure`](Self::failure) instead.
    fn output(
        &self,
        targets: &[PathBuf],
        stdout: String,
        stderr: String,
    ) -> Result<Vec<Self::Output>>;

    /// Turns a non-zero exit code into this action's error; by default
    /// the tool's [`failed`](Tool::failed).
    ///
    /// Both streams are already lossy-decoded and trimmed; the default keeps them as they
    /// are. A process killed by a signal has no exit code and never gets here.
    fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
        Self::Tool::failed(code, stdout, stderr)
    }
}

/// Appends the tool's arguments, so that each option renders in one line.
pub trait PushArgs<'a> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::testing::Sh;
    use crate::errors::ProcessError;

    /// Overrides nothing but the required items, so the defaults show.
    struct Echo;

    impl Operation for Echo {
        type Tool = Sh;
        type Output = (String, String);
        const BATCH: bool = false;

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
    fn the_defaults_validate_everything_and_share_no_output() {
        assert!(Echo.validate().is_ok());
        assert_eq!(Echo.shared_output(), None);
    }

    #[test]
    fn the_default_failure_is_the_tool_s_failed_error() {
        match Echo.failure(2, "printed".into(), "bad".into()) {
            Error::Process(ProcessError::Failed {
                program,
                code,
                stdout,
                stderr,
            }) => {
                assert_eq!(program, "sh");
                assert_eq!(code, 2);
                assert_eq!(stdout, "printed");
                assert_eq!(stderr, "bad");
            }
            other => panic!("expected Process(Failed), got {other:?}"),
        }
    }

    #[test]
    fn the_default_failure_keeps_stdout_apart_from_the_message() {
        let error = Echo.failure(2, "printed".into(), "bad".into());

        assert_eq!(error.to_string(), "`sh` exited with code 2: bad");
    }

    #[test]
    fn push_args_renders_flags_options_built_values_and_targets_in_order() {
        let value = String::from("v");
        let targets = [PathBuf::from("-patched"), PathBuf::from("b")];
        let mut args: Vec<Cow<'_, OsStr>> = Vec::new();

        args.flag("--force");
        args.option("--sign", &value);
        args.built(format!("--n={}", 3));
        args.targets(&targets);

        let rendered: Vec<&OsStr> = args.iter().map(|a| a.as_ref()).collect();
        assert_eq!(
            rendered,
            ["--force", "--sign", "v", "--n=3", "--", "-patched", "b"].map(OsStr::new)
        );
        assert!(matches!(args[0], Cow::Borrowed(_)));
        assert!(matches!(args[2], Cow::Borrowed(_)));
        assert!(matches!(args[3], Cow::Owned(_)));
    }
}
