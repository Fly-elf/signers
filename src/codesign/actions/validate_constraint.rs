use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::action::PushArgs;
use crate::codesign::action::action;
use crate::codesign::action::sealed::{SharedRun, ToArgs};
use crate::errors::CodesignError;

action! {
    /// The action of [`Codesign::validate_constraint`](crate::Codesign#method.validate_constraint): the
    /// `A` in `Codesign<ValidateConstraint>`.
    ///
    /// It has no options, so there are no setters to chain;
    /// [`per_target`](crate::Codesign#method.per_target) is the only one, for several plists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// validate_constraint(["launch.plist", "library.plist"]).await?;
    /// # Ok(()) }
    /// ```
    ValidateConstraint => () {}
    setters {}
}

impl<S, R> SharedRun for ValidateConstraint<S, R> {}

impl ToArgs for Options {
    type Output = ();
    const PER_TARGET: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();
        args.flag("--validate-constraint");
        args.targets(targets);
        args
    }

    // macOS 27 exits 0 and prints "Constraint validation failed" for every readable plist,
    // valid ones included; only an `error:` line marks a real rejection.
    fn output(
        &self,
        targets: &[PathBuf],
        stdout: String,
        stderr: String,
    ) -> crate::errors::Result<Vec<()>> {
        if stderr.lines().any(|line| line.starts_with("error:")) {
            return Err(CodesignError::ConstraintInvalid { stdout, stderr }.into());
        }
        Ok(vec![(); targets.len()])
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::codesign::validate_constraint;
    use crate::errors::Error;

    const BOGUS_FAILED: &str = "Constraint validation failed";
    const ERROR_REPORT: &str = "error: Lightweight Code requirement failed validation for category Launch\n\tError Domain=LWCRVerificationError Code=1 \"Error: Unknown Key, Context: bogus-key-xyz\" UserInfo={NSLocalizedDescription=Error: Unknown Key, Context: bogus-key-xyz}";

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    fn action() -> Options {
        validate_constraint("a.plist").options
    }

    fn args_of<S>(builder: &ValidateConstraint<S>) -> Vec<OsString> {
        builder
            .options
            .to_args(&builder.core.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    fn invalid(result: crate::errors::Result<Vec<()>>) -> (String, String) {
        match result {
            Err(Error::Codesign(CodesignError::ConstraintInvalid { stdout, stderr })) => {
                (stdout, stderr)
            }
            other => panic!("expected ConstraintInvalid, got {other:?}"),
        }
    }

    #[test]
    fn the_action_only_validates_the_plists() {
        assert_eq!(
            args_of(&validate_constraint("c.plist")),
            ["--validate-constraint", "--", "c.plist"].map(OsString::from)
        );
    }

    #[test]
    fn every_plist_is_passed_in_order() {
        assert_eq!(
            args_of(&validate_constraint(["a.plist", "b.plist", "-c.plist"])),
            [
                "--validate-constraint",
                "--",
                "a.plist",
                "b.plist",
                "-c.plist"
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn the_bogus_failed_line_alone_is_a_success() {
        let outputs = action()
            .output(&paths(&["a"]), String::new(), BOGUS_FAILED.to_owned())
            .unwrap();

        assert_eq!(outputs, [()]);
    }

    #[test]
    fn an_empty_stderr_is_a_success() {
        let outputs = action()
            .output(&paths(&["a", "b", "c"]), String::new(), String::new())
            .unwrap();

        assert_eq!(outputs.len(), 3);
    }

    #[test]
    fn an_error_line_is_a_rejection_that_keeps_both_streams() {
        let stderr = format!("{ERROR_REPORT}\n{BOGUS_FAILED}");

        let (stdout, kept) =
            invalid(action().output(&paths(&["a"]), "some output".to_owned(), stderr.clone()));

        assert_eq!(stdout, "some output");
        assert_eq!(kept, stderr);
    }

    #[test]
    fn an_error_line_after_other_lines_is_still_a_rejection() {
        let stderr = format!("{BOGUS_FAILED}\nwarning: something\n{ERROR_REPORT}");

        invalid(action().output(&paths(&["a", "b"]), String::new(), stderr));
    }

    #[test]
    fn an_error_line_without_the_bogus_line_is_a_rejection() {
        invalid(action().output(
            &paths(&["a"]),
            String::new(),
            "error: bad constraint".to_owned(),
        ));
    }

    #[test]
    fn error_text_inside_a_line_is_not_a_rejection() {
        let stderr = format!("{BOGUS_FAILED}\nwarning: not an error: really");

        let outputs = action()
            .output(&paths(&["a"]), String::new(), stderr)
            .unwrap();

        assert_eq!(outputs, [()]);
    }

    #[test]
    fn exit_code_one_is_a_plain_failure_with_both_streams() {
        for code in [1, 2] {
            match action().failure(
                code,
                "out".to_owned(),
                "Error reading constraint from x.plist".to_owned(),
            ) {
                Error::Codesign(CodesignError::Failed {
                    code: got,
                    stdout,
                    stderr,
                }) => {
                    assert_eq!(got, code);
                    assert_eq!(stdout, "out");
                    assert_eq!(stderr, "Error reading constraint from x.plist");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_rejection_names_its_diagnostics() {
        let error: Error = CodesignError::ConstraintInvalid {
            stdout: String::new(),
            stderr: ERROR_REPORT.to_owned(),
        }
        .into();

        let message = error.to_string();

        assert!(message.starts_with("invalid constraint: "), "{message}");
        assert!(message.contains("Unknown Key"), "{message}");
    }
}
