use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::CodesignError;
use crate::codesign::action::action;
use crate::codesign::tool::Codesign;
use crate::engine::{Operation, PushArgs, SharedRun};

action! {
    /// Builder of a constraint check, returned by
    /// [`validate_constraint`](crate::codesign::validate_constraint).
    ///
    /// It has no options, so there are no setters to chain;
    /// [`per_target`](Self::per_target) is the only one, for several plists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// codesign::validate_constraint(["launch.plist", "library.plist"]).await?;
    /// # Ok(()) }
    /// ```
    ValidateConstraint => () {}
    setters {}
}

impl<S, R> SharedRun for ValidateConstraint<S, R> {}

impl Operation for Options {
    type Tool = Codesign;
    type Output = ();
    const BATCH: bool = true;

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
#[path = "unit_tests/validate_constraint.rs"]
mod tests;
