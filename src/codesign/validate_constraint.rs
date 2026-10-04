use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::errors::CodesignError;

#[derive(Debug, Clone, Default)]
pub struct ValidateConstraint;

impl ToArgs for ValidateConstraint {
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
