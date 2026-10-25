use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::Requirement;
use crate::codesign::action::action;
use crate::codesign::tool::Codesign;
use crate::engine::{Operation, PushArgs, Rejection};
use crate::errors::Output;

action! {
    /// Builder of a run that reads requirements, returned by
    /// [`requirements`](crate::codesign::requirements).
    ///
    /// It has no options. `.await` yields the requirements of each target as a `Vec` of
    /// [`Requirement`], in the order `codesign` keeps them, which is not the order given to
    /// [`Sign::requirements`](crate::codesign::Sign::requirements) when signing.
    ///
    /// # Examples
    ///
    /// Print the designated requirement of an app:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign::{self, RequirementKind};
    ///
    /// let requirements = codesign::requirements("MyApp.app").await?;
    /// for requirement in &requirements {
    ///     if requirement.kind == RequirementKind::Designated {
    ///         println!("{}", requirement.expression);
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Tell the requirements a signature carries from the system's defaults:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// let [ls, cat] = codesign::requirements(["/bin/ls", "/bin/cat"]).await?;
    /// let embedded = ls.iter().chain(&cat).filter(|requirement| !requirement.implicit).count();
    /// println!("{embedded} requirements are part of the signatures");
    /// # Ok(()) }
    /// ```
    Requirements => Vec<Requirement> {}
    setters {}
}

impl Operation for Options {
    type Tool = Codesign;
    type Output = Vec<Requirement>;
    const BATCH: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();
        args.flag("--display");
        args.flag("-r-");
        args.targets(targets);
        args
    }

    /// Parses every stdout line but the blank ones and the constraint dump as a [`Requirement`].
    ///
    /// The action always runs per target, so the run yields one `Vec`, empty when `codesign`
    /// prints no requirement.
    // Constraint dump lines are tab-indented `[Tag]` lines, but the stream is
    // trimmed, which takes the tab off the first one.
    fn output(
        &self,
        _targets: &[PathBuf],
        output: &Output,
    ) -> Result<Vec<Vec<Requirement>>, Rejection> {
        let requirements = output
            .stdout
            .lines()
            .filter(|line| !line.starts_with(['\t', '[']) && !line.trim().is_empty())
            .map(Requirement::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(vec![requirements])
    }
}

#[cfg(test)]
#[path = "unit_tests/requirements.rs"]
mod tests;
