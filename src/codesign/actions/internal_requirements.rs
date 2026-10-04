//! The requirements action and the [`Requirement`]s it returns (`--display -r-`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::Requirement;
use crate::codesign::action::PushArgs;
use crate::codesign::action::sealed::ToArgs;
use crate::errors::Result;

/// The action that reads requirements: the `A` in `Codesign<InternalRequirements>`.
///
/// [`internal_requirements`](crate::Codesign::internal_requirements) creates it. It has no options. `.await` yields the
/// requirements of each target as a `Vec` of [`Requirement`], in the order `codesign` keeps them,
/// which is not the order given to [`requirements`](crate::Codesign::requirements) when signing.
///
/// # Examples
///
/// Print the designated requirement of an app:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::Codesign;
/// use signers::codesign::requirements::RequirementKind;
///
/// let requirements = Codesign::internal_requirements("MyApp.app").await?;
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
/// use signers::Codesign;
///
/// let [ls, cat] = Codesign::internal_requirements(["/bin/ls", "/bin/cat"]).await?;
/// let embedded = ls.iter().chain(&cat).filter(|requirement| !requirement.implicit).count();
/// println!("{embedded} requirements are part of the signatures");
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Default)]
pub struct InternalRequirements;

impl ToArgs for InternalRequirements {
    type Output = Vec<Requirement>;
    const PER_TARGET: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();
        args.flag("--display");
        args.flag("-r-");
        args.targets(targets);
        args
    }

    // Constraint dump lines are tab-indented `[Tag]` lines, but the stream is
    // trimmed, which takes the tab off the first one.
    fn output(
        &self,
        _targets: &[PathBuf],
        stdout: String,
        _stderr: String,
    ) -> Result<Vec<Vec<Requirement>>> {
        let requirements = stdout
            .lines()
            .filter(|line| !line.starts_with(['\t', '[']) && !line.trim().is_empty())
            .map(Requirement::parse)
            .collect::<Result<Vec<_>>>()?;
        Ok(vec![requirements])
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::codesign::Codesign;
    use crate::codesign::RequirementKind;
    use crate::errors::CodesignError;

    const DESIGNATED: &str = r#"designated => identifier "com.apple.ls" and anchor apple"#;
    const DUMP: &str = "\t[Dict]\n\t\t[Key] ccat\n\t\t[Value]\n\t\t\t[Int] 0\n";

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    fn args_of<S>(builder: &Codesign<InternalRequirements, S>) -> Vec<OsString> {
        builder
            .action
            .to_args(&builder.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    fn read(stdout: &str) -> Result<Vec<Requirement>> {
        let mut outputs =
            InternalRequirements.output(&paths(&["a"]), stdout.to_owned(), String::new())?;
        assert_eq!(outputs.len(), 1);
        Ok(outputs.remove(0))
    }

    fn kinds_and_flags(requirements: &[Requirement]) -> Vec<(RequirementKind, bool)> {
        requirements
            .iter()
            .map(|r| (r.kind.clone(), r.implicit))
            .collect()
    }

    #[test]
    fn the_arguments_read_the_requirements_and_nothing_else() {
        let expected = os(&["--display", "-r-", "--", "app"]);

        assert_eq!(args_of(&Codesign::internal_requirements("app")), expected);
        assert_eq!(
            args_of(&Codesign::internal_requirements(vec!["app"])),
            expected
        );
        assert_eq!(args_of(&Codesign::internal_requirements(["app"])), expected);
    }

    #[test]
    fn every_target_is_listed_after_the_separator() {
        assert_eq!(
            args_of(&Codesign::internal_requirements(vec!["a", "-b"])),
            os(&["--display", "-r-", "--", "a", "-b"])
        );
    }

    #[test]
    fn collections_default_to_one_run_per_target() {
        assert!(Codesign::internal_requirements(vec!["a", "b"]).per_target);
        assert!(Codesign::internal_requirements(["a", "b"]).per_target);
        assert!(!Codesign::internal_requirements("a").per_target);
    }

    #[test]
    fn requirements_are_read_in_printed_order() {
        let stdout = format!(
            "host => anchor apple\n{DESIGNATED}\n# library => cdhash H\"00\"\nweird => x\n"
        );

        let found = read(&stdout).unwrap();

        assert_eq!(
            kinds_and_flags(&found),
            [
                (RequirementKind::Host, false),
                (RequirementKind::Designated, false),
                (RequirementKind::Library, true),
                (RequirementKind::Other("weird".into()), false),
            ]
        );
        assert_eq!(
            found[1].expression,
            r#"identifier "com.apple.ls" and anchor apple"#
        );
        assert_eq!(found[2].expression, r#"cdhash H"00""#);
    }

    #[test]
    fn nothing_on_stdout_is_an_empty_list() {
        assert_eq!(read("").unwrap(), vec![]);
        assert_eq!(read("\n\n  \n").unwrap(), vec![]);
    }

    #[test]
    fn the_run_yields_one_list() {
        let outputs = InternalRequirements
            .output(&paths(&["a"]), format!("{DESIGNATED}\n"), String::new())
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].len(), 1);
    }

    #[test]
    fn stderr_is_not_read() {
        let outputs = InternalRequirements
            .output(
                &paths(&["a"]),
                format!("{DESIGNATED}\n"),
                "Executable=/x/a\nnot a requirement\n".to_owned(),
            )
            .unwrap();

        assert_eq!(
            kinds_and_flags(&outputs[0]),
            [(RequirementKind::Designated, false)]
        );
    }

    #[test]
    fn blank_lines_between_requirements_are_skipped() {
        let stdout = format!("\n{DESIGNATED}\n\n   \n# host => anchor apple\n\n");

        assert_eq!(
            kinds_and_flags(&read(&stdout).unwrap()),
            [
                (RequirementKind::Designated, false),
                (RequirementKind::Host, true)
            ]
        );
    }

    #[test]
    fn the_constraint_dump_ahead_of_the_requirements_is_not_one() {
        let stdout = format!("{DUMP}{DUMP}{DESIGNATED}\n# host => anchor apple\n");

        assert_eq!(
            kinds_and_flags(&read(&stdout).unwrap()),
            [
                (RequirementKind::Designated, false),
                (RequirementKind::Host, true)
            ]
        );
    }

    #[test]
    fn a_dump_between_requirements_is_skipped_too() {
        let stdout = format!("{DESIGNATED}\n{DUMP}# host => anchor apple\n");

        assert_eq!(
            kinds_and_flags(&read(&stdout).unwrap()),
            [
                (RequirementKind::Designated, false),
                (RequirementKind::Host, true)
            ]
        );
    }

    /// The stream is trimmed, so the first dump line has lost its tab.
    #[test]
    fn a_dump_whose_first_tab_is_gone_is_still_skipped() {
        let dump = DUMP.trim();
        assert!(dump.starts_with('['));

        assert_eq!(
            kinds_and_flags(&read(&format!("{dump}\n{DESIGNATED}\n")).unwrap()),
            [(RequirementKind::Designated, false)]
        );
        assert_eq!(read(dump).unwrap(), vec![]);
    }

    #[test]
    fn a_malformed_requirement_line_is_rejected() {
        for stdout in [
            "designated\n",
            "garbage line\n",
            &format!("{DESIGNATED}\nnot a requirement\n"),
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>",
        ] {
            let result = read(stdout);
            assert!(
                matches!(
                    &result,
                    Err(crate::Error::Codesign(CodesignError::UnexpectedOutput { detail }))
                        if detail.contains("requirement")
                ),
                "{stdout:?}: {result:?}"
            );
        }
    }

    /// `per_target` exists for actions that can share a run; this one can't,
    /// because the requirements of several targets in one stdout can't be told
    /// apart. Resolves only while `InternalRequirements` is not `SharedRun`.
    #[test]
    fn the_action_cannot_share_a_run() {
        trait AmbiguousIfShared<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfShared<()> for T {}
        impl<T: ?Sized + crate::codesign::action::sealed::SharedRun> AmbiguousIfShared<u8> for T {}

        <InternalRequirements as AmbiguousIfShared<_>>::check();
    }

    #[test]
    fn a_failed_run_keeps_its_exit_code_and_streams() {
        let error = InternalRequirements.failure(1, "out".into(), "err".into());

        assert!(
            matches!(
                &error,
                crate::Error::Codesign(CodesignError::Failed { code: 1, stdout, stderr })
                    if stdout == "out" && stderr == "err"
            ),
            "{error:?}"
        );
    }
}
