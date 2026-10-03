//! The verification action and the types its options take (`--verify`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;
use crate::errors::{CodesignError, Error};
use crate::target::Shape;

#[derive(Debug, Clone, Default)]
pub struct Verify {
    deep: bool,
    strict: Option<Strict>,
    ignore_resources: bool,
    architecture: Option<String>,
    bundle_version: Option<String>,
    check_designated_requirement: bool,
    test_requirement: Option<String>,
    detached: Option<PathBuf>,
    check_notarization: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strict {
    All,
    Symlinks,
    Sideband,
}

impl<S: Shape> Codesign<Verify, S> {
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    pub fn strict(mut self, strict: Strict) -> Self {
        self.action.strict = Some(strict);
        self
    }

    pub fn ignore_resources(mut self, ignore_resources: bool) -> Self {
        self.action.ignore_resources = ignore_resources;
        self
    }

    pub fn architecture(mut self, architecture: impl Into<String>) -> Self {
        self.action.architecture = Some(architecture.into());
        self
    }

    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    pub fn check_designated_requirement(mut self, check: bool) -> Self {
        self.action.check_designated_requirement = check;
        self
    }

    pub fn test_requirement(mut self, requirement: impl Into<String>) -> Self {
        self.action.test_requirement = Some(requirement.into());
        self
    }

    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
        self
    }

    pub fn check_notarization(mut self, check: bool) -> Self {
        self.action.check_notarization = check;
        self
    }
}

impl ToArgs for Verify {
    type Output = ();
    const PER_TARGET: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();

        // `codesign` ignores options given before the operation.
        args.flag("--verify");

        if self.deep {
            args.flag("--deep");
        }
        match self.strict {
            Some(Strict::All) => args.flag("--strict"),
            Some(Strict::Symlinks) => args.flag("--strict=symlinks"),
            Some(Strict::Sideband) => args.flag("--strict=sideband"),
            None => {}
        }
        if self.ignore_resources {
            args.flag("--ignore-resources");
        }
        if let Some(architecture) = &self.architecture {
            args.option("--architecture", architecture);
        }
        if let Some(version) = &self.bundle_version {
            args.option("--bundle-version", version);
        }
        if self.check_designated_requirement {
            args.flag("--verbose=1");
        }
        if let Some(requirement) = &self.test_requirement {
            // `-R` takes `=text` only in this single-argument form; a space would make it a file path.
            args.built(format!("-R={requirement}"));
        }
        if let Some(path) = &self.detached {
            args.option("--detached", path);
        }
        if self.check_notarization {
            args.flag("--check-notarization");
        }

        args.targets(targets);
        args
    }

    fn output(
        &self,
        targets: &[PathBuf],
        _stdout: Vec<u8>,
        _stderr: Vec<u8>,
    ) -> crate::errors::Result<Vec<()>> {
        Ok(vec![(); targets.len()])
    }

    fn failure(&self, code: i32, stderr: String) -> Error {
        match code {
            1 => CodesignError::VerificationFailed { stderr },
            3 => CodesignError::RequirementUnsatisfied { stderr },
            _ => CodesignError::Failed { code, stderr },
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    fn args_of<S>(builder: &Codesign<Verify, S>) -> Vec<OsString> {
        builder
            .action
            .to_args(&builder.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    fn code_of(error: Error) -> Option<(i32, String)> {
        match error {
            Error::Codesign(CodesignError::Failed { code, stderr }) => Some((code, stderr)),
            _ => None,
        }
    }

    #[test]
    fn bare_action_only_verifies() {
        assert_eq!(
            args_of(&Codesign::verify("app")),
            os(&["--verify", "--", "app"])
        );
    }

    /// Every option, in the order the action renders them, each exactly once.
    #[test]
    fn every_option_renders_exactly_once_in_field_order() {
        let action = Codesign::verify("app")
            .check_notarization(true)
            .detached("app.sig")
            .test_requirement("anchor apple")
            .check_designated_requirement(true)
            .bundle_version("A")
            .architecture("arm64")
            .ignore_resources(true)
            .strict(Strict::All)
            .deep(true);
        assert_eq!(
            args_of(&action),
            os(&[
                "--verify",
                "--deep",
                "--strict",
                "--ignore-resources",
                "--architecture",
                "arm64",
                "--bundle-version",
                "A",
                "--verbose=1",
                "-R=anchor apple",
                "--detached",
                "app.sig",
                "--check-notarization",
                "--",
                "app",
            ])
        );
    }

    #[test]
    fn each_option_renders_alone_in_its_own_form() {
        let cases: [(Codesign<Verify>, &[&str]); 9] = [
            (Codesign::verify("app").deep(true), &["--deep"]),
            (Codesign::verify("app").strict(Strict::All), &["--strict"]),
            (
                Codesign::verify("app").ignore_resources(true),
                &["--ignore-resources"],
            ),
            (
                Codesign::verify("app").architecture("x86_64"),
                &["--architecture", "x86_64"],
            ),
            (
                Codesign::verify("app").bundle_version("B"),
                &["--bundle-version", "B"],
            ),
            (
                Codesign::verify("app").check_designated_requirement(true),
                &["--verbose=1"],
            ),
            (
                Codesign::verify("app").test_requirement("anchor apple"),
                &["-R=anchor apple"],
            ),
            (
                Codesign::verify("app").detached("sig"),
                &["--detached", "sig"],
            ),
            (
                Codesign::verify("app").check_notarization(true),
                &["--check-notarization"],
            ),
        ];
        for (action, option) in cases {
            let mut expected = vec!["--verify"];
            expected.extend(option);
            expected.extend(["--", "app"]);
            assert_eq!(args_of(&action), os(&expected));
        }
    }

    /// `--strict` takes its value in the same token, never as a separate argument.
    #[test]
    fn every_strict_level_renders_as_one_token() {
        for (strict, token) in [
            (Strict::All, "--strict"),
            (Strict::Symlinks, "--strict=symlinks"),
            (Strict::Sideband, "--strict=sideband"),
        ] {
            assert_eq!(
                args_of(&Codesign::verify("app").strict(strict)),
                os(&["--verify", token, "--", "app"])
            );
        }
    }

    #[test]
    fn false_removes_the_flag_again() {
        let action = Codesign::verify("app")
            .deep(true)
            .deep(false)
            .ignore_resources(true)
            .ignore_resources(false)
            .check_designated_requirement(true)
            .check_designated_requirement(false)
            .check_notarization(true)
            .check_notarization(false);
        assert_eq!(args_of(&action), os(&["--verify", "--", "app"]));
    }

    #[test]
    fn repeating_a_valued_option_keeps_the_last_value() {
        let action = Codesign::verify("app")
            .strict(Strict::All)
            .strict(Strict::Symlinks)
            .architecture("arm64")
            .architecture("x86_64")
            .bundle_version("A")
            .bundle_version("B")
            .test_requirement("anchor apple")
            .test_requirement("anchor trusted")
            .detached("one.sig")
            .detached("two.sig");
        assert_eq!(
            args_of(&action),
            os(&[
                "--verify",
                "--strict=symlinks",
                "--architecture",
                "x86_64",
                "--bundle-version",
                "B",
                "-R=anchor trusted",
                "--detached",
                "two.sig",
                "--",
                "app",
            ])
        );
    }

    /// The requirement is text, so it stays one argument whatever it contains,
    /// and `-` is text too, not stdin.
    #[test]
    fn a_requirement_is_a_single_argument_whatever_it_contains() {
        for text in [
            "identifier \"com.example.app\" and anchor apple",
            "-",
            "=anchor apple",
            "-R x",
            "",
            "a\nb",
            "héllo ✓",
        ] {
            assert_eq!(
                args_of(&Codesign::verify("app").test_requirement(text)),
                os(&["--verify", &format!("-R={text}"), "--", "app"]),
            );
        }
    }

    #[test]
    fn option_values_with_spaces_stay_whole_arguments() {
        let action = Codesign::verify("app")
            .architecture("arm 64")
            .bundle_version("v 1")
            .detached("my sig.bin");
        assert_eq!(
            args_of(&action),
            os(&[
                "--verify",
                "--architecture",
                "arm 64",
                "--bundle-version",
                "v 1",
                "--detached",
                "my sig.bin",
                "--",
                "app",
            ])
        );
    }

    #[test]
    fn targets_come_last_after_the_separator() {
        assert_eq!(
            args_of(&Codesign::verify(vec!["-a.app", "b c.app"]).deep(true)),
            os(&["--verify", "--deep", "--", "-a.app", "b c.app"])
        );
        assert_eq!(
            args_of(&Codesign::verify(["a", "b"]).strict(Strict::All)),
            os(&["--verify", "--strict", "--", "a", "b"])
        );
    }

    #[test]
    fn there_is_nothing_to_validate() {
        let action = Codesign::verify("app")
            .test_requirement("-")
            .detached("-")
            .action;
        assert!(action.validate().is_ok());
    }

    #[test]
    fn no_option_is_a_shared_output() {
        let action = Codesign::verify("app").detached("app.sig").action;
        assert_eq!(action.shared_output(), None);
    }

    #[test]
    fn the_output_is_one_unit_per_target_whatever_codesign_printed() {
        let action = Codesign::verify("app").action;
        let targets = [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];

        assert_eq!(
            action.output(&targets, Vec::new(), Vec::new()).unwrap(),
            [(), (), ()]
        );
        let noisy = action.output(&targets[..1], b"noise".to_vec(), vec![0xff, 0xfe]);
        assert_eq!(noisy.unwrap(), [()]);
        assert!(
            action
                .output(&[], Vec::new(), Vec::new())
                .unwrap()
                .is_empty()
        );
    }

    /// A verification is read-only, so a batch is checked target by target
    /// unless the caller asks for one process.
    #[test]
    fn the_constructor_defaults_to_one_process_per_target_for_collections() {
        assert!(Codesign::verify(vec!["a.app", "b.app"]).per_target);
        assert!(Codesign::verify(["a.app", "b.app"]).per_target);
        assert!(Codesign::verify(&["a.app", "b.app"][..]).per_target);
        assert!(!Codesign::verify(vec!["a.app"]).per_target(false).per_target);
    }

    #[test]
    fn per_target_renders_no_argument() {
        let on = Codesign::verify(vec!["app"]).per_target(true);
        let off = Codesign::verify(vec!["app"]).per_target(false);
        assert_eq!(args_of(&on), os(&["--verify", "--", "app"]));
        assert_eq!(args_of(&off), os(&["--verify", "--", "app"]));
    }

    #[test]
    fn exit_one_means_the_signature_did_not_verify() {
        let action = Codesign::verify("app").action;
        match action.failure(1, "app: invalid signature".into()) {
            Error::Codesign(CodesignError::VerificationFailed { stderr }) => {
                assert_eq!(stderr, "app: invalid signature");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn exit_three_means_the_requirement_was_not_satisfied() {
        let action = Codesign::verify("app").action;
        match action.failure(3, "test-requirement: failed".into()) {
            Error::Codesign(CodesignError::RequirementUnsatisfied { stderr }) => {
                assert_eq!(stderr, "test-requirement: failed");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn any_other_exit_code_is_the_generic_failure() {
        let action = Codesign::verify("app").action;
        for code in [2, 4, 64, 127, 255] {
            let error = action.failure(code, "boom".into());
            assert_eq!(
                code_of(error),
                Some((code, "boom".to_string())),
                "exit {code}"
            );
        }
    }

    #[test]
    fn the_failure_mapping_ignores_the_options() {
        let action = Codesign::verify("app")
            .test_requirement("anchor apple")
            .deep(true)
            .action;
        assert!(matches!(
            action.failure(1, String::new()),
            Error::Codesign(CodesignError::VerificationFailed { .. })
        ));
        assert!(matches!(
            action.failure(3, String::new()),
            Error::Codesign(CodesignError::RequirementUnsatisfied { .. })
        ));
    }

    #[test]
    fn strict_levels_compare_by_value() {
        assert_eq!(Strict::All, Strict::All);
        assert_ne!(Strict::All, Strict::Symlinks);
        assert_ne!(Strict::Symlinks, Strict::Sideband);
    }
}
