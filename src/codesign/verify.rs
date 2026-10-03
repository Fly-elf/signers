//! The verification action and the types its options take (`--verify`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;
use crate::errors::{Change, CodesignError, Error, ResourceChange};
use crate::target::Shape;

/// Options of the verification action: the `A` in `Codesign<Verify>`.
///
/// [`Codesign::verify`] creates it. You set its options with
/// [the verification setters](Codesign#impl-Codesign%3CVerify,+S%3E). An option you never set keeps
/// `codesign`'s default.
///
/// # Examples
///
/// Check a bundle as strictly as possible, nested code included, and keep going to the end of the
/// list:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign::verify::Strict;
/// use signers::{Codesign, Error};
///
/// let apps = vec!["A.app", "B.app"];
/// match Codesign::verify(apps).deep(true).strict(Strict::All).await {
///     Ok(_) => {}
///     Err(Error::Batch(failures)) => {
///         for (path, error) in &failures {
///             eprintln!("{}: {error}", path.display());
///         }
///     }
///     Err(error) => return Err(error),
/// }
/// # Ok(()) }
/// ```
///
/// Check an unsigned file against the signature that was written for it separately:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::Codesign;
///
/// Codesign::verify("mytool").detached("mytool.sig").await?;
/// # Ok(()) }
/// ```
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

/// The extra restrictions that [`strict`](Codesign#method.strict) applies.
///
/// `codesign` takes one value here, so one is enough, and the last one set wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strict {
    /// Every strict check there is, now and in later macOS versions (`--strict`).
    ///
    /// A new macOS can add checks, so code that passes today can fail later.
    All,
    /// Rejects a symbolic link in a bundle that is broken, points outside the bundle, or isn't
    /// sealed by the signature (`--strict=symlinks`).
    Symlinks,
    /// Rejects resource forks, Finder attributes and similar sideband data (`--strict=sideband`).
    ///
    /// Signing already enforces this, so it rarely changes a result.
    Sideband,
}

/// Options for [`verify`](Codesign::verify).
///
/// Each setter maps to one `codesign` flag. A later call replaces an earlier one, and `false`
/// leaves a flag out.
impl<S: Shape> Codesign<Verify, S> {
    /// Also verifies nested code on its own, not only through the bundle's seal (`--deep`).
    ///
    /// Without it, nested code is checked only against the hash the bundle sealed, so a byte
    /// changed inside a nested library can still pass.
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    /// Applies stricter checks than the default (`--strict`).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    /// use signers::codesign::verify::Strict;
    ///
    /// // Reject a symbolic link that leaves the bundle.
    /// Codesign::verify("MyApp.app").strict(Strict::Symlinks).await?;
    /// # Ok(()) }
    /// ```
    pub fn strict(mut self, strict: Strict) -> Self {
        self.action.strict = Some(strict);
        self
    }

    /// Skips the bundle's resources (`--ignore-resources`).
    ///
    /// A bundle with corrupted or tampered resources passes, so weigh the result accordingly. On a
    /// large bundle it is much faster.
    pub fn ignore_resources(mut self, ignore_resources: bool) -> Self {
        self.action.ignore_resources = ignore_resources;
        self
    }

    /// Verifies only this slice of a universal binary, e.g. `arm64` or `x86_64`
    /// (`--architecture`).
    ///
    /// The default is every slice. A slice the binary doesn't have fails verification.
    pub fn architecture(mut self, architecture: impl Into<String>) -> Self {
        self.action.architecture = Some(architecture.into());
        self
    }

    /// Verifies this version of a versioned bundle instead of `Current` (`--bundle-version`).
    ///
    /// A version the bundle doesn't have fails verification.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    /// Also checks the code against its own designated requirement (`--verbose=1`).
    ///
    /// It also makes a failed verification list the altered files in
    /// [`VerificationFailed::resources`](CodesignError::VerificationFailed). Without it that list
    /// is always empty.
    pub fn check_designated_requirement(mut self, check: bool) -> Self {
        self.action.check_designated_requirement = check;
        self
    }

    /// Requires the code to satisfy this requirement, written as text (`-R=`).
    ///
    /// A valid signature that doesn't satisfy it fails as
    /// [`CodesignError::RequirementUnsatisfied`], and text that doesn't compile as
    /// [`CodesignError::VerificationFailed`]. The text is never a file name, and `-` is not
    /// standard input.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::verify("MyApp.app")
    ///     .test_requirement("identifier \"com.example.myapp\" and anchor apple generic")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn test_requirement(mut self, requirement: impl Into<String>) -> Self {
        self.action.test_requirement = Some(requirement.into());
        self
    }

    /// Verifies an unsigned file against a detached signature written for it (`--detached`).
    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
        self
    }

    /// Forces an online check for a notarization ticket (`--check-notarization`).
    ///
    /// It contacts Apple's servers, so it needs network access. Don't rely on it to reject
    /// unnotarized code: `codesign` accepted an unnotarized ad hoc binary with it.
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

    fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
        match code {
            1 => CodesignError::VerificationFailed {
                stderr,
                resources: resource_changes(&stdout),
            },
            3 => CodesignError::RequirementUnsatisfied { stderr },
            _ => CodesignError::Failed { code, stderr },
        }
        .into()
    }
}

/// Reads the `file added|modified|missing: <path>` lines `--verbose=1` prints, in order.
fn resource_changes(stdout: &str) -> Vec<ResourceChange> {
    const PREFIXES: [(&str, Change); 3] = [
        ("file added: ", Change::Added),
        ("file modified: ", Change::Modified),
        ("file missing: ", Change::Missing),
    ];
    stdout
        .lines()
        .filter_map(|line| {
            PREFIXES.iter().find_map(|&(prefix, change)| {
                line.strip_prefix(prefix).map(|rest| ResourceChange {
                    change,
                    path: PathBuf::from(rest),
                })
            })
        })
        .collect()
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
        match action.failure(1, String::new(), "app: invalid signature".into()) {
            Error::Codesign(CodesignError::VerificationFailed { stderr, resources }) => {
                assert_eq!(stderr, "app: invalid signature");
                assert!(resources.is_empty());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn exit_one_carries_the_altered_resources_printed_on_stdout() {
        let action = Codesign::verify("app").action;
        let stdout = "file modified: /x/app/r.txt\nfile added: /x/app/new.txt".to_string();
        match action.failure(
            1,
            stdout,
            "app: a sealed resource is missing or invalid".into(),
        ) {
            Error::Codesign(CodesignError::VerificationFailed { stderr, resources }) => {
                assert_eq!(stderr, "app: a sealed resource is missing or invalid");
                assert_eq!(
                    pairs(&resources),
                    [
                        (Change::Modified, PathBuf::from("/x/app/r.txt")),
                        (Change::Added, PathBuf::from("/x/app/new.txt")),
                    ]
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn exit_three_ignores_stdout() {
        let action = Codesign::verify("app").action;
        let error = action.failure(3, "file modified: /x".into(), "no".into());
        assert!(matches!(
            error,
            Error::Codesign(CodesignError::RequirementUnsatisfied { ref stderr }) if stderr == "no"
        ));
    }

    fn pairs(resources: &[ResourceChange]) -> Vec<(Change, PathBuf)> {
        resources
            .iter()
            .map(|r| (r.change, r.path.clone()))
            .collect()
    }

    #[test]
    fn no_output_lists_no_resource() {
        assert!(resource_changes("").is_empty());
        assert!(resource_changes("\n\n").is_empty());
    }

    #[test]
    fn each_kind_of_change_is_recognised() {
        let listed = resource_changes("file added: /a\nfile modified: /m\nfile missing: /x\n");
        assert_eq!(
            pairs(&listed),
            [
                (Change::Added, PathBuf::from("/a")),
                (Change::Modified, PathBuf::from("/m")),
                (Change::Missing, PathBuf::from("/x")),
            ]
        );
    }

    #[test]
    fn resources_keep_the_order_they_were_printed_in() {
        let listed = resource_changes("file missing: /z\nfile added: /b\nfile missing: /a\n");
        let paths: Vec<_> = listed.iter().map(|r| r.path.to_str().unwrap()).collect();
        assert_eq!(paths, ["/z", "/b", "/a"]);
    }

    #[test]
    fn lines_that_are_not_a_change_are_ignored() {
        let stdout = [
            "app: valid on disk",
            "file changed: /nope",
            "File added: /nope",
            "file added:/nope",
            " file added: /nope",
            "file added",
            "file modified: /yes",
            "In subcomponent: /nope",
        ]
        .join("\n");
        assert_eq!(
            pairs(&resource_changes(&stdout)),
            [(Change::Modified, PathBuf::from("/yes"))]
        );
    }

    #[test]
    fn a_path_is_everything_after_the_prefix() {
        let listed = resource_changes("file modified: /a b/it's: -x; (y)  \n");
        assert_eq!(listed[0].path, PathBuf::from("/a b/it's: -x; (y)  "));
    }

    #[test]
    fn a_last_line_without_a_newline_still_counts() {
        let listed = resource_changes("file added: /a\nfile added: /b");
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn an_empty_path_is_still_an_entry() {
        let listed = resource_changes("file added: \n");
        assert_eq!(pairs(&listed), [(Change::Added, PathBuf::new())]);
    }

    #[test]
    fn a_path_that_is_not_utf8_is_decoded_lossily() {
        let stdout = String::from_utf8_lossy(b"file modified: /a\xff\xfeb\nfile added: /ok\n");
        let listed = resource_changes(&stdout);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].path, PathBuf::from("/a\u{FFFD}\u{FFFD}b"));
        assert_eq!(listed[1].path, PathBuf::from("/ok"));
    }

    #[test]
    fn exit_three_means_the_requirement_was_not_satisfied() {
        let action = Codesign::verify("app").action;
        match action.failure(3, String::new(), "test-requirement: failed".into()) {
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
            let error = action.failure(code, "file modified: /x".into(), "boom".into());
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
            action.failure(1, String::new(), String::new()),
            Error::Codesign(CodesignError::VerificationFailed { .. })
        ));
        assert!(matches!(
            action.failure(3, String::new(), String::new()),
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
