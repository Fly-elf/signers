use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::action::PushArgs;
use crate::codesign::action::action;
use crate::codesign::action::sealed::{SharedRun, ToArgs};
use crate::codesign::{SignatureSlot, Strict};
use crate::errors::{Change, CodesignError, Error, ResourceChange};

action! {
    /// Options of the verification action: the `A` in `Codesign<Verify>`.
    ///
    /// [`Codesign::verify`](crate::Codesign#method.verify) creates it. You set its options with [the
    /// verification setters](crate::Codesign#impl-Runner%3CVerify,+S,+R%3E). An option you never set
    /// keeps `codesign`'s default.
    ///
    /// # Examples
    ///
    /// Check a bundle as strictly as possible, nested code included, and keep going to the end of the
    /// list:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign::Strict;
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
    Verify => () {
        test_requirement: Option<TestRequirement>,
    }
    setters {
        /// Also verifies nested code on its own, not only through the bundle's seal (`--deep`).
        ///
        /// Without it, nested code is checked only against the hash the bundle sealed, so a byte
        /// changed inside a nested library can still pass.
        deep: bool,
        /// Applies stricter checks than the default (`--strict`).
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn run() -> signers::Result<()> {
        /// use signers::Codesign;
        /// use signers::codesign::Strict;
        ///
        /// // Reject a symbolic link that leaves the bundle.
        /// Codesign::verify("MyApp.app").strict(Strict::Symlinks).await?;
        /// # Ok(()) }
        /// ```
        strict: Option<Strict>,
        /// Skips the bundle's resources (`--ignore-resources`).
        ///
        /// A bundle with corrupted or tampered resources passes, so weigh the result accordingly. On a
        /// large bundle it is much faster.
        ignore_resources: bool,
        /// Verifies only this slice of a universal binary, e.g. `arm64` or `x86_64`
        /// (`--architecture`).
        ///
        /// The default is every slice. A slice the binary doesn't have fails verification.
        architecture: Option<impl Into<String>>,
        /// Verifies this version of a versioned bundle instead of `Current` (`--bundle-version`).
        ///
        /// A version the bundle doesn't have fails verification.
        bundle_version: Option<impl Into<String>>,
        /// Also checks the code against its own designated requirement (`--verbose=1`).
        ///
        /// It also makes a failed verification list the altered files in
        /// [`VerificationFailed::resources`](CodesignError::VerificationFailed). Without it that list
        /// is always empty.
        check_designated_requirement: bool,
        /// Verifies this signature when the code carries two (`--signature-slot`).
        ///
        /// Without it `codesign` picks the slot itself. On code that carries only one signature,
        /// [`Second`](SignatureSlot::Second) can fail as [`CodesignError::VerificationFailed`].
        signature_slot: Option<SignatureSlot>,
        /// Verifies an unsigned file against a detached signature written for it (`--detached`).
        detached: Option<impl Into<PathBuf>>,
        /// Forces an online check for a notarization ticket (`--check-notarization`).
        ///
        /// It contacts Apple's servers, so it needs network access. Don't rely on it to reject
        /// unnotarized code: `codesign` accepted an unnotarized ad hoc binary with it.
        check_notarization: bool,
    }
}

#[derive(Debug, Clone)]
enum TestRequirement {
    Text(String),
    File(PathBuf),
}

impl<S, R> Verify<S, R> {
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
        self.options.test_requirement = Some(TestRequirement::Text(requirement.into()));
        self
    }

    /// Requires the code to satisfy the requirement written in this file (`-R <path>`).
    ///
    /// Failures are the same as for [`test_requirement`](crate::Codesign#method.test_requirement).
    /// It replaces any earlier requirement, text or file. A path of `-` would read standard input,
    /// so it makes `.await` fail with [`Error::StdioPath`] before anything runs.
    pub fn test_requirement_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.options.test_requirement = Some(TestRequirement::File(path.into()));
        self
    }
}

impl<S, R> SharedRun for Verify<S, R> {}

impl ToArgs for Options {
    type Output = ();
    const PER_TARGET: bool = true;

    fn validate(&self) -> crate::errors::Result<()> {
        match &self.test_requirement {
            Some(TestRequirement::File(path)) if path.as_os_str() == "-" => {
                Err(Error::StdioPath("test_requirement_file"))
            }
            _ => Ok(()),
        }
    }

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
        match &self.test_requirement {
            // `-R` takes `=text` only in this single-argument form; a space would make it a file path.
            Some(TestRequirement::Text(text)) => args.built(format!("-R={text}")),
            Some(TestRequirement::File(path)) => args.option("-R", path),
            None => {}
        }
        if let Some(slot) = self.signature_slot {
            args.option("--signature-slot", slot.as_str());
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
        _stdout: String,
        _stderr: String,
    ) -> crate::errors::Result<Vec<()>> {
        Ok(vec![(); targets.len()])
    }

    fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
        match code {
            1 => {
                let resources = resource_changes(&stdout);
                CodesignError::VerificationFailed {
                    stdout,
                    stderr,
                    resources,
                }
            }
            3 => CodesignError::RequirementUnsatisfied { stdout, stderr },
            _ => CodesignError::Failed {
                code,
                stdout,
                stderr,
            },
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
    use crate::codesign::verify;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    fn args_of<S>(builder: &Verify<S>) -> Vec<OsString> {
        builder
            .options
            .to_args(&builder.core.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    fn code_of(error: Error) -> Option<(i32, String)> {
        match error {
            Error::Codesign(CodesignError::Failed { code, stderr, .. }) => Some((code, stderr)),
            _ => None,
        }
    }

    #[test]
    fn bare_action_only_verifies() {
        assert_eq!(args_of(&verify("app")), os(&["--verify", "--", "app"]));
    }

    /// Every option, in the order the action renders them, each exactly once.
    #[test]
    fn every_option_renders_exactly_once_in_field_order() {
        let action = verify("app")
            .check_notarization(true)
            .detached("app.sig")
            .test_requirement("anchor apple")
            .signature_slot(SignatureSlot::Second)
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
                "--signature-slot",
                "2",
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
        let cases: [(Verify, &[&str]); 12] = [
            (verify("app").deep(true), &["--deep"]),
            (verify("app").strict(Strict::All), &["--strict"]),
            (
                verify("app").ignore_resources(true),
                &["--ignore-resources"],
            ),
            (
                verify("app").architecture("x86_64"),
                &["--architecture", "x86_64"],
            ),
            (
                verify("app").bundle_version("B"),
                &["--bundle-version", "B"],
            ),
            (
                verify("app").check_designated_requirement(true),
                &["--verbose=1"],
            ),
            (
                verify("app").test_requirement("anchor apple"),
                &["-R=anchor apple"],
            ),
            (
                verify("app").test_requirement_file("req.txt"),
                &["-R", "req.txt"],
            ),
            (
                verify("app").signature_slot(SignatureSlot::First),
                &["--signature-slot", "1"],
            ),
            (
                verify("app").signature_slot(SignatureSlot::Second),
                &["--signature-slot", "2"],
            ),
            (verify("app").detached("sig"), &["--detached", "sig"]),
            (
                verify("app").check_notarization(true),
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
                args_of(&verify("app").strict(strict)),
                os(&["--verify", token, "--", "app"])
            );
        }
    }

    #[test]
    fn false_removes_the_flag_again() {
        let action = verify("app")
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
        let action = verify("app")
            .strict(Strict::All)
            .strict(Strict::Symlinks)
            .architecture("arm64")
            .architecture("x86_64")
            .bundle_version("A")
            .bundle_version("B")
            .test_requirement("anchor apple")
            .test_requirement("anchor trusted")
            .signature_slot(SignatureSlot::First)
            .signature_slot(SignatureSlot::Second)
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
                "--signature-slot",
                "2",
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
                args_of(&verify("app").test_requirement(text)),
                os(&["--verify", &format!("-R={text}"), "--", "app"]),
            );
        }
    }

    /// The requirement file is a path: two arguments, the path untouched.
    #[test]
    fn a_requirement_file_is_a_flag_and_its_path() {
        for path in [
            "req.txt",
            "dir/my requirement.txt",
            "=anchor apple",
            "-R=x",
            "--verify",
            "-x",
            "./-",
            "héllo ✓.txt",
        ] {
            assert_eq!(
                args_of(&verify("app").test_requirement_file(path)),
                os(&["--verify", "-R", path, "--", "app"]),
                "{path}"
            );
        }
    }

    #[test]
    fn a_requirement_file_path_that_is_not_utf8_is_kept_byte_for_byte() {
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(b"req\xff\xfe.txt".to_vec());
        let args = args_of(&verify("app").test_requirement_file(&path));
        assert_eq!(args[1], OsString::from("-R"));
        assert_eq!(args[2], path);
    }

    #[test]
    fn requirement_text_and_requirement_file_share_one_slot_and_the_last_call_wins() {
        let text_then_file = verify("app")
            .test_requirement("anchor apple")
            .test_requirement_file("req.txt");
        assert_eq!(
            args_of(&text_then_file),
            os(&["--verify", "-R", "req.txt", "--", "app"])
        );

        let file_then_text = verify("app")
            .test_requirement_file("req.txt")
            .test_requirement("anchor apple");
        assert_eq!(
            args_of(&file_then_text),
            os(&["--verify", "-R=anchor apple", "--", "app"])
        );

        let file_twice = verify("app")
            .test_requirement_file("one.txt")
            .test_requirement_file("two.txt");
        assert_eq!(
            args_of(&file_twice),
            os(&["--verify", "-R", "two.txt", "--", "app"])
        );
    }

    #[test]
    fn a_requirement_file_of_stdin_fails_validation_and_names_its_setter() {
        let action = verify("app").test_requirement_file("-");
        let error = action.options.validate().unwrap_err();
        assert!(
            matches!(error, Error::StdioPath("test_requirement_file")),
            "got {error:?}"
        );
    }

    /// A later text requirement replaces the refused file path, so nothing
    /// is left that would read standard input.
    #[test]
    fn replacing_a_refused_requirement_file_makes_validation_pass() {
        let action = verify("app")
            .test_requirement_file("-")
            .test_requirement("anchor apple");
        assert!(action.options.validate().is_ok());
    }

    /// Only the file setter reads `-` as stdin: as text it is requirement
    /// source, and any other file name containing a dash is a plain path.
    #[test]
    fn requirements_other_than_a_lone_dash_file_pass_validation() {
        assert!(
            verify("app")
                .test_requirement("-")
                .options
                .validate()
                .is_ok()
        );
        for path in ["=-", "-x", "--", "./-", "-/req", " -", "- ", ""] {
            let action = verify("app").test_requirement_file(path);
            assert!(action.options.validate().is_ok(), "{path:?}");
        }
        assert!(verify("app").options.validate().is_ok());
    }

    #[test]
    fn a_dash_in_any_other_verify_option_passes_validation() {
        let action = verify("app")
            .detached("-")
            .architecture("-")
            .bundle_version("-");
        assert!(action.options.validate().is_ok());
    }

    #[test]
    fn option_values_with_spaces_stay_whole_arguments() {
        let action = verify("app")
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
            args_of(&verify(vec!["-a.app", "b c.app"]).deep(true)),
            os(&["--verify", "--deep", "--", "-a.app", "b c.app"])
        );
        assert_eq!(
            args_of(&verify(["a", "b"]).strict(Strict::All)),
            os(&["--verify", "--strict", "--", "a", "b"])
        );
    }

    #[test]
    fn there_is_nothing_to_validate() {
        let action = verify("app").test_requirement("-").detached("-").options;
        assert!(action.validate().is_ok());
    }

    #[test]
    fn no_option_is_a_shared_output() {
        let action = verify("app").detached("app.sig").options;
        assert_eq!(action.shared_output(), None);
    }

    #[test]
    fn the_output_is_one_unit_per_target_whatever_codesign_printed() {
        let action = verify("app").options;
        let targets = [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];

        assert_eq!(
            action
                .output(&targets, String::new(), String::new())
                .unwrap(),
            [(), (), ()]
        );
        let noisy = action.output_bytes(&targets[..1], b"noise".to_vec(), vec![0xff, 0xfe]);
        assert_eq!(noisy.unwrap(), [()]);
        assert!(
            action
                .output(&[], String::new(), String::new())
                .unwrap()
                .is_empty()
        );
    }

    /// A verification is read-only, so a batch is checked target by target
    /// unless the caller asks for one process.
    #[test]
    fn the_constructor_defaults_to_one_process_per_target_for_collections() {
        assert!(verify(vec!["a.app", "b.app"]).core.per_target);
        assert!(verify(["a.app", "b.app"]).core.per_target);
        assert!(verify(&["a.app", "b.app"][..]).core.per_target);
        assert!(!verify(vec!["a.app"]).per_target(false).core.per_target);
    }

    #[test]
    fn per_target_renders_no_argument() {
        let on = verify(vec!["app"]).per_target(true);
        let off = verify(vec!["app"]).per_target(false);
        assert_eq!(args_of(&on), os(&["--verify", "--", "app"]));
        assert_eq!(args_of(&off), os(&["--verify", "--", "app"]));
    }

    #[test]
    fn exit_one_means_the_signature_did_not_verify() {
        let action = verify("app").options;
        match action.failure(1, String::new(), "app: invalid signature".into()) {
            Error::Codesign(CodesignError::VerificationFailed {
                stdout,
                stderr,
                resources,
            }) => {
                assert_eq!(stdout, "");
                assert_eq!(stderr, "app: invalid signature");
                assert!(resources.is_empty());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn exit_one_carries_the_altered_resources_printed_on_stdout() {
        let action = verify("app").options;
        let stdout = "file modified: /x/app/r.txt\nfile added: /x/app/new.txt".to_string();
        match action.failure(
            1,
            stdout,
            "app: a sealed resource is missing or invalid".into(),
        ) {
            Error::Codesign(CodesignError::VerificationFailed {
                stdout,
                stderr,
                resources,
            }) => {
                assert_eq!(
                    stdout,
                    "file modified: /x/app/r.txt\nfile added: /x/app/new.txt"
                );
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
    fn exit_three_keeps_stdout_without_reading_resources() {
        let action = verify("app").options;
        let error = action.failure(3, "file modified: /x".into(), "no".into());
        assert!(matches!(
            error,
            Error::Codesign(CodesignError::RequirementUnsatisfied { ref stdout, ref stderr })
                if stdout == "file modified: /x" && stderr == "no"
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
        let action = verify("app").options;
        match action.failure(3, "file /x: ok".into(), "test-requirement: failed".into()) {
            Error::Codesign(CodesignError::RequirementUnsatisfied { stdout, stderr }) => {
                assert_eq!(stdout, "file /x: ok");
                assert_eq!(stderr, "test-requirement: failed");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn any_other_exit_code_is_the_generic_failure() {
        let action = verify("app").options;
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
        let action = verify("app")
            .test_requirement("anchor apple")
            .deep(true)
            .options;
        assert!(matches!(
            action.failure(1, String::new(), String::new()),
            Error::Codesign(CodesignError::VerificationFailed { .. })
        ));
        assert!(matches!(
            action.failure(3, String::new(), String::new()),
            Error::Codesign(CodesignError::RequirementUnsatisfied { .. })
        ));
    }
}
