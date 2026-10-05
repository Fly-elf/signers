//! Backend that runs Apple's `codesign` tool, so it works on macOS only.
//!
//! `codesign` ships with macOS in `/usr/bin` and is looked up on `PATH` each time an action runs.
//! Start at [`Codesign`].

mod action;
mod actions;
mod asynchronous;
mod runner;
mod types;

pub use action::Action;
pub use actions::{
    Display, ExtractCertificates, InternalRequirements, RemoveSignature, Sign, ValidateConstraint,
    Verify,
};
pub use asynchronous::Codesign;
pub use types::{
    Authority, CdHash, Certificate, CmsDigest, CodeDirectory, CodeHashes, Constraints,
    ExecutableSegment, Format, HashType, InfoPlist, Location, OsVersion, Platform,
    PreserveMetadata, Requirement, RequirementKind, RequirementsSummary, SealedResources,
    Signature, SignatureKind, SignatureSlot, SigningFlags, Strict, Timestamp,
};

/// The runner's side of its contract with an action, which no shipped action
/// can show from outside: both yield `()`, keep the default `failure` and
/// always return one output per target.
///
/// A stand-in action fills the gap. It runs the real `codesign`, read-only,
/// so these need macOS like the integration suite does.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::Path;

    use super::action::sealed::ToArgs;
    use super::*;

    /// Displays its targets, yielding the `Executable=<path>` line `codesign`
    /// prints for each, and answers the runner's hooks as told.
    #[derive(Debug, Clone, Default)]
    struct Probe {
        invalid: bool,
        shared_output: Option<&'static str>,
        drop_last_output: bool,
        unreadable: bool,
        file_list: bool,
    }

    impl super::action::sealed::SharedRun for Probe {}

    impl ToArgs for Probe {
        type Output = String;
        const PER_TARGET: bool = true;

        fn validate(&self) -> Result<()> {
            if self.invalid {
                Err(Error::StdioPath("probe"))
            } else {
                Ok(())
            }
        }

        fn shared_output(&self) -> Option<&'static str> {
            self.shared_output
        }

        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
            let list: &[&str] = if self.file_list {
                &["--file-list", "-"]
            } else {
                &[]
            };
            ["--display"]
                .into_iter()
                .chain(list.iter().copied())
                .chain(["--"])
                .map(OsStr::new)
                .chain(targets.iter().map(|target| target.as_os_str()))
                .map(Cow::Borrowed)
                .collect()
        }

        fn output(
            &self,
            _targets: &[PathBuf],
            _stdout: String,
            stderr: String,
        ) -> Result<Vec<String>> {
            if self.unreadable {
                return Err(Error::StdioPath("probe"));
            }
            let mut outputs: Vec<String> = stderr.lines().map(str::to_owned).collect();
            if self.drop_last_output {
                outputs.pop();
            }
            Ok(outputs)
        }

        fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
            CodesignError::UnexpectedOutput {
                detail: format!("probe saw exit {code} with stdout {stdout:?}: {stderr}"),
            }
            .into()
        }
    }

    /// Signed binaries every macOS install has, so displaying them succeeds.
    const SIGNED: [&str; 3] = ["/bin/ls", "/bin/cat", "/bin/echo"];
    const REPORTS: [&str; 3] = [
        "Executable=/bin/ls",
        "Executable=/bin/cat",
        "Executable=/bin/echo",
    ];

    /// A directory holding `names` as text files, which `codesign` refuses to
    /// display: there is no signature on them to report.
    fn unsigned(names: &[&str]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().expect("could not create a temporary directory");
        let paths = names
            .iter()
            .map(|name| {
                let path = dir.path().join(name);
                std::fs::write(&path, "not code\n").expect("could not write a target");
                path
            })
            .collect();
        (dir, paths)
    }

    fn unexpected_output(error: Error) -> String {
        match error {
            Error::Codesign(CodesignError::UnexpectedOutput { detail }) => detail,
            other => panic!("expected UnexpectedOutput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn outputs_follow_the_targets_in_order_and_in_shape() {
        let one: String = new(SIGNED[1], Probe::default()).await.unwrap();
        assert_eq!(one, REPORTS[1]);

        for per_target in [true, false] {
            let many: Vec<String> = new(SIGNED.to_vec(), Probe::default())
                .per_target(per_target)
                .await
                .unwrap();
            let array: [String; 3] = new(SIGNED, Probe::default())
                .per_target(per_target)
                .await
                .unwrap();

            assert_eq!(many, REPORTS, "per_target({per_target})");
            assert_eq!(array, REPORTS, "per_target({per_target})");
        }
    }

    #[tokio::test]
    async fn an_action_starts_from_its_own_per_target_default() {
        let (_dir, unsigned) = unsigned(&["notes.txt"]);
        let batch = vec![PathBuf::from(SIGNED[0]), unsigned[0].clone()];

        let builder = new(batch, Probe::default());
        assert!(builder.per_target);

        // One process per target without being asked: the failure is collected.
        let error = builder.await.unwrap_err();
        assert!(
            matches!(&error, Error::Batch(failures) if failures.len() == 1 && failures[0].0 == unsigned[0]),
            "got {error:?}",
        );
    }

    #[tokio::test]
    async fn a_failed_run_hands_the_hook_both_streams_trimmed() {
        let (_dir, unsigned) = unsigned(&["a.txt"]);
        let batch = vec![PathBuf::from(SIGNED[0]), unsigned[0].clone()];
        let probe = Probe {
            file_list: true,
            ..Probe::default()
        };

        let error = new(batch, probe).per_target(false).await.unwrap_err();

        assert_eq!(
            unexpected_output(error),
            format!(
                "probe saw exit 1 with stdout \"{0}\": Executable={0}\n{1}: code object is not signed at all",
                SIGNED[0],
                unsigned[0].display()
            )
        );
    }

    #[tokio::test]
    async fn a_failed_run_becomes_whatever_the_action_makes_of_it() {
        let (_dir, unsigned) = unsigned(&["a.txt", "b.txt"]);
        let expected = |path: &PathBuf| {
            format!(
                "probe saw exit 1 with stdout \"\": {}: code object is not signed at all",
                path.display()
            )
        };

        let error = new(&unsigned[0], Probe::default()).await.unwrap_err();
        assert_eq!(unexpected_output(error), expected(&unsigned[0]));

        // A one-element collection keeps the setter and, per target, collects.
        let error = new(vec![unsigned[0].clone()], Probe::default())
            .await
            .unwrap_err();
        let Error::Batch(failures) = error else {
            panic!("expected Batch, got {error:?}");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, unsigned[0]);

        let error = new(vec![unsigned[0].clone()], Probe::default())
            .per_target(false)
            .await
            .unwrap_err();
        assert_eq!(unexpected_output(error), expected(&unsigned[0]));

        // `codesign` stops at the first target it refuses, so one process for
        // both has only the first to complain about.
        let error = new(unsigned.clone(), Probe::default())
            .per_target(false)
            .await
            .unwrap_err();
        assert_eq!(unexpected_output(error), expected(&unsigned[0]));

        let error = new(unsigned.clone(), Probe::default()).await.unwrap_err();
        let Error::Batch(failures) = error else {
            panic!("expected Batch, got {error:?}");
        };
        let failures: Vec<(PathBuf, String)> = failures
            .into_iter()
            .map(|(path, error)| (path, unexpected_output(error)))
            .collect();
        assert_eq!(
            failures,
            [
                (unsigned[0].clone(), expected(&unsigned[0])),
                (unsigned[1].clone(), expected(&unsigned[1])),
            ]
        );
    }

    #[tokio::test]
    async fn an_output_count_other_than_the_target_count_is_unexpected_output() {
        let short = Probe {
            drop_last_output: true,
            ..Probe::default()
        };

        let one_process = new(SIGNED.to_vec(), short.clone())
            .per_target(false)
            .await
            .unwrap_err();
        let detail = unexpected_output(one_process);
        assert!(
            detail.contains('2') && detail.contains('3'),
            "the detail does not name both counts: {detail}"
        );

        let single = new(SIGNED[0], short.clone()).await.unwrap_err();
        let detail = unexpected_output(single);
        assert!(
            detail.contains('0') && detail.contains('1'),
            "the detail does not name both counts: {detail}"
        );

        // Per target, the mismatch is that target's failure like any other.
        let per_target = new(SIGNED, short).await.unwrap_err();
        let Error::Batch(failures) = per_target else {
            panic!("expected Batch, got {per_target:?}");
        };
        let failed: Vec<PathBuf> = failures
            .into_iter()
            .map(|(path, error)| {
                unexpected_output(error);
                path
            })
            .collect();
        assert_eq!(failed, SIGNED.map(PathBuf::from));
    }

    /// What `codesign` printed on a successful exit is the action's to read,
    /// and so is the verdict that it cannot be read.
    #[tokio::test]
    async fn an_error_from_the_output_hook_fails_the_run() {
        let unreadable = Probe {
            unreadable: true,
            ..Probe::default()
        };

        let single = new(SIGNED[0], unreadable.clone()).await.unwrap_err();
        assert!(
            matches!(single, Error::StdioPath("probe")),
            "got {single:?}"
        );

        let one_process = new(SIGNED.to_vec(), unreadable.clone())
            .per_target(false)
            .await
            .unwrap_err();
        assert!(
            matches!(one_process, Error::StdioPath("probe")),
            "got {one_process:?}"
        );

        let per_target = new(SIGNED.to_vec(), unreadable).await.unwrap_err();
        let Error::Batch(failures) = per_target else {
            panic!("expected Batch, got {per_target:?}");
        };
        let failed: Vec<PathBuf> = failures
            .into_iter()
            .map(|(path, error)| {
                assert!(matches!(error, Error::StdioPath("probe")), "got {error:?}");
                path
            })
            .collect();
        assert_eq!(failed, SIGNED.map(PathBuf::from));
    }

    #[tokio::test]
    async fn a_shared_output_is_refused_per_target_for_any_action() {
        let sharing = Probe {
            shared_output: Some("probe_file"),
            ..Probe::default()
        };

        let refused = new(SIGNED.to_vec(), sharing.clone()).await.unwrap_err();
        assert!(
            matches!(refused, Error::SharedOutputPerTarget("probe_file")),
            "got {refused:?}"
        );

        let refused = new(SIGNED, sharing.clone()).await.unwrap_err();
        assert!(
            matches!(refused, Error::SharedOutputPerTarget("probe_file")),
            "got {refused:?}"
        );

        let allowed = new(SIGNED.to_vec(), sharing.clone())
            .per_target(false)
            .await;
        assert_eq!(allowed.unwrap(), REPORTS);

        // `validate` still comes first.
        let invalid = Probe {
            invalid: true,
            ..sharing
        };
        let error = new(SIGNED.to_vec(), invalid).await.unwrap_err();
        assert!(matches!(error, Error::StdioPath("probe")), "got {error:?}");
    }

    /// One target is one process, so there is no second process to
    /// share an output with, even for an action that defaults to per target.
    #[tokio::test]
    async fn a_shared_output_is_not_refused_for_a_single_target() {
        let sharing = Probe {
            shared_output: Some("probe_file"),
            ..Probe::default()
        };

        let report = new(SIGNED[0], sharing.clone()).await.unwrap();
        assert_eq!(report, REPORTS[0]);

        let invalid = Probe {
            invalid: true,
            ..sharing
        };
        let error = new(SIGNED[0], invalid).await.unwrap_err();
        assert!(matches!(error, Error::StdioPath("probe")), "got {error:?}");
    }

    /// `A::PER_TARGET` is true for the probe, yet a single target never
    /// starts per target; the other shapes do.
    #[test]
    fn the_constructor_default_is_false_for_a_single_target_whatever_the_action() {
        const { assert!(Probe::PER_TARGET) };

        assert!(!new("a", Probe::default()).per_target);
        assert!(!new(String::from("a"), Probe::default()).per_target);
        assert!(!new(Path::new("a"), Probe::default()).per_target);
        assert!(!new(PathBuf::from("a"), Probe::default()).per_target);

        assert!(new(vec!["a"], Probe::default()).per_target);
        assert!(new(vec!["a", "b"], Probe::default()).per_target);
        assert!(new(&["a", "b"][..], Probe::default()).per_target);
        assert!(new(["a"], Probe::default()).per_target);
        assert!(new(["a", "b"], Probe::default()).per_target);
    }

    /// The setter is typed on the shape, not on the length.
    #[test]
    fn a_one_element_collection_keeps_the_per_target_setter() {
        let from_vec = new(vec!["a"], Probe::default()).per_target(false);
        assert!(!from_vec.per_target);
        let from_array = new(["a"], Probe::default()).per_target(false);
        assert!(!from_array.per_target);

        assert!(
            new(vec!["a"], Probe::default())
                .per_target(false)
                .per_target(true)
                .per_target
        );
    }
}
