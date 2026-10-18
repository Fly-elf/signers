use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use futures_util::StreamExt;

use super::operation::Operation;
use super::process::{RunError, spawn};
use super::tool::Tool;
use crate::errors::{Error, ProcessError, Result};

pub(crate) async fn check_exists(path: &Path) -> Result<()> {
    match tokio::fs::try_exists(path).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::TargetNotFound(path.to_owned())),
        Err(source) => Err(Error::TargetAccess {
            path: path.to_owned(),
            source,
        }),
    }
}

/// Checks the options and targets, then runs `codesign` once over all targets or once per target.
pub(crate) async fn execute<O: Operation>(
    op: &O,
    targets: &[PathBuf],
    batch: bool,
) -> Result<Vec<O::Output>> {
    op.validate()?;
    if batch && let Some(option) = op.shared_output() {
        return Err(Error::SharedOutputPerTarget(option));
    }

    if targets.is_empty() {
        return Err(Error::NoTargets);
    }
    if let Some(index) = targets.iter().position(|t| t.as_os_str().is_empty()) {
        return Err(Error::EmptyTarget(index));
    }
    for target in targets {
        check_exists(target).await?;
    }

    // One run over all targets, and its error stays plain.
    if !batch {
        return run_once(op, targets).await.map_err(RunError::into_error);
    }

    let cap = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    // The runs are built before they are buffered: mapping the stream
    // itself doesn't compile inside a `Send` boxed future (higher-ranked
    // lifetime limitation).
    let runs: Vec<_> = targets
        .iter()
        .map(|target| run_once(op, std::slice::from_ref(target)))
        .collect();
    let results: Vec<std::result::Result<Vec<O::Output>, RunError>> =
        futures_util::stream::iter(runs)
            .buffered(cap)
            .collect()
            .await;

    let mut outputs = Vec::with_capacity(targets.len());
    let mut failures = Vec::new();
    for (target, result) in targets.iter().zip(results) {
        match result {
            Ok(output) => outputs.extend(output),
            // The tool itself couldn't start: that isn't about this target.
            Err(RunError::Unstarted(error)) => return Err(error),
            Err(RunError::Failed(error)) => failures.push((target.clone(), error)),
        }
    }
    if failures.is_empty() {
        Ok(outputs)
    } else {
        Err(Error::Batch(failures))
    }
}

/// Runs one `codesign` over `targets` and turns its exit into outputs or an error.
async fn run_once<O: Operation>(
    op: &O,
    targets: &[PathBuf],
) -> std::result::Result<Vec<O::Output>, RunError> {
    let exit = spawn::<O::Tool>(&op.to_args(targets)).await?;
    let outputs = exit
        .success::<O::Tool>(|code, stdout, stderr| op.failure(code, stdout, stderr))
        .and_then(|(stdout, stderr)| op.output(targets, stdout, stderr))
        .map_err(RunError::Failed)?;
    if outputs.len() != targets.len() {
        return Err(RunError::Failed(O::Tool::error(
            ProcessError::UnexpectedOutput {
                program: O::Tool::PROGRAM,
                detail: format!("{} outputs for {} targets", outputs.len(), targets.len()),
            },
        )));
    }
    Ok(outputs)
}

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

    use super::*;
    use crate::engine::runtime::RunFuture;
    use crate::engine::tool::testing::Real;
    use crate::engine::{Async, Job, SharedRun};
    use crate::target::{IntoTargets, Shape};

    /// The run of a stand-in action, built on `Job` as the real actions are.
    struct Run<S> {
        job: Job<S, Async>,
        probe: Probe,
    }

    impl<S: Shape> Run<S> {
        fn per_target(mut self, per_target: bool) -> Self {
            self.job.batch = per_target;
            self
        }
    }

    impl<S: Shape> IntoFuture for Run<S> {
        type Output = Result<S::Out<String>>;
        type IntoFuture = RunFuture<S::Out<String>>;

        fn into_future(self) -> Self::IntoFuture {
            self.job.run(self.probe)
        }
    }

    fn new<T: IntoTargets>(target: T, probe: Probe) -> Run<T::Shape> {
        Run {
            job: Job::new::<Probe, T>(target),
            probe,
        }
    }

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

    impl SharedRun for Probe {}

    impl Operation for Probe {
        type Tool = Real;
        type Output = String;
        const BATCH: bool = true;

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
            ProcessError::UnexpectedOutput {
                program: "codesign",
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
            Error::Process(ProcessError::UnexpectedOutput { detail, .. }) => detail,
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
        assert!(builder.job.batch);

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

    /// Targets that exist, run by a tool that doesn't.
    #[derive(Debug, Clone, Copy)]
    struct Gone;

    impl Operation for Gone {
        type Tool = crate::engine::tool::testing::Missing;
        type Output = ();
        const BATCH: bool = true;

        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
            targets
                .iter()
                .map(|t| Cow::Borrowed(t.as_os_str()))
                .collect()
        }

        fn output(&self, targets: &[PathBuf], _: String, _: String) -> Result<Vec<()>> {
            Ok(vec![(); targets.len()])
        }
    }

    /// A tool that can't start says nothing about any target, so a batch reports it once,
    /// as itself, rather than once per target inside `Error::Batch`.
    #[tokio::test]
    async fn a_batch_stops_on_a_tool_that_cannot_start() {
        let targets = SIGNED.map(PathBuf::from);

        for batch in [true, false] {
            let error = execute(&Gone, &targets, batch).await.unwrap_err();

            assert!(
                matches!(
                    &error,
                    Error::Process(ProcessError::NotFound { program })
                        if *program == "signers-no-such-program"
                ),
                "batch({batch}): got {error:?}",
            );
        }
    }

    #[tokio::test]
    async fn check_exists_names_the_missing_path() {
        let error = check_exists(Path::new("/definitely/not/here"))
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::TargetNotFound(path) if path == Path::new("/definitely/not/here")),
            "got {error:?}",
        );
        check_exists(Path::new(SIGNED[0])).await.unwrap();
    }
}
