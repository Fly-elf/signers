//! The checks that come before a run, and the run itself: once over all targets or once per
//! target, concurrently.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use futures_util::StreamExt;

use super::operation::Operation;
use super::process::{RunError, spawn};
use super::tool::Tool;
use crate::errors::{Error, ProcessError, Result};

/// Fails with [`Error::PathNotFound`] or [`Error::PathAccess`] unless `path` exists.
pub(crate) async fn check_exists(path: &Path) -> Result<()> {
    match tokio::fs::try_exists(path).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::PathNotFound(path.to_owned())),
        Err(source) => Err(Error::PathAccess {
            path: path.to_owned(),
            source,
        }),
    }
}

/// Checks the options and targets, then runs the tool once over all targets or, with `batch`, once
/// per target.
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
    tracing::debug!(target: "signers", program = O::Tool::PROGRAM, runs = targets.len(), concurrency = cap, "batch");
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

    collect(targets, results)
}

/// Folds the runs of a batch into the outputs, or into the failures of every target.
fn collect<T>(
    targets: &[PathBuf],
    results: Vec<std::result::Result<Vec<T>, RunError>>,
) -> Result<Vec<T>> {
    // Nothing started: the tool itself is unusable, which isn't about any target.
    if results
        .iter()
        .all(|result| matches!(result, Err(RunError::Unstarted(_))))
    {
        return match results.into_iter().next() {
            Some(Err(error)) => Err(error.into_error()),
            _ => Ok(Vec::new()),
        };
    }

    let mut outputs = Vec::with_capacity(targets.len());
    let mut failures = Vec::new();
    for (target, result) in targets.iter().zip(results) {
        match result {
            Ok(output) => outputs.extend(output),
            Err(error) => failures.push((target.clone(), error.into_error())),
        }
    }
    if failures.is_empty() {
        Ok(outputs)
    } else {
        Err(Error::Batch(failures))
    }
}

/// Runs the tool once over `targets` and turns its exit into outputs or an error.
async fn run_once<O: Operation>(
    op: &O,
    targets: &[PathBuf],
) -> std::result::Result<Vec<O::Output>, RunError> {
    let exit = spawn::<O::Tool>(&op.to_args(targets)).await?;
    let (stdout, stderr) = exit
        .success::<O::Tool>(|code, stdout, stderr| op.failure(code, stdout, stderr))
        .map_err(RunError::Failed)?;
    let outputs = match op.output(targets, stdout.clone(), stderr.clone()) {
        Ok(outputs) => outputs,
        Err(Error::Process(ProcessError::UnexpectedOutput {
            program, detail, ..
        })) => {
            return Err(RunError::Failed(Error::Process(
                ProcessError::UnexpectedOutput {
                    program,
                    detail,
                    stdout,
                    stderr,
                },
            )));
        }
        Err(other) => return Err(RunError::Failed(other)),
    };
    if outputs.len() != targets.len() {
        return Err(RunError::Failed(O::Tool::error(
            ProcessError::UnexpectedOutput {
                program: O::Tool::PROGRAM,
                detail: format!("{} outputs for {} targets", outputs.len(), targets.len()),
                stdout,
                stderr,
            },
        )));
    }
    Ok(outputs)
}

#[cfg(test)]
mod collect_tests {
    use std::io;

    use super::*;

    type Runs = Vec<std::result::Result<Vec<u8>, RunError>>;

    fn paths(count: usize) -> Vec<PathBuf> {
        (0..count).map(|i| PathBuf::from(format!("t{i}"))).collect()
    }

    fn unstarted(program: &'static str) -> RunError {
        RunError::Unstarted(Error::Process(ProcessError::NotFound { program }))
    }

    fn failed(program: &'static str) -> RunError {
        RunError::Failed(Error::Process(ProcessError::NotFound { program }))
    }

    fn program(error: &Error) -> &'static str {
        match error {
            Error::Process(ProcessError::NotFound { program }) => program,
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn all_runs_unstarted_report_the_first_error_alone() {
        let results: Runs = vec![
            Err(unstarted("first")),
            Err(unstarted("second")),
            Err(unstarted("third")),
        ];

        let error = collect(&paths(3), results).unwrap_err();

        assert_eq!(program(&error), "first");
    }

    #[test]
    fn a_single_unstarted_run_reports_its_error_alone() {
        let error = collect::<u8>(&paths(1), vec![Err(unstarted("only"))]).unwrap_err();

        assert_eq!(program(&error), "only");
    }

    #[test]
    fn unstarted_runs_next_to_ok_runs_are_collected_per_target() {
        let results: Runs = vec![
            Ok(vec![1]),
            Err(unstarted("a")),
            Ok(vec![2]),
            Err(unstarted("b")),
        ];
        let targets = paths(4);

        let Error::Batch(failures) = collect(&targets, results).unwrap_err() else {
            panic!("expected Batch");
        };

        let reported: Vec<(&PathBuf, &str)> = failures
            .iter()
            .map(|(target, error)| (target, program(error)))
            .collect();
        assert_eq!(reported, [(&targets[1], "a"), (&targets[3], "b")]);
    }

    #[test]
    fn unstarted_and_failed_runs_are_all_collected_in_input_order() {
        let results: Runs = vec![
            Err(failed("a")),
            Ok(vec![1]),
            Err(unstarted("b")),
            Err(failed("c")),
            Err(unstarted("d")),
        ];
        let targets = paths(5);

        let Error::Batch(failures) = collect(&targets, results).unwrap_err() else {
            panic!("expected Batch");
        };

        let reported: Vec<(&PathBuf, &str)> = failures
            .iter()
            .map(|(target, error)| (target, program(error)))
            .collect();
        assert_eq!(
            reported,
            [
                (&targets[0], "a"),
                (&targets[2], "b"),
                (&targets[3], "c"),
                (&targets[4], "d"),
            ]
        );
    }

    #[test]
    fn failed_runs_without_any_unstarted_one_are_collected_too() {
        let results: Runs = vec![Err(failed("a")), Err(failed("b"))];
        let targets = paths(2);

        let Error::Batch(failures) = collect(&targets, results).unwrap_err() else {
            panic!("expected Batch");
        };

        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].0, targets[0]);
        assert_eq!(failures[1].0, targets[1]);
    }

    #[test]
    fn a_lone_failed_run_is_a_batch_of_one() {
        let targets = paths(1);

        let error = collect::<u8>(&targets, vec![Err(failed("a"))]).unwrap_err();

        assert!(matches!(&error, Error::Batch(failures) if failures.len() == 1));
    }

    #[test]
    fn all_ok_runs_yield_their_outputs_in_order() {
        let results: Runs = vec![Ok(vec![1]), Ok(vec![2]), Ok(vec![3])];

        assert_eq!(collect(&paths(3), results).unwrap(), [1, 2, 3]);
    }

    #[test]
    fn an_unstarted_run_keeps_its_own_error_inside_the_batch() {
        let source = io::Error::from(io::ErrorKind::PermissionDenied);
        let results: Runs = vec![
            Ok(vec![1]),
            Err(RunError::Unstarted(Error::Process(ProcessError::Spawn {
                program: "tool",
                source,
            }))),
        ];

        let Error::Batch(failures) = collect(&paths(2), results).unwrap_err() else {
            panic!("expected Batch");
        };

        assert!(matches!(
            &failures[0].1,
            Error::Process(ProcessError::Spawn { program: "tool", source })
                if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }
}

#[cfg(test)]
mod stream_tests {
    use std::borrow::Cow;
    use std::ffi::OsStr;

    use super::*;
    use crate::engine::tool::testing::Sh;

    /// How the stand-in operation answers once `sh` has printed its two streams.
    #[derive(Clone, Copy)]
    enum Reads {
        Unreadable,
        OneTooFew,
        Other,
        Fine,
    }

    /// Runs `sh` printing `out` on stdout and `err` on stderr, both padded with whitespace.
    struct Printer(Reads);

    impl Operation for Printer {
        type Tool = Sh;
        type Output = ();
        const BATCH: bool = false;

        fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
            ["-c", "printf '  out\n'; printf 'err  \n' >&2", "sh"]
                .into_iter()
                .map(OsStr::new)
                .chain(targets.iter().map(|target| target.as_os_str()))
                .map(Cow::Borrowed)
                .collect()
        }

        fn output(&self, targets: &[PathBuf], _: String, _: String) -> Result<Vec<()>> {
            match self.0 {
                Reads::Unreadable => Err(Error::Process(ProcessError::UnexpectedOutput {
                    program: "sh",
                    detail: "not a report".into(),
                    stdout: String::new(),
                    stderr: String::new(),
                })),
                Reads::OneTooFew => Ok(vec![(); targets.len() - 1]),
                Reads::Other => Err(Error::NoTargets),
                Reads::Fine => Ok(vec![(); targets.len()]),
            }
        }
    }

    async fn run(reads: Reads) -> std::result::Result<Vec<()>, RunError> {
        run_once(&Printer(reads), &[PathBuf::from("a"), PathBuf::from("b")]).await
    }

    fn unexpected_output(error: RunError) -> (String, String, String) {
        match error.into_error() {
            Error::Process(ProcessError::UnexpectedOutput {
                detail,
                stdout,
                stderr,
                ..
            }) => (detail, stdout, stderr),
            other => panic!("expected UnexpectedOutput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unreadable_output_carries_the_streams_of_the_run() {
        let error = run(Reads::Unreadable).await.expect_err("must fail");

        assert!(matches!(error, RunError::Failed(_)));
        assert_eq!(
            unexpected_output(error),
            (
                "not a report".to_owned(),
                "out".to_owned(),
                "err".to_owned()
            )
        );
    }

    #[tokio::test]
    async fn an_output_count_mismatch_carries_the_streams_of_the_run() {
        let error = run(Reads::OneTooFew).await.expect_err("must fail");

        assert!(matches!(error, RunError::Failed(_)));
        assert_eq!(
            unexpected_output(error),
            (
                "1 outputs for 2 targets".to_owned(),
                "out".to_owned(),
                "err".to_owned()
            )
        );
    }

    #[tokio::test]
    async fn another_error_from_the_output_hook_passes_through_untouched() {
        let error = run(Reads::Other).await.expect_err("must fail");

        assert!(matches!(error, RunError::Failed(Error::NoTargets)));
    }

    #[tokio::test]
    async fn a_readable_output_yields_one_output_per_target() {
        assert_eq!(run(Reads::Fine).await.ok().unwrap().len(), 2);
    }
}

/// The runner's side of its contract with an operation, which no shipped action
/// can show from outside: both yield `()`, keep the default `failure` and
/// always return one output per target.
///
/// A stand-in operation fills the gap. It runs the real `codesign`, read-only,
/// so these need macOS like the integration suite does.
#[cfg(all(test, target_os = "macos"))]
#[path = "unit_tests/execute.rs"]
mod tests;
