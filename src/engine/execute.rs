//! The checks that come before a run, and the run itself: once over all targets or once per
//! target, concurrently.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use futures_util::{FutureExt, StreamExt};

use super::operation::{Operation, Rejection};
use super::process::{RunError, exit, spawn};
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
    run_per_target(op, targets, cap).await
}

/// Runs the tool once per target, `cap` at a time. A finished run frees its slot at once, whatever
/// the runs before it are doing; the results still come back in input order.
async fn run_per_target<O: Operation>(
    op: &O,
    targets: &[PathBuf],
    cap: usize,
) -> Result<Vec<O::Output>> {
    // The runs are built before they are buffered: mapping the stream
    // itself doesn't compile inside a `Send` boxed future (higher-ranked
    // lifetime limitation).
    let runs: Vec<_> = targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            run_once(op, std::slice::from_ref(target)).map(move |result| (index, result))
        })
        .collect();
    let mut results = futures_util::stream::iter(runs)
        .buffer_unordered(cap)
        .collect::<Vec<_>>()
        .await;
    results.sort_unstable_by_key(|(index, _)| *index);

    collect(
        targets,
        results.into_iter().map(|(_, result)| result).collect(),
    )
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
    let output = spawn::<O::Tool>(&op.to_args(targets)).await?;
    let output = exit::<O::Tool>(output, |code, output| op.failure(code, output))
        .map_err(RunError::Failed)?;
    let detail = match op.output(targets, &output) {
        Ok(outputs) if outputs.len() == targets.len() => return Ok(outputs),
        Ok(outputs) => format!("{} outputs for {} targets", outputs.len(), targets.len()),
        Err(Rejection::Unreadable(detail)) => detail,
        Err(Rejection::Error(error)) => return Err(RunError::Failed(error)),
    };
    Err(RunError::Failed(O::Tool::error(
        ProcessError::UnexpectedOutput { detail, output },
    )))
}

#[cfg(test)]
#[path = "unit_tests/execute_collect.rs"]
mod execute_collect;

#[cfg(test)]
#[path = "unit_tests/execute_stream.rs"]
mod execute_stream;

#[cfg(test)]
#[path = "unit_tests/execute_per_target.rs"]
mod execute_per_target;

/// The runner's side of its contract with an operation, which no shipped action
/// can show from outside: both yield `()`, keep the default `failure` and
/// always return one output per target.
///
/// A stand-in operation fills the gap. It runs the real `codesign`, read-only,
/// so these need macOS like the integration suite does.
#[cfg(all(test, target_os = "macos"))]
#[path = "unit_tests/execute.rs"]
mod tests;
