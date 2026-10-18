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
