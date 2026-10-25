use std::borrow::Cow;
use std::ffi::OsStr;

use super::*;
use crate::engine::tool::testing::Sh;
use crate::errors::Output;

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

    fn output(&self, targets: &[PathBuf], _: &Output) -> std::result::Result<Vec<()>, Rejection> {
        match self.0 {
            Reads::Unreadable => Err(Rejection::Unreadable("not a report".into())),
            Reads::OneTooFew => Ok(vec![(); targets.len() - 1]),
            Reads::Other => Err(Error::NoTargets.into()),
            Reads::Fine => Ok(vec![(); targets.len()]),
        }
    }
}

async fn run(reads: Reads) -> std::result::Result<Vec<()>, RunError> {
    run_once(&Printer(reads), &[PathBuf::from("a"), PathBuf::from("b")]).await
}

fn unexpected_output(error: RunError) -> (String, String, String) {
    match error.into_error() {
        Error::Process(ProcessError::UnexpectedOutput { detail, output }) => {
            assert_eq!(output.program, "sh");
            assert!(output.status.success());
            (detail, output.stdout, output.stderr)
        }
        other => panic!("expected UnexpectedOutput, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unreadable_output_carries_the_output_of_the_run() {
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
async fn an_output_count_mismatch_carries_the_output_of_the_run() {
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
