use std::borrow::Cow;
use std::ffi::OsStr;

use super::*;
use crate::engine::tool::testing::Sh;
use crate::errors::Output;

/// A target named `head…` waits until `last` exists, giving up with exit 9 after about 10 s;
/// any other target creates its own file. A target whose name holds `fail` then exits 3; the
/// others print their own path.
const SCRIPT: &str = r#"
case "$2" in
  *head*)
    n=0
    until [ -e "$1" ]; do
      n=$((n + 1))
      [ "$n" -gt 200 ] && exit 9
      sleep 0.05
    done ;;
  *) : > "$2" ;;
esac
case "$2" in *fail*) exit 3 ;; esac
printf '%s\n' "$2"
"#;

/// Holds the head run until the run of `last` has started, so the head can only finish if a
/// slot freed behind it was handed on while it was still running.
struct Relay {
    last: PathBuf,
}

impl Operation for Relay {
    type Tool = Sh;
    type Output = String;
    const BATCH: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        [OsStr::new("-c"), OsStr::new(SCRIPT), OsStr::new("sh")]
            .into_iter()
            .chain([self.last.as_os_str()])
            .chain(targets.iter().map(|target| target.as_os_str()))
            .map(Cow::Borrowed)
            .collect()
    }

    fn output(
        &self,
        _: &[PathBuf],
        output: &Output,
    ) -> std::result::Result<Vec<String>, Rejection> {
        Ok(vec![output.stdout.clone()])
    }
}

/// `names` as paths in a fresh directory, with the last of them as the relay's `last`.
fn relay(names: &[&str]) -> (tempfile::TempDir, Relay, Vec<PathBuf>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let targets: Vec<PathBuf> = names.iter().map(|name| dir.path().join(name)).collect();
    let last = targets.last().expect("one target at least").clone();
    (dir, Relay { last }, targets)
}

#[tokio::test]
async fn a_slow_first_run_leaves_the_other_slot_to_every_run_behind_it() {
    let (_dir, op, targets) = relay(&["head", "a", "b", "c", "d"]);

    let outputs = run_per_target(&op, &targets, 2)
        .await
        .expect("the head sees the last run start");

    let expected: Vec<String> = targets.iter().map(|t| t.display().to_string()).collect();
    assert_eq!(outputs, expected);
}

#[tokio::test]
async fn failures_keep_the_input_order_when_later_runs_finish_first() {
    let (_dir, op, targets) = relay(&["head-fail", "a", "b-fail", "c", "d"]);

    let Error::Batch(failures) = run_per_target(&op, &targets, 2).await.unwrap_err() else {
        panic!("expected Batch");
    };

    let reported: Vec<(&PathBuf, Option<i32>)> = failures
        .iter()
        .map(|(target, error)| match error {
            Error::Process(ProcessError::Failed { output }) => (target, output.status.code()),
            other => panic!("expected Failed, got {other:?}"),
        })
        .collect();
    assert_eq!(reported, [(&targets[0], Some(3)), (&targets[2], Some(3))]);
}
