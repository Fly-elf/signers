use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Path;

use super::*;
use crate::engine::operation::Rejection;
use crate::engine::tool::testing::Sh;
use crate::errors::Output;
use crate::target::IntoTargets;

/// An operation that asks for a run per target, like a read-only action.
struct Batching;
/// An operation that keeps one run for all targets, like a mutating action.
struct Serial;

macro_rules! stand_in {
    ($name:ident, $batch:expr) => {
        impl Operation for $name {
            type Tool = Sh;
            type Output = ();
            const BATCH: bool = $batch;

            fn to_args<'a>(&'a self, _: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
                Vec::new()
            }

            fn output(
                &self,
                targets: &[PathBuf],
                _: &Output,
            ) -> std::result::Result<Vec<()>, Rejection> {
                Ok(vec![(); targets.len()])
            }
        }
    };
}
stand_in!(Batching, true);
stand_in!(Serial, false);

fn job_for<O: Operation, T: IntoTargets>(target: T) -> Job<T::Shape, ()> {
    Job::new::<O, T>(target)
}

/// `O::BATCH` is true, yet a single target never starts as a batch; the other shapes do.
#[test]
fn batch_starts_from_the_action_unless_the_target_is_single() {
    const { assert!(Batching::BATCH) };

    assert!(!job_for::<Batching, _>("a").batch);
    assert!(!job_for::<Batching, _>(String::from("a")).batch);
    assert!(!job_for::<Batching, _>(Path::new("a")).batch);
    assert!(!job_for::<Batching, _>(PathBuf::from("a")).batch);

    assert!(job_for::<Batching, _>(vec!["a"]).batch);
    assert!(job_for::<Batching, _>(vec!["a", "b"]).batch);
    assert!(job_for::<Batching, _>(&["a", "b"][..]).batch);
    assert!(job_for::<Batching, _>(["a"]).batch);
    assert!(job_for::<Batching, _>(["a", "b"]).batch);
}

#[test]
fn batch_stays_off_for_every_shape_when_the_action_is_not_batch() {
    const { assert!(!Serial::BATCH) };

    assert!(!job_for::<Serial, _>("a").batch);
    assert!(!job_for::<Serial, _>(vec!["a", "b"]).batch);
    assert!(!job_for::<Serial, _>(&["a", "b"][..]).batch);
    assert!(!job_for::<Serial, _>(["a", "b"]).batch);
}

#[test]
fn the_targets_keep_their_order_duplicates_and_empty_entries() {
    let job = job_for::<Batching, _>(vec!["b", "", "a", "b"]);
    assert_eq!(job.targets, ["b", "", "a", "b"].map(PathBuf::from));
}
