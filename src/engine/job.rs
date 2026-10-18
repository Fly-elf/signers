//! The state every action builder carries: its targets, and whether to run per target.

use std::marker::PhantomData;
use std::path::PathBuf;

use super::execute::execute;
use super::operation::Operation;
use super::runtime::Runtime;
use crate::target::{self, IntoTargets, Shape};

/// The targets of an action and how they are run, over target shape `S` and runtime `R`.
///
/// `S` fixes what a run yields; `R` how it is driven.
#[derive(Debug, Clone)]
pub struct Job<S, R> {
    pub(crate) targets: Vec<PathBuf>,
    pub(crate) batch: bool,
    marker: PhantomData<fn() -> (S, R)>,
}

impl<S, R> Job<S, R>
where
    S: Shape,
{
    /// Starts with the operation's batching default, except for a single target, which runs once.
    pub(crate) fn new<O, T>(target: T) -> Self
    where
        O: Operation,
        T: IntoTargets<Shape = S>,
    {
        Self {
            targets: target.into_targets(),
            batch: O::BATCH && !<S as target::sealed::Shape>::SINGLE,
            marker: PhantomData,
        }
    }
}

impl<S, R> Job<S, R>
where
    S: Shape,
    R: Runtime,
{
    /// Runs `op` over the targets and wraps the outputs in the shape `S`.
    pub(crate) fn run<O>(self, op: O) -> R::Output<S::Out<O::Output>>
    where
        O: Operation + Send + 'static,
    {
        R::drive::<O::Tool, _>(
            async move { execute(&op, &self.targets, self.batch).await.map(S::wrap) },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::path::Path;

    use super::*;
    use crate::engine::tool::testing::Sh;
    use crate::errors::Result;
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

                fn output(&self, targets: &[PathBuf], _: String, _: String) -> Result<Vec<()>> {
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
}
