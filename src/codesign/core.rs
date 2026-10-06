use std::marker::PhantomData;
use std::path::PathBuf;

use crate::codesign::action::sealed::ToArgs;
use crate::target::{self, IntoTargets, Shape};

#[derive(Debug, Clone)]
pub struct Core<S, R> {
    pub(super) targets: Vec<PathBuf>,
    pub(super) per_target: bool,
    marker: PhantomData<fn() -> (S, R)>,
}

impl<S, R> Core<S, R>
where
    S: Shape,
{
    pub(super) fn new<O, T>(target: T) -> Self
    where
        O: ToArgs,
        T: IntoTargets<Shape = S>,
    {
        Self {
            targets: target.into_targets(),
            per_target: O::PER_TARGET && !<S as target::sealed::Shape>::SINGLE,
            marker: PhantomData,
        }
    }
}

#[cfg(feature = "blocking")]
impl<S, R> Core<S, R> {
    pub(super) fn into_runtime<R2>(self) -> Core<S, R2> {
        Core {
            targets: self.targets,
            per_target: self.per_target,
            marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::codesign::actions::{display::Options as Display, sign::Options as Sign};

    fn core_for<O: ToArgs, T: IntoTargets>(target: T) -> Core<T::Shape, ()> {
        Core::new::<O, T>(target)
    }

    /// `O::PER_TARGET` is true for display, yet a single target never
    /// starts per target; the other shapes do.
    #[test]
    fn per_target_starts_from_the_action_unless_the_target_is_single() {
        const { assert!(Display::PER_TARGET) };

        assert!(!core_for::<Display, _>("a").per_target);
        assert!(!core_for::<Display, _>(String::from("a")).per_target);
        assert!(!core_for::<Display, _>(Path::new("a")).per_target);
        assert!(!core_for::<Display, _>(PathBuf::from("a")).per_target);

        assert!(core_for::<Display, _>(vec!["a"]).per_target);
        assert!(core_for::<Display, _>(vec!["a", "b"]).per_target);
        assert!(core_for::<Display, _>(&["a", "b"][..]).per_target);
        assert!(core_for::<Display, _>(["a"]).per_target);
        assert!(core_for::<Display, _>(["a", "b"]).per_target);
    }

    #[test]
    fn per_target_stays_off_for_every_shape_when_the_action_is_not_per_target() {
        const { assert!(!Sign::PER_TARGET) };

        assert!(!core_for::<Sign, _>("a").per_target);
        assert!(!core_for::<Sign, _>(vec!["a", "b"]).per_target);
        assert!(!core_for::<Sign, _>(&["a", "b"][..]).per_target);
        assert!(!core_for::<Sign, _>(["a", "b"]).per_target);
    }

    #[test]
    fn the_targets_keep_their_order_duplicates_and_empty_entries() {
        let core = core_for::<Display, _>(vec!["b", "", "a", "b"]);
        assert_eq!(core.targets, ["b", "", "a", "b"].map(PathBuf::from));
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn changing_the_runtime_keeps_targets_and_per_target() {
        for per_target in [true, false] {
            let mut core = core_for::<Display, _>(vec!["a", "", "a"]);
            core.per_target = per_target;

            let moved: Core<_, u8> = core.into_runtime();

            assert_eq!(moved.targets, ["a", "", "a"].map(PathBuf::from));
            assert_eq!(moved.per_target, per_target);
        }
    }
}
