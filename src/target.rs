//! The paths an action runs on, and the shape of what `.await` returns for them.
//!
//! Only [`IntoTargets`] is public, re-exported at the crate root. The shapes appear in public
//! signatures but can't be named from outside, so their behaviour is documented in prose on
//! `IntoTargets`, the `codesign` module and `per_target`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Crate-only items of the public traits, where other crates can't reach them.
pub(crate) mod sealed {
    use std::path::PathBuf;

    /// Crate-only side of [`Shape`](super::Shape); also seals it.
    pub trait Shape {
        /// Whether this is [`One`](super::One), the shape of a single target.
        const SINGLE: bool;

        /// Gives `outputs`, one per target in order, this shape.
        ///
        /// The runner always passes exactly one output per target.
        ///
        /// # Panics
        ///
        /// [`One`](super::One) panics on an empty `Vec`, and [`Array<N>`](super::Array) on a
        /// `Vec` whose length isn't `N`.
        fn wrap<T: Send + 'static>(outputs: Vec<T>) -> <Self as super::Shape>::Out<T>
        where
            Self: super::Shape;
    }

    /// Crate-only side of [`IntoTargets`](super::IntoTargets); also seals it.
    pub trait IntoTargets {
        /// Converts `self` into the target paths, in order, empty ones included.
        ///
        /// `vec!["b", "", "a"]` gives `["b", "", "a"]` as `PathBuf`s.
        fn into_targets(self) -> Vec<PathBuf>;
    }
}

/// How the outputs of `.await` follow the targets: one value, a `Vec` or an array.
///
/// Picked by the target type through [`IntoTargets::Shape`]. Sealed: [`One`], [`Many`] and
/// [`Array`] are the only shapes, uninhabited and used only as type parameters.
pub trait Shape: sealed::Shape + Send + 'static {
    /// What `.await` yields when each target yields a `T`: `T`, `Vec<T>` or `[T; N]`.
    type Out<T: Send + 'static>: Send + 'static;
}

/// The shape of a single target: `.await` yields one output.
#[derive(Debug, Clone, Copy)]
pub enum One {}

/// The shape of a `Vec` or slice of targets: `.await` yields a `Vec` of outputs.
#[derive(Debug, Clone, Copy)]
pub enum Many {}

/// The shape of an array of `N` targets: `.await` yields an array of `N` outputs.
#[derive(Debug, Clone, Copy)]
pub enum Array<const N: usize> {}

impl Shape for One {
    type Out<T: Send + 'static> = T;
}

impl Shape for Many {
    type Out<T: Send + 'static> = Vec<T>;
}

impl<const N: usize> Shape for Array<N> {
    type Out<T: Send + 'static> = [T; N];
}

impl sealed::Shape for One {
    const SINGLE: bool = true;

    fn wrap<T: Send + 'static>(mut outputs: Vec<T>) -> T {
        match outputs.pop() {
            Some(output) => output,
            None => unreachable!("a single target always yields one output"),
        }
    }
}

impl sealed::Shape for Many {
    const SINGLE: bool = false;

    fn wrap<T: Send + 'static>(outputs: Vec<T>) -> Vec<T> {
        outputs
    }
}

impl<const N: usize> sealed::Shape for Array<N> {
    const SINGLE: bool = false;

    fn wrap<T: Send + 'static>(outputs: Vec<T>) -> <Self as Shape>::Out<T> {
        match outputs.try_into() {
            Ok(outputs) => outputs,
            Err(_) => unreachable!("an array of N targets always yields N outputs"),
        }
    }
}

/// The shapes of a collection of targets, [`Many`] and [`Array`], whatever its length.
///
/// Bounds [`per_target`](crate::codesign::Sign::per_target), which has nothing to split on a
/// single target.
pub trait Multi: Shape {}

impl Multi for Many {}
impl<const N: usize> Multi for Array<N> {}

/// The targets of an action: one path, or a `Vec`, slice or array of paths.
///
/// Every action constructor takes one. The implementors below are the path types it accepts,
/// on their own or in a `Vec`, slice or array.
///
/// The target type also fixes what `.await`, or the blocking `.run()`, returns, one output per
/// target in input order: the output itself for a single path, a `Vec` for a `Vec` or slice, an
/// array of `N` for an array of `N`. Only a `Vec`, slice or array has
/// [`per_target`](crate::codesign::Sign::per_target), even with one element.
///
/// Every path is kept: order and duplicates too, and each path reaches `codesign` byte for byte,
/// non-UTF-8 included. A path starting with `-` is never read as an option. `.await` refuses an
/// empty path with [`Error::EmptyTarget`](crate::Error::EmptyTarget), and no path at all with
/// [`Error::NoTargets`](crate::Error::NoTargets).
///
/// The trait is sealed and has nothing to call: the actions convert their targets themselves.
/// To pass a type of your own, convert it to one of the path types first.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use std::path::PathBuf;
///
/// use signers::codesign;
///
/// let built = PathBuf::from("target/release/mytool");
/// let one: () = codesign::sign_adhoc(&built).await?;
/// let all: Vec<()> = codesign::sign_adhoc(vec!["liba.dylib", "libb.dylib"]).await?;
/// let [a, b]: [(); 2] = codesign::sign_adhoc(["liba.dylib", "libb.dylib"]).await?;
/// # Ok(()) }
/// ```
///
/// A reference to an array is neither an array nor a slice, so it doesn't compile. Pass the
/// array by value, or use `vec![…]`:
///
/// ```compile_fail,E0277
/// # use signers::codesign;
/// codesign::sign_adhoc(&["liba.dylib", "libb.dylib"]);
/// ```
///
/// Other crates can't implement it:
///
/// ```compile_fail,E0277
/// struct Bundle;
///
/// impl signers::IntoTargets for Bundle {
/// #   type Shape = <&'static str as signers::IntoTargets>::Shape;
/// }
/// ```
///
/// Nor convert targets through it:
///
/// ```compile_fail,E0599
/// use signers::IntoTargets;
///
/// let paths = "mytool".into_targets();
/// ```
pub trait IntoTargets: sealed::IntoTargets {
    /// Fixes what `.await` returns: `One` for a single path, `Many` for a `Vec` or slice,
    /// `Array<N>` for an array of `N`. Hidden: users never name it.
    #[doc(hidden)]
    type Shape: Shape;
}

/// Implements [`IntoTargets`] for single-path types, with shape [`One`].
macro_rules! impl_target {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl IntoTargets for $ty {
                type Shape = One;
            }

            impl sealed::IntoTargets for $ty {
                fn into_targets(self) -> Vec<PathBuf> {
                    vec![self.into()]
                }
            }
        )+
    };
}

impl_target!(&str, String, OsString, &Path, PathBuf, &PathBuf);

impl<T: Into<PathBuf>> IntoTargets for Vec<T> {
    type Shape = Many;
}

impl<T: Into<PathBuf>> sealed::IntoTargets for Vec<T> {
    fn into_targets(self) -> Vec<PathBuf> {
        self.into_iter().map(Into::into).collect()
    }
}

impl<T: Into<PathBuf> + Clone> IntoTargets for &[T] {
    type Shape = Many;
}

impl<T: Into<PathBuf> + Clone> sealed::IntoTargets for &[T] {
    fn into_targets(self) -> Vec<PathBuf> {
        self.iter().cloned().map(Into::into).collect()
    }
}

impl<T: Into<PathBuf>, const N: usize> IntoTargets for [T; N] {
    type Shape = Array<N>;
}

impl<T: Into<PathBuf>, const N: usize> sealed::IntoTargets for [T; N] {
    fn into_targets(self) -> Vec<PathBuf> {
        self.into_iter().map(Into::into).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::sealed::{IntoTargets as _, Shape as _};
    use super::*;

    #[test]
    fn single_targets() {
        let expected = vec![PathBuf::from("app")];
        assert_eq!("app".into_targets(), expected);
        assert_eq!(String::from("app").into_targets(), expected);
        assert_eq!(OsString::from("app").into_targets(), expected);
        assert_eq!(Path::new("app").into_targets(), expected);
        assert_eq!(PathBuf::from("app").into_targets(), expected);

        // Parenthesised, or the by-value `PathBuf` impl wins the method lookup.
        let owned = PathBuf::from("app");
        assert_eq!((&owned).into_targets(), expected);
        assert_eq!(
            owned,
            PathBuf::from("app"),
            "the borrowed target was consumed"
        );
    }

    #[test]
    fn collection_targets() {
        let expected = vec![PathBuf::from("a"), PathBuf::from("b")];
        assert_eq!(vec!["a", "b"].into_targets(), expected);
        assert_eq!(
            vec![PathBuf::from("a"), PathBuf::from("b")].into_targets(),
            expected
        );

        let slice: &[&str] = &["a", "b"];
        assert_eq!(slice.into_targets(), expected);

        let paths: &[PathBuf] = &expected;
        assert_eq!(paths.into_targets(), expected);
    }

    /// Order is what pairs a target with its diagnostics, and a repeated target
    /// is the caller's business — neither is ours to tidy up.
    #[test]
    fn collections_keep_their_order_and_their_duplicates() {
        let expected = vec![PathBuf::from("b"), PathBuf::from("a"), PathBuf::from("b")];
        assert_eq!(vec!["b", "a", "b"].into_targets(), expected);
        assert_eq!(["b", "a", "b"].into_targets(), expected);
    }

    /// A path is bytes, not text: anything that round-trips through `PathBuf`
    /// has to survive, or the target reaching `codesign` is not the one asked
    /// for.
    #[cfg(unix)]
    #[test]
    fn targets_that_are_not_utf8_survive_unchanged() {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(vec![b'a', 0xff, b'b']);
        let expected = vec![PathBuf::from(&raw)];
        assert_eq!(raw.clone().into_targets(), expected);
        assert_eq!(vec![PathBuf::from(&raw)].into_targets(), expected);
    }

    /// An empty path is still a target: dropping it would leave fewer outputs
    /// than inputs. Refusing it is the runner's job (`Error::EmptyTarget`).
    #[test]
    fn an_empty_single_target_is_kept() {
        let expected = vec![PathBuf::new()];
        assert_eq!("".into_targets(), expected);
        assert_eq!(String::new().into_targets(), expected);
        assert_eq!(OsString::new().into_targets(), expected);
        assert_eq!(Path::new("").into_targets(), expected);
        assert_eq!(PathBuf::new().into_targets(), expected);
        assert_eq!((&PathBuf::new()).into_targets(), expected);
    }

    #[test]
    fn empty_entries_keep_their_place_in_collections() {
        let expected = vec![PathBuf::new(), PathBuf::from("a"), PathBuf::new()];
        assert_eq!(vec!["", "a", ""].into_targets(), expected);

        let slice: &[&str] = &["", "a", ""];
        assert_eq!(slice.into_targets(), expected);

        assert_eq!(["", "a", ""].into_targets(), expected);
    }

    #[test]
    fn array_targets() {
        let expected = vec![PathBuf::from("a"), PathBuf::from("b")];
        assert_eq!(["a", "b"].into_targets(), expected);
        assert_eq!(
            [String::from("a"), String::from("b")].into_targets(),
            expected
        );
        assert_eq!(
            [PathBuf::from("a"), PathBuf::from("b")].into_targets(),
            expected
        );

        let none: [&str; 0] = [];
        assert!(none.into_targets().is_empty());
    }

    /// Compiles only when `target` has the shape `S`.
    fn assert_shape<S: Shape>(_target: impl IntoTargets<Shape = S>) {}

    #[test]
    fn the_target_type_fixes_the_shape() {
        assert_shape::<One>("a");
        assert_shape::<One>(String::from("a"));
        assert_shape::<One>(OsString::from("a"));
        assert_shape::<One>(Path::new("a"));
        assert_shape::<One>(PathBuf::from("a"));
        assert_shape::<One>(&PathBuf::from("a"));

        assert_shape::<Many>(vec!["a", "b"]);
        assert_shape::<Many>(Vec::<PathBuf>::new());
        let slice: &[&str] = &["a", "b"];
        assert_shape::<Many>(slice);

        assert_shape::<Array<2>>(["a", "b"]);
        assert_shape::<Array<1>>([PathBuf::from("a")]);
        let none: [&str; 0] = [];
        assert_shape::<Array<0>>(none);
    }

    /// `Multi` follows the shape, not the length: the bound compiles
    /// for every collection target and, by design, for no single one.
    #[test]
    fn collection_targets_are_multi() {
        fn multi_shape_of<T: IntoTargets>(_: &T)
        where
            T::Shape: Multi,
        {
        }

        multi_shape_of(&vec!["a"]);
        multi_shape_of(&vec![PathBuf::from("a"), PathBuf::from("b")]);
        multi_shape_of(&&["a", "b"][..]);
        multi_shape_of(&["a"]);
        multi_shape_of(&["a", "b", "c"]);
        multi_shape_of(&[] as &[&str; 0]);
    }

    /// `SINGLE` is what keeps a lone target's error plain: a one-element
    /// collection is still a collection.
    #[test]
    fn only_the_single_target_shape_is_single() {
        assert_eq!(
            [
                One::SINGLE,
                Many::SINGLE,
                Array::<0>::SINGLE,
                Array::<1>::SINGLE,
                Array::<3>::SINGLE,
            ],
            [true, false, false, false, false],
        );
    }

    #[test]
    fn wrap_gives_the_outputs_the_shape_of_the_targets() {
        assert_eq!(One::wrap(vec!["only"]), "only");

        assert_eq!(Many::wrap(vec![1, 2, 3]), vec![1, 2, 3]);
        assert_eq!(Many::wrap(vec![1]), vec![1]);
        assert_eq!(Many::wrap(Vec::<u8>::new()), Vec::<u8>::new());

        assert_eq!(Array::<3>::wrap(vec![1, 2, 3]), [1, 2, 3]);
        assert_eq!(Array::<1>::wrap(vec![1]), [1]);
        assert_eq!(Array::<0>::wrap(Vec::<u8>::new()), [0_u8; 0]);
    }
}
