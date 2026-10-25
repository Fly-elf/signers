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
/// than inputs. Refusing it is the engine's job (`Error::EmptyTarget`).
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
