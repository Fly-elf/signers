//! Every action's `target` parameter is generic over [`IntoTargets`].
//! It's a convenient way to specify files to work with — supported types:
//! - A single path: [`str`], [`String`], [`OsString`], [`Path`] or [`PathBuf`] — owned or
//!   borrowed
//! - A batch: `Vec` or a slice, of anything from the list above
//!
//! Empty paths are dropped — if nothing is left, [`Error::NoTargets`](crate::Error::NoTargets) is returned.
//!
//! # Examples
//! ```
//! use signers::target::IntoTargets;
//! use std::ffi::OsString;
//! use std::path::{Path, PathBuf};
//!
//! let expected = vec![PathBuf::from("app")];
//!
//! assert_eq!("app".into_targets(), expected);                   // &str
//! assert_eq!(String::from("app").into_targets(), expected);     // String
//! assert_eq!(OsString::from("app").into_targets(), expected);   // OsString
//! assert_eq!(Path::new("app").into_targets(), expected);        // &Path
//! assert_eq!(PathBuf::from("app").into_targets(), expected);    // PathBuf
//! assert_eq!((&PathBuf::from("app")).into_targets(), expected); // &PathBuf
//! ```
//!
//! A batch can be a `Vec` or a slice — but not a bare array literal. `&["a.app", "b.app"]` is a
//! reference to a fixed-size array (`&[&str; 2]`), a different type from the slice (`&[&str]`)
//! that `IntoTargets` is actually implemented for. Rust converts one into the other in plenty of
//! places, but not while `Codesign::sign` is still working out which type you mean — so an array
//! literal handed straight to an action doesn't compile:
//!
//! ```compile_fail
//! # use signers::codesign::Codesign;
//! Codesign::sign(&["a.app", "b.app"], "-");
//! // error[E0277]: the trait `IntoTargets` is not implemented for `&[&str; 2]`
//! ```
//!
//! `vec![..]` sidesteps the problem — it's a real `Vec`, nothing to convert. Or tell Rust up
//! front that you mean a slice, with a typed `let`:
//!
//! ```
//! use signers::target::IntoTargets;
//! use std::path::PathBuf;
//!
//! let expected = vec![PathBuf::from("a"), PathBuf::from("b")];
//!
//! assert_eq!(vec!["a", "b"].into_targets(), expected); // Vec<&str>, order preserved
//!
//! let slice: &[&str] = &["a", "b"]; // the `let` says up front: this is a slice
//! assert_eq!(slice.into_targets(), expected); // &[&str]
//! ```

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A convenient way to specify files to operate on.
///
/// This is what lets every action take a path exactly as you already have it
/// — a `&str` literal, an owned `String`, a `PathBuf` you built earlier — with
/// no conversion of your own to write.
///
/// Implemented for:
/// - A single path: [`str`], [`String`], [`OsString`], [`Path`] or [`PathBuf`]
///   — owned or borrowed
/// - A batch: `Vec` or a slice, of anything from the list above
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::codesign::Codesign;
/// use std::path::PathBuf;
///
/// let target = PathBuf::from("MyApp.app");
///
/// Codesign::sign("MyApp.app", "-").await?;            // a &str literal, as-is
/// Codesign::sign(&target, "-").await?;                // a borrowed PathBuf, as-is
/// Codesign::sign(vec!["a.app", "b.app"], "-").await?; // a batch
/// # Ok(()) }
/// ```
pub trait IntoTargets {
    /// Turns `self` into the paths an action runs on, dropping any that are empty.
    fn into_targets(self) -> Vec<PathBuf>;
}

/// Implements [`IntoTargets`] for a single-path type convertible into [`PathBuf`],
/// dropping the result if it's empty instead of returning a one-element vector.
macro_rules! impl_target {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl IntoTargets for $ty {
                fn into_targets(self) -> Vec<PathBuf> {
                    let path: PathBuf = self.into();
                    if path.as_os_str().is_empty() {
                        Vec::new()
                    } else {
                        vec![path]
                    }
                }
            }
        )+
    };
}

impl_target!(&str, String, OsString, &Path, PathBuf, &PathBuf);

impl<T: Into<PathBuf>> IntoTargets for Vec<T> {
    fn into_targets(self) -> Vec<PathBuf> {
        self.into_iter()
            .map(Into::into)
            .filter(|p| !p.as_os_str().is_empty())
            .collect()
    }
}

impl<T: Into<PathBuf> + Clone> IntoTargets for &[T] {
    fn into_targets(self) -> Vec<PathBuf> {
        self.iter()
            .cloned()
            .map(Into::into)
            .filter(|p| !p.as_os_str().is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(
            vec!["b", "a", "b"].into_targets(),
            vec![PathBuf::from("b"), PathBuf::from("a"), PathBuf::from("b")],
        );
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

    #[test]
    fn empty_single_target_yields_empty_list() {
        assert!("".into_targets().is_empty());
        assert!(String::new().into_targets().is_empty());
        assert!(OsString::new().into_targets().is_empty());
        assert!(Path::new("").into_targets().is_empty());
        assert!(PathBuf::new().into_targets().is_empty());
        assert!((&PathBuf::new()).into_targets().is_empty());
    }

    #[test]
    fn empty_entries_are_skipped_in_collections() {
        let expected = vec![PathBuf::from("a")];
        assert_eq!(vec!["", "a", ""].into_targets(), expected);

        let slice: &[&str] = &["", "a"];
        assert_eq!(slice.into_targets(), expected);
    }
}
