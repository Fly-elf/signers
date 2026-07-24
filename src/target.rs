//! The [`IntoTargets`] conversion trait, shared by every signing backend.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Converts a single path, or a collection of paths, into the canonical target
/// list every `Codesign` action operates on.
///
/// Accepts the common path-like types directly, as well as a `Vec` or slice of
/// anything convertible into a [`PathBuf`]:
///
/// ```
/// use signers::target::IntoTargets;
/// use std::path::PathBuf;
///
/// assert_eq!("MyApp.app".into_targets(), vec![PathBuf::from("MyApp.app")]);
/// assert_eq!(
///     vec!["a.app", "b.app"].into_targets(),
///     vec![PathBuf::from("a.app"), PathBuf::from("b.app")],
/// );
/// ```
///
/// Empty targets are dropped: an empty single target yields an empty list (no
/// allocation), and empty entries in a collection are skipped. Actions turn an
/// empty resulting list into an error rather than acting on nothing.
///
/// Note: array literals such as `&["a", "b"]` do not coerce to `&[T]` on their
/// own — pass a `Vec` (`vec!["a", "b"]`) or slice them explicitly (`&["a", "b"][...]`).
pub trait IntoTargets {
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

impl_target!(&str, String, OsString, &Path, PathBuf);

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
    }

    #[test]
    fn empty_single_target_yields_empty_list() {
        assert!("".into_targets().is_empty());
        assert!(String::new().into_targets().is_empty());
        assert!(OsString::new().into_targets().is_empty());
        assert!(Path::new("").into_targets().is_empty());
        assert!(PathBuf::new().into_targets().is_empty());
    }

    #[test]
    fn empty_entries_are_skipped_in_collections() {
        let expected = vec![PathBuf::from("a")];
        assert_eq!(vec!["", "a", ""].into_targets(), expected);

        let slice: &[&str] = &["", "a"];
        assert_eq!(slice.into_targets(), expected);
    }
}
