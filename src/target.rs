//! The paths an action runs on; see [`IntoTargets`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The targets of an action: one path, or a `Vec` or slice of paths.
///
/// Every action takes `impl IntoTargets`. The implementors below are the path types it accepts,
/// on their own or in a `Vec` or slice.
///
/// Empty paths are dropped. If none are left, `.await` fails with
/// [`Error::NoTargets`](crate::Error::NoTargets). Order and duplicates are kept, and each path
/// reaches `codesign` byte for byte, non-UTF-8 included. A path starting with `-` is never read
/// as an option.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use std::path::PathBuf;
///
/// use signers::Codesign;
///
/// let built = PathBuf::from("target/release/mytool");
/// Codesign::sign_adhoc(&built).await?;
/// Codesign::sign_adhoc(vec!["liba.dylib", "libb.dylib"]).await?;
/// # Ok(()) }
/// ```
///
/// An array literal is neither a `Vec` nor a slice, so it doesn't compile. Use `vec![…]`:
///
/// ```compile_fail
/// # use signers::Codesign;
/// Codesign::sign_adhoc(&["liba.dylib", "libb.dylib"]);
/// ```
pub trait IntoTargets {
    /// Converts `self` into the target paths, dropping empty ones.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    ///
    /// use signers::IntoTargets;
    ///
    /// assert_eq!(vec!["b", "", "a"].into_targets(), [PathBuf::from("b"), PathBuf::from("a")]);
    /// ```
    fn into_targets(self) -> Vec<PathBuf>;
}

/// Implements [`IntoTargets`] for single-path types: an empty path yields no target.
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
