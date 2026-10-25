use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::action::action;
use crate::codesign::tool::Codesign;
use crate::engine::{Operation, PushArgs, SharedRun};

action! {
    /// Builder of a signature removal, returned by
    /// [`remove_signature`](crate::codesign::remove_signature).
    ///
    /// Its only option is [`bundle_version`](Self::bundle_version). With this operation, `codesign`
    /// ignores `--deep` and `--architecture`, still removes the signature under `--dryrun`, and
    /// crashes on `--file-list`. So those options aren't offered.
    ///
    /// # Examples
    ///
    /// Remove the signature from one version of a framework, and leave the other versions signed:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// codesign::remove_signature("Engine.framework")
    ///     .bundle_version("A")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    RemoveSignature => () {}
    setters {
        /// Removes the signature from this version of a versioned bundle only (`--bundle-version`).
        ///
        /// The version names a directory under the bundle's `Versions`. Without this option,
        /// `codesign` uses the version that `Current` points to.
        bundle_version: Option<impl Into<String>>,
    }
}

impl<S, R> SharedRun for RemoveSignature<S, R> {}

impl Operation for Options {
    type Tool = Codesign;
    type Output = ();
    const BATCH: bool = false;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();

        // `codesign` follows a verb-noun rule: options given before the
        // operation are silently ignored, so it always goes first.
        args.flag("--remove-signature");

        if let Some(bundle_version) = &self.bundle_version {
            args.option("--bundle-version", bundle_version);
        }

        args.targets(targets);
        args
    }

    fn output(
        &self,
        targets: &[PathBuf],
        _stdout: String,
        _stderr: String,
    ) -> crate::errors::Result<Vec<()>> {
        Ok(vec![(); targets.len()])
    }
}

#[cfg(test)]
#[path = "unit_tests/remove_signature.rs"]
mod tests;
