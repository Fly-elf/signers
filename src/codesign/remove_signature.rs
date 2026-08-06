//! The signature-removal action (`codesign --remove-signature`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;

/// The signature-removal action, and the options it was configured with
/// (`codesign --remove-signature`).
///
/// You never build one: [`Codesign::remove_signature`] does, and it is the only
/// way to get one. Its single option lives on
/// [`Codesign<RemoveSignature>`](Codesign#impl-Codesign%3CRemoveSignature%3E) —
/// [`bundle_version`](Codesign::bundle_version).
///
/// Accept only `bundle_version` as an option, other documented options are skipped
/// because they are ignored by `codesign` (`--deep`, `--architecture`, `--dryrun`).
///
/// # Examples
///
/// Strip a patched binary before re-signing it
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
///
/// Codesign::remove_signature("patched.dylib").await?;
/// # Ok(()) }
/// ```
///
/// Strip several targets in one run.
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
///
/// Codesign::remove_signature(vec!["MyApp.app", "MyLib.dylib"]).await?;
/// # Ok(()) }
/// ```
///
/// Strip one version of a versioned framework, leaving the others signed:
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
///
/// Codesign::remove_signature("MyLib.framework")
///     .bundle_version("A")
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Default)]
pub struct RemoveSignature {
    bundle_version: Option<String>,
}

impl Codesign<RemoveSignature> {
    /// Version to operate on inside a versioned bundle, i.e. a name under its
    /// `Versions` directory (`--bundle-version`).
    ///
    /// The one place removal is selective: the versions not named keep their
    /// signatures. Without it `codesign` strips the bundle's default version.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }
}

impl ToArgs for RemoveSignature {
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
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    /// Renders the arguments, taking ownership so assertions can compare them
    /// against plain `OsString`s.
    fn args_of(builder: &Codesign<RemoveSignature>) -> Vec<OsString> {
        builder
            .action
            .to_args(&builder.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    #[test]
    fn bare_action_only_removes() {
        assert_eq!(
            args_of(&Codesign::remove_signature("app")),
            os(&["--remove-signature", "--", "app"])
        );
    }

    /// Every option this action can render, so that adding one without
    /// rendering it — or rendering it in the wrong form — fails here.
    #[test]
    fn every_option_renders_exactly_once() {
        assert_eq!(
            args_of(&Codesign::remove_signature("app").bundle_version("A")),
            os(&["--remove-signature", "--bundle-version", "A", "--", "app"])
        );
    }

    #[test]
    fn repeating_the_bundle_version_keeps_the_last_one() {
        assert_eq!(
            args_of(
                &Codesign::remove_signature("app")
                    .bundle_version("A")
                    .bundle_version("B")
            ),
            os(&["--remove-signature", "--bundle-version", "B", "--", "app"])
        );
    }

    #[test]
    fn targets_come_last() {
        assert_eq!(
            args_of(&Codesign::remove_signature(vec!["a.app", "b.app"]).bundle_version("A")),
            os(&[
                "--remove-signature",
                "--bundle-version",
                "A",
                "--",
                "a.app",
                "b.app",
            ])
        );
    }

    /// Nothing to reject: unlike `sign`, no option value is unrepresentable
    /// here, so the default no-op `validate` has to stay a no-op.
    #[test]
    fn there_is_nothing_to_validate() {
        let action = Codesign::remove_signature("app").bundle_version("A");
        assert!(action.action.validate().is_ok());
    }
}
