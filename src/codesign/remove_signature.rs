//! The signature-removal action (`--remove-signature`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;

/// Options of the signature-removal action: the `A` in `Codesign<RemoveSignature>`.
///
/// [`Codesign::remove_signature`] creates it. Its only option is
/// [`bundle_version`](Codesign#impl-Codesign%3CRemoveSignature%3E). With this operation,
/// `codesign` ignores `--deep` and `--architecture`, still removes the signature under
/// `--dryrun`, and crashes on `--file-list`. So those options aren't offered.
///
/// # Examples
///
/// Remove the signature from one version of a framework, and leave the other versions signed:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::Codesign;
///
/// Codesign::remove_signature("Engine.framework")
///     .bundle_version("A")
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Default)]
pub struct RemoveSignature {
    bundle_version: Option<String>,
}

/// Options for [`remove_signature`](Codesign::remove_signature).
impl Codesign<RemoveSignature> {
    /// Removes the signature from this version of a versioned bundle only (`--bundle-version`).
    ///
    /// `version` names a directory under the bundle's `Versions`. Without this option,
    /// `codesign` uses the version that `Current` points to.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }
}

impl ToArgs for RemoveSignature {
    type Output = ();

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

    fn output(&self, _stdout: Vec<u8>, _stderr: Vec<u8>) -> crate::errors::Result<()> {
        Ok(())
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

    #[test]
    fn the_output_ignores_whatever_codesign_printed() {
        let action = Codesign::remove_signature("app");
        assert_eq!(action.action.output(Vec::new(), Vec::new()).unwrap(), ());
        assert_eq!(
            action
                .action
                .output(b"noise".to_vec(), vec![0xff, 0xfe])
                .unwrap(),
            ()
        );
    }
}
