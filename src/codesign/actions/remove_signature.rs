//! The signature-removal action (`--remove-signature`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::Codesign;
use crate::codesign::action::PushArgs;
use crate::codesign::action::sealed::{SharedRun, ToArgs};
use crate::target::Shape;

/// Options of the signature-removal action: the `A` in `Codesign<RemoveSignature>`.
///
/// [`Codesign::remove_signature`] creates it. Its only option is
/// [`bundle_version`](Codesign#impl-Codesign%3CRemoveSignature,+S%3E). With this operation,
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
impl<S: Shape> Codesign<RemoveSignature, S> {
    /// Removes the signature from this version of a versioned bundle only (`--bundle-version`).
    ///
    /// `version` names a directory under the bundle's `Versions`. Without this option,
    /// `codesign` uses the version that `Current` points to.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }
}

impl SharedRun for RemoveSignature {}

impl ToArgs for RemoveSignature {
    type Output = ();
    const PER_TARGET: bool = false;

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
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    /// Renders the arguments, taking ownership so assertions can compare them
    /// against plain `OsString`s.
    fn args_of<S>(builder: &Codesign<RemoveSignature, S>) -> Vec<OsString> {
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
    fn the_output_is_one_unit_per_target_whatever_codesign_printed() {
        let action = Codesign::remove_signature("app").action;
        let targets = [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];

        let silent: Vec<()> = action
            .output(&targets, String::new(), String::new())
            .unwrap();
        assert_eq!(silent.len(), 3);

        let noisy = action.output_bytes(&targets[..1], b"noise".to_vec(), vec![0xff, 0xfe]);
        assert_eq!(noisy.unwrap().len(), 1);

        let none = action.output(&[], "noise".into(), String::new());
        assert_eq!(none.unwrap().len(), 0);
    }

    /// A removal mutates its targets, so the batch stays one `codesign` process
    /// unless the caller asks otherwise.
    #[test]
    fn the_constructor_defaults_to_one_process_for_all_targets() {
        assert!(!Codesign::remove_signature("app").per_target);
        assert!(!Codesign::remove_signature(vec!["a.app", "b.app"]).per_target);
        assert!(!Codesign::remove_signature(["a.app", "b.app"]).per_target);
    }

    #[test]
    fn per_target_keeps_the_last_value_and_renders_no_argument() {
        let action = Codesign::remove_signature(vec!["app"]).per_target(true);
        assert!(action.per_target);
        assert_eq!(args_of(&action), os(&["--remove-signature", "--", "app"]));

        let action = action.per_target(false);
        assert!(!action.per_target);
        assert_eq!(args_of(&action), os(&["--remove-signature", "--", "app"]));
    }

    /// The only option names a version to act on: nothing here writes a file
    /// that several processes would have to share.
    #[test]
    fn no_option_is_a_shared_output() {
        let action = Codesign::remove_signature("app").bundle_version("A");
        assert_eq!(action.action.shared_output(), None);
    }

    /// A removal has no exit code of its own to tell apart, so every one of
    /// them stays the generic failure, whatever it printed on standard output.
    #[test]
    fn a_failed_run_is_reported_with_its_code_and_diagnostics() {
        let action = Codesign::remove_signature("app").action;
        for code in [1, 2, 3] {
            match action.failure(
                code,
                "file modified: /x".into(),
                "app: bundle format unrecognized".into(),
            ) {
                crate::errors::Error::Codesign(crate::errors::CodesignError::Failed {
                    code: reported,
                    stdout,
                    stderr,
                }) => {
                    assert_eq!(reported, code);
                    assert_eq!(stdout, "file modified: /x");
                    assert_eq!(stderr, "app: bundle format unrecognized");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
        }
    }
}
