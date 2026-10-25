use std::ffi::OsString;
use std::future::IntoFuture;

use super::*;
use crate::codesign::remove_signature;
use crate::errors::testing::{exited, ran};

fn os(strings: &[&str]) -> Vec<OsString> {
    strings.iter().map(OsString::from).collect()
}

/// Renders the arguments, taking ownership so assertions can compare them
/// against plain `OsString`s.
fn args_of<S>(builder: &RemoveSignature<S>) -> Vec<OsString> {
    builder
        .options
        .to_args(&builder.job.targets)
        .into_iter()
        .map(Cow::into_owned)
        .collect()
}

#[test]
fn bare_action_only_removes() {
    assert_eq!(
        args_of(&remove_signature("app")),
        os(&["--remove-signature", "--", "app"])
    );
}

/// Every option this action can render, so that adding one without
/// rendering it — or rendering it in the wrong form — fails here.
#[test]
fn every_option_renders_exactly_once() {
    assert_eq!(
        args_of(&remove_signature("app").bundle_version("A")),
        os(&["--remove-signature", "--bundle-version", "A", "--", "app"])
    );
}

#[test]
fn repeating_the_bundle_version_keeps_the_last_one() {
    assert_eq!(
        args_of(
            &remove_signature("app")
                .bundle_version("A")
                .bundle_version("B")
        ),
        os(&["--remove-signature", "--bundle-version", "B", "--", "app"])
    );
}

#[test]
fn targets_come_last() {
    assert_eq!(
        args_of(&remove_signature(vec!["a.app", "b.app"]).bundle_version("A")),
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
    let action = remove_signature("app").bundle_version("A");
    assert!(action.options.validate().is_ok());
}

#[test]
fn the_output_is_one_unit_per_target_whatever_codesign_printed() {
    let action = remove_signature("app").options;
    let targets = [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];

    let silent: Vec<()> = action.output(&targets, &ran("", String::new())).unwrap();
    assert_eq!(silent.len(), 3);

    let noisy = action.output(&targets[..1], &ran("noise", "\u{FFFD}\u{FFFD}"));
    assert_eq!(noisy.unwrap().len(), 1);

    let none = action.output(&[], &ran("noise", String::new()));
    assert_eq!(none.unwrap().len(), 0);
}

/// A removal mutates its targets, so the batch stays one `codesign` process
/// unless the caller asks otherwise.
#[test]
fn the_constructor_defaults_to_one_process_for_all_targets() {
    assert!(!remove_signature("app").job.batch);
    assert!(!remove_signature(vec!["a.app", "b.app"]).job.batch);
    assert!(!remove_signature(["a.app", "b.app"]).job.batch);
}

#[test]
fn per_target_keeps_the_last_value_and_renders_no_argument() {
    let action = remove_signature(vec!["app"]).per_target(true);
    assert!(action.job.batch);
    assert_eq!(args_of(&action), os(&["--remove-signature", "--", "app"]));

    let action = action.per_target(false);
    assert!(!action.job.batch);
    assert_eq!(args_of(&action), os(&["--remove-signature", "--", "app"]));
}

/// The only option names a version to act on: nothing here writes a file
/// that several processes would have to share.
#[test]
fn no_option_is_a_shared_output() {
    let action = remove_signature("app").bundle_version("A");
    assert_eq!(action.options.shared_output(), None);
}

/// A removal has no exit code of its own to tell apart, so every one of
/// them stays the generic failure, whatever it printed on standard output.
#[test]
fn a_failed_run_is_reported_with_its_code_and_diagnostics() {
    let action = remove_signature("app").options;
    for code in [1, 2, 3] {
        match action.failure(
            code,
            exited(
                "codesign",
                code,
                "file modified: /x",
                "app: bundle format unrecognized",
            ),
        ) {
            crate::errors::Error::Process(crate::errors::ProcessError::Failed { output }) => {
                assert_eq!(output.program, "codesign");
                assert_eq!(output.status.code(), Some(code));
                assert_eq!(output.stdout, "file modified: /x");
                assert_eq!(output.stderr, "app: bundle format unrecognized");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}

/// The run is boxed with `Send`, so it can move to another task.
#[test]
fn the_run_future_can_be_sent_to_another_thread() {
    fn assert_send<T: Send>(_: &T) {}

    assert_send(&remove_signature("app").into_future());
    assert_send(
        &remove_signature(vec!["a", "b"])
            .per_target(true)
            .into_future(),
    );
}
