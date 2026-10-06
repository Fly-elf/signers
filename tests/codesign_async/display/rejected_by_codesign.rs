//! Targets `codesign` has no signature to report for, and option values it
//! refuses: each a plain `codesign` failure carrying its diagnostics.

use signers::codesign::display;
use signers::{CodesignError, Error};

use crate::support::fixture::Workspace;
use crate::support::inspect;

/// The diagnostics of a run `codesign` ended with exit code 1.
fn exit_1(error: Error) -> String {
    match error {
        Error::Codesign(CodesignError::Failed {
            code: 1, stderr, ..
        }) => stderr,
        other => panic!("expected `codesign` to exit 1, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unsigned_target_is_an_error() {
    let workspace = Workspace::new();
    // The fixture arrives linker-signed, so the bundle's executable is
    // stripped too: otherwise `codesign` reports that signature for the bundle.
    let bundle = workspace.app_bundle("Unsigned");
    crate::support::inspect::codesign(&[
        "--remove-signature".as_ref(),
        bundle.join("Contents/MacOS/Unsigned").as_ref(),
    ])
    .expect_success("strip the bundle's executable");
    let targets = [
        workspace.unsigned("hello"),
        bundle,
        workspace.write("notes.txt", "never signed\n"),
    ];

    for target in targets {
        let stderr = exit_1(display(&target).await.unwrap_err());

        assert!(
            stderr.contains("code object is not signed at all"),
            "{stderr}"
        );
        assert!(stderr.contains(&target.display().to_string()), "{stderr}");
    }
}

#[tokio::test]
async fn an_architecture_the_target_lacks_is_an_error() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let error = display(&target).architecture("i386").await.unwrap_err();

    let stderr = exit_1(error);
    assert!(
        stderr.contains("object file format unrecognized"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_bundle_version_the_bundle_lacks_is_an_error() {
    let workspace = Workspace::new();
    let framework = workspace.framework("Kit");
    super::adhoc_sign(&framework, &[]);

    let error = display(&framework).bundle_version("Z").await.unwrap_err();

    let stderr = exit_1(error);
    assert!(
        stderr.contains("cannot find code object on disk"),
        "{stderr}"
    );
}

/// The signature lives in the detached file, so without it there is nothing
/// to report.
#[tokio::test]
async fn a_detached_signature_is_needed_to_read_it() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let detached = workspace.join("hello.sig");
    super::adhoc_sign(&target, &["--detached", detached.to_str().unwrap()]);

    let stderr = exit_1(display(&target).await.unwrap_err());

    assert!(
        stderr.contains("code object is not signed at all"),
        "{stderr}"
    );
}

/// A run over several targets reads no entitlements, so `codesign` prints
/// nothing on standard output before it refuses the unsigned one: the error
/// carries exactly that, next to the diagnostics.
#[tokio::test]
async fn a_failed_one_process_run_carries_the_empty_stdout_codesign_left() {
    let workspace = Workspace::new();
    let signed = workspace.adhoc_signed("hello");
    let unsigned = workspace.write("notes.txt", "never signed\n");
    let oracle = inspect::codesign(&[
        "--display".as_ref(),
        "--verbose=4".as_ref(),
        "--".as_ref(),
        signed.as_ref(),
        unsigned.as_ref(),
    ]);
    assert!(!oracle.success);

    let error = display(vec![signed, unsigned.clone()])
        .per_target(false)
        .await
        .unwrap_err();

    match error {
        Error::Codesign(CodesignError::Failed { stdout, stderr, .. }) => {
            assert_eq!(stdout, oracle.stdout.trim());
            assert!(stdout.is_empty(), "{stdout}");
            assert!(stderr.contains(&unsigned.display().to_string()), "{stderr}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
