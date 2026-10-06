//! Tests that need the process's working directory somewhere specific.

use std::env;
use std::future::IntoFuture;

use signers::codesign::extract_certificates;
use signers::codesign::{display, sign, verify};

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};

#[test]
fn a_target_starting_with_a_dash_is_not_mistaken_for_an_option() {
    let _serialised = crate::serialised();

    // Only a *relative* path can start with a dash, hence the working
    // directory. Without the `--` separator the arguments end up as
    // `codesign --sign - -patched.bin`, and `codesign` reads the target as a
    // run of short options ("unknown architecture name") instead of a path.
    let workspace = Workspace::new();
    let target = workspace.unsigned("-patched.bin");
    let previous = env::current_dir().expect("no working directory");
    env::set_current_dir(workspace.path()).expect("could not enter the workspace");

    let result = crate::runtime().block_on(
        sign("-patched.bin", "-")
            .identifier("com.example.dashed")
            .into_future(),
    );

    env::set_current_dir(previous).expect("could not leave the workspace");
    result.expect("a dash-prefixed target was not signed");
    inspect::assert_valid(&target);
    assert_eq!(Signature::of(&target).identifier(), "com.example.dashed");
}

#[test]
fn a_verified_target_starting_with_a_dash_is_not_mistaken_for_an_option() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("-signed.bin");
    let unsigned = workspace.unsigned("-unsigned.bin");
    let previous = env::current_dir().expect("no working directory");
    env::set_current_dir(workspace.path()).expect("could not enter the workspace");

    let valid = crate::runtime().block_on(verify("-signed.bin").into_future());
    let invalid = crate::runtime().block_on(verify("-unsigned.bin").into_future());

    env::set_current_dir(previous).expect("could not leave the workspace");
    valid.expect("a dash-prefixed target did not verify");
    assert!(target.exists());
    // Read as an option, the name would be a syntax error rather than a verdict.
    let error = invalid.unwrap_err();
    assert!(
        matches!(
            error,
            signers::Error::Codesign(signers::CodesignError::VerificationFailed { ref stderr, .. })
                if stderr.contains("not signed at all")
        ),
        "got {error:?}"
    );
    assert!(unsigned.exists());
}

#[test]
fn a_dash_prefixed_target_is_displayed_not_parsed_as_an_option() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.presigned("-patched.bin", &["-i", "com.example.dashed"]);
    let previous = env::current_dir().expect("no working directory");
    env::set_current_dir(workspace.path()).expect("could not enter the workspace");

    let result = crate::runtime().block_on(display("-patched.bin").into_future());

    env::set_current_dir(previous).expect("could not leave the workspace");
    let signature = result.expect("a dash-prefixed target was not displayed");
    assert_eq!(signature.identifier, "com.example.dashed");
    assert_eq!(signature.raw(), Signature::of(&target).raw());
}

#[test]
fn a_dash_prefixed_target_has_its_certificates_extracted_and_saved() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.join("-ls");
    std::fs::copy("/bin/ls", &target).expect("could not copy /bin/ls");
    let out = workspace.join("out");
    let previous = env::current_dir().expect("no working directory");
    env::set_current_dir(workspace.path()).expect("could not enter the workspace");

    let result = crate::runtime().block_on(extract_certificates("-ls").save_to(&out).into_future());

    env::set_current_dir(previous).expect("could not leave the workspace");
    let chain = result.expect("a dash-prefixed target was not read");
    let ders: Vec<&[u8]> = chain.iter().map(|c| c.der()).collect();
    assert_eq!(ders, inspect::certificates(&target));
    assert!(out.join("-ls.pem").is_file(), "no -ls.pem");
}

/// `.` has no file name of its own: the PEM file is named after the directory
/// it stands for, and a relative `save_to` resolves against the working
/// directory.
#[test]
fn the_current_directory_as_target_is_saved_under_its_own_name() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let app = std::path::Path::new("/System/Applications/Calculator.app");
    let previous = env::current_dir().expect("no working directory");
    env::set_current_dir(app).expect("could not enter the bundle");

    let result = crate::runtime().block_on(
        extract_certificates(".")
            .save_to(workspace.path())
            .into_future(),
    );

    env::set_current_dir(previous).expect("could not leave the bundle");
    let chain = result.expect("the current directory was not read");
    assert!(!chain.is_empty());
    assert!(
        workspace.join("Calculator.app.pem").is_file(),
        "no Calculator.app.pem"
    );
}
