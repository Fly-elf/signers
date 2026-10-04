//! Verifying bundles: sealed resources, nested code and symlinks — what the
//! default check lets through and the options that tighten or loosen it.

use std::fs;

use signers::codesign::Strict;
use signers::{Codesign, Error};

use super::{break_signature, flip_byte, verification_failed};
use crate::support::fixture::Workspace;
use crate::support::inspect;

/// A signed `.app` with one sealed resource, `Contents/Resources/data.txt`.
fn app_with_a_resource(workspace: &Workspace) -> std::path::PathBuf {
    let app = workspace.app_bundle("Hello");
    workspace.dir("Hello.app/Contents/Resources");
    workspace.write("Hello.app/Contents/Resources/data.txt", "original\n");
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), app.as_ref()])
        .expect_success("pre-sign the bundle");
    app
}

/// A signed `.app` whose `Contents/Frameworks/libnested.dylib` is signed on its
/// own and then broken, leaving the app's seal over it untouched.
fn app_with_a_broken_nested_dylib(workspace: &Workspace) -> std::path::PathBuf {
    let app = workspace.app_bundle("Hello");
    let frameworks = workspace.dir("Hello.app/Contents/Frameworks");
    let nested = frameworks.join("libnested.dylib");
    fs::copy(workspace.unsigned_dylib("source.dylib"), &nested).unwrap();
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), nested.as_ref()])
        .expect_success("pre-sign the nested dylib");
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), app.as_ref()])
        .expect_success("pre-sign the bundle");
    flip_byte(&nested, 0x2000);
    app
}

#[tokio::test]
async fn a_signed_bundle_verifies() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);

    Codesign::verify(&app).await.unwrap();
}

#[tokio::test]
async fn a_signed_framework_verifies() {
    let workspace = Workspace::new();
    let framework = workspace.framework("Hello");
    Codesign::sign(&framework, "-").await.unwrap();

    Codesign::verify(&framework).await.unwrap();
}

#[tokio::test]
async fn an_unsigned_bundle_does_not_verify() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("Hello");

    let error = Codesign::verify(&app).await.unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn a_modified_resource_breaks_the_seal() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);
    fs::write(app.join("Contents/Resources/data.txt"), "tampered\n").unwrap();

    let error = Codesign::verify(&app).await.unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains("a sealed resource is missing or invalid"),
        "got {stderr}"
    );
}

#[tokio::test]
async fn an_added_resource_breaks_the_seal() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);
    workspace.write("Hello.app/Contents/Resources/extra.txt", "unsealed\n");

    let error = Codesign::verify(&app).await.unwrap_err();

    verification_failed(error);
}

#[tokio::test]
async fn ignoring_resources_lets_a_modified_resource_through() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);
    fs::write(app.join("Contents/Resources/data.txt"), "tampered\n").unwrap();

    Codesign::verify(&app).ignore_resources(true).await.unwrap();
}

#[tokio::test]
async fn ignore_resources_false_checks_resources_again() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);
    fs::write(app.join("Contents/Resources/data.txt"), "tampered\n").unwrap();

    let error = Codesign::verify(&app)
        .ignore_resources(true)
        .ignore_resources(false)
        .await
        .unwrap_err();

    verification_failed(error);
}

/// Ignoring resources doesn't ignore the code: a modified executable still
/// fails.
#[tokio::test]
async fn ignoring_resources_still_checks_the_executable() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);
    break_signature(&app.join("Contents/MacOS/Hello"));

    let error = Codesign::verify(&app)
        .ignore_resources(true)
        .await
        .unwrap_err();

    verification_failed(error);
}

/// The check adds to the verification, it never replaces it: the same broken
/// bundle fails the same way.
#[tokio::test]
async fn checking_the_designated_requirement_still_reports_a_modified_resource() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);
    fs::write(app.join("Contents/Resources/data.txt"), "tampered\n").unwrap();

    let error = Codesign::verify(&app)
        .check_designated_requirement(true)
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains("a sealed resource is missing or invalid"),
        "got {stderr}"
    );
}

#[tokio::test]
async fn checking_the_designated_requirement_passes_a_valid_signature() {
    let workspace = Workspace::new();
    let app = app_with_a_resource(&workspace);

    Codesign::verify(&app)
        .check_designated_requirement(true)
        .await
        .unwrap();
}

/// Nested code is covered by its parent's seal through the nested code's
/// CDHash only: a modified page inside it goes unseen unless `deep` is on.
#[tokio::test]
async fn nested_code_is_checked_in_depth_only_with_deep() {
    let workspace = Workspace::new();
    let app = app_with_a_broken_nested_dylib(&workspace);

    Codesign::verify(&app).await.unwrap();

    let error = Codesign::verify(&app).deep(true).await.unwrap_err();
    let stderr = verification_failed(error);
    assert!(stderr.contains("libnested.dylib"), "got {stderr}");
}

#[tokio::test]
async fn deep_false_goes_back_to_the_shallow_check() {
    let workspace = Workspace::new();
    let app = app_with_a_broken_nested_dylib(&workspace);

    Codesign::verify(&app).deep(true).deep(false).await.unwrap();
}

#[tokio::test]
async fn deep_passes_when_the_nested_code_is_intact() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("Hello");
    let nested = workspace
        .dir("Hello.app/Contents/Frameworks")
        .join("libnested.dylib");
    fs::copy(workspace.unsigned_dylib("source.dylib"), &nested).unwrap();
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), nested.as_ref()])
        .expect_success("pre-sign the nested dylib");
    Codesign::sign(&app, "-").await.unwrap();

    Codesign::verify(&app).deep(true).await.unwrap();
}

/// A bundle holding a symlink that leaves it verifies by default, and fails
/// under the strict levels that check symlinks.
fn app_with_an_escaping_symlink(workspace: &Workspace) -> std::path::PathBuf {
    let app = workspace.app_bundle("Hello");
    workspace.dir("Hello.app/Contents/Resources");
    std::os::unix::fs::symlink("/etc/hosts", app.join("Contents/Resources/link")).unwrap();
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), app.as_ref()])
        .expect_success("pre-sign the bundle");
    app
}

#[tokio::test]
async fn an_escaping_symlink_passes_unless_strict() {
    let workspace = Workspace::new();
    let app = app_with_an_escaping_symlink(&workspace);

    Codesign::verify(&app).await.unwrap();
}

#[tokio::test]
async fn strict_all_and_symlinks_reject_an_escaping_symlink() {
    let workspace = Workspace::new();
    let app = app_with_an_escaping_symlink(&workspace);

    for strict in [Strict::All, Strict::Symlinks] {
        let error = Codesign::verify(&app).strict(strict).await.unwrap_err();
        let stderr = verification_failed(error);
        assert!(
            stderr.contains("invalid destination for symbolic link in bundle"),
            "{strict:?}: got {stderr}"
        );
    }
}

/// `sideband` checks something else than symlinks, so a bundle that only has
/// a bad symlink passes it.
#[tokio::test]
async fn strict_sideband_does_not_check_symlinks() {
    let workspace = Workspace::new();
    let app = app_with_an_escaping_symlink(&workspace);

    Codesign::verify(&app)
        .strict(Strict::Sideband)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_last_strict_level_wins() {
    let workspace = Workspace::new();
    let app = app_with_an_escaping_symlink(&workspace);

    Codesign::verify(&app)
        .strict(Strict::All)
        .strict(Strict::Sideband)
        .await
        .unwrap();

    let error = Codesign::verify(&app)
        .strict(Strict::Sideband)
        .strict(Strict::All)
        .await
        .unwrap_err();
    verification_failed(error);
}

#[tokio::test]
async fn every_strict_level_accepts_a_clean_target() {
    let workspace = Workspace::new();
    let binary = workspace.adhoc_signed("hello");
    let app = app_with_a_resource(&workspace);

    for strict in [Strict::All, Strict::Symlinks, Strict::Sideband] {
        for target in [&binary, &app] {
            Codesign::verify(target)
                .strict(strict)
                .await
                .unwrap_or_else(|e: Error| panic!("{strict:?} on {}: {e}", target.display()));
        }
    }
}

/// Every version of a framework is signed on its own; one broken version is
/// found only when that version is the one asked for.
#[tokio::test]
async fn a_bundle_version_selects_which_version_is_verified() {
    let workspace = Workspace::new();
    let framework = workspace.versioned_framework("Hello", &["A", "B"]);
    for version in ["A", "B"] {
        inspect::codesign(&[
            "--sign".as_ref(),
            "-".as_ref(),
            "--bundle-version".as_ref(),
            version.as_ref(),
            framework.as_ref(),
        ])
        .expect_success("pre-sign a framework version");
    }
    flip_byte(&framework.join("Versions/B/Hello"), 0x2000);

    Codesign::verify(&framework).await.unwrap();
    Codesign::verify(&framework)
        .bundle_version("A")
        .await
        .unwrap();
    let error = Codesign::verify(&framework)
        .bundle_version("B")
        .await
        .unwrap_err();
    verification_failed(error);
}

#[tokio::test]
async fn an_unsigned_version_does_not_verify() {
    let workspace = Workspace::new();
    let framework = workspace.versioned_framework("Hello", &["A", "B"]);
    inspect::codesign(&[
        "--sign".as_ref(),
        "-".as_ref(),
        "--bundle-version".as_ref(),
        "A".as_ref(),
        framework.as_ref(),
    ])
    .expect_success("pre-sign a framework version");

    Codesign::verify(&framework)
        .bundle_version("A")
        .await
        .unwrap();
    let error = Codesign::verify(&framework)
        .bundle_version("B")
        .await
        .unwrap_err();
    verification_failed(error);
}

#[tokio::test]
async fn an_unknown_bundle_version_does_not_verify() {
    let workspace = Workspace::new();
    let framework = workspace.framework("Hello");
    Codesign::sign(&framework, "-").await.unwrap();

    let error = Codesign::verify(&framework)
        .bundle_version("Z")
        .await
        .unwrap_err();

    let stderr = verification_failed(error);
    assert!(
        stderr.contains("cannot find code object on disk"),
        "got {stderr}"
    );
}

#[tokio::test]
async fn the_last_bundle_version_wins() {
    let workspace = Workspace::new();
    let framework = workspace.framework("Hello");
    Codesign::sign(&framework, "-").await.unwrap();

    Codesign::verify(&framework)
        .bundle_version("Z")
        .bundle_version("A")
        .await
        .unwrap();
}
