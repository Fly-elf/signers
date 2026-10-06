//! `.app` bundles and versioned frameworks: what a removal reaches, what it
//! leaves behind, and `bundle_version` selecting which version it applies to.

use std::ffi::OsStr;

use signers::Codesign;
use signers::codesign::remove_signature;

use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn an_app_bundle_loses_its_signature() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Hello");
    Codesign::sign(&bundle, "-").await.unwrap();
    inspect::assert_valid(&bundle);

    remove_signature(&bundle).await.unwrap();

    assert!(!inspect::is_signed(&bundle));
    // A bundle's signature lives in its main executable, so that is where the
    // removal actually lands.
    assert!(!inspect::is_signed(&bundle.join("Contents/MacOS/Hello")));
}

/// Removal is not a reset: the resource seal is invalidated but the directory
/// that held it stays, empty. Anything rebuilding a bundle from this state has
/// to expect it.
#[tokio::test]
async fn the_code_signature_directory_is_left_behind_empty() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Leftovers");
    Codesign::sign(&bundle, "-").await.unwrap();
    let signature_dir = bundle.join("Contents/_CodeSignature");
    assert!(signature_dir.join("CodeResources").is_file());

    remove_signature(&bundle).await.unwrap();

    assert!(signature_dir.is_dir(), "the directory itself was removed");
    assert!(
        !signature_dir.join("CodeResources").is_file(),
        "the resource seal survived the removal"
    );
}

/// The gotcha worth a test of its own: a caller who strips an app expecting
/// *nothing* signed inside it is wrong, and `--deep` does not change that —
/// which is why the builder has no `deep` setter to reach for.
#[tokio::test]
async fn nested_code_keeps_its_signature() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Host");
    let nested = workspace.framework_in(&bundle.join("Contents/Frameworks"), "Nested");
    Codesign::sign(&nested, "-").await.unwrap();
    Codesign::sign(&bundle, "-").await.unwrap();

    remove_signature(&bundle).await.unwrap();

    assert!(!inspect::is_signed(&bundle));
    assert!(
        inspect::is_signed(&nested),
        "the nested framework was stripped as well"
    );
}

#[tokio::test]
async fn a_framework_loses_its_signature() {
    let workspace = Workspace::new();
    let bundle = workspace.framework("Hello");
    Codesign::sign(&bundle, "-").await.unwrap();
    inspect::assert_valid(&bundle);

    remove_signature(&bundle).await.unwrap();

    assert!(!inspect::is_signed(&bundle));
}

#[tokio::test]
async fn a_bundle_version_selects_which_version_to_strip() {
    let workspace = Workspace::new();
    let bundle = workspace.versioned_framework("Hello", &["A", "B"]);
    for version in ["A", "B"] {
        inspect::codesign(&[
            "--sign".as_ref(),
            "-".as_ref(),
            "--bundle-version".as_ref(),
            OsStr::new(version),
            bundle.as_ref(),
        ])
        .expect_success("pre-sign a framework version");
    }

    remove_signature(&bundle).bundle_version("B").await.unwrap();

    assert!(!inspect::is_signed_version(&bundle, "B"));
    assert!(
        inspect::is_signed_version(&bundle, "A"),
        "the version that was not selected was stripped too"
    );
}

/// Without a selector `codesign` operates on the version `Current` points at,
/// so a default-version removal leaves the others alone.
#[tokio::test]
async fn no_bundle_version_strips_the_current_one() {
    let workspace = Workspace::new();
    let bundle = workspace.versioned_framework("Hello", &["A", "B"]);
    for version in ["A", "B"] {
        inspect::codesign(&[
            "--sign".as_ref(),
            "-".as_ref(),
            "--bundle-version".as_ref(),
            OsStr::new(version),
            bundle.as_ref(),
        ])
        .expect_success("pre-sign a framework version");
    }

    remove_signature(&bundle).await.unwrap();

    assert!(!inspect::is_signed_version(&bundle, "A"));
    assert!(inspect::is_signed_version(&bundle, "B"));
}
