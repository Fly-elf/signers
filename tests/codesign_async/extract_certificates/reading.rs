//! One target at a time: the chain read back, its order, ad hoc and unsigned
//! targets, and target paths `codesign` could misread.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use signers::{Codesign, CodesignError, Error};

use super::{PLATFORM_BINARY, SYSTEM_APP, ders, platform_copy};
use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn a_signed_binary_yields_its_chain_as_codesign_extracts_it() {
    let target = Path::new(PLATFORM_BINARY);

    let chain = Codesign::extract_certificates(target).await.unwrap();

    let expected = inspect::certificates(target);
    assert!(!expected.is_empty(), "{PLATFORM_BINARY} carries no chain");
    assert_eq!(ders(&chain), expected);
}

#[tokio::test]
async fn the_chain_runs_from_the_leaf_to_the_root() {
    let chain = Codesign::extract_certificates(PLATFORM_BINARY)
        .await
        .unwrap();

    let names: Vec<(String, String)> = chain
        .iter()
        .map(|certificate| inspect::subject_and_issuer(certificate.der()))
        .collect();
    assert!(names.len() >= 2, "no intermediate to order: {names:?}");
    for pair in names.windows(2) {
        assert_eq!(
            pair[0].1, pair[1].0,
            "not issued by the next one: {names:?}"
        );
    }
    let (root_subject, root_issuer) = names.last().unwrap();
    assert_eq!(
        root_subject, root_issuer,
        "the last one is no root: {names:?}"
    );
}

#[tokio::test]
async fn into_der_hands_back_the_bytes_der_shows() {
    let chain = Codesign::extract_certificates(PLATFORM_BINARY)
        .await
        .unwrap();

    for certificate in chain {
        let shown = certificate.der().to_vec();
        assert_eq!(certificate.into_der(), shown);
    }
}

#[tokio::test]
async fn a_bundle_yields_the_chain_of_its_signature() {
    let chain = Codesign::extract_certificates(SYSTEM_APP).await.unwrap();

    let expected = inspect::certificates(Path::new(SYSTEM_APP));
    assert!(!expected.is_empty(), "{SYSTEM_APP} carries no chain");
    assert_eq!(ders(&chain), expected);
}

#[tokio::test]
async fn an_ad_hoc_signature_has_no_certificates() {
    let workspace = Workspace::new();
    let targets = [
        workspace.adhoc_signed("hello"),
        workspace.presigned("identified", &["-i", "com.example.identified"]),
    ];

    for target in targets {
        let chain = Codesign::extract_certificates(&target).await.unwrap();

        assert_eq!(chain, [], "{}", target.display());
    }
}

#[tokio::test]
async fn an_unsigned_target_is_a_codesign_failure() {
    let workspace = Workspace::new();
    let targets = [
        workspace.unsigned("hello"),
        workspace.write("notes.txt", "never signed\n"),
    ];

    for target in targets {
        let error = Codesign::extract_certificates(&target).await.unwrap_err();

        let Error::Codesign(CodesignError::Failed {
            code: 1, stderr, ..
        }) = error
        else {
            panic!("expected `codesign` to exit 1, got {error:?}");
        };
        assert!(
            stderr.contains("code object is not signed at all"),
            "{stderr}"
        );
        assert!(stderr.contains(&target.display().to_string()), "{stderr}");
    }
}

/// Spaces, a leading `-` and characters beyond ASCII (APFS refuses names that
/// are not UTF-8), in the target's own name and in a directory above it.
#[tokio::test]
async fn awkward_target_paths_are_read_as_given() {
    let workspace = Workspace::new();
    let awkward_dir = workspace.dir("-dir with space");
    let non_ascii = OsStr::new("café ls");
    let targets: Vec<PathBuf> = vec![
        platform_copy(&workspace, "with space"),
        platform_copy(&workspace, "-leading-dash"),
        platform_copy(&workspace, non_ascii),
        platform_copy(&workspace, awkward_dir.join("-nested")),
    ];
    let expected = inspect::certificates(Path::new(PLATFORM_BINARY));

    for target in targets {
        let chain = Codesign::extract_certificates(&target).await.unwrap();

        assert_eq!(ders(&chain), expected, "{}", target.display());
    }
}
