//! Several targets: one `codesign` per target by default, one for all of them
//! with `per_target(false)`, and what each does with entitlements and with a
//! target that has no signature.

use std::path::PathBuf;

use signers::Codesign;
use signers::codesign::display::Signature;

use crate::support::fixture::{Workspace, fixture_str};
use crate::support::inspect;

/// Three targets told apart by identifier; the middle one has entitlements.
fn three_targets(workspace: &Workspace) -> Vec<PathBuf> {
    let entitlements = fixture_str("entitlements.plist");
    vec![
        workspace.presigned("first", &["-i", "com.example.first"]),
        workspace.presigned(
            "second",
            &["-i", "com.example.second", "--entitlements", &entitlements],
        ),
        workspace.presigned("third", &["-i", "com.example.third"]),
    ]
}

fn identifiers(signatures: &[Signature]) -> Vec<&str> {
    signatures.iter().map(|s| s.identifier.as_str()).collect()
}

#[tokio::test]
async fn each_target_gets_its_own_signature_in_input_order() {
    let workspace = Workspace::new();
    let mut targets = three_targets(&workspace);
    targets.reverse();

    for per_target in [true, false] {
        let signatures = Codesign::display(targets.clone())
            .per_target(per_target)
            .await
            .unwrap();

        assert_eq!(
            identifiers(&signatures),
            [
                "com.example.third",
                "com.example.second",
                "com.example.first"
            ],
            "per_target({per_target})"
        );
        for (signature, target) in signatures.iter().zip(&targets) {
            assert_eq!(
                signature.raw().trim_end(),
                inspect::Signature::of(target).raw(),
                "per_target({per_target})"
            );
        }
    }
}

#[tokio::test]
async fn an_array_of_targets_yields_an_array_of_signatures() {
    let workspace = Workspace::new();
    let [first, second, _] = <[PathBuf; 3]>::try_from(three_targets(&workspace)).unwrap();

    let [a, b] = Codesign::display([first, second]).await.unwrap();

    assert_eq!(a.identifier, "com.example.first");
    assert_eq!(b.identifier, "com.example.second");
}

/// Entitlements can only be attributed when `codesign` sees one target at a
/// time, which is what a collection does unless told otherwise.
#[tokio::test]
async fn entitlements_are_read_per_target_by_default() {
    let workspace = Workspace::new();
    let targets = three_targets(&workspace);

    let signatures = Codesign::display(targets.clone()).await.unwrap();

    let expected: plist::Dictionary =
        plist::from_bytes(inspect::entitlements(&targets[1]).as_bytes()).unwrap();
    assert_eq!(signatures[0].entitlements, None);
    assert_eq!(signatures[1].entitlements, Some(expected));
    assert_eq!(signatures[2].entitlements, None);
}

#[tokio::test]
async fn one_run_for_all_targets_reads_no_entitlements() {
    let workspace = Workspace::new();
    let targets = three_targets(&workspace);

    let signatures = Codesign::display(targets).per_target(false).await.unwrap();

    assert!(
        signatures.iter().all(|s| s.entitlements.is_none()),
        "{:?}",
        signatures
            .iter()
            .map(|s| &s.entitlements)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn unsigned_targets_are_collected_in_input_order_by_default() {
    let workspace = Workspace::new();
    let first_unsigned = workspace.unsigned("first unsigned");
    let signed = workspace.adhoc_signed("signed");
    let second_unsigned = workspace.unsigned("second unsigned");

    let error = Codesign::display(vec![
        first_unsigned.clone(),
        signed,
        second_unsigned.clone(),
    ])
    .await
    .unwrap_err();

    let failures = crate::batch_failures(error);
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, [&first_unsigned, &second_unsigned]);
    for (path, error) in failures {
        let stderr = crate::codesign_error(error);
        assert!(
            stderr.contains("code object is not signed at all"),
            "{stderr}"
        );
        assert!(stderr.contains(&path.display().to_string()), "{stderr}");
    }
}

/// One process stops at the first target with no signature, after printing
/// the reports of the targets before it.
#[tokio::test]
async fn one_run_for_all_targets_fails_as_a_whole_on_an_unsigned_target() {
    let workspace = Workspace::new();
    let signed = workspace.presigned("signed", &["-i", "com.example.signed"]);
    let unsigned = workspace.unsigned("unsigned");

    let error = Codesign::display(vec![signed, unsigned.clone()])
        .per_target(false)
        .await
        .unwrap_err();

    let stderr = crate::codesign_error(error);
    assert!(
        stderr.contains("code object is not signed at all"),
        "{stderr}"
    );
    assert!(stderr.contains(&unsigned.display().to_string()), "{stderr}");
    assert!(stderr.contains("Identifier=com.example.signed"), "{stderr}");
}

/// Mixed kinds of target in one run, each report still matched to its own.
#[tokio::test]
async fn targets_of_different_kinds_are_told_apart() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Hello");
    super::adhoc_sign(&bundle, &[]);
    let file = workspace.write("notes.txt", "signed text\n");
    super::adhoc_sign(&file, &[]);
    let binary = workspace.adhoc_signed("hello");
    let targets = vec![bundle, file, binary];

    for per_target in [true, false] {
        let signatures = Codesign::display(targets.clone())
            .per_target(per_target)
            .await
            .unwrap();

        for (signature, target) in signatures.iter().zip(&targets) {
            assert_eq!(
                signature.identifier,
                inspect::Signature::of(target).identifier(),
                "per_target({per_target})"
            );
        }
    }
}
