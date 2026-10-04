//! `signature_slot` on display: which of a code object's signatures is
//! reported. Every signature this machine can make is a single one, so the
//! second slot is only ever checked against what `codesign` itself answers.

use std::path::Path;

use signers::Codesign;
use signers::codesign::SignatureSlot;

use crate::support::fixture::Workspace;
use crate::support::inspect;

/// The `codesign --display --verbose=4` run for `path` in `slot`.
fn oracle(path: &Path, slot: &str) -> inspect::Run {
    inspect::codesign(&[
        "--display".as_ref(),
        "--verbose=4".as_ref(),
        "--signature-slot".as_ref(),
        slot.as_ref(),
        path.as_ref(),
    ])
}

/// The value of a `Key=value` line of the report `codesign` printed.
fn printed(run: &inspect::Run, key: &str) -> String {
    let prefix = format!("{key}=");
    run.stderr
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {key} line in {}", run.stderr))
        .to_owned()
}

/// The identity of the signature read from `path` in `slot` must be the one
/// `codesign` reports for it.
fn assert_reads_slot(signature: &signers::codesign::display::Signature, path: &Path, slot: &str) {
    let expected = oracle(path, slot);
    assert!(expected.success, "{}", expected.stderr);
    assert_eq!(signature.identifier, printed(&expected, "Identifier"));
    assert_eq!(signature.cd_hash, printed(&expected, "CDHash"));
    assert_eq!(
        signature.executable,
        Path::new(&printed(&expected, "Executable"))
    );
}

#[tokio::test]
async fn the_first_slot_reads_the_same_report_as_no_slot() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.slot"]);

    for path in [target.as_path(), Path::new("/bin/ls")] {
        let default = Codesign::display(path).await.unwrap();
        let first = Codesign::display(path)
            .signature_slot(SignatureSlot::First)
            .await
            .unwrap();

        assert_eq!(first.raw(), default.raw(), "{}", path.display());
        assert_reads_slot(&first, path, "1");
        assert_eq!(first.requirements, default.requirements);
    }
}

#[tokio::test]
async fn the_second_slot_of_an_ad_hoc_binary_follows_codesign() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.slot"]);

    let signature = Codesign::display(&target)
        .signature_slot(SignatureSlot::Second)
        .await
        .unwrap();

    assert_reads_slot(&signature, &target, "2");
    assert_eq!(signature.identifier, "com.example.slot");
}

#[tokio::test]
async fn an_unsigned_target_fails_in_either_slot() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    for slot in [SignatureSlot::First, SignatureSlot::Second] {
        let error = Codesign::display(&target)
            .signature_slot(slot)
            .await
            .unwrap_err();

        let stderr = crate::codesign_error(error);
        assert!(
            stderr.contains("code object is not signed at all"),
            "{slot:?}: {stderr}"
        );
    }
}

#[tokio::test]
async fn the_last_slot_wins() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let signature = Codesign::display(&target)
        .signature_slot(SignatureSlot::Second)
        .signature_slot(SignatureSlot::First)
        .await
        .unwrap();

    assert_reads_slot(&signature, &target, "1");
}

#[tokio::test]
async fn a_slot_applies_to_every_target_of_a_collection() {
    let workspace = Workspace::new();
    let targets = vec![
        workspace.presigned("first", &["-i", "com.example.first"]),
        workspace.presigned("second", &["-i", "com.example.second"]),
    ];

    for per_target in [true, false] {
        let signatures = Codesign::display(targets.clone())
            .signature_slot(SignatureSlot::First)
            .per_target(per_target)
            .await
            .unwrap();

        for (signature, target) in signatures.iter().zip(&targets) {
            assert_reads_slot(signature, target, "1");
        }
    }
}

#[tokio::test]
async fn a_slot_combines_with_the_other_display_options() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("Host");
    super::adhoc_sign(&app, &[]);

    let signature = Codesign::display(&app)
        .signature_slot(SignatureSlot::First)
        .deep(true)
        .await
        .unwrap();

    assert_eq!(signature.identifier, "com.example.Host");
}
