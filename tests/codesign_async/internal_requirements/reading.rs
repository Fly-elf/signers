//! One target, read back: the requirements embedded in how it was signed,
//! compared with what `codesign -d -r-` prints for it.

use std::path::Path;

use signers::Codesign;
use signers::codesign::requirements::{Requirement, RequirementKind};

use super::{lines_of, printed};
use crate::support::fixture::{Workspace, fixture_str};
use crate::support::inspect;

async fn read(path: &Path) -> Vec<Requirement> {
    Codesign::internal_requirements(path)
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

async fn assert_agrees_with_codesign(path: &Path) -> Vec<Requirement> {
    let found = read(path).await;
    assert_eq!(lines_of(&found), printed(path), "{}", path.display());
    found
}

#[tokio::test]
async fn a_system_binary_has_its_explicit_designated_requirement() {
    let found = assert_agrees_with_codesign(Path::new("/bin/ls")).await;

    let [only] = &found[..] else {
        panic!("expected one requirement, got {found:?}")
    };
    assert_eq!(only.kind, RequirementKind::Designated);
    assert_eq!(
        only.expression,
        r#"identifier "com.apple.ls" and anchor apple"#
    );
    assert!(!only.implicit);
}

#[tokio::test]
async fn an_ad_hoc_binary_has_an_implicit_designated_requirement() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let found = assert_agrees_with_codesign(&target).await;

    let [only] = &found[..] else {
        panic!("expected one requirement, got {found:?}")
    };
    assert_eq!(only.kind, RequirementKind::Designated);
    assert!(only.implicit);
    assert!(
        only.expression.starts_with(r#"cdhash H""#),
        "{}",
        only.expression
    );
    assert!(
        only.expression
            .contains(&inspect::Signature::of(&target).cd_hash().to_owned())
    );
}

#[tokio::test]
async fn a_linker_signed_binary_is_read_like_any_ad_hoc_one() {
    let workspace = Workspace::new();
    let target = workspace.linker_signed("hello");

    let found = assert_agrees_with_codesign(&target).await;

    assert!(found.iter().all(|r| r.implicit), "{found:?}");
}

#[tokio::test]
async fn embedded_requirements_come_back_in_the_printed_order() {
    let workspace = Workspace::new();
    let target = workspace.presigned(
        "hello",
        &[
            "-r=host => anchor apple; designated => identifier \"com.example.hello\"; library => identifier \"com.example.lib\"",
        ],
    );

    let found = assert_agrees_with_codesign(&target).await;

    let kinds: Vec<&RequirementKind> = found.iter().map(|r| &r.kind).collect();
    assert_eq!(
        kinds,
        [
            &RequirementKind::Host,
            &RequirementKind::Designated,
            &RequirementKind::Library
        ]
    );
    assert!(found.iter().all(|r| !r.implicit));
    assert_eq!(found[0].expression, "anchor apple");
    assert_eq!(found[1].expression, r#"identifier "com.example.hello""#);
}

#[tokio::test]
async fn the_guest_and_plugin_kinds_are_read_and_the_missing_designated_is_implicit() {
    let workspace = Workspace::new();
    let target = workspace.presigned(
        "hello",
        &["-r=guest => anchor apple; plugin => anchor apple"],
    );

    let found = assert_agrees_with_codesign(&target).await;

    let summary: Vec<(&RequirementKind, bool)> =
        found.iter().map(|r| (&r.kind, r.implicit)).collect();
    assert_eq!(
        summary,
        [
            (&RequirementKind::Guest, false),
            (&RequirementKind::Plugin, false),
            (&RequirementKind::Designated, true),
        ]
    );
}

#[tokio::test]
async fn an_expression_with_quotes_and_spaces_is_kept_whole() {
    let workspace = Workspace::new();
    let target = workspace.presigned(
        "hello",
        &[r#"-r=designated => identifier "com.example.a b" and anchor apple generic"#],
    );

    let found = assert_agrees_with_codesign(&target).await;

    assert_eq!(
        found[0].expression,
        r#"identifier "com.example.a b" and anchor apple generic"#
    );
}

/// Entitlements and constraints ride along in the signature; none of them
/// may leak into the requirements.
#[tokio::test]
async fn requirements_are_read_from_a_target_with_entitlements_and_constraints() {
    let workspace = Workspace::new();
    let entitlements = fixture_str("entitlements.plist");
    let constraint = fixture_str("launch-constraint.plist");
    let target = workspace.presigned(
        "hello",
        &[
            "--entitlements",
            &entitlements,
            "--launch-constraint-self",
            &constraint,
            "--library-constraint",
            &constraint,
            "-r=host => anchor apple; designated => identifier \"com.example.hello\"",
        ],
    );

    let found = assert_agrees_with_codesign(&target).await;

    assert_eq!(found.len(), 2);
}

#[tokio::test]
async fn a_launch_constraint_alone_leaves_the_implicit_requirement_intact() {
    let workspace = Workspace::new();
    let constraint = fixture_str("launch-constraint.plist");
    let target = workspace.presigned("hello", &["--launch-constraint-self", &constraint]);

    let found = assert_agrees_with_codesign(&target).await;

    assert!(!found.is_empty());
    assert!(found.iter().all(|r| r.implicit), "{found:?}");
}

#[tokio::test]
async fn bundles_and_plain_files_have_requirements_too() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Hello");
    super::adhoc_sign(&bundle, &[]);
    let file = workspace.write("notes.txt", "signed text\n");
    super::adhoc_sign(&file, &[]);

    for target in [bundle, file] {
        let found = assert_agrees_with_codesign(&target).await;
        assert!(!found.is_empty(), "{}", target.display());
    }
}

#[tokio::test]
async fn awkward_file_names_do_not_disturb_the_requirements() {
    let workspace = Workspace::new();

    for name in ["with spaces.bin", "-dashed", "ünïcödé", "a => b"] {
        let target = workspace.presigned(name, &[]);

        assert_agrees_with_codesign(&target).await;
    }
}
