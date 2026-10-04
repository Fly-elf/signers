//! The internal requirements of a single target, read from `codesign -r-` and
//! compared with the lines the CLI prints for the same target.

use std::path::{Path, PathBuf};

use signers::Codesign;
use signers::codesign::display::{Requirement, RequirementKind};

use crate::support::fixture::{Workspace, fixture_str};
use crate::support::inspect;

/// What `codesign -d -r-` prints on stdout for `path`, one entry per line.
fn printed(path: &Path) -> Vec<String> {
    inspect::codesign(&["-d".as_ref(), "-r-".as_ref(), path.as_ref()])
        .expect_success("print the requirements")
        .stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn word(kind: &RequirementKind) -> &str {
    match kind {
        RequirementKind::Designated => "designated",
        RequirementKind::Host => "host",
        RequirementKind::Guest => "guest",
        RequirementKind::Library => "library",
        RequirementKind::Plugin => "plugin",
        RequirementKind::Other(word) => word,
        _ => panic!("a kind this test does not know: {kind:?}"),
    }
}

/// The line `codesign` would print for `requirement`.
fn line_of(requirement: &Requirement) -> String {
    format!(
        "{}{} => {}",
        if requirement.implicit { "# " } else { "" },
        word(&requirement.kind),
        requirement.expression
    )
}

async fn read(path: &Path) -> Vec<Requirement> {
    Codesign::display(path)
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .requirements
        .expect("a single target has requirements")
}

async fn assert_agrees_with_codesign(path: &Path) -> Vec<Requirement> {
    let found = read(path).await;
    let lines: Vec<String> = found.iter().map(line_of).collect();
    assert_eq!(lines, printed(path), "{}", path.display());
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

/// The constraint dump and the entitlements plist surround the requirement
/// lines on stdout; all three must be told apart.
#[tokio::test]
async fn requirements_are_read_between_a_constraint_dump_and_the_entitlements() {
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

    let signature = Codesign::display(&target).await.unwrap();

    let found = signature.requirements.expect("no requirements read");
    let lines: Vec<String> = found.iter().map(line_of).collect();
    assert_eq!(lines, printed(&target));
    assert_eq!(found.len(), 2);
    let expected: plist::Dictionary =
        plist::from_bytes(inspect::entitlements(&target).as_bytes()).unwrap();
    assert!(!expected.is_empty());
    assert_eq!(signature.entitlements, Some(expected));
}

#[tokio::test]
async fn a_constraint_dump_without_entitlements_leaves_the_requirements_intact() {
    let workspace = Workspace::new();
    let constraint = fixture_str("launch-constraint.plist");
    let target = workspace.presigned("hello", &["--launch-constraint-self", &constraint]);

    let signature = Codesign::display(&target).await.unwrap();

    assert_eq!(signature.entitlements, None);
    let lines: Vec<String> = signature
        .requirements
        .unwrap()
        .iter()
        .map(line_of)
        .collect();
    assert_eq!(lines, printed(&target));
    assert!(!lines.is_empty());
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

#[tokio::test]
async fn requirements_do_not_alter_the_raw_report() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-r=designated => anchor apple"]);

    let signature = Codesign::display(&target).await.unwrap();

    assert_eq!(signature.raw(), inspect::Signature::of(&target).raw());
}

/// One `codesign` per target, the default for a collection, can attribute
/// each target's requirements; one process for all of them cannot.
#[tokio::test]
async fn collections_read_requirements_per_target_unless_run_as_one_process() {
    let workspace = Workspace::new();
    let targets: Vec<PathBuf> = vec![
        workspace.presigned("first", &["-i", "com.example.first"]),
        workspace.presigned(
            "second",
            &["-r=designated => identifier \"com.example.second\""],
        ),
        PathBuf::from("/bin/ls"),
    ];

    let separate = Codesign::display(targets.clone()).await.unwrap();
    let together = Codesign::display(targets.clone())
        .per_target(false)
        .await
        .unwrap();

    for (signature, target) in separate.iter().zip(&targets) {
        let lines: Vec<String> = signature
            .requirements
            .as_ref()
            .expect("per target keeps requirements")
            .iter()
            .map(line_of)
            .collect();
        assert_eq!(lines, printed(target), "{}", target.display());
    }
    assert!(together.iter().all(|s| s.requirements.is_none()));
    let [a, b] = Codesign::display([targets[0].clone(), targets[1].clone()])
        .await
        .unwrap();
    assert!(a.requirements.is_some() && b.requirements.is_some());
    let [a, b] = Codesign::display([targets[0].clone(), targets[1].clone()])
        .per_target(false)
        .await
        .unwrap();
    assert!(a.requirements.is_none() && b.requirements.is_none());
}

#[tokio::test]
async fn a_single_target_given_as_a_collection_has_requirements() {
    for per_target in [true, false] {
        let signatures = Codesign::display(vec!["/bin/ls"])
            .per_target(per_target)
            .await
            .unwrap();

        assert_eq!(
            signatures[0]
                .requirements
                .as_ref()
                .map(|r| r.iter().map(line_of).collect::<Vec<_>>()),
            Some(printed(Path::new("/bin/ls"))),
            "per_target({per_target})"
        );
    }
}
