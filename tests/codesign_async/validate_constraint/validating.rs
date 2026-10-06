//! One plist at a time: which constraints are accepted, which are rejected
//! and what the rejection says.

use signers::codesign::validate_constraint;

use super::{cli_rejection, constraint_invalid};
use crate::support::fixture::{Workspace, fixture};

const ACCEPTED: [&str; 4] = [
    "launch-constraint.plist",
    "constraint-team.plist",
    "constraint-and.plist",
    "constraint-optional-unknown.plist",
];

/// Each rejected plist with the part of the diagnostics that says why.
const REJECTED: [(&str, &str); 4] = [
    (
        "bad-constraint.plist",
        "Unknown Key, Context: bogus-key-xyz",
    ),
    (
        "constraint-nested-unknown.plist",
        "Unknown Key, Context: $or -> bogus-key-xyz",
    ),
    (
        "constraint-empty.plist",
        "Dictionary does not specify any constraints",
    ),
    ("constraint-wrapped.plist", "Unknown Key, Context: comp"),
];

#[tokio::test]
async fn a_valid_constraint_yields_unit() {
    for name in ACCEPTED {
        let plist = fixture(name);
        assert_eq!(cli_rejection(&plist), None, "{name}: harness assumption");

        let (): () = validate_constraint(&plist)
            .await
            .unwrap_or_else(|e| panic!("{name} was rejected: {e}"));
    }
}

#[tokio::test]
async fn an_invalid_constraint_is_rejected_although_codesign_exits_zero() {
    for (name, reason) in REJECTED {
        let plist = fixture(name);
        assert!(
            cli_rejection(&plist).is_some(),
            "{name}: harness assumption"
        );

        let stderr = constraint_invalid(validate_constraint(&plist).await.unwrap_err());

        assert!(stderr.contains("error:"), "{name}: {stderr}");
        assert!(stderr.contains(reason), "{name}: {stderr}");
    }
}

#[tokio::test]
async fn the_rejection_carries_what_codesign_printed() {
    let plist = fixture("bad-constraint.plist");
    let printed = cli_rejection(&plist).expect("harness assumption");

    let stderr = constraint_invalid(validate_constraint(&plist).await.unwrap_err());

    assert_eq!(stderr, printed.trim());
}

#[tokio::test]
async fn the_rejection_message_names_the_reason() {
    let error = validate_constraint(fixture("bad-constraint.plist"))
        .await
        .unwrap_err();

    let message = error.to_string();

    assert!(message.starts_with("invalid constraint: "), "{message}");
    assert!(message.contains("Unknown Key"), "{message}");
}

#[tokio::test]
async fn a_valid_constraint_is_accepted_through_every_target_type() {
    let plist = fixture("constraint-team.plist");

    validate_constraint(plist.clone()).await.unwrap();
    validate_constraint(plist.as_path()).await.unwrap();
    validate_constraint(plist.to_str().unwrap()).await.unwrap();
}

#[tokio::test]
async fn the_plist_is_left_untouched() {
    let workspace = Workspace::new();
    let valid = workspace.write(
        "valid.plist",
        &std::fs::read_to_string(fixture("constraint-team.plist")).unwrap(),
    );
    let invalid = workspace.write(
        "invalid.plist",
        &std::fs::read_to_string(fixture("bad-constraint.plist")).unwrap(),
    );
    let before = [&valid, &invalid].map(|path| std::fs::read(path).unwrap());

    validate_constraint(&valid).await.unwrap();
    validate_constraint(&invalid).await.unwrap_err();

    assert_eq!(std::fs::read(&valid).unwrap(), before[0]);
    assert_eq!(std::fs::read(&invalid).unwrap(), before[1]);
}

/// Spaces, non-ASCII text and a leading dash must reach `codesign` as one
/// intact path, not be split or read as an option.
#[tokio::test]
async fn awkward_plist_paths_are_validated_all_the_same() {
    let workspace = Workspace::new();
    let valid = std::fs::read_to_string(fixture("constraint-team.plist")).unwrap();
    let invalid = std::fs::read_to_string(fixture("bad-constraint.plist")).unwrap();

    workspace.dir("ok");
    workspace.dir("bad");

    for name in [
        "with space.plist",
        "-leading-dash.plist",
        "perché ☃.plist",
        "--validate-constraint",
    ] {
        let ok = workspace.write(format!("ok/{name}"), &valid);
        let bad = workspace.write(format!("bad/{name}"), &invalid);

        validate_constraint(&ok)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        constraint_invalid(validate_constraint(&bad).await.unwrap_err());
    }
}
