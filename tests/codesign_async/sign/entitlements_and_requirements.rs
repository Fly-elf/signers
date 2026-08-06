//! Policy embedded in the signature: entitlements, internal requirements, and
//! launch constraints.

use signers::Codesign;

use crate::support::fixture::{Workspace, fixture};
use crate::support::inspect::{self, Signature};

#[tokio::test]
async fn entitlements_are_embedded() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .entitlements(fixture("entitlements.plist"))
        .await
        .unwrap();

    let entitlements = inspect::entitlements(&target);
    assert!(
        entitlements.contains("com.apple.security.cs.allow-jit"),
        "got {entitlements}"
    );
    assert!(
        entitlements.contains("com.apple.security.get-task-allow"),
        "got {entitlements}"
    );
}

#[tokio::test]
async fn the_entitlement_and_threading_switches_are_accepted_together() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .entitlements(fixture("entitlements.plist"))
        .generate_entitlement_der(true)
        .force_library_entitlements(true)
        .single_threaded_signing(true)
        .await
        .unwrap();

    inspect::assert_valid(&target);
    assert!(inspect::entitlements(&target).contains("allow-jit"));
}

#[tokio::test]
async fn internal_requirements_are_embedded() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let requirement = r#"designated => identifier "com.example.required""#;

    Codesign::sign(&target, "-")
        .identifier("com.example.required")
        .requirements(format!("={requirement}"))
        .await
        .unwrap();

    assert_eq!(inspect::designated_requirement(&target), requirement);
}

#[tokio::test]
async fn a_launch_constraint_is_embedded() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .launch_constraint_self(fixture("launch-constraint.plist"))
        .await
        .unwrap();

    inspect::assert_valid(&target);
    assert!(Signature::of(&target).has_self_launch_constraints());
}

#[tokio::test]
async fn constraint_validity_is_only_enforced_on_request() {
    // The same invalid constraint twice: `codesign` downgrades it to a warning
    // unless asked to treat it as an error.
    let workspace = Workspace::new();
    let tolerated = workspace.unsigned("tolerated");
    let rejected = workspace.unsigned("rejected");

    Codesign::sign(&tolerated, "-")
        .launch_constraint_self(fixture("bad-constraint.plist"))
        .await
        .unwrap();
    inspect::assert_valid(&tolerated);

    let error = Codesign::sign(&rejected, "-")
        .launch_constraint_self(fixture("bad-constraint.plist"))
        .enforce_constraint_validity(true)
        .await
        .unwrap_err();

    assert!(super::codesign_error(error).contains("bogus-key-xyz"));
    assert!(
        !inspect::is_signed(&rejected),
        "the rejected target was signed anyway"
    );
}
