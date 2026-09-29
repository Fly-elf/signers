//! Policy embedded in the signature: entitlements, internal requirements, and
//! launch constraints.

use std::path::PathBuf;

use signers::Codesign;
use signers::codesign::sign::Sign;

use crate::support::fixture::{Workspace, fixture};
use crate::support::inspect::{self, Constraint, Signature};

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

/// `codesign` drops entitlements from a library unless told otherwise, and
/// reports success either way.
#[tokio::test]
async fn a_library_keeps_its_entitlements_only_when_forced() {
    let workspace = Workspace::new();
    let dropped = workspace.unsigned_dylib("dropped.dylib");
    let forced = workspace.unsigned_dylib("forced.dylib");

    Codesign::sign(&dropped, "-")
        .entitlements(fixture("entitlements.plist"))
        .await
        .unwrap();
    Codesign::sign(&forced, "-")
        .entitlements(fixture("entitlements.plist"))
        .force_library_entitlements(true)
        .await
        .unwrap();

    let dropped = inspect::entitlements(&dropped);
    assert!(dropped.is_empty(), "entitlements kept unforced: {dropped}");
    assert!(inspect::entitlements(&forced).contains("allow-jit"));
}

/// DER entitlements are what `codesign` generates anyway, and threading leaves
/// no trace in the signature: being accepted is all there is to check.
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
async fn each_constraint_is_embedded_as_its_own_kind() {
    type Setter = fn(Codesign<Sign>, PathBuf) -> Codesign<Sign>;
    let cases: [(Setter, Constraint); 4] = [
        (|b, p| b.launch_constraint_self(p), Constraint::LaunchSelf),
        (
            |b, p| b.launch_constraint_parent(p),
            Constraint::LaunchParent,
        ),
        (
            |b, p| b.launch_constraint_responsible(p),
            Constraint::LaunchResponsible,
        ),
        (|b, p| b.library_constraint(p), Constraint::Library),
    ];
    let workspace = Workspace::new();

    for (index, (set, kind)) in cases.into_iter().enumerate() {
        let target = workspace.unsigned(format!("constrained-{index}"));

        set(
            Codesign::sign(&target, "-"),
            fixture("launch-constraint.plist"),
        )
        .await
        .unwrap_or_else(|e| panic!("`codesign` rejected {kind:?}: {e}"));

        inspect::assert_valid(&target);
        let signature = Signature::of(&target);
        for other in Constraint::ALL {
            assert_eq!(
                signature.has_constraint(other),
                other == kind,
                "{other:?} after setting {kind:?}",
            );
        }
    }
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

    assert!(crate::codesign_error(error).contains("bogus-key-xyz"));
    assert!(
        !inspect::is_signed(&rejected),
        "the rejected target was signed anyway"
    );
}
