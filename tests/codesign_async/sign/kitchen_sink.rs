//! Every compatible option set at once — not "more of the same" as the other
//! modules, but the guard for a failure mode none of them can catch on their
//! own: an option that's correct alone and silently wrong in company.

use std::fs;

use signers::Codesign;
use signers::codesign::{SigningFlags, Timestamp};

use crate::support::fixture::{Workspace, fixture, output_of};
use crate::support::inspect::{self, Constraint, Signature};

#[tokio::test]
async fn a_fully_loaded_builder_renders_a_command_codesign_accepts() {
    // Individually an option can look fine and still be wrong in company: a
    // misspelled flag, a value passed as `--flag value` where `codesign` only
    // accepts `--flag=value`, or two options that quietly cancel out.
    //
    // The identifier is the one `launch-constraint.plist` insists on: the
    // kernel kills a process that breaches its own launch constraint, and the
    // last assertion here is that the result still runs.
    //
    // `enforce_constraint_validity` stays out: since macOS 27 `codesign` fails
    // every constraint under it, valid or not.
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.previous"]);
    let list = workspace.join("signed.txt");
    let requirement = r#"designated => identifier "com.example.constrained""#;

    Codesign::sign(&target, "-")
        .identifier("com.example.constrained")
        .requirements(format!("={requirement}"))
        .keychain("/nonexistent/does-not.keychain")
        .entitlements(fixture("entitlements.plist"))
        .generate_entitlement_der(true)
        .force_library_entitlements(true)
        .options(SigningFlags::RUNTIME | SigningFlags::KILL | SigningFlags::HARD)
        .runtime_version("13.1")
        .launch_constraint_self(fixture("launch-constraint.plist"))
        .force(true)
        .page_size(4096)
        .timestamp(Timestamp::Disabled)
        .strip_disallowed_xattrs(true)
        .single_threaded_signing(true)
        .file_list(&list)
        .await
        .unwrap();

    inspect::assert_valid(&target);
    let signature = Signature::of(&target);
    assert_eq!(signature.identifier(), "com.example.constrained");
    assert_eq!(
        signature.flags(),
        super::ADHOC
            | SigningFlags::HARD.bits()
            | SigningFlags::KILL.bits()
            | SigningFlags::RUNTIME.bits(),
    );
    assert_eq!(signature.runtime_version(), Some("13.1.0"));
    assert_eq!(signature.page_size(), Some(4096));
    assert!(signature.has_constraint(Constraint::LaunchSelf));
    assert!(inspect::entitlements(&target).contains("allow-jit"));
    assert_eq!(inspect::designated_requirement(&target), requirement);
    assert!(!fs::read_to_string(&list).unwrap().is_empty());
    assert_eq!(output_of(&target), "hello, signers");
}
