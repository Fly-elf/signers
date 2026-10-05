//! Every action run once on a valid target, the result checked against what
//! the real `codesign` reports.

use std::path::Path;

use signers::blocking::Codesign;
use signers::codesign::RequirementKind;

use crate::support::fixture::{Workspace, fixture};
use crate::support::inspect;

#[test]
fn sign_signs_the_target() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let () = Codesign::sign(&target, "-").run().unwrap();

    inspect::assert_valid(&target);
}

/// Re-signing needs `--force`: its success shows the setter reached `codesign`.
#[test]
fn sign_adhoc_re_signs_with_the_options_set() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.original"]);

    let () = Codesign::sign_adhoc(&target)
        .force(true)
        .identifier("com.example.blocking")
        .run()
        .unwrap();

    inspect::assert_valid(&target);
    assert_eq!(
        inspect::Signature::of(&target).identifier(),
        "com.example.blocking"
    );
}

#[test]
fn remove_signature_strips_the_signature() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let () = Codesign::remove_signature(&target).run().unwrap();

    assert!(!inspect::is_signed(&target), "the signature is still there");
}

#[test]
fn verify_accepts_a_valid_signature() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let () = Codesign::verify(&target).run().unwrap();

    inspect::assert_valid(&target);
}

#[test]
fn display_reports_what_codesign_reports() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let signature = Codesign::display(&target).run().unwrap();

    let oracle = inspect::Signature::of(&target);
    assert_eq!(signature.raw(), oracle.raw());
    assert_eq!(signature.field("Identifier"), Some(oracle.identifier()));
}

#[test]
fn internal_requirements_reads_the_designated_requirement() {
    let target = Path::new("/bin/ls");

    let found = Codesign::internal_requirements(target).run().unwrap();

    let [only] = &found[..] else {
        panic!("expected one requirement, got {found:?}")
    };
    assert_eq!(only.kind, RequirementKind::Designated);
    assert!(!only.implicit);
    assert_eq!(
        format!("designated => {}", only.expression),
        inspect::designated_requirement(target)
    );
}

#[test]
fn validate_constraint_accepts_a_valid_constraint() {
    let () = Codesign::validate_constraint(fixture("constraint-team.plist"))
        .run()
        .unwrap();
}

#[test]
fn extract_certificates_yields_the_chain_codesign_extracts() {
    let target = Path::new("/bin/ls");

    let chain = Codesign::extract_certificates(target).run().unwrap();

    let expected = inspect::certificates(target);
    assert!(!expected.is_empty(), "/bin/ls carries no chain");
    let ders: Vec<&[u8]> = chain.iter().map(|certificate| certificate.der()).collect();
    assert_eq!(ders, expected);
}

#[test]
fn extract_certificates_saves_the_chain_where_asked() {
    let workspace = Workspace::new();
    let out = workspace.join("certificates");

    Codesign::extract_certificates("/bin/ls")
        .save_to(&out)
        .run()
        .unwrap();

    let saved = std::fs::read_to_string(out.join("ls.pem")).unwrap();
    let expected: String = inspect::certificates(Path::new("/bin/ls"))
        .iter()
        .map(|der| inspect::pem(der))
        .collect();
    assert_eq!(saved, expected);
}
