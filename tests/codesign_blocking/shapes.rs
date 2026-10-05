//! What `.run()` yields for each shape of targets: one output for one path, a
//! `Vec` for a `Vec` or slice, an array for an array, always in input order.

use std::path::{Path, PathBuf};

use signers::blocking::Codesign;
use signers::codesign::Signature;

use crate::support::fixture::Workspace;
use crate::support::inspect;

const TARGETS: [&str; 3] = ["/bin/ls", "/bin/cat", "/bin/echo"];

fn reports(signatures: &[Signature]) -> Vec<&str> {
    signatures.iter().map(Signature::raw).collect()
}

fn oracle() -> Vec<String> {
    TARGETS
        .iter()
        .map(|target| inspect::Signature::of(Path::new(target)).raw().to_owned())
        .collect()
}

#[test]
fn one_path_yields_one_output() {
    let signature: Signature = Codesign::display(TARGETS[1]).run().unwrap();

    assert_eq!(signature.raw(), oracle()[1]);
}

#[test]
fn a_collection_yields_one_output_per_target_in_order_both_ways() {
    let expected = oracle();

    for per_target in [true, false] {
        let from_vec: Vec<Signature> = Codesign::display(TARGETS.to_vec())
            .per_target(per_target)
            .run()
            .unwrap();
        let from_slice: Vec<Signature> = Codesign::display(&TARGETS[..])
            .per_target(per_target)
            .run()
            .unwrap();
        let from_array: [Signature; 3] = Codesign::display(TARGETS)
            .per_target(per_target)
            .run()
            .unwrap();

        assert_eq!(reports(&from_vec), expected, "per_target({per_target})");
        assert_eq!(reports(&from_slice), expected, "per_target({per_target})");
        assert_eq!(reports(&from_array), expected, "per_target({per_target})");
    }
}

#[test]
fn a_batch_changes_every_target_both_ways() {
    for per_target in [false, true] {
        let workspace = Workspace::new();
        let targets: Vec<PathBuf> = ["a", "b", "c"]
            .into_iter()
            .map(|name| workspace.unsigned(name))
            .collect();

        let outputs: Vec<()> = Codesign::sign_adhoc(targets.clone())
            .per_target(per_target)
            .run()
            .unwrap();
        assert_eq!(outputs.len(), 3, "per_target({per_target})");
        targets
            .iter()
            .for_each(|target| inspect::assert_valid(target));

        let [(), ()] = Codesign::remove_signature([&targets[0], &targets[2]])
            .per_target(per_target)
            .run()
            .unwrap();
        assert!(!inspect::is_signed(&targets[0]), "per_target({per_target})");
        inspect::assert_valid(&targets[1]);
        assert!(!inspect::is_signed(&targets[2]), "per_target({per_target})");
    }
}

/// An action that always runs one process per target still yields its outputs
/// in the shape and order of its targets.
#[test]
fn an_action_without_the_setter_keeps_the_shape() {
    let [first, second] = Codesign::extract_certificates(["/bin/ls", "/bin/cat"])
        .run()
        .unwrap();
    let ders = |chain: &[signers::codesign::Certificate]| -> Vec<Vec<u8>> {
        chain.iter().map(|c| c.der().to_vec()).collect()
    };

    assert_eq!(ders(&first), inspect::certificates(Path::new("/bin/ls")));
    assert_eq!(ders(&second), inspect::certificates(Path::new("/bin/cat")));

    let found = Codesign::internal_requirements(vec!["/bin/ls", "/bin/cat"])
        .run()
        .unwrap();
    assert_eq!(found.len(), 2);
    for (requirements, target) in found.iter().zip(["/bin/ls", "/bin/cat"]) {
        let [only] = &requirements[..] else {
            panic!("expected one requirement for {target}, got {requirements:?}")
        };
        assert_eq!(
            format!("designated => {}", only.expression),
            inspect::designated_requirement(Path::new(target))
        );
    }
}
