//! Signing a target that starts out unsigned: the happy path, identifier
//! derivation, and everything `IntoTargets` accepts to get there.

use signers::codesign::Codesign;

use crate::support::fixture::{Workspace, output_of};
use crate::support::inspect::{self, Signature};

#[tokio::test]
async fn an_unsigned_binary_gets_a_valid_ad_hoc_signature() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    assert!(
        !inspect::is_signed(&target),
        "the fixture started out signed"
    );

    Codesign::sign(&target, "-").await.unwrap();

    inspect::assert_valid(&target);
    let signature = Signature::of(&target);
    assert_eq!(signature.signature(), "adhoc");
    assert_eq!(signature.flags(), super::ADHOC);
    assert_eq!(signature.flag_names(), ["adhoc"]);
    assert!(
        signature.format().starts_with("Mach-O"),
        "got {}",
        signature.format()
    );
}

#[tokio::test]
async fn a_signed_binary_still_runs() {
    // Apple Silicon refuses to execute code whose signature does not check out,
    // so this is the end-to-end proof that signing left the Mach-O intact.
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-").await.unwrap();

    assert_eq!(output_of(&target), "hello, signers");
}

#[tokio::test]
async fn every_slice_of_a_universal_binary_is_signed() {
    // The realistic shape for a re-signed app binary: each slice carries its
    // own CodeDirectory, and one `sign` has to cover all of them.
    let workspace = Workspace::new();
    let Some(target) = workspace.unsigned_universal("hello-universal") else {
        return; // this toolchain has only one architecture's SDK
    };

    Codesign::sign(&target, "-")
        .identifier("com.example.universal")
        .await
        .unwrap();

    inspect::assert_valid(&target);
    let signature = Signature::of(&target);
    assert!(
        signature.format().starts_with("Mach-O universal"),
        "got {}",
        signature.format()
    );
    for arch in ["arm64", "x86_64"] {
        let slice = Signature::of_arch(&target, arch);
        assert_eq!(
            slice.identifier(),
            "com.example.universal",
            "in the {arch} slice"
        );
        assert_eq!(slice.flags(), super::ADHOC, "in the {arch} slice");
    }
    assert_eq!(output_of(&target), "hello, signers");
}

#[tokio::test]
async fn the_identifier_is_derived_from_the_file_name() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-").await.unwrap();

    // `codesign` appends a hash of the enclosing directory when the derived
    // identifier contains no dot, so only the stem is predictable.
    let identifier = Signature::of(&target).identifier().to_string();
    assert!(identifier.starts_with("hello"), "got {identifier}");
}

#[tokio::test]
async fn an_explicit_identifier_replaces_the_derived_one() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .identifier("com.example.explicit")
        .await
        .unwrap();

    assert_eq!(Signature::of(&target).identifier(), "com.example.explicit");
}

#[tokio::test]
async fn a_prefix_completes_a_derived_identifier() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    Codesign::sign(&target, "-")
        .prefix("com.example.")
        .await
        .unwrap();

    assert_eq!(Signature::of(&target).identifier(), "com.example.hello");
}

#[tokio::test]
async fn every_target_in_a_batch_is_signed() {
    let workspace = Workspace::new();
    let targets = ["first", "second", "third"].map(|name| workspace.unsigned(name));

    Codesign::sign(targets.to_vec(), "-")
        .identifier("com.example.batch")
        .await
        .unwrap();

    for target in &targets {
        inspect::assert_valid(target);
        assert_eq!(Signature::of(target).identifier(), "com.example.batch");
    }
}

#[tokio::test]
async fn every_kind_of_target_argument_reaches_codesign() {
    let workspace = Workspace::new();
    let as_str = workspace.unsigned("as_str");
    let as_string = workspace.unsigned("as_string");
    let as_os_string = workspace.unsigned("as_os_string");
    let as_path = workspace.unsigned("as_path");
    let as_path_buf = workspace.unsigned("as_path_buf");
    let as_path_buf_ref = workspace.unsigned("as_path_buf_ref");
    let as_vec = workspace.unsigned("as_vec");
    let as_slice = workspace.unsigned("as_slice");

    Codesign::sign(as_str.to_str().unwrap(), "-").await.unwrap();
    Codesign::sign(as_string.to_str().unwrap().to_owned(), "-")
        .await
        .unwrap();
    Codesign::sign(as_os_string.clone().into_os_string(), "-")
        .await
        .unwrap();
    Codesign::sign(as_path.as_path(), "-").await.unwrap();
    Codesign::sign(as_path_buf.clone(), "-").await.unwrap();
    // The one a caller reaches for most: a borrowed field, neither cloned nor
    // narrowed to `&Path` at the call site.
    Codesign::sign(&as_path_buf_ref, "-").await.unwrap();
    Codesign::sign(vec![as_vec.clone()], "-").await.unwrap();
    Codesign::sign(std::slice::from_ref(&as_slice), "-")
        .await
        .unwrap();

    for target in [
        as_str,
        as_string,
        as_os_string,
        as_path,
        as_path_buf,
        as_path_buf_ref,
        as_vec,
        as_slice,
    ] {
        inspect::assert_valid(&target);
    }
}

#[tokio::test]
async fn spaces_and_non_ascii_in_a_path_are_passed_through_verbatim() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("héllo wörld ✓.bin");

    Codesign::sign(&target, "-")
        .identifier("com.example.unicode")
        .await
        .unwrap();

    inspect::assert_valid(&target);
    assert_eq!(Signature::of(&target).identifier(), "com.example.unicode");
}
