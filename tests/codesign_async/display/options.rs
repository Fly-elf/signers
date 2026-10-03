//! The display options: which slice, which bundle version, nested code, and a
//! detached signature. Each is checked against the report the CLI prints when
//! handed the same flag.

use signers::Codesign;
use signers::codesign::display::{Format, Location};

use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn the_architecture_picks_one_slice_of_a_universal_binary() {
    let workspace = Workspace::new();
    let Some(target) = workspace.unsigned_universal("universal") else {
        crate::support::skip!("this toolchain cannot build a universal binary");
    };
    super::adhoc_sign(&target, &[]);

    for arch in ["x86_64", "arm64"] {
        let signature = Codesign::display(&target)
            .architecture(arch)
            .await
            .unwrap_or_else(|e| panic!("{arch}: {e}"));

        assert_eq!(signature.format, Format::MachOThin(arch.to_owned()));
        assert_eq!(
            signature.raw(),
            super::report(&target, &["--architecture", arch])
        );
        assert_eq!(
            signature.cd_hash,
            inspect::Signature::of_arch(&target, arch).cd_hash()
        );
    }
}

#[tokio::test]
async fn the_bundle_version_picks_one_version_of_a_framework() {
    let workspace = Workspace::new();
    let framework = workspace.versioned_framework("Kit", &["A", "B"]);
    for version in ["A", "B"] {
        let identifier = format!("com.example.Kit.{version}");
        super::adhoc_sign(
            &framework,
            &["--bundle-version", version, "-i", &identifier],
        );
    }

    let current = Codesign::display(&framework).await.unwrap();
    let chosen = Codesign::display(&framework)
        .bundle_version("B")
        .await
        .unwrap();

    assert_eq!(current.identifier, "com.example.Kit.A");
    assert_eq!(chosen.identifier, "com.example.Kit.B");
    assert!(
        chosen.executable.ends_with("Versions/B/Kit"),
        "{}",
        chosen.executable.display()
    );
    assert_eq!(
        chosen.raw(),
        super::report(&framework, &["--bundle-version", "B"])
    );
}

#[tokio::test]
async fn deep_lists_the_nested_code_and_only_then() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("Host");
    let frameworks = app.join("Contents/Frameworks");
    std::fs::create_dir_all(&frameworks).unwrap();
    workspace.framework_in(&frameworks, "Inner");
    workspace.framework_in(&frameworks, "Other");
    super::adhoc_sign(&app, &["--deep"]);

    let shallow = Codesign::display(&app).await.unwrap();
    let deep = Codesign::display(&app).deep(true).await.unwrap();
    let undone = Codesign::display(&app)
        .deep(true)
        .deep(false)
        .await
        .unwrap();

    let printed: Vec<String> = super::report(&app, &["--deep"])
        .lines()
        .filter_map(|line| line.strip_prefix("Nested="))
        .map(str::to_owned)
        .collect();
    assert_eq!(printed.len(), 2, "the CLI printed {printed:?}");
    assert_eq!(deep.nested, printed);
    assert!(shallow.nested.is_empty(), "{:?}", shallow.nested);
    assert!(undone.nested.is_empty(), "{:?}", undone.nested);
}

#[tokio::test]
async fn a_detached_signature_is_read_for_its_target() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let detached = workspace.join("hello.sig");
    let detached_arg = detached.to_str().unwrap();
    super::adhoc_sign(
        &target,
        &["--detached", detached_arg, "-i", "com.example.detached"],
    );
    assert!(!inspect::is_signed(&target), "the signature was embedded");

    let signature = Codesign::display(&target)
        .detached(&detached)
        .await
        .unwrap();

    assert_eq!(signature.identifier, "com.example.detached");
    assert_eq!(
        signature.code_directory.location,
        Location::ExplicitDetached
    );
    assert_eq!(
        signature.raw(),
        super::report(&target, &["--detached", detached_arg])
    );
}
