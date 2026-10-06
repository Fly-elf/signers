//! The checks made before any `codesign` starts: a refused run is one plain
//! error, whichever way the batch is split, and no target is touched.

use std::fs;
use std::path::PathBuf;

use signers::Error;
use signers::codesign::blocking::{display, sign, sign_adhoc, sign_for_distribution, verify};
use signers::codesign::blocking::{
    extract_certificates, remove_signature, requirements, validate_constraint,
};

use crate::support::fixture::Workspace;

#[test]
fn no_targets_is_rejected() {
    for per_target in [false, true] {
        let error = sign_adhoc(Vec::<PathBuf>::new())
            .per_target(per_target)
            .run()
            .unwrap_err();
        assert!(matches!(error, Error::NoTargets), "got {error:?}");

        let none: [PathBuf; 0] = [];
        let error = sign_adhoc(none).per_target(per_target).run().unwrap_err();
        assert!(matches!(error, Error::NoTargets), "got {error:?}");
    }
}

#[test]
fn an_empty_target_is_rejected_by_its_position() {
    let workspace = Workspace::new();
    let present = workspace.unsigned("hello");
    let before = fs::read(&present).unwrap();

    let error = sign_adhoc("").run().unwrap_err();
    assert!(matches!(error, Error::EmptyTarget(0)), "got {error:?}");

    for per_target in [false, true] {
        let batch = vec![present.clone(), PathBuf::new()];
        let error = sign_adhoc(batch).per_target(per_target).run().unwrap_err();
        assert!(matches!(error, Error::EmptyTarget(1)), "got {error:?}");
    }
    assert_eq!(fs::read(&present).unwrap(), before);
}

/// Every action checks its targets before it runs.
#[test]
fn a_missing_target_is_reported_by_every_action() {
    let workspace = Workspace::new();
    let missing = workspace.join("nowhere.bin");

    let errors = [
        sign(&missing, "-").run().unwrap_err(),
        sign_adhoc(&missing).run().unwrap_err(),
        sign_for_distribution(&missing, "-").run().unwrap_err(),
        remove_signature(&missing).run().unwrap_err(),
        verify(&missing).run().unwrap_err(),
        display(&missing).run().unwrap_err(),
        requirements(&missing).run().unwrap_err(),
        validate_constraint(&missing).run().unwrap_err(),
        extract_certificates(&missing).run().unwrap_err(),
    ];

    for error in errors {
        assert!(
            matches!(&error, Error::TargetNotFound(path) if *path == missing),
            "got {error:?}"
        );
    }
}

#[test]
fn a_missing_target_aborts_the_whole_batch() {
    let workspace = Workspace::new();
    let present = workspace.unsigned("hello");
    let before = fs::read(&present).unwrap();
    let missing = workspace.join("nowhere.bin");

    for per_target in [false, true] {
        let error = sign_adhoc([present.clone(), missing.clone()])
            .per_target(per_target)
            .run()
            .unwrap_err();
        assert!(
            matches!(&error, Error::TargetNotFound(path) if *path == missing),
            "per_target({per_target}): got {error:?}"
        );
    }
    assert_eq!(fs::read(&present).unwrap(), before);
}

#[test]
fn an_unreadable_parent_directory_is_an_access_error() {
    use std::os::unix::fs::PermissionsExt;

    if crate::support::running_as_root() {
        crate::support::skip!("root is exempt from the permission bits this relies on");
    }
    let workspace = Workspace::new();
    let locked = workspace.dir("locked");
    let target = workspace.join("locked/hidden.bin");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    let error = verify(&target).run().unwrap_err();

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    match error {
        Error::TargetAccess { path, source } => {
            assert_eq!(path, target);
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected TargetAccess, got {other:?}"),
    }
}

#[test]
fn a_dash_for_a_path_is_refused() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let before = fs::read(&target).unwrap();

    let error = sign_adhoc(&target).file_list("-").run().unwrap_err();
    assert!(
        matches!(error, Error::StdioPath("file_list")),
        "got {error:?}"
    );

    let error = verify(&target)
        .test_requirement_file("-")
        .run()
        .unwrap_err();
    assert!(
        matches!(error, Error::StdioPath("test_requirement_file")),
        "got {error:?}"
    );
    assert_eq!(fs::read(&target).unwrap(), before);
}

#[test]
fn a_shared_output_file_is_refused_per_target() {
    let workspace = Workspace::new();
    let targets = vec![workspace.unsigned("a"), workspace.unsigned("b")];
    let before: Vec<Vec<u8>> = targets.iter().map(|path| fs::read(path).unwrap()).collect();

    let error = sign_adhoc(targets.clone())
        .detached(workspace.join("signature"))
        .per_target(true)
        .run()
        .unwrap_err();

    assert!(
        matches!(error, Error::SharedOutputPerTarget("detached")),
        "got {error:?}"
    );
    let after: Vec<Vec<u8>> = targets.iter().map(|path| fs::read(path).unwrap()).collect();
    assert_eq!(after, before);
    assert!(!workspace.join("signature").exists());
}
