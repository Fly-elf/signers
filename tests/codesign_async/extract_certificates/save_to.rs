//! `save_to`: one PEM file per target with a chain, named after the target,
//! never overwriting anything, plus the I/O failures it can run into.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use signers::{Codesign, Error};

use super::{PLATFORM_BINARY, SYSTEM_APP, ders, expected_pem, file_names, platform_copy, read};
use crate::support::fixture::Workspace;
use crate::support::inspect;

#[tokio::test]
async fn the_chain_is_written_as_pem_named_after_the_target() {
    let workspace = Workspace::new();
    let target = platform_copy(&workspace, "tool");
    let out = workspace.dir("out");

    let chain = Codesign::extract_certificates(&target)
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["tool.pem"]);
    assert_eq!(read(&out, "tool.pem"), expected_pem(&target));
    assert_eq!(ders(&chain), inspect::certificates(&target));
}

/// Leaf first, one block per certificate, each decoding back to the bytes
/// `.await` yielded.
#[tokio::test]
async fn the_pem_file_round_trips_to_the_chain() {
    let workspace = Workspace::new();
    let out = workspace.join("out");

    let chain = Codesign::extract_certificates(PLATFORM_BINARY)
        .save_to(&out)
        .await
        .unwrap();

    let pem = read(&out, "ls.pem");
    let blocks: Vec<String> = pem
        .split_inclusive("-----END CERTIFICATE-----\n")
        .map(str::to_owned)
        .collect();
    assert_eq!(blocks.len(), chain.len(), "{pem}");
    for (block, certificate) in blocks.iter().zip(&chain) {
        assert_eq!(inspect::der(block), certificate.der());
    }
}

#[tokio::test]
async fn a_bundle_is_saved_under_its_bundle_name() {
    let workspace = Workspace::new();
    let out = workspace.join("out");

    Codesign::extract_certificates(SYSTEM_APP)
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["Calculator.app.pem"]);
    assert_eq!(
        read(&out, "Calculator.app.pem"),
        expected_pem(Path::new(SYSTEM_APP))
    );
}

/// A path ending in `..` has no file name of its own: the file is named after
/// the directory it resolves to.
#[tokio::test]
async fn a_target_ending_in_a_parent_reference_is_named_after_what_it_resolves_to() {
    let workspace = Workspace::new();
    let out = workspace.join("out");
    let target = Path::new(SYSTEM_APP).join("Contents/..");

    Codesign::extract_certificates(&target)
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["Calculator.app.pem"]);
}

/// The batch runs concurrently, so the names are claimed in no particular
/// order; with every chain the same, any assignment is right as long as each
/// file is whole and none is lost.
#[tokio::test]
async fn the_same_path_repeated_gets_numbered_files() {
    let workspace = Workspace::new();
    let out = workspace.join("out");
    let expected = expected_pem(Path::new(PLATFORM_BINARY));

    let chains = Codesign::extract_certificates(vec![PLATFORM_BINARY; 3])
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["ls.pem", "ls2.pem", "ls3.pem"]);
    for name in ["ls.pem", "ls2.pem", "ls3.pem"] {
        assert_eq!(read(&out, name), expected, "{name}");
    }
    let full = inspect::certificates(Path::new(PLATFORM_BINARY));
    for chain in &chains {
        assert_eq!(ders(chain), full);
    }
}

#[tokio::test]
async fn targets_sharing_a_file_name_across_directories_get_numbered_files() {
    let workspace = Workspace::new();
    workspace.dir("a");
    workspace.dir("b");
    let targets = vec![
        platform_copy(&workspace, "a/ls"),
        PathBuf::from(PLATFORM_BINARY),
        platform_copy(&workspace, "b/ls"),
    ];
    let out = workspace.join("out");

    Codesign::extract_certificates(targets)
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["ls.pem", "ls2.pem", "ls3.pem"]);
}

#[tokio::test]
async fn files_already_there_are_never_overwritten() {
    let workspace = Workspace::new();
    let out = workspace.dir("out");
    fs::write(out.join("ls.pem"), "first\n").unwrap();
    fs::write(out.join("ls3.pem"), "third\n").unwrap();
    let expected = expected_pem(Path::new(PLATFORM_BINARY));

    Codesign::extract_certificates(vec![PLATFORM_BINARY; 2])
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(
        file_names(&out),
        ["ls.pem", "ls2.pem", "ls3.pem", "ls4.pem"]
    );
    assert_eq!(read(&out, "ls.pem"), "first\n");
    assert_eq!(read(&out, "ls3.pem"), "third\n");
    assert_eq!(read(&out, "ls2.pem"), expected);
    assert_eq!(read(&out, "ls4.pem"), expected);
}

#[tokio::test]
async fn running_again_into_the_same_directory_adds_a_file() {
    let workspace = Workspace::new();
    let out = workspace.join("out");
    let builder = Codesign::extract_certificates(PLATFORM_BINARY).save_to(&out);

    builder.clone().await.unwrap();
    builder.await.unwrap();

    assert_eq!(file_names(&out), ["ls.pem", "ls2.pem"]);
}

#[tokio::test]
async fn an_ad_hoc_target_gets_no_file() {
    let workspace = Workspace::new();
    let adhoc = workspace.adhoc_signed("adhoc");
    let signed = platform_copy(&workspace, "signed");
    let out = workspace.dir("out");

    let chains = Codesign::extract_certificates(vec![adhoc.clone(), signed])
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(chains[0], []);
    assert_eq!(file_names(&out), ["signed.pem"]);

    let chain = Codesign::extract_certificates(&adhoc)
        .save_to(&out)
        .await
        .unwrap();
    assert_eq!(chain, []);
    assert_eq!(file_names(&out), ["signed.pem"]);
}

#[tokio::test]
async fn a_missing_directory_is_created_with_its_parents() {
    let workspace = Workspace::new();
    let out = workspace.join("not/there/yet");

    Codesign::extract_certificates(PLATFORM_BINARY)
        .save_to(&out)
        .await
        .unwrap();

    assert_eq!(file_names(&out), ["ls.pem"]);
}

#[tokio::test]
async fn the_last_directory_set_wins() {
    let workspace = Workspace::new();
    let first = workspace.join("first");
    let last = workspace.join("last");

    Codesign::extract_certificates(PLATFORM_BINARY)
        .save_to(&first)
        .save_to(&last)
        .await
        .unwrap();

    assert!(!first.exists(), "{} was created", first.display());
    assert_eq!(file_names(&last), ["ls.pem"]);
}

/// Spaces, a leading `-` and characters beyond ASCII (APFS refuses names that
/// are not UTF-8) all carry over to the file name unchanged.
#[tokio::test]
async fn awkward_target_names_carry_over_to_the_file_name() {
    let workspace = Workspace::new();
    let names: [&OsStr; 3] = [
        "with space".as_ref(),
        "-leading-dash".as_ref(),
        OsStr::new("café ls"),
    ];
    let targets: Vec<PathBuf> = names
        .iter()
        .map(|name| platform_copy(&workspace, name))
        .collect();
    let out = workspace.join("out");

    Codesign::extract_certificates(targets)
        .save_to(&out)
        .await
        .unwrap();

    for name in names {
        let mut file = name.to_owned();
        file.push(".pem");
        let path = out.join(&file);
        let written = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} was not written: {e}", path.display()));
        assert_eq!(written, expected_pem(Path::new(PLATFORM_BINARY)));
    }
    assert_eq!(fs::read_dir(&out).unwrap().count(), names.len());
}

/// The directory is a regular file: an I/O error naming it, and the file left
/// as it was.
#[tokio::test]
async fn a_directory_that_is_a_file_is_an_io_error() {
    let workspace = Workspace::new();
    let out = workspace.write("out", "not a directory\n");

    let error = Codesign::extract_certificates(PLATFORM_BINARY)
        .save_to(&out)
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains(&out.display().to_string()),
        "unhelpful message: {error}"
    );
    match error {
        Error::Io { path, .. } => assert_eq!(path, out),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fs::read_to_string(&out).unwrap(), "not a directory\n");
}

#[tokio::test]
async fn an_io_error_in_a_batch_is_collected_per_target() {
    let workspace = Workspace::new();
    let out = workspace.write("out", "not a directory\n");
    let signed = platform_copy(&workspace, "signed");
    let targets = vec![PathBuf::from(PLATFORM_BINARY), signed.clone()];

    let error = Codesign::extract_certificates(targets)
        .save_to(&out)
        .await
        .unwrap_err();

    let failures = crate::batch_failures(error);
    let failed: Vec<&Path> = failures.iter().map(|(path, _)| path.as_path()).collect();
    assert_eq!(failed, [Path::new(PLATFORM_BINARY), &signed]);
    for (_, error) in failures {
        assert!(
            matches!(&error, Error::Io { path, .. } if *path == out),
            "got {error:?}"
        );
    }
}

#[tokio::test]
async fn a_read_only_directory_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt;

    if crate::support::running_as_root() {
        crate::support::skip!("root is exempt from the permission bits this relies on");
    }
    let workspace = Workspace::new();
    let out = workspace.dir("out");
    fs::set_permissions(&out, fs::Permissions::from_mode(0o555)).unwrap();

    let result = Codesign::extract_certificates(PLATFORM_BINARY)
        .save_to(&out)
        .await;

    fs::set_permissions(&out, fs::Permissions::from_mode(0o755)).unwrap();
    match result.unwrap_err() {
        Error::Io { path, source } => {
            assert!(path.starts_with(&out), "{}", path.display());
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(file_names(&out), Vec::<String>::new());
}
