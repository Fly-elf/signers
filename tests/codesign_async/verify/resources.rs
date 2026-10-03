//! The sealed resources a failed verification names: what
//! `check_designated_requirement` adds to the error, and when it adds nothing.
//!
//! Each expectation is read off the real `codesign` first (its own
//! `--verbose=1` output), so the paths are never the library's own invention.

use std::fs;
use std::path::{Path, PathBuf};

use signers::errors::{Change, ResourceChange};
use signers::{Codesign, Error};

use super::{break_signature, verification_failed_with_resources};
use crate::support::fixture::Workspace;
use crate::support::inspect;

/// A signed `.app` sealing `Contents/Resources/{a,b,c}.txt`.
fn sealed_app(workspace: &Workspace, name: &str) -> PathBuf {
    let app = workspace.app_bundle(name);
    workspace.dir(format!("{name}.app/Contents/Resources"));
    for file in ["a", "b", "c"] {
        workspace.write(
            format!("{name}.app/Contents/Resources/{file}.txt"),
            "original\n",
        );
    }
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), app.as_ref()])
        .expect_success("pre-sign the bundle");
    app
}

fn resources_dir(app: &Path) -> PathBuf {
    app.join("Contents/Resources")
}

/// What a list of altered resources says, as plain pairs: `ResourceChange` is
/// not buildable outside the crate, but its fields are readable.
fn pairs(resources: &[ResourceChange]) -> Vec<(Change, PathBuf)> {
    resources
        .iter()
        .map(|r| (r.change, r.path.clone()))
        .collect()
}

/// The resources `codesign --verify --verbose=1` itself lists for `app`.
fn listed_by_codesign(app: &Path) -> Vec<(Change, PathBuf)> {
    let run = inspect::codesign(&["--verify".as_ref(), "--verbose=1".as_ref(), app.as_ref()]);
    assert!(!run.success, "the bundle was expected to be altered");
    run.stdout
        .lines()
        .filter_map(|line| {
            let (change, path) = [
                ("file added: ", Change::Added),
                ("file modified: ", Change::Modified),
                ("file missing: ", Change::Missing),
            ]
            .into_iter()
            .find_map(|(prefix, change)| line.strip_prefix(prefix).map(|path| (change, path)))?;
            Some((change, PathBuf::from(path)))
        })
        .collect()
}

async fn resources_of(app: &Path) -> Vec<(Change, PathBuf)> {
    let error = Codesign::verify(app)
        .check_designated_requirement(true)
        .await
        .unwrap_err();
    pairs(&verification_failed_with_resources(error).1)
}

fn change(change: Change, path: impl Into<PathBuf>) -> (Change, PathBuf) {
    (change, path.into())
}

#[tokio::test]
async fn a_modified_resource_is_named() {
    let workspace = Workspace::new();
    let app = sealed_app(&workspace, "Hello");
    let file = resources_dir(&app).join("a.txt");
    fs::write(&file, "tampered\n").unwrap();

    let resources = resources_of(&app).await;

    assert_eq!(
        resources,
        [change(Change::Modified, fs::canonicalize(&file).unwrap())]
    );
    assert_eq!(resources, listed_by_codesign(&app));
}

#[tokio::test]
async fn an_added_resource_is_named() {
    let workspace = Workspace::new();
    let app = sealed_app(&workspace, "Hello");
    let file = workspace.write("Hello.app/Contents/Resources/extra.txt", "unsealed\n");

    let resources = resources_of(&app).await;

    assert_eq!(
        resources,
        [change(Change::Added, fs::canonicalize(&file).unwrap())]
    );
    assert_eq!(resources, listed_by_codesign(&app));
}

#[tokio::test]
async fn a_missing_resource_is_named() {
    let workspace = Workspace::new();
    let app = sealed_app(&workspace, "Hello");
    let file = fs::canonicalize(resources_dir(&app).join("b.txt")).unwrap();
    fs::remove_file(&file).unwrap();

    let resources = resources_of(&app).await;

    assert_eq!(resources, [change(Change::Missing, file)]);
    assert_eq!(resources, listed_by_codesign(&app));
}

/// Every altered resource is listed, whatever kind of change each one is.
/// `codesign` doesn't print them in the same order from one run to the next,
/// so the lists are compared by path; the order of one run is kept by the
/// parser's own unit tests.
#[tokio::test]
async fn every_altered_resource_is_listed_whatever_its_kind() {
    let workspace = Workspace::new();
    let app = sealed_app(&workspace, "Hello");
    let dir = resources_dir(&app);
    fs::write(dir.join("a.txt"), "tampered\n").unwrap();
    fs::remove_file(dir.join("b.txt")).unwrap();
    workspace.write("Hello.app/Contents/Resources/d.txt", "unsealed\n");
    workspace.write("Hello.app/Contents/Resources/e.txt", "unsealed\n");

    let mut resources = resources_of(&app).await;
    let mut expected = listed_by_codesign(&app);
    resources.sort_by(|a, b| a.1.cmp(&b.1));
    expected.sort_by(|a, b| a.1.cmp(&b.1));

    let kinds: Vec<Change> = resources.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(resources.len(), 4);
    for expected in [Change::Added, Change::Modified, Change::Missing] {
        assert!(
            kinds.contains(&expected),
            "no {expected:?} in {resources:?}"
        );
    }
    assert_eq!(resources, expected);
    assert!(resources.iter().all(|(_, path)| path.is_absolute()));
}

/// The list comes from `--verbose=1`, which only the option turns on: without
/// it the same bundle fails with the same diagnostics and nothing listed.
#[tokio::test]
async fn without_the_option_no_resource_is_listed() {
    let workspace = Workspace::new();
    let app = sealed_app(&workspace, "Hello");
    fs::write(resources_dir(&app).join("a.txt"), "tampered\n").unwrap();

    let plain = Codesign::verify(&app).await.unwrap_err();
    let (plain_stderr, plain_resources) = verification_failed_with_resources(plain);
    let checked = Codesign::verify(&app)
        .check_designated_requirement(true)
        .await
        .unwrap_err();
    let (checked_stderr, checked_resources) = verification_failed_with_resources(checked);

    assert!(plain_resources.is_empty());
    assert_eq!(checked_resources.len(), 1);
    assert_eq!(plain_stderr, checked_stderr);

    let off = Codesign::verify(&app)
        .check_designated_requirement(true)
        .check_designated_requirement(false)
        .await
        .unwrap_err();
    assert!(verification_failed_with_resources(off).1.is_empty());
}

/// Without a sealed resource that changed, there is nothing to list: a broken
/// executable fails verification without naming any file.
#[tokio::test]
async fn a_broken_signature_lists_no_resource() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    break_signature(&target);

    let error = Codesign::verify(&target)
        .check_designated_requirement(true)
        .await
        .unwrap_err();

    assert!(verification_failed_with_resources(error).1.is_empty());
}

#[tokio::test]
async fn an_unsigned_target_lists_no_resource() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("Hello");

    let error = Codesign::verify(&app)
        .check_designated_requirement(true)
        .await
        .unwrap_err();

    assert!(verification_failed_with_resources(error).1.is_empty());
}

#[tokio::test]
async fn a_valid_bundle_verifies_with_the_check_and_lists_nothing() {
    let workspace = Workspace::new();
    let app = sealed_app(&workspace, "Hello");

    Codesign::verify(&app)
        .check_designated_requirement(true)
        .await
        .unwrap();
}

/// Paths come back as raw bytes up to the end of the line, so spaces and
/// punctuation stay in them.
#[tokio::test]
async fn a_resource_path_with_spaces_and_punctuation_is_kept_whole() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("My App");
    workspace.dir("My App.app/Contents/Resources/sub dir");
    let odd = workspace.write(
        "My App.app/Contents/Resources/sub dir/we're -odd; (really): file.txt",
        "original\n",
    );
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), app.as_ref()])
        .expect_success("pre-sign the bundle");
    fs::write(&odd, "tampered\n").unwrap();

    let resources = resources_of(&app).await;

    assert_eq!(
        resources,
        [change(Change::Modified, fs::canonicalize(&odd).unwrap())]
    );
    assert_eq!(resources, listed_by_codesign(&app));
}

/// Tampered nested code is reported on stderr only, so `deep` adds no list.
#[tokio::test]
async fn tampered_nested_code_is_named_by_the_diagnostics_not_the_list() {
    let workspace = Workspace::new();
    let app = workspace.app_bundle("Hello");
    let nested = workspace
        .dir("Hello.app/Contents/Frameworks")
        .join("libnested.dylib");
    fs::copy(workspace.unsigned_dylib("source.dylib"), &nested).unwrap();
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), nested.as_ref()])
        .expect_success("pre-sign the nested dylib");
    inspect::codesign(&["--sign".as_ref(), "-".as_ref(), app.as_ref()])
        .expect_success("pre-sign the bundle");
    super::flip_byte(&nested, 0x2000);

    let error = Codesign::verify(&app)
        .deep(true)
        .check_designated_requirement(true)
        .await
        .unwrap_err();

    let (stderr, resources) = verification_failed_with_resources(error);
    assert!(stderr.contains("libnested.dylib"), "got {stderr}");
    assert!(resources.is_empty());
}

/// One process per target: each failure lists the resources of its own
/// bundle only.
#[tokio::test]
async fn each_target_of_a_batch_lists_its_own_resources() {
    let workspace = Workspace::new();
    let first = sealed_app(&workspace, "First");
    let second = sealed_app(&workspace, "Second");
    let valid = sealed_app(&workspace, "Valid");
    let first_file = fs::canonicalize(resources_dir(&first).join("a.txt")).unwrap();
    let second_file = fs::canonicalize(resources_dir(&second).join("c.txt")).unwrap();
    fs::write(&first_file, "tampered\n").unwrap();
    fs::remove_file(&second_file).unwrap();

    let error = Codesign::verify(vec![first.clone(), valid, second.clone()])
        .check_designated_requirement(true)
        .await
        .unwrap_err();

    let Error::Batch(failures) = error else {
        panic!("expected a batch, got {error:?}");
    };
    assert_eq!(failures.len(), 2);
    let mut failures = failures.into_iter();
    let (one, one_error) = failures.next().unwrap();
    let (two, two_error) = failures.next().unwrap();
    assert_eq!((one, two), (first, second));
    assert_eq!(
        pairs(&verification_failed_with_resources(one_error).1),
        [change(Change::Modified, first_file)]
    );
    assert_eq!(
        pairs(&verification_failed_with_resources(two_error).1),
        [change(Change::Missing, second_file)]
    );
}

/// One process for all targets: whatever `codesign` printed before stopping
/// is what the error lists.
#[tokio::test]
async fn one_process_lists_what_codesign_printed() {
    let workspace = Workspace::new();
    let first = sealed_app(&workspace, "First");
    let second = sealed_app(&workspace, "Second");
    fs::write(resources_dir(&first).join("a.txt"), "tampered\n").unwrap();
    fs::write(resources_dir(&second).join("a.txt"), "tampered\n").unwrap();

    let expected = {
        let run = inspect::codesign(&[
            "--verify".as_ref(),
            "--verbose=1".as_ref(),
            first.as_ref(),
            second.as_ref(),
        ]);
        run.stdout.lines().count()
    };
    let error = Codesign::verify(vec![first, second])
        .per_target(false)
        .check_designated_requirement(true)
        .await
        .unwrap_err();

    let (_, resources) = verification_failed_with_resources(error);
    assert_eq!(resources.len(), expected);
    assert!(!resources.is_empty());
}
