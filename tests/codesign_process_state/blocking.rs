//! The blocking run when `codesign` can't be found, can't be started, dies or
//! prints nothing usable, and when its runtime can't be built at all.

use std::fs::File;
use std::io;

use signers::blocking::Codesign;
use signers::{CodesignError, Error};

use crate::executable_path::{ScopedPath, fake_codesign, plain_targets};
use crate::support::fixture::Workspace;
use crate::support::inspect;

#[test]
fn a_missing_codesign_binary_is_reported_as_such() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let targets = plain_targets(&workspace, &["a.bin", "b.bin"]);

    let (single, batch) = {
        let _path = ScopedPath::to(&workspace.dir("empty"));
        (
            Codesign::sign_adhoc(&target).run(),
            Codesign::sign_adhoc(targets).per_target(true).run(),
        )
    };

    for error in [single.unwrap_err(), batch.unwrap_err()] {
        assert!(
            matches!(error, Error::Codesign(CodesignError::NotFound)),
            "got {error:?}"
        );
    }
    assert!(!inspect::is_signed(&target), "something signed the target");
}

#[test]
fn a_codesign_that_cannot_be_executed_is_a_spawn_failure() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = workspace.dir("bin");
    workspace.write("bin/codesign", "#!/bin/sh\nexit 0\n"); // no execute bit

    let result = {
        let _path = ScopedPath::to(&bin);
        Codesign::sign_adhoc(&target).run()
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::Spawn(source)) => {
            assert_eq!(source.kind(), io::ErrorKind::PermissionDenied)
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
}

#[test]
fn a_codesign_killed_by_a_signal_is_reported_as_terminated() {
    use std::os::unix::process::ExitStatusExt;

    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(&workspace, "echo partial; echo warning >&2; kill -9 $$");

    let result = {
        let _path = ScopedPath::to(&bin);
        Codesign::sign_adhoc(&target).run()
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::Terminated {
            status,
            stdout,
            stderr,
        }) => {
            assert_eq!(status.signal(), Some(9), "killed by something else");
            assert_eq!(stdout, "partial");
            assert_eq!(stderr, "warning");
        }
        other => panic!("expected Terminated, got {other:?}"),
    }
}

/// A display that exits 0 with no report for its target.
#[test]
fn a_report_short_of_the_targets_is_unexpected_output() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(&workspace, "exit 0");

    let result = {
        let _path = ScopedPath::to(&bin);
        Codesign::display(&target).run()
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::UnexpectedOutput { detail }) => {
            assert!(!detail.is_empty(), "the error does not say what was wrong");
        }
        other => panic!("expected UnexpectedOutput, got {other:?}"),
    }
}

/// The runtime of a blocking call drives the processes of a batch
/// concurrently, as `.await` does.
#[test]
fn per_target_processes_overlap() {
    let _serialised = crate::serialised();

    let cap = std::thread::available_parallelism().map_or(1, usize::from);
    if cap < 2 {
        crate::support::skip!("one CPU: the processes are not allowed to overlap");
    }
    let workspace = Workspace::new();
    let names: Vec<String> = (0..2 * cap).map(|i| format!("target-{i}.bin")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let targets = plain_targets(&workspace, &names);
    let alive = workspace.dir("alive");
    let seen = workspace.dir("seen");
    // Each process marks itself alive, counts the marks, and unmarks itself.
    let bin = fake_codesign(
        &workspace,
        &format!(
            ": > '{alive}'/$$\n\
             set -- '{alive}'/*\n\
             echo $# > '{seen}'/$$\n\
             /bin/sleep 0.3\n\
             /bin/rm '{alive}'/$$",
            alive = alive.display(),
            seen = seen.display(),
        ),
    );

    let result = {
        let _path = ScopedPath::to(&bin);
        Codesign::sign_adhoc(targets).per_target(true).run()
    };

    assert_eq!(result.unwrap().len(), 2 * cap);
    let counts: Vec<usize> = std::fs::read_dir(&seen)
        .unwrap()
        .map(|entry| {
            let count = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            count.trim().parse().unwrap()
        })
        .collect();
    assert_eq!(counts.len(), 2 * cap, "not one process per target");
    let most = counts.into_iter().max().unwrap();
    assert!(most > 1, "the processes ran one after the other");
    assert!(
        most <= cap,
        "{most} processes alive at once, with {cap} allowed"
    );
}

/// With every file descriptor taken, the runtime's event queue can't be
/// created. The target is missing, so a runtime that did get built would
/// report that instead.
#[test]
fn a_runtime_that_cannot_be_built_is_a_spawn_failure() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let missing = workspace.join("nowhere.bin");

    let mut held = Vec::new();
    let exhausted = loop {
        match File::open("/dev/null") {
            Ok(file) => held.push(file),
            Err(error) => break error,
        }
    };
    let result = Codesign::verify(&missing).run();
    drop(held);

    match result.unwrap_err() {
        Error::Codesign(CodesignError::Spawn(source)) => {
            assert_eq!(source.raw_os_error(), exhausted.raw_os_error(), "{source}")
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
}
