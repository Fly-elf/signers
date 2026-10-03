//! Tests that need `PATH` pointed away from the real `codesign` binary.
//!
//! Between them they cover every way a run can fail once the pre-flight checks
//! have passed: the binary missing, the binary unusable, the process killed,
//! and the process exiting with nothing to say for itself. The last two are
//! reached through a stand-in `codesign` script, since the real one cannot be
//! asked to crash or to fail silently on demand.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::future::IntoFuture;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use signers::Codesign;
use signers::{CodesignError, Error};

use crate::support::fixture::Workspace;
use crate::support::inspect;

#[test]
fn a_missing_codesign_binary_is_reported_as_such() {
    let _serialised = crate::serialised();

    // Prepared while `codesign` is still reachable.
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    // An empty directory rather than no `PATH` at all: with the variable
    // unset, `execvp` falls back to a built-in default that does contain
    // `codesign`. Scoped, since the assertions below need the real one back.
    let result = {
        let _path = ScopedPath::to(&workspace.dir("empty"));
        crate::runtime().block_on(Codesign::sign(&target, "-").into_future())
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::NotFound) => {}
        other => panic!("expected CodesignNotFound, got {other:?}"),
    }
    assert!(
        !inspect::is_signed(&target),
        "something signed the target anyway"
    );
}

/// The other half of the distinction: `codesign` is *there*, so this is not the
/// "not found on `PATH`" failure, and must not be reported as it.
#[test]
fn a_codesign_that_cannot_be_executed_is_a_spawn_failure() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = workspace.dir("bin");
    workspace.write("bin/codesign", "#!/bin/sh\nexit 0\n"); // no execute bit

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(Codesign::sign(&target, "-").into_future())
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::Spawn(source)) => {
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied)
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
}

/// A killed process has no exit code and, as here, usually no diagnostics —
/// nothing that could be mistaken for `codesign` rejecting the target.
#[test]
fn a_codesign_killed_by_a_signal_is_reported_as_terminated() {
    use std::os::unix::process::ExitStatusExt;

    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(&workspace, "kill -9 $$");

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(Codesign::sign(&target, "-").into_future())
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::Terminated { status, stderr }) => {
            assert_eq!(
                status.signal(),
                Some(9),
                "killed by something else: {status}"
            );
            assert!(stderr.is_empty(), "the stand-in said something: {stderr}");
        }
        other => panic!("expected Terminated, got {other:?}"),
    }
}

#[test]
fn a_silent_failure_still_reports_its_exit_code() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(&workspace, "exit 3");

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(Codesign::sign(&target, "-").into_future())
    };

    let error = result.unwrap_err();
    match &error {
        Error::Codesign(CodesignError::Failed { code, stderr }) => {
            assert_eq!(*code, 3);
            assert!(stderr.is_empty(), "the stand-in said something: {stderr}");
        }
        other => panic!("expected Codesign, got {other:?}"),
    }
    // The exit code is all there is to report, so it had better survive into
    // the message the caller ends up printing.
    let message = error.to_string();
    assert!(message.contains("code 3"), "unhelpful message: {message}");
    assert!(
        message.contains("no diagnostics"),
        "unhelpful message: {message}"
    );
}

#[test]
fn one_process_handles_every_target_unless_asked_otherwise() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["a.bin", "b.bin", "c.bin"]);
    let (bin, calls) = recording_codesign(&workspace, "exit 0");

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(
            Codesign::sign(targets.clone(), "-")
                .force(true)
                .into_future(),
        )
    };

    assert_eq!(result.unwrap().len(), 3);
    let mut expected = vec![
        "--sign".to_owned(),
        "-".into(),
        "--force".into(),
        "--".into(),
    ];
    expected.extend(targets.iter().map(|target| target.display().to_string()));
    assert_eq!(recorded_calls(&calls), [expected]);
}

/// The same configuration, once per target, each process handed that target
/// alone (ADR-0013) — and the option itself reaching none of them as a flag.
#[test]
fn per_target_starts_one_process_for_each_target() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["a.bin", "b.bin", "c.bin"]);
    let (bin, calls) = recording_codesign(&workspace, "exit 0");

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(
            Codesign::sign(targets.clone(), "-")
                .force(true)
                .per_target(true)
                .into_future(),
        )
    };

    assert_eq!(result.unwrap().len(), 3);
    let expected: Vec<Vec<String>> = targets
        .iter()
        .map(|target| {
            let target = target.display().to_string();
            vec![
                "--sign".into(),
                "-".into(),
                "--force".into(),
                "--".into(),
                target,
            ]
        })
        .collect();
    assert_eq!(recorded_calls(&calls), expected);
}

/// Up to one process per CPU at a time and no more: the cap is what keeps a
/// batch of thousands from exhausting file descriptors.
#[test]
fn per_target_processes_overlap_but_never_exceed_the_cpu_count() {
    let _serialised = crate::serialised();

    let cap = std::thread::available_parallelism().map_or(1, usize::from);
    let workspace = Workspace::new();
    let names: Vec<String> = (0..3 * cap).map(|i| format!("target-{i}.bin")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let targets = plain_targets(&workspace, &names);
    let alive = workspace.dir("alive");
    let seen = workspace.dir("seen");
    // Each process marks itself alive, counts the marks, and unmarks itself
    // before it exits: a count can run low, never high, so it cannot fail a
    // runner that respects the cap.
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
        crate::runtime().block_on(Codesign::sign(targets, "-").per_target(true).into_future())
    };

    assert_eq!(result.unwrap().len(), 3 * cap);
    let counts: Vec<usize> = fs::read_dir(&seen)
        .unwrap()
        .map(|entry| {
            let count = fs::read_to_string(entry.unwrap().path()).unwrap();
            count.trim().parse().unwrap()
        })
        .collect();
    assert_eq!(counts.len(), 3 * cap, "not one process per target");
    let most = counts.into_iter().max().unwrap();
    assert!(
        most <= cap,
        "{most} processes alive at once, with {cap} allowed"
    );
    if cap > 1 {
        assert!(most > 1, "the processes ran one after the other");
    }
}

/// Completion order is not input order: here the first target is the last to
/// fail, and still has to be listed first.
#[test]
fn per_target_failures_keep_the_order_of_the_targets_not_of_the_exits() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["slow.bin", "quick-1.bin", "quick-2.bin"]);
    let bin = fake_codesign(
        &workspace,
        "for last; do :; done\n\
         case \"$last\" in *slow*) /bin/sleep 0.5 ;; esac\n\
         echo \"refused $last\" >&2\n\
         exit 4",
    );

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(
            Codesign::sign(targets.clone(), "-")
                .per_target(true)
                .into_future(),
        )
    };

    let failures = match result.unwrap_err() {
        Error::Batch(failures) => failures,
        other => panic!("expected Batch, got {other:?}"),
    };
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, targets.iter().collect::<Vec<_>>());
    for (path, error) in &failures {
        match error {
            Error::Codesign(CodesignError::Failed { code, stderr }) => {
                assert_eq!(*code, 4);
                assert_eq!(*stderr, format!("refused {}", path.display()));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}

/// A process that dies is a failure of the one target it was working on, like
/// any other: only a `codesign` that never started fails the run as a whole.
#[test]
fn a_per_target_process_killed_by_a_signal_is_charged_to_its_target() {
    use std::os::unix::process::ExitStatusExt;

    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["fine-1.bin", "doomed.bin", "fine-2.bin"]);
    let bin = fake_codesign(
        &workspace,
        "for last; do :; done\n\
         case \"$last\" in *doomed*) kill -9 $$ ;; esac\n\
         exit 0",
    );

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(
            Codesign::sign(targets.clone(), "-")
                .per_target(true)
                .into_future(),
        )
    };

    let failures = match result.unwrap_err() {
        Error::Batch(failures) => failures,
        other => panic!("expected Batch, got {other:?}"),
    };
    let [(path, error)] = &failures[..] else {
        panic!("expected exactly one failure, got {failures:?}");
    };
    assert_eq!(*path, targets[1]);
    match error {
        Error::Codesign(CodesignError::Terminated { status, .. }) => {
            assert_eq!(
                status.signal(),
                Some(9),
                "killed by something else: {status}"
            )
        }
        other => panic!("expected Terminated, got {other:?}"),
    }
}

/// No target is to blame for a `codesign` that is not there, so there is
/// nothing to collect: the run fails as a whole, with the plain error.
#[test]
fn a_missing_codesign_binary_fails_a_per_target_batch_as_a_whole() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["a.bin", "b.bin", "c.bin"]);

    let (from_a_list, from_an_array) = {
        let _path = ScopedPath::to(&workspace.dir("empty"));
        let runtime = crate::runtime();
        (
            runtime.block_on(
                Codesign::sign(targets.clone(), "-")
                    .per_target(true)
                    .into_future(),
            ),
            runtime.block_on(
                Codesign::sign([targets[0].clone(), targets[1].clone()], "-")
                    .per_target(true)
                    .into_future(),
            ),
        )
    };

    for error in [from_a_list.unwrap_err(), from_an_array.unwrap_err()] {
        assert!(
            matches!(error, Error::Codesign(CodesignError::NotFound)),
            "got {error:?}"
        );
    }
}

#[test]
fn a_codesign_that_cannot_be_executed_fails_a_per_target_batch_as_a_whole() {
    let _serialised = crate::serialised();

    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["a.bin", "b.bin", "c.bin"]);
    let bin = workspace.dir("bin");
    workspace.write("bin/codesign", "#!/bin/sh\nexit 0\n"); // no execute bit

    let result = {
        let _path = ScopedPath::to(&bin);
        crate::runtime().block_on(Codesign::sign(targets, "-").per_target(true).into_future())
    };

    match result.unwrap_err() {
        Error::Codesign(CodesignError::Spawn(source)) => {
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied)
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
}

/// Plain files standing in for targets: all a stand-in `codesign` needs is for
/// them to exist.
fn plain_targets(workspace: &Workspace, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|name| workspace.write(name, "irrelevant\n"))
        .collect()
}

/// A stand-in `codesign` that records every invocation before running `then`:
/// one file per process under the returned directory, holding the arguments
/// that process was started with, one per line.
///
/// ```ignore
/// let (bin, calls) = recording_codesign(&workspace, "exit 0");
/// ```
fn recording_codesign(workspace: &Workspace, then: &str) -> (PathBuf, PathBuf) {
    let calls = workspace.dir("calls");
    let script = format!("printf '%s\\n' \"$@\" > '{}'/$$\n{then}", calls.display());
    (fake_codesign(workspace, &script), calls)
}

/// What [`recording_codesign`] recorded: the argument list of each process,
/// ordered by argument list since the processes may have run concurrently.
fn recorded_calls(calls: &Path) -> Vec<Vec<String>> {
    let mut recorded: Vec<Vec<String>> = fs::read_dir(calls)
        .unwrap_or_else(|e| panic!("could not list {}: {e}", calls.display()))
        .map(|entry| {
            let call = fs::read_to_string(entry.unwrap().path()).unwrap();
            call.lines().map(str::to_owned).collect()
        })
        .collect();
    recorded.sort();
    recorded
}

/// Writes an executable stand-in for `codesign` running `script`, and returns
/// the directory to point `PATH` at.
///
/// ```ignore
/// let bin = fake_codesign(&workspace, "exit 3");
/// ```
fn fake_codesign(workspace: &Workspace, script: &str) -> PathBuf {
    let bin = workspace.dir("bin");
    let codesign = workspace.write("bin/codesign", &format!("#!/bin/sh\n{script}\n"));
    fs::set_permissions(&codesign, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("could not make the stand-in executable: {e}"));
    bin
}

/// `PATH` pointed at one directory for as long as this is held.
///
/// The previous value comes back on drop, including while a panicking test
/// unwinds, so a failure here cannot leak into whatever runs next.
#[must_use = "PATH is restored as soon as this is dropped"]
struct ScopedPath(Option<OsString>);

impl ScopedPath {
    /// Replaces `PATH` with `dir` alone.
    ///
    /// The caller must hold [`crate::serialised`]: mutating the environment is
    /// only sound while no other thread reads it, and every tokio runtime in
    /// this binary is built inside a test body, after this call.
    fn to(dir: &Path) -> Self {
        let previous = env::var_os("PATH");
        // SAFETY: single-threaded with respect to the environment, as above.
        unsafe { env::set_var("PATH", dir) };
        Self(previous)
    }
}

impl Drop for ScopedPath {
    fn drop(&mut self) {
        // SAFETY: as in `to` — the runtime that read `PATH` is gone by now.
        unsafe {
            match self.0.take() {
                Some(path) => env::set_var("PATH", path),
                None => env::remove_var("PATH"),
            }
        }
    }
}
