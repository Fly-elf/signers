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

use signers::Error;
use signers::codesign::Codesign;

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
        Error::CodesignNotFound => {}
        other => panic!("expected CodesignNotFound, got {other:?}"),
    }
    assert!(
        !inspect::is_signed(&target),
        "something signed the target anyway"
    );
}

/// The other half of the distinction: `codesign` is *there*, so this is not the
/// "install the Command Line Tools" failure, and must not be reported as it.
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
        Error::Spawn(source) => assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied),
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
        Error::Terminated { status, stderr } => {
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
        Error::Codesign { code, stderr } => {
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
