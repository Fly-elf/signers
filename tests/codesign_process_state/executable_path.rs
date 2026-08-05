//! Tests that need `PATH` pointed away from the real `codesign` binary.

use std::env;
use std::future::IntoFuture;

use signers::Error;
use signers::codesign::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect;

#[test]
fn a_missing_codesign_binary_is_reported_as_a_spawn_failure() {
    let _serialised = crate::serialised();

    // Prepared while `codesign` is still reachable.
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");
    let previous = env::var_os("PATH");

    // Pointed at the workspace rather than unset: with no `PATH` at all,
    // `execvp` falls back to a built-in default that does contain `codesign`.
    //
    // SAFETY: mutating the environment is only unsound while another thread
    // reads it. `serialised()` excludes the other test in this binary, and the
    // runtime that spawns the process is created below, after this call.
    unsafe { env::set_var("PATH", workspace.path()) };

    let result = crate::runtime().block_on(Codesign::sign(&target, "-").into_future());

    // SAFETY: as above — still single-threaded with respect to the environment.
    unsafe {
        match previous {
            Some(path) => env::set_var("PATH", path),
            None => env::remove_var("PATH"),
        }
    }

    match result.unwrap_err() {
        Error::Spawn(source) => assert_eq!(source.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected Spawn, got {other:?}"),
    }
    assert!(!inspect::is_signed(&target), "something signed the target anyway");
}
