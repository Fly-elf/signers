//! Tests that need the process's working directory somewhere specific.

use std::env;
use std::future::IntoFuture;

use signers::Codesign;

use crate::support::fixture::Workspace;
use crate::support::inspect::{self, Signature};

#[test]
fn a_target_starting_with_a_dash_is_not_mistaken_for_an_option() {
    let _serialised = crate::serialised();

    // Only a *relative* path can start with a dash, hence the working
    // directory. Without the `--` separator the arguments end up as
    // `codesign --sign - -patched.bin`, and `codesign` reads the target as a
    // run of short options ("unknown architecture name") instead of a path.
    let workspace = Workspace::new();
    let target = workspace.unsigned("-patched.bin");
    let previous = env::current_dir().expect("no working directory");
    env::set_current_dir(workspace.path()).expect("could not enter the workspace");

    let result = crate::runtime().block_on(
        Codesign::sign("-patched.bin", "-")
            .identifier("com.example.dashed")
            .into_future(),
    );

    env::set_current_dir(previous).expect("could not leave the workspace");
    result.expect("a dash-prefixed target was not signed");
    inspect::assert_valid(&target);
    assert_eq!(Signature::of(&target).identifier(), "com.example.dashed");
}
