//! `Codesign::display`, end to end — one submodule per test category, named
//! for what it covers; see each submodule's own doc comment for the detail.
//!
//! Every value read back is checked against what the `codesign` CLI itself
//! reports for the same target, never against `signers`.

mod options;
mod per_target;
mod preflight;
mod reading;
mod rejected_by_codesign;
mod requirements;
mod signature_slot;
mod with_identity;

use std::ffi::OsStr;
use std::path::Path;

use crate::support::inspect;

/// Signs `path` ad hoc through the `codesign` CLI, with `args` before the target.
fn adhoc_sign(path: &Path, args: &[&str]) {
    let mut argv: Vec<&OsStr> = vec!["--force".as_ref(), "--sign".as_ref(), "-".as_ref()];
    argv.extend(args.iter().map(OsStr::new));
    argv.push(path.as_ref());
    inspect::codesign(&argv).expect_success(&format!("sign {}", path.display()));
}

/// The `codesign --display --verbose=4` report for `path`, with `args` before
/// the target, as the CLI prints it, without its trailing newline.
fn report(path: &Path, args: &[&str]) -> String {
    let mut argv: Vec<&OsStr> = vec!["--display".as_ref(), "--verbose=4".as_ref()];
    argv.extend(args.iter().map(OsStr::new));
    argv.push(path.as_ref());
    inspect::codesign(&argv)
        .expect_success(&format!("display {}", path.display()))
        .stderr
        .trim_end()
        .to_owned()
}
