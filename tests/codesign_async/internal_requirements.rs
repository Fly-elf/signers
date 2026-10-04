//! `Codesign::internal_requirements`, end to end — one submodule per test
//! category, named for what it covers; see each submodule's own doc comment
//! for the detail.
//!
//! Every requirement read back is checked against the lines the `codesign`
//! CLI itself prints for `-d -r-` on the same target, never against `signers`.

mod batches;
mod preflight;
mod reading;

use std::path::Path;

use signers::codesign::{Requirement, RequirementKind};

use crate::support::inspect;

/// What `codesign -d -r-` prints on stdout for `path`, one entry per line.
fn printed(path: &Path) -> Vec<String> {
    inspect::codesign(&["-d".as_ref(), "-r-".as_ref(), path.as_ref()])
        .expect_success("print the requirements")
        .stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn word(kind: &RequirementKind) -> &str {
    match kind {
        RequirementKind::Designated => "designated",
        RequirementKind::Host => "host",
        RequirementKind::Guest => "guest",
        RequirementKind::Library => "library",
        RequirementKind::Plugin => "plugin",
        RequirementKind::Other(word) => word,
        _ => panic!("a kind this test does not know: {kind:?}"),
    }
}

/// The line `codesign` would print for `requirement`.
fn line_of(requirement: &Requirement) -> String {
    format!(
        "{}{} => {}",
        if requirement.implicit { "# " } else { "" },
        word(&requirement.kind),
        requirement.expression
    )
}

fn lines_of(requirements: &[Requirement]) -> Vec<String> {
    requirements.iter().map(line_of).collect()
}

/// Signs `path` ad hoc through the `codesign` CLI.
fn adhoc_sign(path: &Path, args: &[&str]) {
    let mut argv: Vec<&std::ffi::OsStr> = vec!["--force".as_ref(), "--sign".as_ref(), "-".as_ref()];
    argv.extend(args.iter().map(std::ffi::OsStr::new));
    argv.push(path.as_ref());
    inspect::codesign(&argv).expect_success(&format!("sign {}", path.display()));
}
