//! `Codesign::extract_certificates`, end to end — one submodule per test
//! category, named for what it covers; see each submodule's own doc comment
//! for the detail.
//!
//! Every chain read back is checked against the DER files the `codesign` CLI
//! itself extracts for the same target, and every PEM file against what the
//! system `openssl` makes of those, never against `signers`.

mod batches;
mod preflight;
mod reading;
mod save_to;
mod with_identity;

use std::fs;
use std::path::{Path, PathBuf};

use signers::codesign::extract_certificates::Certificate;

use crate::support::fixture::Workspace;
use crate::support::inspect;

/// A platform binary: signed by Apple with a full certificate chain, present
/// on every Mac.
const PLATFORM_BINARY: &str = "/bin/ls";

/// A system app bundle, signed by Apple, read but never modified.
const SYSTEM_APP: &str = "/System/Applications/Calculator.app";

/// A copy of [`PLATFORM_BINARY`] at `<workspace>/<name>`, signature included,
/// so a target with a real chain can carry any name.
fn platform_copy(workspace: &Workspace, name: impl AsRef<Path>) -> PathBuf {
    let target = workspace.join(name);
    fs::copy(PLATFORM_BINARY, &target)
        .unwrap_or_else(|e| panic!("could not copy {PLATFORM_BINARY}: {e}"));
    target
}

/// The DER bytes of each certificate, in order.
fn ders(chain: &[Certificate]) -> Vec<&[u8]> {
    chain.iter().map(Certificate::der).collect()
}

/// The PEM file `save_to` must write for `target`: its chain as the system
/// `openssl` encodes each certificate, leaf first.
fn expected_pem(target: &Path) -> String {
    inspect::certificates(target)
        .iter()
        .map(|der| inspect::pem(der))
        .collect()
}

/// The names of the files in `dir`, sorted.
fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("could not list {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The contents of `<dir>/<name>`.
fn read(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}
