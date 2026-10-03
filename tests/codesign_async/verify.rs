//! `Codesign::verify`, end to end — one submodule per test category, named for
//! what it covers.
//!
//! Every target is made valid or broken with the `codesign` CLI itself and
//! every expectation about the broken ones is confirmed against it first, so a
//! test cannot pass because the library and the test agree on a mistake.
//!
//! Verifying never changes its target, and is the only action whose failure is
//! the whole point: a target that does not verify is an error, told apart by
//! the exit code `codesign` chose.

mod bundles;
mod options;
mod per_target;
mod preflight;
mod requirements;
mod resources;
mod verifying;

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use signers::errors::ResourceChange;
use signers::{CodesignError, Error};

/// Unwraps the `VerificationFailed` a target that does not verify must
/// produce, returning its diagnostics.
fn verification_failed(error: Error) -> String {
    match error {
        Error::Codesign(CodesignError::VerificationFailed { stderr, .. }) => {
            assert!(!stderr.is_empty(), "the failure carried no diagnostics");
            stderr
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

/// Unwraps the `VerificationFailed` a target that does not verify must
/// produce, returning its diagnostics and the altered resources it names.
fn verification_failed_with_resources(error: Error) -> (String, Vec<ResourceChange>) {
    match error {
        Error::Codesign(CodesignError::VerificationFailed { stderr, resources }) => {
            (stderr, resources)
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

/// Unwraps the `RequirementUnsatisfied` a validly signed target that misses a
/// requirement must produce, returning its diagnostics.
fn requirement_unsatisfied(error: Error) -> String {
    match error {
        Error::Codesign(CodesignError::RequirementUnsatisfied { stderr }) => {
            assert!(!stderr.is_empty(), "the failure carried no diagnostics");
            stderr
        }
        other => panic!("expected RequirementUnsatisfied, got {other:?}"),
    }
}

/// Inverts every bit of the byte at `offset` in `path`, in place.
///
/// Offset `0x2000` of an arm64 fixture is zero padding inside its first code
/// page: flipping it leaves the Mach-O readable but breaks that page's hash, so
/// the signature no longer matches the code.
fn flip_byte(path: &Path, offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("could not open {}: {e}", path.display()));
    let mut byte = [0u8];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut byte)
        .unwrap_or_else(|e| panic!("{} is shorter than {offset} bytes: {e}", path.display()));
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&[!byte[0]]).unwrap();
}

/// Breaks the code signature of a signed Mach-O without making it unreadable,
/// checking with `codesign` that it is now invalid.
fn break_signature(path: &Path) {
    flip_byte(path, 0x2000);
    assert!(
        crate::support::inspect::verify(path).is_err(),
        "the harness did not manage to break {}",
        path.display()
    );
}
