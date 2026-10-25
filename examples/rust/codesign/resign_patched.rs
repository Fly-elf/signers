//! Re-signs a binary after patching it, keeping the identifier and entitlements it had.
//!
//! Patching invalidates the signature, and on Apple silicon the system kills unsigned or
//! invalid code, so an ad hoc signature is the usual last step. Edit `BINARY` before running.

use signers::codesign::{self, PreserveMetadata, SigningFlags};
use signers::{CodesignError, Error};

const BINARY: &str = "patched/MyTool";

fn main() -> anyhow::Result<()> {
    let before = codesign::blocking::display(BINARY).run()?;
    println!(
        "before: {} (entitlements: {})",
        before.identifier,
        before.entitlements.is_some()
    );

    // A patched binary fails verification; any other error is a real problem.
    match codesign::blocking::verify(BINARY).run() {
        Ok(()) => println!("the signature is still valid"),
        Err(error @ Error::Codesign(CodesignError::VerificationFailed { .. })) => {
            println!(
                "invalid, as expected: {}",
                error.stderr().unwrap_or_default()
            );
        }
        Err(error) => return Err(error.into()),
    }

    // Without IDENTIFIER the ad hoc identifier becomes `<name>-<hash>`, and without ENTITLEMENTS,
    // FLAGS and RUNTIME the patched code loses what it relied on.
    codesign::blocking::sign_adhoc(BINARY)
        .force(true)
        .preserve_metadata(
            PreserveMetadata::IDENTIFIER
                | PreserveMetadata::ENTITLEMENTS
                | PreserveMetadata::FLAGS
                | PreserveMetadata::RUNTIME,
        )
        .run()?;

    codesign::blocking::verify(BINARY).run()?;

    let after = codesign::blocking::display(BINARY).run()?;
    println!(
        "after: {} (ad hoc: {}, hardened runtime: {})",
        after.identifier,
        after.signature == codesign::SignatureKind::AdHoc,
        after.code_directory.flags.contains(SigningFlags::RUNTIME)
    );
    Ok(())
}
