//! Triages several binaries and bundles: who signed them, with what, and whether they verify.
//!
//! Each target is read concurrently, and a failing target does not hide the others. Edit
//! `TARGETS` before running.

use futures_util::future::join_all;
use signers::codesign::{
    self, Authority, Requirement, RequirementKind, Signature, SignatureKind, SigningFlags, Strict,
};

const TARGETS: [&str; 3] = [
    "/bin/ls",
    "/System/Applications/Calculator.app",
    "build/MyTool",
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One call over all the targets would be shorter, but it reports a failure as
    // `Error::Batch` and drops the signatures of the targets that succeeded. One run per target
    // keeps every partial result.
    let reports = join_all(TARGETS.map(inspect)).await;
    for (target, report) in TARGETS.iter().zip(reports) {
        println!("{target}");
        match report {
            Ok((signature, requirements, verdict)) => {
                print_report(&signature, &requirements, verdict);
            }
            Err(error) => println!("  unreadable: {error}"),
        }
    }

    // Writes the certificate chain of each signed target to `certs/<name>.pem`.
    codesign::extract_certificates(TARGETS)
        .save_to("certs")
        .await?;
    Ok(())
}

// A target that fails verification still gets its report, so the verdict is a value here.
async fn inspect(
    target: &str,
) -> signers::Result<(Signature, Vec<Requirement>, signers::Result<()>)> {
    let (signature, requirements, verdict) = tokio::join!(
        codesign::display(target),
        codesign::requirements(target),
        codesign::verify(target).strict(Strict::All),
    );
    Ok((signature?, requirements?, verdict))
}

fn print_report(signature: &Signature, requirements: &[Requirement], verdict: signers::Result<()>) {
    println!("  identifier: {}", signature.identifier);
    println!(
        "  team: {}",
        signature.team_identifier.as_deref().unwrap_or("-")
    );
    match &signature.signature {
        SignatureKind::AdHoc => println!("  signature: ad hoc"),
        SignatureKind::Certificate { authorities, .. } => match authorities.first() {
            Some(Authority::Name(leaf)) => println!("  signature: certificate of {leaf}"),
            _ => println!("  signature: certificate"),
        },
        _ => println!("  signature: unknown kind"),
    }
    println!(
        "  hardened runtime: {}",
        signature
            .code_directory
            .flags
            .contains(SigningFlags::RUNTIME)
    );
    if let Some(entitlements) = &signature.entitlements {
        let keys: Vec<_> = entitlements.keys().collect();
        println!("  entitlements: {keys:?}");
    }
    if let Some(designated) = requirements
        .iter()
        .find(|requirement| requirement.kind == RequirementKind::Designated)
    {
        println!("  designated requirement: {}", designated.expression);
    }
    match verdict {
        Ok(()) => println!("  verify: ok"),
        Err(error) => println!("  verify: {error}"),
    }
}
