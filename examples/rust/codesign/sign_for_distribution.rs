//! Signs an app for distribution outside the Mac App Store and checks the result.
//!
//! Needs a Developer ID Application certificate (paid Apple Developer Program) in a keychain,
//! and network access for the timestamp. Notarization itself (`notarytool`, `stapler`) is out
//! of scope for this crate. Edit the paths and `IDENTITY` before running.

use signers::codesign;

const IDENTITY: &str = "Developer ID Application: Jane Doe (A1B2C3D4E5)";
const TEAM: &str = "A1B2C3D4E5";
const APP: &str = "build/MyApp.app";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Nested code first, like any bundle: see the `codesign_sign_bundle` example.
    codesign::sign_for_distribution(
        [
            "build/MyApp.app/Contents/Helpers/helper",
            "build/MyApp.app/Contents/Frameworks/Lib.framework",
        ],
        IDENTITY,
    )
    .await?;

    // Hardened runtime and a secure timestamp, which notarization requires.
    codesign::sign_for_distribution(APP, IDENTITY)
        .entitlements("MyApp.entitlements")
        .await?;

    // Besides a valid seal, the app must be signed by a Developer ID of our team.
    let requirement = format!("anchor apple generic and certificate leaf[subject.OU] = \"{TEAM}\"");
    codesign::verify(APP)
        .deep(true)
        .strict(codesign::Strict::All)
        .test_requirement(requirement)
        .await?;

    let signature = codesign::display(APP).await?;
    anyhow::ensure!(
        signature.team_identifier.as_deref() == Some(TEAM),
        "signed by team {:?}, expected {TEAM}",
        signature.team_identifier
    );
    Ok(())
}
