//! Signs an app bundle the way a build step does: nested code first, then the app.
//!
//! Edit the paths and `IDENTITY` before running.

use signers::codesign::{self, SigningFlags, Strict, Timestamp};

// "-" signs ad hoc, which is enough to run the app on this Mac. For a real identity:
// - list the ones in your keychains with `security find-identity -v -p codesigning`;
// - a free "Apple Development" certificate comes from Xcode, in Settings > Accounts >
//   Manage Certificates;
// - a self-signed code-signing certificate comes from Keychain Access, in Certificate
//   Assistant > Create a Certificate. It is good for local use only.
const IDENTITY: &str = "-";

const APP: &str = "build/MyApp.app";

fn main() -> anyhow::Result<()> {
    // Inside out: a bundle's seal covers the code nested in it, so nested code must be signed
    // before the bundle. `.deep(true)` would do it all at once, but Apple discourages it for
    // signing because it applies one set of options to everything.
    codesign::blocking::sign(
        [
            "build/MyApp.app/Contents/Helpers/helper",
            "build/MyApp.app/Contents/Frameworks/Lib.framework",
        ],
        IDENTITY,
    )
    .force(true)
    .run()?;

    codesign::blocking::sign(APP, IDENTITY)
        .entitlements("MyApp.entitlements")
        .options(SigningFlags::RUNTIME)
        // Skips the timestamp server, so signing works offline. Release builds want it enabled.
        .timestamp(Timestamp::Disabled)
        .force(true)
        .run()?;

    // Verification is the one place `.deep(true)` belongs: it checks nested code on its own.
    codesign::blocking::verify(APP)
        .deep(true)
        .strict(Strict::All)
        .run()?;
    Ok(())
}
