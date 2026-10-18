"""Signs an app bundle the way a build step does: nested code first, then the app.

Edit the paths and `IDENTITY` before running.
"""

from signers import codesign

# "-" signs ad hoc, which is enough to run the app on this Mac. For a real identity:
# - list the ones in your keychains with `security find-identity -v -p codesigning`;
# - a free "Apple Development" certificate comes from Xcode, in Settings > Accounts >
#   Manage Certificates;
# - a self-signed code-signing certificate comes from Keychain Access, in Certificate
#   Assistant > Create a Certificate. It is good for local use only.
IDENTITY = "-"

APP = "build/MyApp.app"


def main() -> None:
    # Inside out: a bundle's seal covers the code nested in it, so nested code must be
    # signed before the bundle. `deep=True` would do it all at once, but Apple
    # discourages it for signing because it applies one set of options to everything.
    codesign.sign(
        [
            "build/MyApp.app/Contents/Helpers/helper",
            "build/MyApp.app/Contents/Frameworks/Lib.framework",
        ],
        IDENTITY,
        force=True,
    )

    codesign.sign(
        APP,
        IDENTITY,
        entitlements="MyApp.entitlements",
        options=codesign.SigningFlags.RUNTIME,
        # Skips the timestamp server, so signing works offline. Release builds want it.
        timestamp=codesign.Timestamp.DISABLED,
        force=True,
    )

    # Verification is the one place `deep=True` belongs: it checks nested code on its own.
    codesign.verify(APP, deep=True, strict=codesign.Strict.ALL)


if __name__ == "__main__":
    main()
