"""Signs an app for distribution outside the Mac App Store and checks the result.

Needs a Developer ID Application certificate (paid Apple Developer Program) in a
keychain, and network access for the timestamp. Notarization itself (`notarytool`,
`stapler`) is out of scope for this package. Edit the paths and `IDENTITY` before running.
"""

import asyncio

from signers import codesign
from signers.codesign import aio

IDENTITY = "Developer ID Application: Jane Doe (A1B2C3D4E5)"
TEAM = "A1B2C3D4E5"
APP = "build/MyApp.app"


async def main() -> None:
    # Nested code first, like any bundle: see `sign_bundle.py`.
    await aio.sign_for_distribution(
        [
            "build/MyApp.app/Contents/Helpers/helper",
            "build/MyApp.app/Contents/Frameworks/Lib.framework",
        ],
        IDENTITY,
    )

    # Hardened runtime and a secure timestamp, which notarization requires.
    await aio.sign_for_distribution(APP, IDENTITY, entitlements="MyApp.entitlements")

    # Besides a valid seal, the app must be signed by a Developer ID of our team.
    await aio.verify(
        APP,
        deep=True,
        strict=codesign.Strict.ALL,
        test_requirement=f'anchor apple generic and certificate leaf[subject.OU] = "{TEAM}"',
    )

    signature = await aio.display(APP)
    if signature.team_identifier != TEAM:
        raise RuntimeError(
            f"signed by team {signature.team_identifier}, expected {TEAM}"
        )


if __name__ == "__main__":
    asyncio.run(main())
