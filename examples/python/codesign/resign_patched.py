"""Re-signs a binary after patching it, keeping the identifier and entitlements it had.

Patching invalidates the signature, and on Apple silicon the system kills unsigned or
invalid code, so an ad hoc signature is the usual last step. Edit `BINARY` before running.
"""

from signers import codesign

BINARY = "patched/MyTool"


def main() -> None:
    before = codesign.display(BINARY)
    print(
        f"before: {before.identifier} (entitlements: {before.entitlements is not None})"
    )

    # A patched binary fails verification; any other error is a real problem.
    try:
        codesign.verify(BINARY)
        print("the signature is still valid")
    except codesign.VerificationFailedError as error:
        print(f"invalid, as expected: {error.stderr}")

    # Without IDENTIFIER the ad hoc identifier becomes `<name>-<hash>`, and without
    # ENTITLEMENTS, FLAGS and RUNTIME the patched code loses what it relied on.
    codesign.sign_adhoc(
        BINARY,
        force=True,
        preserve_metadata=codesign.PreserveMetadata.IDENTIFIER
        | codesign.PreserveMetadata.ENTITLEMENTS
        | codesign.PreserveMetadata.FLAGS
        | codesign.PreserveMetadata.RUNTIME,
    )

    codesign.verify(BINARY)

    after = codesign.display(BINARY)
    print(
        f"after: {after.identifier} (ad hoc: {after.signature is None}, "
        f"hardened runtime: {codesign.SigningFlags.RUNTIME in after.code_directory.flags})"
    )


if __name__ == "__main__":
    main()
