from enum import Enum, Flag, FlagBoundary

__all__ = ["PreserveMetadata", "SignatureSlot", "SigningFlags", "Strict", "Timestamp"]


class SigningFlags(Flag, boundary=FlagBoundary.KEEP):
    """Code signing flags that `sign`'s `options` seals into the signature.

    Combine them with `|`. The values are the bits `codesign -dv` prints as
    `flags=0x...`. Bits without a member are kept, such as the ad hoc bit `0x2` that
    `display` reports in `CodeDirectory.flags`.

    Example:
        ```python
        from signers.codesign import SigningFlags, sign

        sign(
            "MyApp.app",
            "Developer ID Application: Jane Doe (A1B2C3D4E5)",
            options=SigningFlags.RUNTIME | SigningFlags.LIBRARY,
        )
        ```
    """

    HOST = 0x0001
    """Lets the code host guest code (`host`)."""
    HARD = 0x0100
    """Asks the system to deny the process a resource rather than invalidate its
    identity (`hard`).
    """
    KILL = 0x0200
    """Kills the process as soon as its signature becomes invalid (`kill`)."""
    EXPIRES = 0x0400
    """Fails verification once any certificate in the chain has expired (`expires`)."""
    LIBRARY = 0x2000
    """Lets the executable load only system libraries or its own team's (`library`)."""
    RUNTIME = 0x1_0000
    """Opts into the hardened runtime, which notarization requires (`runtime`)."""
    LINKER_SIGNED = 0x2_0000
    """Marks the signature as the linker's: replaced without `force`, never preserved
    (`linker-signed`).
    """


class PreserveMetadata(Flag):
    """Parts of the old signature that `sign`'s `preserve_metadata` carries over.

    Combine them with `|`.

    Example:
        ```python
        from signers.codesign import PreserveMetadata, sign_adhoc

        # Re-sign a patched binary and keep the identifier and entitlements it had.
        sign_adhoc(
            "patched",
            force=True,
            preserve_metadata=PreserveMetadata.IDENTIFIER
            | PreserveMetadata.ENTITLEMENTS,
        )
        ```
    """

    IDENTIFIER = 1 << 0
    """The signing identifier (`identifier`)."""
    ENTITLEMENTS = 1 << 1
    """The entitlements (`entitlements`)."""
    REQUIREMENTS = 1 << 2
    """All the internal requirements, since they can't be picked one by one
    (`requirements`).
    """
    FLAGS = 1 << 3
    """The code signing flags (`flags`)."""
    RUNTIME = 1 << 4
    """The hardened runtime version (`runtime`)."""
    LAUNCH_CONSTRAINTS = 1 << 5
    """The launch constraints, unless a `launch_constraint_*` option is set
    (`launch-constraints`).
    """
    LIBRARY_CONSTRAINTS = 1 << 6
    """The library constraint, unless `library_constraint` is set
    (`library-constraints`).
    """


class Timestamp(Enum):
    """Where `sign`'s `timestamp` gets a secure timestamp from, if anywhere.

    Leaving the option unset isn't the same as `DISABLED`: unset lets `codesign` decide.
    To use another server, pass its URL as a `str` instead of a member
    (`--timestamp=<url>`).

    Example:
        ```python
        from signers.codesign import Timestamp, sign

        identity = "Developer ID Application: Jane Doe (A1B2C3D4E5)"

        # An offline build: no timestamp server is contacted.
        sign("MyApp.app", identity, timestamp=Timestamp.DISABLED)

        # Your own timestamp authority instead of Apple's.
        sign("MyApp.app", identity, timestamp="http://tsa.example.com")
        ```
    """

    ENABLED = "ENABLED"
    """Apple's timestamp server (`--timestamp`)."""
    DISABLED = "DISABLED"
    """No timestamp (`--timestamp=none`)."""


class Strict(Enum):
    """The extra restrictions that `verify`'s `strict` applies.

    `codesign` takes one value here, so one is enough.
    """

    ALL = "ALL"
    """Every strict check there is, now and in later macOS versions (`--strict`).

    A new macOS can add checks, so code that passes today can fail later.
    """
    SYMLINKS = "SYMLINKS"
    """Rejects a symbolic link in a bundle that is broken, points outside the bundle, or
    isn't sealed by the signature (`--strict=symlinks`).
    """
    SIDEBAND = "SIDEBAND"
    """Rejects resource forks, Finder attributes and similar sideband data
    (`--strict=sideband`).

    Signing already enforces this, so it rarely changes a result.
    """


class SignatureSlot(Enum):
    """Which of the two signatures of a code object to use (`--signature-slot`).

    Without it, `codesign` uses the slot the system prefers. The second slot exists only
    if the code carries two signatures. Pass it to `verify` or `display`.
    """

    FIRST = "FIRST"
    """The first signature (`1`)."""
    SECOND = "SECOND"
    """The second signature (`2`)."""
