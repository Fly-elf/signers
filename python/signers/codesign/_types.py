# pyright: reportPrivateUsage=false
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum, Flag, FlagBoundary
from pathlib import Path
from typing import Any, Protocol, Self, TypeVar

from ._options import SigningFlags

__all__ = [
    "CdHash",
    "Certificate",
    "CertificateSignature",
    "CmsDigest",
    "CodeDirectory",
    "CodeHashes",
    "Constraints",
    "ExecutableSegment",
    "Format",
    "FormatKind",
    "HashType",
    "Location",
    "OsVersion",
    "Platform",
    "Requirement",
    "RequirementKind",
    "RequirementsSummary",
    "SealedResources",
    "Signature",
]

_Native = dict[str, Any]


class FormatKind(Enum):
    """The kind of code a signature is on (`Format.kind`)."""

    MACHO_THIN = "MACHO_THIN"
    """A Mach-O for one architecture, e.g. `arm64`."""
    MACHO_UNIVERSAL = "MACHO_UNIVERSAL"
    """A universal Mach-O, with its architectures in the order printed."""
    GENERIC = "GENERIC"
    """Any file that isn't a Mach-O, such as a script."""
    DISK_IMAGE = "DISK_IMAGE"
    """A disk image."""
    BUNDLE = "BUNDLE"
    """A bundle with code inside."""
    INFO_PLIST_BUNDLE = "INFO_PLIST_BUNDLE"
    """A bundle with an `Info.plist` and no executable."""
    INSTALLER_PACKAGE = "INSTALLER_PACKAGE"
    """An installer package bundle."""
    WIDGET = "WIDGET"
    """A widget bundle."""
    OTHER = "OTHER"
    """A format this package doesn't know; `Format.other` holds it as printed."""


class Location(Enum):
    """Where a signature is stored.

    `CodeDirectory.location` holds a `str` for a location with no member here.
    """

    EMBEDDED = "EMBEDDED"
    """Inside the code itself, or in its extended attributes."""
    EXPLICIT_DETACHED = "EXPLICIT_DETACHED"
    """In a separate file, read with `display`'s `detached`."""
    SYSTEM = "SYSTEM"
    """In the system's database of detached signatures."""


class Platform(Enum):
    """The platform a Mach-O was built for (`VersionPlatform`).

    The members are the values of the Mach-O `PLATFORM_*` constants.
    `Signature.platform` holds the number, as an `int`, for a platform with no member.
    """

    MAC_OS = "MAC_OS"
    """macOS."""
    IOS = "IOS"
    """iOS."""
    TV_OS = "TV_OS"
    """tvOS."""
    WATCH_OS = "WATCH_OS"
    """watchOS."""
    BRIDGE_OS = "BRIDGE_OS"
    """bridgeOS."""
    MAC_CATALYST = "MAC_CATALYST"
    """Mac Catalyst."""
    IOS_SIMULATOR = "IOS_SIMULATOR"
    """The iOS simulator."""
    TV_OS_SIMULATOR = "TV_OS_SIMULATOR"
    """The tvOS simulator."""
    WATCH_OS_SIMULATOR = "WATCH_OS_SIMULATOR"
    """The watchOS simulator."""
    DRIVER_KIT = "DRIVER_KIT"
    """DriverKit."""
    VISION_OS = "VISION_OS"
    """visionOS."""
    VISION_OS_SIMULATOR = "VISION_OS_SIMULATOR"
    """The visionOS simulator."""


class HashType(Enum):
    """A hash algorithm, as `codesign` names it.

    A field that holds a hash algorithm holds a `str` instead for one this package has
    no member for: its name, or `UNKNOWN(n)` for one that `codesign` only numbers.
    """

    SHA1 = "SHA1"
    """SHA-1 (`sha1`)."""
    SHA256 = "SHA256"
    """SHA-256 (`sha256`)."""
    SHA256_TRUNCATED = "SHA256_TRUNCATED"
    """SHA-256 cut to 20 bytes (`sha256T`)."""
    SHA384 = "SHA384"
    """SHA-384 (`sha384`)."""


class RequirementKind(Enum):
    """What a `Requirement` is for (`codesign`'s requirement types).

    `Requirement.kind` holds the word `codesign` printed, as a `str`, for a kind this
    package has no member for.
    """

    DESIGNATED = "DESIGNATED"
    """What the code must satisfy to be considered the same code, across versions
    (`designated`).
    """
    HOST = "HOST"
    """What the code that hosts this one must satisfy (`host`)."""
    GUEST = "GUEST"
    """What the code hosted by this one, its guests, must satisfy (`guest`)."""
    LIBRARY = "LIBRARY"
    """What the libraries this code loads must satisfy (`library`)."""
    PLUGIN = "PLUGIN"
    """What the plug-ins this code loads must satisfy (`plugin`)."""


class Constraints(Flag, boundary=FlagBoundary.KEEP):
    """The launch and library constraints that code carries.

    Check a flag with `in`. The report says which kinds exist, not what they require.
    Bits without a member are kept.

    Example:
        ```python
        from signers import codesign

        signature = codesign.display("MyApp.app")
        if codesign.Constraints.LAUNCH_SELF in signature.constraints:
            print("constrained at launch")
        ```
    """

    LAUNCH_SELF = 1
    """Constraints on the process itself (`Has Self Launch Constraints`)."""
    LAUNCH_PARENT = 1 << 1
    """Constraints on its parent process (`Has Parent Launch Constraints`)."""
    LAUNCH_RESPONSIBLE = 1 << 2
    """Constraints on its responsible process
    (`Has Responsible Launch Constraints`).
    """
    LIBRARY_LOAD = 1 << 3
    """Constraints on the libraries it loads (`Has Library Load Constraints`)."""


def _location(value: str | _Native) -> Location | str:
    return Location[value] if isinstance(value, str) else str(value["other"])


def _platform(value: str | _Native) -> Platform | int:
    return Platform[value] if isinstance(value, str) else int(value["other"])


def _hash_type(value: str | _Native) -> HashType | str:
    return HashType[value] if isinstance(value, str) else str(value["other"])


def _requirement_kind(value: str | _Native) -> RequirementKind | str:
    return RequirementKind[value] if isinstance(value, str) else str(value["other"])


@dataclass(frozen=True, slots=True)
class Format:
    """The kind of code a signature is on (`Format`).

    Only the fields of its `kind` are filled; the others keep their defaults.
    """

    kind: FormatKind
    """What kind of code it is."""
    archs: tuple[str, ...] = ()
    """The architectures: one for `MACHO_THIN`, all of them in the order printed for
    `MACHO_UNIVERSAL`, empty otherwise.
    """
    app: bool | None = None
    """For `BUNDLE`: `True` for an application bundle; `None` otherwise."""
    executable: Format | None = None
    """For `BUNDLE`: the format of the bundle's main executable; `None` otherwise."""
    other: str | None = None
    """For `OTHER`: the format as printed; `None` otherwise."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        executable = d["executable"]
        return cls(
            kind=FormatKind[d["kind"]],
            archs=tuple(d["archs"]),
            app=d["app"],
            executable=None if executable is None else cls._from_native(executable),
            other=d["other"],
        )


@dataclass(frozen=True, slots=True)
class CodeHashes:
    """How many hashes a code directory holds, printed as `code+special`."""

    code: int
    """The hashes of the code pages."""
    special: int
    """The hashes of the special slots, such as the requirements and the resources."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(code=d["code"], special=d["special"])


@dataclass(frozen=True, slots=True)
class CodeDirectory:
    """The code directory of a signature (`CodeDirectory`)."""

    version: int
    """The version of the code directory structure, e.g. `0x20400`."""
    size: int
    """The size of the code directory in bytes."""
    flags: SigningFlags
    """The signing flags sealed into the signature.

    Bits that `SigningFlags` has no name for are kept, such as the ad hoc bit `0x2`.
    """
    hashes: CodeHashes
    """How many hashes the code directory holds."""
    location: Location | str
    """Where the signature is stored; a `str` for a location with no `Location` member.
    """

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(
            version=d["version"],
            size=d["size"],
            flags=SigningFlags(d["flags"]),
            hashes=CodeHashes._from_native(d["hashes"]),
            location=_location(d["location"]),
        )


@dataclass(frozen=True, slots=True)
class OsVersion:
    """An OS or SDK version."""

    major: int
    """The major version."""
    minor: int
    """The minor version."""
    patch: int
    """The patch version."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(major=d["major"], minor=d["minor"], patch=d["patch"])


@dataclass(frozen=True, slots=True)
class CdHash:
    """The code directory hash for one algorithm (`CandidateCDHash`)."""

    algorithm: HashType | str
    """The algorithm of the code directory this hash is of."""
    truncated: str
    """The hash cut to 20 bytes, in hex."""
    full: str | None
    """The whole hash, in hex, when `codesign` prints it (`CandidateCDHashFull`)."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(
            algorithm=_hash_type(d["algorithm"]),
            truncated=d["truncated"],
            full=d["full"],
        )


@dataclass(frozen=True, slots=True)
class CmsDigest:
    """The CMS digest of a signature (`CMSDigest`)."""

    digest: str
    """The digest, in hex."""
    kind: int
    """The number of its algorithm (`CMSDigestType`)."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(digest=d["digest"], kind=d["kind"])


@dataclass(frozen=True, slots=True)
class ExecutableSegment:
    """The executable segment of a Mach-O, as its code directory seals it."""

    base: int
    """The segment's base, as printed."""
    limit: int
    """The segment's limit, as printed."""
    flags: int
    """The segment's flags, as printed in hex."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(base=d["base"], limit=d["limit"], flags=d["flags"])


@dataclass(frozen=True, slots=True)
class CertificateSignature:
    """How code signed with a certificate was signed (`Signature`).

    `Signature.signature` is `None` for an ad hoc signature, which names no signer.
    """

    size: int
    """The size of the signature in bytes."""
    authorities: tuple[str | None, ...]
    """The certificate chain by common name, leaf first (`Authority`).

    An entry is `None` for a certificate whose name `codesign` couldn't read.
    """

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(size=d["size"], authorities=tuple(d["authorities"]))


@dataclass(frozen=True, slots=True)
class SealedResources:
    """The seal over a bundle's resources (`Sealed Resources`)."""

    version: int
    """The version of the resource rules."""
    rules: int
    """How many rules there are."""
    files: int
    """How many files are sealed."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(version=d["version"], rules=d["rules"], files=d["files"])


@dataclass(frozen=True, slots=True)
class RequirementsSummary:
    """How many requirements a signature embeds, and their size.

    Maps to `Internal requirements`. `requirements` reads the requirements themselves.
    """

    count: int
    """How many requirements there are."""
    size: int
    """Their size in bytes."""

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(count=d["count"], size=d["size"])


@dataclass(frozen=True, slots=True)
class Requirement:
    """A code requirement of a signature: what it is for, and the expression to satisfy.

    `requirements` returns them.
    """

    kind: RequirementKind | str
    """What the requirement is for; a `str` for a kind with no `RequirementKind` member.
    """
    expression: str
    """The requirement as source text.

    For example `identifier "com.apple.ls" and anchor apple`. It isn't parsed: pass it
    to `verify`'s `test_requirement`, for instance.
    """
    implicit: bool
    """`True` when the signature doesn't embed this requirement and `codesign` shows the
    system's default instead, such as the designated requirement of an ad hoc signature,
    which names the code's hashes.
    """

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(
            kind=_requirement_kind(d["kind"]),
            expression=d["expression"],
            implicit=d["implicit"],
        )


@dataclass(frozen=True, slots=True)
class Certificate:
    """One certificate of a signature's chain, as DER bytes.

    The bytes are the certificate as `codesign` extracted it. They are not parsed: hand
    them to an X.509 parser, or write them to a file to inspect with
    `openssl x509 -inform der`.
    """

    der: bytes
    """The certificate in DER encoding."""


class _FromNative(Protocol):
    @classmethod
    def _from_native(cls, d: _Native) -> Self: ...


_T = TypeVar("_T", bound=_FromNative)


def _optional(build: type[_T], value: _Native | None) -> _T | None:
    return None if value is None else build._from_native(value)


@dataclass(frozen=True, slots=True)
class Signature:
    """The signature of one target, as `codesign --display` reports it.

    Each field comes from a line of the report; fields that are `None` or empty are for
    lines `codesign` prints only for some signatures. Nothing is lost to the typed view:
    `raw` holds the report as printed, minus trailing whitespace, and `field` looks up
    any line, mapped or not. A line this package doesn't know is ignored.

    Read it, don't build it: later versions can add fields. Where a field names an enum,
    a value without a member is held as the raw `str` or `int`.

    Example:
        ```python
        from signers import codesign

        signature = codesign.display("MyApp.app")

        print(signature.identifier, signature.cd_hash)
        if codesign.SigningFlags.RUNTIME in signature.code_directory.flags:
            print("hardened runtime")
        if signature.signature is not None:
            print(f"signed through {len(signature.signature.authorities)} certificates")
        ```
    """

    executable: Path
    """The path of the main executable (`Executable`).

    For a bundle it is the executable inside it, and for a versioned bundle read with
    `bundle_version` it names that version. The report is decoded lossily, so a byte
    that isn't UTF-8 in the path becomes U+FFFD.
    """
    identifier: str
    """The signing identifier (`Identifier`)."""
    format: Format
    """What kind of code it is (`Format`)."""
    code_directory: CodeDirectory
    """The code directory, which seals the code (`CodeDirectory`)."""
    platform_identifier: int | None
    """The platform identifier of an Apple system binary (`Platform identifier`)."""
    library_validation_warning: str | None
    """The warning `codesign` gives when library validation can't protect the code
    (`Library validation warning`).
    """
    platform: Platform | int | None
    """The platform the Mach-O was built for (`VersionPlatform`)."""
    min_os: OsVersion | None
    """The oldest OS version the code runs on (`VersionMin`)."""
    sdk: OsVersion | None
    """The SDK version the code was built with (`VersionSDK`)."""
    hash_type: HashType | str
    """The hash algorithm of the chosen code directory (`Hash type`)."""
    hash_choices: tuple[HashType | str, ...]
    """Every hash algorithm the signature carries a code directory for (`Hash choices`).
    """
    cd_hashes: tuple[CdHash, ...]
    """The code directory hash for each algorithm in the signature (`CandidateCDHash`).
    """
    cd_hash: str
    """The hash that identifies the code, in hex (`CDHash`)."""
    cms_digest: CmsDigest | None
    """The CMS digest and its type (`CMSDigest`, `CMSDigestType`)."""
    executable_segment: ExecutableSegment | None
    """Where the executable segment of the Mach-O sits (`Executable Segment`)."""
    page_size: int | None
    """The size of the pages the code is hashed in; `None` when the code isn't paged
    (`Page size`).
    """
    signature: CertificateSignature | None
    """How the code was signed with a certificate (`Signature`); `None` for an ad hoc
    signature.
    """
    timestamp: str | None
    """The secure timestamp, as `codesign` prints it (`Timestamp`).

    A signature has either this or `signed_time`. The text follows the user's locale and
    time zone, so don't parse it.
    """
    signed_time: str | None
    """The time the signature was made, as `codesign` prints it (`Signed Time`).

    The text follows the user's locale and time zone, so don't parse it.
    """
    notarization_ticket: str | None
    """The notarization ticket stapled to the code (`Notarization Ticket`)."""
    info_plist: int | None
    """The number of entries of the `Info.plist` the signature covers; `None` when it
    covers none (`Info.plist`).
    """
    team_identifier: str | None
    """The Team ID of the signer; `None` for ad hoc and for unteamed certificates
    (`TeamIdentifier`).
    """
    runtime_version: OsVersion | None
    """The hardened runtime version; only code signed with the runtime option has one
    (`Runtime Version`).
    """
    sealed_resources: SealedResources | None
    """The seal over the resources; `None` when nothing is sealed (`Sealed Resources`).
    """
    internal_requirements: RequirementsSummary | None
    """How many requirements the signature embeds, and their size; `None` when there
    are none (`Internal requirements`). `requirements` reads the requirements
    themselves.
    """
    total_signatures: int | None
    """The number of signatures in the code (`Total signatures`).

    `None` when the report has no such line, as for code signed by the linker.
    """
    chosen_signature: int | None
    """The index of the signature this report describes (`Chosen signature`).

    `None` when the report has no such line, as for code signed by the linker.
    """
    nested: tuple[str, ...]
    """The code nested directly in a bundle, as `codesign` prints each path (`Nested`).

    Only `display`'s `deep` lists them; without it this is empty.
    """
    constraints: Constraints
    """The launch and library constraints the code carries."""
    entitlements: dict[str, object] | None
    """The entitlements as a dict, or `None` if the target has none.

    Values are the plist's: `str`, `int`, `float`, `bool`, `bytes`, `datetime.datetime`,
    `list` and `dict`. They are read only when `codesign` runs over a single target,
    because over several in one run it prints entitlements that can't be matched back to
    their targets. With `per_target=False` and several targets, this is `None` for all
    of them.
    """
    raw: str = dataclasses.field(repr=False)
    """The report as `codesign` printed it, minus trailing whitespace. It is the same in
    every run mode, whether the target ran alone or with others.
    """

    def field(self, key: str) -> str | None:
        """Returns the value of the first report line that reads `key=value`, or `None`.

        The key is the text before the first `=`, with no trimming: `"Identifier"`,
        `"Authority"`. A key that repeats, such as `Authority`, gives its first line. It
        reaches lines the typed fields don't map.

        Example:
            ```python
            from signers import codesign

            signature = codesign.display("mytool")
            assert signature.field("Identifier") == signature.identifier
            ```
        """
        for line in self.raw.split("\n"):
            name, separator, value = line.partition("=")
            if separator and name == key:
                return value.removesuffix("\r")
        return None

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        platform = d["platform"]
        return cls(
            executable=Path(d["executable"]),
            identifier=d["identifier"],
            format=Format._from_native(d["format"]),
            code_directory=CodeDirectory._from_native(d["code_directory"]),
            platform_identifier=d["platform_identifier"],
            library_validation_warning=d["library_validation_warning"],
            platform=None if platform is None else _platform(platform),
            min_os=_optional(OsVersion, d["min_os"]),
            sdk=_optional(OsVersion, d["sdk"]),
            hash_type=_hash_type(d["hash_type"]),
            hash_choices=tuple(_hash_type(h) for h in d["hash_choices"]),
            cd_hashes=tuple(CdHash._from_native(h) for h in d["cd_hashes"]),
            cd_hash=d["cd_hash"],
            cms_digest=_optional(CmsDigest, d["cms_digest"]),
            executable_segment=_optional(ExecutableSegment, d["executable_segment"]),
            page_size=d["page_size"],
            signature=_optional(CertificateSignature, d["signature"]),
            timestamp=d["timestamp"],
            signed_time=d["signed_time"],
            notarization_ticket=d["notarization_ticket"],
            info_plist=d["info_plist"],
            team_identifier=d["team_identifier"],
            runtime_version=_optional(OsVersion, d["runtime_version"]),
            sealed_resources=_optional(SealedResources, d["sealed_resources"]),
            internal_requirements=_optional(
                RequirementsSummary, d["internal_requirements"]
            ),
            total_signatures=d["total_signatures"],
            chosen_signature=d["chosen_signature"],
            nested=tuple(d["nested"]),
            constraints=Constraints(d["constraints"]),
            entitlements=d["entitlements"],
            raw=d["raw"],
        )
