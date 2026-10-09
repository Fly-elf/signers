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
    "RequirementsSummary",
    "SealedResources",
    "Signature",
]

_Native = dict[str, Any]


class FormatKind(Enum):
    MACHO_THIN = "MACHO_THIN"
    MACHO_UNIVERSAL = "MACHO_UNIVERSAL"
    GENERIC = "GENERIC"
    DISK_IMAGE = "DISK_IMAGE"
    BUNDLE = "BUNDLE"
    INFO_PLIST_BUNDLE = "INFO_PLIST_BUNDLE"
    INSTALLER_PACKAGE = "INSTALLER_PACKAGE"
    WIDGET = "WIDGET"
    OTHER = "OTHER"


class Location(Enum):
    EMBEDDED = "EMBEDDED"
    EXPLICIT_DETACHED = "EXPLICIT_DETACHED"
    SYSTEM = "SYSTEM"


class Platform(Enum):
    MAC_OS = "MAC_OS"
    IOS = "IOS"
    TV_OS = "TV_OS"
    WATCH_OS = "WATCH_OS"
    BRIDGE_OS = "BRIDGE_OS"
    MAC_CATALYST = "MAC_CATALYST"
    IOS_SIMULATOR = "IOS_SIMULATOR"
    TV_OS_SIMULATOR = "TV_OS_SIMULATOR"
    WATCH_OS_SIMULATOR = "WATCH_OS_SIMULATOR"
    DRIVER_KIT = "DRIVER_KIT"
    VISION_OS = "VISION_OS"
    VISION_OS_SIMULATOR = "VISION_OS_SIMULATOR"


class HashType(Enum):
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA256_TRUNCATED = "SHA256_TRUNCATED"
    SHA384 = "SHA384"


class Constraints(Flag, boundary=FlagBoundary.KEEP):
    LAUNCH_SELF = 1
    LAUNCH_PARENT = 1 << 1
    LAUNCH_RESPONSIBLE = 1 << 2
    LIBRARY_LOAD = 1 << 3


def _location(value: str | _Native) -> Location | str:
    return Location[value] if isinstance(value, str) else str(value["other"])


def _platform(value: str | _Native) -> Platform | int:
    return Platform[value] if isinstance(value, str) else int(value["other"])


def _hash_type(value: str | _Native) -> HashType | str:
    return HashType[value] if isinstance(value, str) else str(value["other"])


@dataclass(frozen=True, slots=True)
class Format:
    kind: FormatKind
    archs: tuple[str, ...] = ()
    app: bool | None = None
    executable: Format | None = None
    other: str | None = None

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
    code: int
    special: int

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(code=d["code"], special=d["special"])


@dataclass(frozen=True, slots=True)
class CodeDirectory:
    version: int
    size: int
    flags: SigningFlags
    hashes: CodeHashes
    location: Location | str

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
    major: int
    minor: int
    patch: int

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(major=d["major"], minor=d["minor"], patch=d["patch"])


@dataclass(frozen=True, slots=True)
class CdHash:
    algorithm: HashType | str
    truncated: str
    full: str | None

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(
            algorithm=_hash_type(d["algorithm"]),
            truncated=d["truncated"],
            full=d["full"],
        )


@dataclass(frozen=True, slots=True)
class CmsDigest:
    digest: str
    kind: int

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(digest=d["digest"], kind=d["kind"])


@dataclass(frozen=True, slots=True)
class ExecutableSegment:
    base: int
    limit: int
    flags: int

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(base=d["base"], limit=d["limit"], flags=d["flags"])


@dataclass(frozen=True, slots=True)
class CertificateSignature:
    size: int
    authorities: tuple[str | None, ...]

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(size=d["size"], authorities=tuple(d["authorities"]))


@dataclass(frozen=True, slots=True)
class SealedResources:
    version: int
    rules: int
    files: int

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(version=d["version"], rules=d["rules"], files=d["files"])


@dataclass(frozen=True, slots=True)
class RequirementsSummary:
    count: int
    size: int

    @classmethod
    def _from_native(cls, d: _Native) -> Self:
        return cls(count=d["count"], size=d["size"])


class _FromNative(Protocol):
    @classmethod
    def _from_native(cls, d: _Native) -> Self: ...


_T = TypeVar("_T", bound=_FromNative)


def _optional(build: type[_T], value: _Native | None) -> _T | None:
    return None if value is None else build._from_native(value)


@dataclass(frozen=True, slots=True)
class Signature:
    executable: Path
    identifier: str
    format: Format
    code_directory: CodeDirectory
    platform_identifier: int | None
    library_validation_warning: str | None
    platform: Platform | int | None
    min_os: OsVersion | None
    sdk: OsVersion | None
    hash_type: HashType | str
    hash_choices: tuple[HashType | str, ...]
    cd_hashes: tuple[CdHash, ...]
    cd_hash: str
    cms_digest: CmsDigest | None
    executable_segment: ExecutableSegment | None
    page_size: int | None
    signature: CertificateSignature | None
    timestamp: str | None
    signed_time: str | None
    notarization_ticket: str | None
    info_plist: int | None
    team_identifier: str | None
    runtime_version: OsVersion | None
    sealed_resources: SealedResources | None
    internal_requirements: RequirementsSummary | None
    total_signatures: int | None
    chosen_signature: int | None
    nested: tuple[str, ...]
    constraints: Constraints
    entitlements: dict[str, object] | None
    raw: str = dataclasses.field(repr=False)

    def field(self, key: str) -> str | None:
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
