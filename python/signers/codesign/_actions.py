# pyright: reportPrivateUsage=false
import os
from collections.abc import Sequence
from enum import Flag
from typing import overload

from .. import _native
from .._errors import _call
from .._targets import StrPath, _normalize
from ._options import PreserveMetadata, SignatureSlot, SigningFlags, Strict, Timestamp
from ._types import Signature


def _path(path: StrPath | None) -> str | None:
    return None if path is None else os.fspath(path)


def _bits(flags: Flag | None) -> int | None:
    return None if flags is None else flags.value


def _timestamp(timestamp: Timestamp | str | None) -> str | None:
    return timestamp.name if isinstance(timestamp, Timestamp) else timestamp


@overload
def remove_signature(
    target: StrPath,
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None: ...
@overload
def remove_signature(
    target: Sequence[StrPath],
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None: ...
def remove_signature(
    target: StrPath | Sequence[StrPath],
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None:
    targets, _ = _normalize(target)
    _call(
        _native.codesign_remove_signature,
        targets,
        per_target=per_target,
        bundle_version=bundle_version,
    )


@overload
def sign(
    target: StrPath,
    identity: str,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None: ...

@overload
def sign(
    target: Sequence[StrPath],
    identity: str,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None: ...


def sign(
    target: StrPath | Sequence[StrPath],
    identity: str,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None:
    targets, _ = _normalize(target)
    _call(
        _native.codesign_sign,
        targets,
        identity,
        {
            "identifier": identifier,
            "requirements": requirements,
            "prefix": prefix,
            "keychain": _path(keychain),
            "entitlements": _path(entitlements),
            "force_library_entitlements": force_library_entitlements,
            "generate_entitlement_der": generate_entitlement_der,
            "options": _bits(options),
            "runtime_version": runtime_version,
            "launch_constraint_self": _path(launch_constraint_self),
            "launch_constraint_parent": _path(launch_constraint_parent),
            "launch_constraint_responsible": _path(launch_constraint_responsible),
            "library_constraint": _path(library_constraint),
            "enforce_constraint_validity": enforce_constraint_validity,
            "force": force,
            "deep": deep,
            "preserve_metadata": _bits(preserve_metadata),
            "page_size": page_size,
            "timestamp": _timestamp(timestamp),
            "bundle_version": bundle_version,
            "strip_disallowed_xattrs": strip_disallowed_xattrs,
            "single_threaded_signing": single_threaded_signing,
            "dry_run": dry_run,
            "detached": _path(detached),
            "detached_database": detached_database,
            "file_list": _path(file_list),
        },
        per_target=per_target,
    )


@overload
def sign_adhoc(
    target: StrPath,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None: ...

@overload
def sign_adhoc(
    target: Sequence[StrPath],
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None: ...


def sign_adhoc(
    target: StrPath | Sequence[StrPath],
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None:
    targets, _ = _normalize(target)
    _call(
        _native.codesign_sign_adhoc,
        targets,
        {
            "identifier": identifier,
            "requirements": requirements,
            "prefix": prefix,
            "keychain": _path(keychain),
            "entitlements": _path(entitlements),
            "force_library_entitlements": force_library_entitlements,
            "generate_entitlement_der": generate_entitlement_der,
            "options": _bits(options),
            "runtime_version": runtime_version,
            "launch_constraint_self": _path(launch_constraint_self),
            "launch_constraint_parent": _path(launch_constraint_parent),
            "launch_constraint_responsible": _path(launch_constraint_responsible),
            "library_constraint": _path(library_constraint),
            "enforce_constraint_validity": enforce_constraint_validity,
            "force": force,
            "deep": deep,
            "preserve_metadata": _bits(preserve_metadata),
            "page_size": page_size,
            "timestamp": _timestamp(timestamp),
            "bundle_version": bundle_version,
            "strip_disallowed_xattrs": strip_disallowed_xattrs,
            "single_threaded_signing": single_threaded_signing,
            "dry_run": dry_run,
            "detached": _path(detached),
            "detached_database": detached_database,
            "file_list": _path(file_list),
        },
        per_target=per_target,
    )


@overload
def sign_for_distribution(
    target: StrPath,
    identity: str,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None: ...

@overload
def sign_for_distribution(
    target: Sequence[StrPath],
    identity: str,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None: ...


def sign_for_distribution(
    target: StrPath | Sequence[StrPath],
    identity: str,
    *,
    per_target: bool | None = None,
    identifier: str | None = None,
    requirements: str | None = None,
    prefix: str | None = None,
    keychain: StrPath | None = None,
    entitlements: StrPath | None = None,
    force_library_entitlements: bool = False,
    generate_entitlement_der: bool = False,
    options: SigningFlags | None = None,
    runtime_version: str | None = None,
    launch_constraint_self: StrPath | None = None,
    launch_constraint_parent: StrPath | None = None,
    launch_constraint_responsible: StrPath | None = None,
    library_constraint: StrPath | None = None,
    enforce_constraint_validity: bool = False,
    force: bool = False,
    deep: bool = False,
    preserve_metadata: PreserveMetadata | None = None,
    page_size: int | None = None,
    timestamp: Timestamp | str | None = None,
    bundle_version: str | None = None,
    strip_disallowed_xattrs: bool = False,
    single_threaded_signing: bool = False,
    dry_run: bool = False,
    detached: StrPath | None = None,
    detached_database: bool = False,
    file_list: StrPath | None = None,
) -> None:
    targets, _ = _normalize(target)
    _call(
        _native.codesign_sign_for_distribution,
        targets,
        identity,
        {
            "identifier": identifier,
            "requirements": requirements,
            "prefix": prefix,
            "keychain": _path(keychain),
            "entitlements": _path(entitlements),
            "force_library_entitlements": force_library_entitlements,
            "generate_entitlement_der": generate_entitlement_der,
            "options": _bits(options),
            "runtime_version": runtime_version,
            "launch_constraint_self": _path(launch_constraint_self),
            "launch_constraint_parent": _path(launch_constraint_parent),
            "launch_constraint_responsible": _path(launch_constraint_responsible),
            "library_constraint": _path(library_constraint),
            "enforce_constraint_validity": enforce_constraint_validity,
            "force": force,
            "deep": deep,
            "preserve_metadata": _bits(preserve_metadata),
            "page_size": page_size,
            "timestamp": _timestamp(timestamp),
            "bundle_version": bundle_version,
            "strip_disallowed_xattrs": strip_disallowed_xattrs,
            "single_threaded_signing": single_threaded_signing,
            "dry_run": dry_run,
            "detached": _path(detached),
            "detached_database": detached_database,
            "file_list": _path(file_list),
        },
        per_target=per_target,
    )


@overload
def verify(
    target: StrPath,
    *,
    per_target: bool | None = None,
    deep: bool = False,
    strict: Strict | None = None,
    ignore_resources: bool = False,
    architecture: str | None = None,
    bundle_version: str | None = None,
    check_designated_requirement: bool = False,
    test_requirement: str | None = None,
    test_requirement_file: StrPath | None = None,
    detached: StrPath | None = None,
    check_notarization: bool = False,
    signature_slot: SignatureSlot | None = None,
) -> None: ...
@overload
def verify(
    target: Sequence[StrPath],
    *,
    per_target: bool | None = None,
    deep: bool = False,
    strict: Strict | None = None,
    ignore_resources: bool = False,
    architecture: str | None = None,
    bundle_version: str | None = None,
    check_designated_requirement: bool = False,
    test_requirement: str | None = None,
    test_requirement_file: StrPath | None = None,
    detached: StrPath | None = None,
    check_notarization: bool = False,
    signature_slot: SignatureSlot | None = None,
) -> None: ...
def verify(
    target: StrPath | Sequence[StrPath],
    *,
    per_target: bool | None = None,
    deep: bool = False,
    strict: Strict | None = None,
    ignore_resources: bool = False,
    architecture: str | None = None,
    bundle_version: str | None = None,
    check_designated_requirement: bool = False,
    test_requirement: str | None = None,
    test_requirement_file: StrPath | None = None,
    detached: StrPath | None = None,
    check_notarization: bool = False,
    signature_slot: SignatureSlot | None = None,
) -> None:
    if test_requirement is not None and test_requirement_file is not None:
        raise TypeError(
            "test_requirement and test_requirement_file are mutually exclusive"
        )
    targets, _ = _normalize(target)
    _call(
        _native.codesign_verify,
        targets,
        {
            "deep": deep,
            "strict": None if strict is None else strict.name,
            "ignore_resources": ignore_resources,
            "architecture": architecture,
            "bundle_version": bundle_version,
            "check_designated_requirement": check_designated_requirement,
            "test_requirement": test_requirement,
            "test_requirement_file": _path(test_requirement_file),
            "detached": _path(detached),
            "check_notarization": check_notarization,
            "signature_slot": None if signature_slot is None else signature_slot.name,
        },
        per_target=per_target,
    )


@overload
def validate_constraint(plist: StrPath, *, per_target: bool | None = None) -> None: ...
@overload
def validate_constraint(
    plist: Sequence[StrPath], *, per_target: bool | None = None
) -> None: ...
def validate_constraint(
    plist: StrPath | Sequence[StrPath], *, per_target: bool | None = None
) -> None:
    targets, _ = _normalize(plist)
    _call(_native.codesign_validate_constraint, targets, per_target=per_target)


# A str is also a Sequence[str]; the first overload wins, as intended.
@overload
def display(  # pyright: ignore[reportOverlappingOverload]
    target: StrPath,
    *,
    per_target: bool | None = None,
    architecture: str | None = None,
    bundle_version: str | None = None,
    deep: bool = False,
    signature_slot: SignatureSlot | None = None,
    detached: StrPath | None = None,
) -> Signature: ...
@overload
def display(
    target: Sequence[StrPath],
    *,
    per_target: bool | None = None,
    architecture: str | None = None,
    bundle_version: str | None = None,
    deep: bool = False,
    signature_slot: SignatureSlot | None = None,
    detached: StrPath | None = None,
) -> list[Signature]: ...
def display(
    target: StrPath | Sequence[StrPath],
    *,
    per_target: bool | None = None,
    architecture: str | None = None,
    bundle_version: str | None = None,
    deep: bool = False,
    signature_slot: SignatureSlot | None = None,
    detached: StrPath | None = None,
) -> Signature | list[Signature]:
    targets, single = _normalize(target)
    native = _call(
        _native.codesign_display,
        targets,
        {
            "architecture": architecture,
            "bundle_version": bundle_version,
            "deep": deep,
            "signature_slot": None if signature_slot is None else signature_slot.name,
            "detached": _path(detached),
        },
        per_target=per_target,
    )
    if single:
        return Signature._from_native(native)
    return [Signature._from_native(d) for d in native]
