# pyright: reportPrivateUsage=false
"""Awaitable form of the `codesign` actions, for asyncio."""

from collections.abc import Sequence
from typing import overload

from .. import _native
from .._errors import _acall
from .._targets import StrPath, _normalize
from ._actions import (
    _certificates,
    _display_options,
    _path,
    _requirements,
    _sign_options,
    _signatures,
    _verify_options,
)
from ._options import PreserveMetadata, SignatureSlot, SigningFlags, Strict, Timestamp
from ._types import Certificate, Requirement, Signature

__all__ = [
    "display",
    "extract_certificates",
    "remove_signature",
    "requirements",
    "sign",
    "sign_adhoc",
    "sign_for_distribution",
    "validate_constraint",
    "verify",
]


@overload
async def remove_signature(
    target: StrPath,
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None: ...
@overload
async def remove_signature(
    target: Sequence[StrPath],
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None: ...
async def remove_signature(
    target: StrPath | Sequence[StrPath],
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None:
    """Awaitable form of `codesign.remove_signature`."""
    targets, _ = _normalize(target)
    await _acall(
        _native.codesign_remove_signature_async,
        targets,
        per_target=per_target,
        bundle_version=bundle_version,
    )


@overload
async def sign(
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
async def sign(
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
async def sign(
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
    """Awaitable form of `codesign.sign`."""
    targets, _ = _normalize(target)
    await _acall(
        _native.codesign_sign_async,
        targets,
        identity,
        _sign_options(
            identifier=identifier,
            requirements=requirements,
            prefix=prefix,
            keychain=keychain,
            entitlements=entitlements,
            force_library_entitlements=force_library_entitlements,
            generate_entitlement_der=generate_entitlement_der,
            options=options,
            runtime_version=runtime_version,
            launch_constraint_self=launch_constraint_self,
            launch_constraint_parent=launch_constraint_parent,
            launch_constraint_responsible=launch_constraint_responsible,
            library_constraint=library_constraint,
            enforce_constraint_validity=enforce_constraint_validity,
            force=force,
            deep=deep,
            preserve_metadata=preserve_metadata,
            page_size=page_size,
            timestamp=timestamp,
            bundle_version=bundle_version,
            strip_disallowed_xattrs=strip_disallowed_xattrs,
            single_threaded_signing=single_threaded_signing,
            dry_run=dry_run,
            detached=detached,
            detached_database=detached_database,
            file_list=file_list,
        ),
        per_target=per_target,
    )


@overload
async def sign_adhoc(
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
async def sign_adhoc(
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
async def sign_adhoc(
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
    """Awaitable form of `codesign.sign_adhoc`."""
    targets, _ = _normalize(target)
    await _acall(
        _native.codesign_sign_adhoc_async,
        targets,
        _sign_options(
            identifier=identifier,
            requirements=requirements,
            prefix=prefix,
            keychain=keychain,
            entitlements=entitlements,
            force_library_entitlements=force_library_entitlements,
            generate_entitlement_der=generate_entitlement_der,
            options=options,
            runtime_version=runtime_version,
            launch_constraint_self=launch_constraint_self,
            launch_constraint_parent=launch_constraint_parent,
            launch_constraint_responsible=launch_constraint_responsible,
            library_constraint=library_constraint,
            enforce_constraint_validity=enforce_constraint_validity,
            force=force,
            deep=deep,
            preserve_metadata=preserve_metadata,
            page_size=page_size,
            timestamp=timestamp,
            bundle_version=bundle_version,
            strip_disallowed_xattrs=strip_disallowed_xattrs,
            single_threaded_signing=single_threaded_signing,
            dry_run=dry_run,
            detached=detached,
            detached_database=detached_database,
            file_list=file_list,
        ),
        per_target=per_target,
    )


@overload
async def sign_for_distribution(
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
async def sign_for_distribution(
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
async def sign_for_distribution(
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
    """Awaitable form of `codesign.sign_for_distribution`."""
    targets, _ = _normalize(target)
    await _acall(
        _native.codesign_sign_for_distribution_async,
        targets,
        identity,
        _sign_options(
            identifier=identifier,
            requirements=requirements,
            prefix=prefix,
            keychain=keychain,
            entitlements=entitlements,
            force_library_entitlements=force_library_entitlements,
            generate_entitlement_der=generate_entitlement_der,
            options=options,
            runtime_version=runtime_version,
            launch_constraint_self=launch_constraint_self,
            launch_constraint_parent=launch_constraint_parent,
            launch_constraint_responsible=launch_constraint_responsible,
            library_constraint=library_constraint,
            enforce_constraint_validity=enforce_constraint_validity,
            force=force,
            deep=deep,
            preserve_metadata=preserve_metadata,
            page_size=page_size,
            timestamp=timestamp,
            bundle_version=bundle_version,
            strip_disallowed_xattrs=strip_disallowed_xattrs,
            single_threaded_signing=single_threaded_signing,
            dry_run=dry_run,
            detached=detached,
            detached_database=detached_database,
            file_list=file_list,
        ),
        per_target=per_target,
    )


@overload
async def verify(
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
async def verify(
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
async def verify(
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
    """Awaitable form of `codesign.verify`."""
    targets, _ = _normalize(target)
    await _acall(
        _native.codesign_verify_async,
        targets,
        _verify_options(
            deep=deep,
            strict=strict,
            ignore_resources=ignore_resources,
            architecture=architecture,
            bundle_version=bundle_version,
            check_designated_requirement=check_designated_requirement,
            test_requirement=test_requirement,
            test_requirement_file=test_requirement_file,
            detached=detached,
            check_notarization=check_notarization,
            signature_slot=signature_slot,
        ),
        per_target=per_target,
    )


@overload
async def validate_constraint(
    plist: StrPath, *, per_target: bool | None = None
) -> None: ...
@overload
async def validate_constraint(
    plist: Sequence[StrPath], *, per_target: bool | None = None
) -> None: ...
async def validate_constraint(
    plist: StrPath | Sequence[StrPath], *, per_target: bool | None = None
) -> None:
    """Awaitable form of `codesign.validate_constraint`."""
    targets, _ = _normalize(plist)
    await _acall(
        _native.codesign_validate_constraint_async, targets, per_target=per_target
    )


@overload
async def display(  # pyright: ignore[reportOverlappingOverload]
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
async def display(
    target: Sequence[StrPath],
    *,
    per_target: bool | None = None,
    architecture: str | None = None,
    bundle_version: str | None = None,
    deep: bool = False,
    signature_slot: SignatureSlot | None = None,
    detached: StrPath | None = None,
) -> list[Signature]: ...
async def display(
    target: StrPath | Sequence[StrPath],
    *,
    per_target: bool | None = None,
    architecture: str | None = None,
    bundle_version: str | None = None,
    deep: bool = False,
    signature_slot: SignatureSlot | None = None,
    detached: StrPath | None = None,
) -> Signature | list[Signature]:
    """Awaitable form of `codesign.display`."""
    targets, single = _normalize(target)
    native = await _acall(
        _native.codesign_display_async,
        targets,
        _display_options(
            architecture=architecture,
            bundle_version=bundle_version,
            deep=deep,
            signature_slot=signature_slot,
            detached=detached,
        ),
        per_target=per_target,
    )
    return _signatures(native, single)


@overload
async def requirements(target: StrPath) -> list[Requirement]: ...  # pyright: ignore[reportOverlappingOverload]
@overload
async def requirements(target: Sequence[StrPath]) -> list[list[Requirement]]: ...
async def requirements(
    target: StrPath | Sequence[StrPath],
) -> list[Requirement] | list[list[Requirement]]:
    """Awaitable form of `codesign.requirements`."""
    targets, single = _normalize(target)
    native = await _acall(_native.codesign_requirements_async, targets)
    return _requirements(native, single)


@overload
async def extract_certificates(  # pyright: ignore[reportOverlappingOverload]
    target: StrPath, *, save_to: StrPath | None = None
) -> list[Certificate]: ...
@overload
async def extract_certificates(
    target: Sequence[StrPath], *, save_to: StrPath | None = None
) -> list[list[Certificate]]: ...
async def extract_certificates(
    target: StrPath | Sequence[StrPath], *, save_to: StrPath | None = None
) -> list[Certificate] | list[list[Certificate]]:
    """Awaitable form of `codesign.extract_certificates`."""
    targets, single = _normalize(target)
    native = await _acall(
        _native.codesign_extract_certificates_async, targets, save_to=_path(save_to)
    )
    return _certificates(native, single)
