# pyright: reportPrivateUsage=false
import os
from collections.abc import Sequence
from enum import Flag
from typing import TYPE_CHECKING, Any, overload

from .. import _native
from .._errors import _call
from .._targets import StrPath, _normalize
from ._options import PreserveMetadata, SignatureSlot, SigningFlags, Strict, Timestamp
from ._types import Certificate, Requirement, Signature

if TYPE_CHECKING:
    from .._native import DisplayOptions, SignOptions, VerifyOptions


def _path(path: StrPath | None) -> str | None:
    return None if path is None else os.fspath(path)


def _bits(flags: Flag | None) -> int | None:
    return None if flags is None else flags.value


def _timestamp(timestamp: Timestamp | str | None) -> str | None:
    return timestamp.name if isinstance(timestamp, Timestamp) else timestamp


def _sign_options(
    *,
    identifier: str | None,
    requirements: str | None,
    prefix: str | None,
    keychain: StrPath | None,
    entitlements: StrPath | None,
    force_library_entitlements: bool,
    generate_entitlement_der: bool,
    options: SigningFlags | None,
    runtime_version: str | None,
    launch_constraint_self: StrPath | None,
    launch_constraint_parent: StrPath | None,
    launch_constraint_responsible: StrPath | None,
    library_constraint: StrPath | None,
    enforce_constraint_validity: bool,
    force: bool,
    deep: bool,
    preserve_metadata: PreserveMetadata | None,
    page_size: int | None,
    timestamp: Timestamp | str | None,
    bundle_version: str | None,
    strip_disallowed_xattrs: bool,
    single_threaded_signing: bool,
    dry_run: bool,
    detached: StrPath | None,
    detached_database: bool,
    file_list: StrPath | None,
) -> "SignOptions":
    return {
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
    }


def _verify_options(
    *,
    deep: bool,
    strict: Strict | None,
    ignore_resources: bool,
    architecture: str | None,
    bundle_version: str | None,
    check_designated_requirement: bool,
    test_requirement: str | None,
    test_requirement_file: StrPath | None,
    detached: StrPath | None,
    check_notarization: bool,
    signature_slot: SignatureSlot | None,
) -> "VerifyOptions":
    if test_requirement is not None and test_requirement_file is not None:
        raise TypeError(
            "test_requirement and test_requirement_file are mutually exclusive"
        )
    return {
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
    }


def _display_options(
    *,
    architecture: str | None,
    bundle_version: str | None,
    deep: bool,
    signature_slot: SignatureSlot | None,
    detached: StrPath | None,
) -> "DisplayOptions":
    return {
        "architecture": architecture,
        "bundle_version": bundle_version,
        "deep": deep,
        "signature_slot": None if signature_slot is None else signature_slot.name,
        "detached": _path(detached),
    }


def _signatures(native: Any, single: bool) -> Signature | list[Signature]:
    if single:
        return Signature._from_native(native)
    return [Signature._from_native(d) for d in native]


def _requirements(
    native: Any, single: bool
) -> list[Requirement] | list[list[Requirement]]:
    if single:
        return [Requirement._from_native(d) for d in native]
    return [[Requirement._from_native(d) for d in chain] for chain in native]


def _certificates(
    native: Any, single: bool
) -> list[Certificate] | list[list[Certificate]]:
    if single:
        return [Certificate(der) for der in native]
    return [[Certificate(der) for der in chain] for chain in native]


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
    """Removes the signature from the target (`--remove-signature`).

    On a bundle, `codesign` removes the main executable's signature and the resource
    seal. It leaves nested code signed and an empty `_CodeSignature` directory behind.
    It accepts unsigned targets, and files that aren't code, without changing them.

    You don't need to remove a signature before re-signing: `sign` with `force=True`
    replaces it in one step.

    Args:
        target: The path to strip, or a sequence of paths.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is one run: it
            changes the targets in order and stops at the first it rejects. With `True`
            every target runs and the failures come together in a `BatchError`, but the
            runs overlap in no fixed order.
        bundle_version: Removes the signature from this version of a versioned bundle
            only. The version names a directory under the bundle's `Versions`. Without
            it, `codesign` uses the version that `Current` points to
            (`--bundle-version`).

    Returns:
        `None`, for one path and for a sequence alike.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        CodesignFailedError: `codesign` rejected a target. The targets before it have
            already changed.
        BatchError: With `per_target=True`, every target that failed, each with its own
            error.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`), or printed output that couldn't be read.

    Example:
        ```python
        from signers import codesign

        codesign.remove_signature(["mytool", "libfoo.dylib"])
        ```
    """
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
    """Signs the target with the identity that `identity` names (`--sign`).

    Signing an already signed target fails with "is already signed" unless you set
    `force`. A signature added by the linker doesn't need `force`.

    Sign the nested code first, then the bundle that seals it. This replaces the
    deprecated `deep`.

    Args:
        target: The path to sign, or a sequence of paths.
        identity: The signing identity: `"-"` for an ad hoc signature (see
            `sign_adhoc`), otherwise a certificate with its private key from the
            keychain search list. It is the name of an identity preference, part of the
            certificate's common name that matches only one certificate (an exact match
            wins, case-sensitive), or the certificate's SHA-1 hash as 40 hex digits.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is one run: it
            changes the targets in order and stops at the first it rejects. With `True`
            every target runs and the failures come together in a `BatchError`, but the
            runs overlap in no fixed order. A bundle in the same call as the code nested
            in it can then be sealed before that code is signed, which leaves the
            bundle's signature invalid: sign the nested code in an earlier call.
        identifier: Seals this identifier instead of deriving one from `Info.plist` or
            the file name. Every target in the batch gets it, and each program should
            have its own (`--identifier`).
        requirements: Embeds internal requirements from a file, or from source prefixed
            with `=`. The kinds of requirement you don't specify get `codesign`'s
            defaults. `"-"` raises `StdioPathError` (`--requirements`).
        prefix: Prefixes a derived identifier that contains no dot, e.g. with
            `"com.example."`. Include the trailing dot. It has no effect when you set
            `identifier` (`--prefix`).
        keychain: Looks up the signing identity in this keychain only. It doesn't need
            to be on the search list, so a temporary one works, but the certificate
            chain still comes from the search list only (`--keychain`).
        entitlements: Embeds the entitlements in this plist. `codesign` leaves them out
            of libraries unless you also set `force_library_entitlements`
            (`--entitlements`).
        force_library_entitlements: Embeds the entitlements in libraries too, not only
            in main executables. Without it, `codesign` signs a library with no
            entitlements and reports no error (`--force-library-entitlements`).
        generate_entitlement_der: Embeds the entitlements as DER as well as XML. This
            has been the default since macOS 12 (`--generate-entitlement-der`).
        options: The `SigningFlags` to seal. This replaces the whole set, including the
            one from `sign_for_distribution`; `None` keeps it (`--options`).
        runtime_version: Records this hardened runtime version instead of the SDK's.
            Only takes effect with `SigningFlags.RUNTIME`; without that flag, `codesign`
            ignores it (`--runtime-version`).
        launch_constraint_self: Embeds the launch constraint in this plist, on the
            executable itself (`--launch-constraint-self`).
        launch_constraint_parent: Embeds the launch constraint in this plist, on the
            executable's parent process (`--launch-constraint-parent`).
        launch_constraint_responsible: Embeds the launch constraint in this plist, on
            the executable's responsible process (`--launch-constraint-responsible`).
        library_constraint: Embeds the constraint in this plist on the libraries the
            executable may load. System libraries are exempt (`--library-constraint`).
        enforce_constraint_validity: Makes an invalid constraint fail the signing
            instead of only warning. By default `codesign` reports unknown keys and
            malformed constraints but signs anyway, so you can sign constraints meant
            for a newer macOS. On macOS 27.0 it rejects every constraint when this is
            set, valid ones included (`--enforce-constraint-validity`).
        force: Replaces an existing signature instead of failing. Patching a binary
            breaks its signature but leaves it in place, so re-signing it needs `force`.
            Setting it on an unsigned target does no harm (`--force`).
        deep: Signs the nested code too, applying every option to it as well. Apple
            deprecated this for signing in macOS 13, because the options rarely suit the
            nested code: sign the nested code first and the bundle last instead
            (`--deep`).
        preserve_metadata: The `PreserveMetadata` parts of the signature being replaced
            to reuse. Needs `force`, since without it there is nothing to replace.
            Values you set explicitly win over preserved ones, and `codesign` ignores
            this option when the old signature came from the linker
            (`--preserve-metadata`).
        page_size: Sets the signing page size in bytes, or `0` for a single page.
            Anything but a power of two or `0` makes `codesign` fail. Only the main
            executable is affected, not resources (`--pagesize`).
        timestamp: Whether to get a secure timestamp, and from where: a `Timestamp`
            member, or the URL of a timestamp server as a `str`. If you don't set it,
            `codesign` decides on its own. The server is contacted during the call, and
            if it can't be reached the signing fails. Ad hoc signatures ignore this
            option (`--timestamp`).
        bundle_version: Signs this version of a versioned bundle instead of the current
            one. The version names a directory under the bundle's `Versions`, e.g. `"A"`
            (`--bundle-version`).
        strip_disallowed_xattrs: Removes extended attributes that block signing, such as
            resource forks. Without it, a target that carries one fails with "resource
            fork, Finder information, or similar detritus not allowed"
            (`--strip-disallowed-xattrs`).
        single_threaded_signing: Builds the resource seal on one thread
            (`--single-threaded-signing`).
        dry_run: Runs the whole signing, identity and keychain access included, but
            writes nothing (`--dryrun`).
        detached: Writes the signature to this file and leaves the target unchanged.
            Every target's signature goes to this one file, so with `per_target=True`
            the call raises `SharedOutputPerTargetError` (`--detached`).
        detached_database: Writes a detached signature to the system database. This
            needs root; otherwise `codesign` fails with "cannot access a database" and
            leaves the target unchanged (`--detached-database`).
        file_list: Appends to this file the paths that signing may have changed, one per
            line. Any file not listed is unchanged; a listed file may be unchanged too.
            `"-"` (standard output on the command line) raises `StdioPathError`, and
            with `per_target=True` the call raises `SharedOutputPerTargetError`, since
            every process would append to the same file (`--file-list`).

    Returns:
        `None`, for one path and for a sequence alike.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        StdioPathError: `requirements` or `file_list` is `"-"`.
        SharedOutputPerTargetError: `per_target` is true with `detached` or `file_list`.
        CodesignFailedError: `codesign` rejected a target. The targets before it have
            already changed.
        BatchError: With `per_target=True`, every target that failed, each with its own
            error.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`), or printed output that couldn't be read.

    Example:
        ```python
        from signers import codesign

        identity = "Apple Development: Jane Doe (A1B2C3D4E5)"
        codesign.sign("MyApp.app/Contents/Frameworks/Engine.framework", identity)
        codesign.sign("MyApp.app", identity, entitlements="MyApp.entitlements")
        ```
    """
    targets, _ = _normalize(target)
    _call(
        _native.codesign_sign,
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
    """Signs the target ad hoc, with no certificate (`--sign -`).

    An ad hoc signature names no signer. That suits local use, including re-signing
    patched binaries, but not distribution. It never gets a timestamp.

    Signing an already signed target fails with "is already signed" unless you set
    `force`. A signature added by the linker doesn't need `force`.

    Args:
        target: The path to sign, or a sequence of paths.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is one run: it
            changes the targets in order and stops at the first it rejects. With `True`
            every target runs and the failures come together in a `BatchError`, but the
            runs overlap in no fixed order. A bundle in the same call as the code nested
            in it can then be sealed before that code is signed, which leaves the
            bundle's signature invalid: sign the nested code in an earlier call.
        identifier: Seals this identifier instead of deriving one from `Info.plist` or
            the file name. Every target in the batch gets it, and each program should
            have its own (`--identifier`).
        requirements: Embeds internal requirements from a file, or from source prefixed
            with `=`. The kinds of requirement you don't specify get `codesign`'s
            defaults. `"-"` raises `StdioPathError` (`--requirements`).
        prefix: Prefixes a derived identifier that contains no dot, e.g. with
            `"com.example."`. Include the trailing dot. It has no effect when you set
            `identifier` (`--prefix`).
        keychain: Looks up the signing identity in this keychain only. It doesn't need
            to be on the search list, so a temporary one works, but the certificate
            chain still comes from the search list only (`--keychain`).
        entitlements: Embeds the entitlements in this plist. `codesign` leaves them out
            of libraries unless you also set `force_library_entitlements`
            (`--entitlements`).
        force_library_entitlements: Embeds the entitlements in libraries too, not only
            in main executables. Without it, `codesign` signs a library with no
            entitlements and reports no error (`--force-library-entitlements`).
        generate_entitlement_der: Embeds the entitlements as DER as well as XML. This
            has been the default since macOS 12 (`--generate-entitlement-der`).
        options: The `SigningFlags` to seal. This replaces the whole set, including the
            one from `sign_for_distribution`; `None` keeps it (`--options`).
        runtime_version: Records this hardened runtime version instead of the SDK's.
            Only takes effect with `SigningFlags.RUNTIME`; without that flag, `codesign`
            ignores it (`--runtime-version`).
        launch_constraint_self: Embeds the launch constraint in this plist, on the
            executable itself (`--launch-constraint-self`).
        launch_constraint_parent: Embeds the launch constraint in this plist, on the
            executable's parent process (`--launch-constraint-parent`).
        launch_constraint_responsible: Embeds the launch constraint in this plist, on
            the executable's responsible process (`--launch-constraint-responsible`).
        library_constraint: Embeds the constraint in this plist on the libraries the
            executable may load. System libraries are exempt (`--library-constraint`).
        enforce_constraint_validity: Makes an invalid constraint fail the signing
            instead of only warning. By default `codesign` reports unknown keys and
            malformed constraints but signs anyway, so you can sign constraints meant
            for a newer macOS. On macOS 27.0 it rejects every constraint when this is
            set, valid ones included (`--enforce-constraint-validity`).
        force: Replaces an existing signature instead of failing. Patching a binary
            breaks its signature but leaves it in place, so re-signing it needs `force`.
            Setting it on an unsigned target does no harm (`--force`).
        deep: Signs the nested code too, applying every option to it as well. Apple
            deprecated this for signing in macOS 13, because the options rarely suit the
            nested code: sign the nested code first and the bundle last instead
            (`--deep`).
        preserve_metadata: The `PreserveMetadata` parts of the signature being replaced
            to reuse. Needs `force`, since without it there is nothing to replace.
            Values you set explicitly win over preserved ones, and `codesign` ignores
            this option when the old signature came from the linker
            (`--preserve-metadata`).
        page_size: Sets the signing page size in bytes, or `0` for a single page.
            Anything but a power of two or `0` makes `codesign` fail. Only the main
            executable is affected, not resources (`--pagesize`).
        timestamp: Whether to get a secure timestamp, and from where: a `Timestamp`
            member, or the URL of a timestamp server as a `str`. If you don't set it,
            `codesign` decides on its own. The server is contacted during the call, and
            if it can't be reached the signing fails. Ad hoc signatures ignore this
            option (`--timestamp`).
        bundle_version: Signs this version of a versioned bundle instead of the current
            one. The version names a directory under the bundle's `Versions`, e.g. `"A"`
            (`--bundle-version`).
        strip_disallowed_xattrs: Removes extended attributes that block signing, such as
            resource forks. Without it, a target that carries one fails with "resource
            fork, Finder information, or similar detritus not allowed"
            (`--strip-disallowed-xattrs`).
        single_threaded_signing: Builds the resource seal on one thread
            (`--single-threaded-signing`).
        dry_run: Runs the whole signing, identity and keychain access included, but
            writes nothing (`--dryrun`).
        detached: Writes the signature to this file and leaves the target unchanged.
            Every target's signature goes to this one file, so with `per_target=True`
            the call raises `SharedOutputPerTargetError` (`--detached`).
        detached_database: Writes a detached signature to the system database. This
            needs root; otherwise `codesign` fails with "cannot access a database" and
            leaves the target unchanged (`--detached-database`).
        file_list: Appends to this file the paths that signing may have changed, one per
            line. Any file not listed is unchanged; a listed file may be unchanged too.
            `"-"` (standard output on the command line) raises `StdioPathError`, and
            with `per_target=True` the call raises `SharedOutputPerTargetError`, since
            every process would append to the same file (`--file-list`).

    Returns:
        `None`, for one path and for a sequence alike.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        StdioPathError: `requirements` or `file_list` is `"-"`.
        SharedOutputPerTargetError: `per_target` is true with `detached` or `file_list`.
        CodesignFailedError: `codesign` rejected a target. The targets before it have
            already changed.
        BatchError: With `per_target=True`, every target that failed, each with its own
            error.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`), or printed output that couldn't be read.

    Example:
        ```python
        from signers import codesign

        # The patch broke the old signature; `force` replaces it.
        codesign.sign_adhoc("patched.dylib", force=True)

        codesign.sign_adhoc(["liba.dylib", "libb.dylib"], force=True)
        ```
    """
    targets, _ = _normalize(target)
    _call(
        _native.codesign_sign_adhoc,
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
    """Signs the target for notarization: hardened runtime and timestamp.

    This is `sign` with `options=SigningFlags.RUNTIME` and `timestamp=Timestamp.ENABLED`
    already set (`--options runtime --timestamp`). Passing `options` or `timestamp`
    replaces the preset, so keep `RUNTIME` in `options`. The call fetches the timestamp
    from Apple's server, so without network access the signing fails.

    Signing an already signed target fails with "is already signed" unless you set
    `force`. A signature added by the linker doesn't need `force`.

    Args:
        target: The path to sign, or a sequence of paths.
        identity: The signing identity, usually a Developer ID Application certificate:
            part of its common name that matches only one certificate, or its SHA-1 hash
            as 40 hex digits. See `sign`.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is one run: it
            changes the targets in order and stops at the first it rejects. With `True`
            every target runs and the failures come together in a `BatchError`, but the
            runs overlap in no fixed order. A bundle in the same call as the code nested
            in it can then be sealed before that code is signed, which leaves the
            bundle's signature invalid: sign the nested code in an earlier call.
        identifier: Seals this identifier instead of deriving one from `Info.plist` or
            the file name. Every target in the batch gets it, and each program should
            have its own (`--identifier`).
        requirements: Embeds internal requirements from a file, or from source prefixed
            with `=`. The kinds of requirement you don't specify get `codesign`'s
            defaults. `"-"` raises `StdioPathError` (`--requirements`).
        prefix: Prefixes a derived identifier that contains no dot, e.g. with
            `"com.example."`. Include the trailing dot. It has no effect when you set
            `identifier` (`--prefix`).
        keychain: Looks up the signing identity in this keychain only. It doesn't need
            to be on the search list, so a temporary one works, but the certificate
            chain still comes from the search list only (`--keychain`).
        entitlements: Embeds the entitlements in this plist. `codesign` leaves them out
            of libraries unless you also set `force_library_entitlements`
            (`--entitlements`).
        force_library_entitlements: Embeds the entitlements in libraries too, not only
            in main executables. Without it, `codesign` signs a library with no
            entitlements and reports no error (`--force-library-entitlements`).
        generate_entitlement_der: Embeds the entitlements as DER as well as XML. This
            has been the default since macOS 12 (`--generate-entitlement-der`).
        options: The `SigningFlags` to seal. This replaces the whole set, including the
            one from `sign_for_distribution`; `None` keeps it (`--options`).
        runtime_version: Records this hardened runtime version instead of the SDK's.
            Only takes effect with `SigningFlags.RUNTIME`; without that flag, `codesign`
            ignores it (`--runtime-version`).
        launch_constraint_self: Embeds the launch constraint in this plist, on the
            executable itself (`--launch-constraint-self`).
        launch_constraint_parent: Embeds the launch constraint in this plist, on the
            executable's parent process (`--launch-constraint-parent`).
        launch_constraint_responsible: Embeds the launch constraint in this plist, on
            the executable's responsible process (`--launch-constraint-responsible`).
        library_constraint: Embeds the constraint in this plist on the libraries the
            executable may load. System libraries are exempt (`--library-constraint`).
        enforce_constraint_validity: Makes an invalid constraint fail the signing
            instead of only warning. By default `codesign` reports unknown keys and
            malformed constraints but signs anyway, so you can sign constraints meant
            for a newer macOS. On macOS 27.0 it rejects every constraint when this is
            set, valid ones included (`--enforce-constraint-validity`).
        force: Replaces an existing signature instead of failing. Patching a binary
            breaks its signature but leaves it in place, so re-signing it needs `force`.
            Setting it on an unsigned target does no harm (`--force`).
        deep: Signs the nested code too, applying every option to it as well. Apple
            deprecated this for signing in macOS 13, because the options rarely suit the
            nested code: sign the nested code first and the bundle last instead
            (`--deep`).
        preserve_metadata: The `PreserveMetadata` parts of the signature being replaced
            to reuse. Needs `force`, since without it there is nothing to replace.
            Values you set explicitly win over preserved ones, and `codesign` ignores
            this option when the old signature came from the linker
            (`--preserve-metadata`).
        page_size: Sets the signing page size in bytes, or `0` for a single page.
            Anything but a power of two or `0` makes `codesign` fail. Only the main
            executable is affected, not resources (`--pagesize`).
        timestamp: Whether to get a secure timestamp, and from where: a `Timestamp`
            member, or the URL of a timestamp server as a `str`. If you don't set it,
            `codesign` decides on its own. The server is contacted during the call, and
            if it can't be reached the signing fails. Ad hoc signatures ignore this
            option (`--timestamp`).
        bundle_version: Signs this version of a versioned bundle instead of the current
            one. The version names a directory under the bundle's `Versions`, e.g. `"A"`
            (`--bundle-version`).
        strip_disallowed_xattrs: Removes extended attributes that block signing, such as
            resource forks. Without it, a target that carries one fails with "resource
            fork, Finder information, or similar detritus not allowed"
            (`--strip-disallowed-xattrs`).
        single_threaded_signing: Builds the resource seal on one thread
            (`--single-threaded-signing`).
        dry_run: Runs the whole signing, identity and keychain access included, but
            writes nothing (`--dryrun`).
        detached: Writes the signature to this file and leaves the target unchanged.
            Every target's signature goes to this one file, so with `per_target=True`
            the call raises `SharedOutputPerTargetError` (`--detached`).
        detached_database: Writes a detached signature to the system database. This
            needs root; otherwise `codesign` fails with "cannot access a database" and
            leaves the target unchanged (`--detached-database`).
        file_list: Appends to this file the paths that signing may have changed, one per
            line. Any file not listed is unchanged; a listed file may be unchanged too.
            `"-"` (standard output on the command line) raises `StdioPathError`, and
            with `per_target=True` the call raises `SharedOutputPerTargetError`, since
            every process would append to the same file (`--file-list`).

    Returns:
        `None`, for one path and for a sequence alike.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        StdioPathError: `requirements` or `file_list` is `"-"`.
        SharedOutputPerTargetError: `per_target` is true with `detached` or `file_list`.
        CodesignFailedError: `codesign` rejected a target. The targets before it have
            already changed.
        BatchError: With `per_target=True`, every target that failed, each with its own
            error.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`), or printed output that couldn't be read.

    Example:
        ```python
        from signers import codesign

        codesign.sign_for_distribution(
            "MyApp.app",
            "Developer ID Application: Jane Doe (A1B2C3D4E5)",
            entitlements="MyApp.entitlements",
            options=codesign.SigningFlags.RUNTIME | codesign.SigningFlags.LIBRARY,
        )
        ```
    """
    targets, _ = _normalize(target)
    _call(
        _native.codesign_sign_for_distribution,
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
    """Checks the signature of the target (`--verify`), changing nothing.

    Without options it checks that the signature is intact and covers the code. Whether
    the system would run the code is a different question: verified code can still be
    refused by Gatekeeper.

    Given a sequence, each target is verified on its own by default, so one call reports
    every target that failed, as `BatchError`. `per_target=False` runs one `codesign`
    instead, which stops at the first target it rejects.

    Args:
        target: The path to check, or a sequence of paths.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is `True` for a
            sequence. With `False` one run stops at the first target it rejects.
        deep: Also verifies nested code on its own, not only through the bundle's seal.
            Without it, nested code is checked only against the hash the bundle sealed,
            so a byte changed inside a nested library can still pass (`--deep`).
        strict: Applies this `Strict` level of checks, stricter than the default
            (`--strict`).
        ignore_resources: Skips the bundle's resources. A bundle with corrupted or
            tampered resources passes, so weigh the result accordingly; on a large
            bundle it is much faster (`--ignore-resources`).
        architecture: Verifies only this slice of a universal binary, e.g. `"arm64"` or
            `"x86_64"`. The default is every slice, and a slice the binary doesn't have
            fails verification (`--architecture`).
        bundle_version: Verifies this version of a versioned bundle instead of
            `Current`. A version the bundle doesn't have fails verification
            (`--bundle-version`).
        check_designated_requirement: Also checks the code against its own designated
            requirement. It also makes a failed verification list the altered files in
            `VerificationFailedError.resources`; without it that list is always empty
            (`--verbose=1`).
        test_requirement: Requires the code to satisfy this requirement, written as
            text. A valid signature that doesn't satisfy it raises
            `RequirementUnsatisfiedError`, and text that doesn't compile
            `VerificationFailedError`. The text is never a file name, and `"-"` is not
            standard input (`-R=`).
        test_requirement_file: Requires the code to satisfy the requirement written in
            this file. Failures are the same as for `test_requirement`, and giving both
            is a `TypeError`. `"-"` raises `StdioPathError` (`-R <path>`).
        detached: Verifies an unsigned file against a detached signature written for it
            (`--detached`).
        check_notarization: Forces an online check for a notarization ticket. It
            contacts Apple's servers, so it needs network access. Don't rely on it to
            reject unnotarized code: `codesign` accepted an unnotarized ad hoc binary
            with it (`--check-notarization`).
        signature_slot: Verifies this `SignatureSlot` when the code carries two. Without
            it `codesign` picks the slot itself. On code with only one signature,
            `SECOND` can fail as `VerificationFailedError` (`--signature-slot`).

    Returns:
        `None`, for one path and for a sequence alike: every target verified.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        TypeError: `test_requirement` and `test_requirement_file` were both given.
        StdioPathError: `test_requirement_file` is `"-"`.
        VerificationFailedError: The signature is invalid or modified, the target is
            unsigned, or the `test_requirement` text doesn't compile.
        RequirementUnsatisfiedError: A valid signature that fails the requirement.
        BatchError: Every target that failed, each with its own error. With
            `per_target=False`, the first target `codesign` rejects raises its own error
            instead.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`).

    Example:
        ```python
        from signers import codesign

        codesign.verify("MyApp.app", deep=True)

        # Tell a broken signature from a requirement that isn't met.
        try:
            codesign.verify("mytool", test_requirement="anchor apple")
            print("signed by Apple")
        except codesign.RequirementUnsatisfiedError:
            print("validly signed, but not by Apple")
        ```
    """
    targets, _ = _normalize(target)
    _call(
        _native.codesign_verify,
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
def validate_constraint(plist: StrPath, *, per_target: bool | None = None) -> None: ...
@overload
def validate_constraint(
    plist: Sequence[StrPath], *, per_target: bool | None = None
) -> None: ...
def validate_constraint(
    plist: StrPath | Sequence[StrPath], *, per_target: bool | None = None
) -> None:
    """Checks that each plist is a valid launch or library constraint.

    Maps to `--validate-constraint`. A constraint plist holds the bare constraint
    dictionary, such as `{ "team-identifier": "A1B2C3D4E5" }`. It is not the
    `ccat`/`comp`/`reqs` wrapper that `display` reports, which is rejected.

    Given a sequence, each plist is checked on its own by default, so one call reports
    every plist that failed, as `BatchError`. `per_target=False` runs one `codesign`
    instead. Then the first plist `codesign` can't read stops the run, and the plists
    after it go unchecked. The rejections of the plists before it can't be told apart:
    the whole run fails with one `ConstraintInvalidError`.

    Args:
        plist: The constraint plist, or a sequence of plists.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is `True` for a
            sequence. With `False` one run stops at the first target it rejects.

    Returns:
        `None`, for one plist and for a sequence alike.

    Raises:
        TypeError: `plist` is neither a path nor a sequence of paths.
        NoTargetsError: `plist` is an empty sequence.
        EmptyTargetError: A plist is an empty path.
        TargetNotFoundError: A plist doesn't exist.
        TargetAccessError: Whether a plist exists couldn't be checked.
        ConstraintInvalidError: A constraint has an unknown key or is empty.
        CodesignFailedError: A plist isn't a dictionary (exit code 1).
        BatchError: Every target that failed, each with its own error. With
            `per_target=False`, the first target `codesign` rejects raises its own error
            instead.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`).

    Example:
        ```python
        from signers import codesign

        codesign.validate_constraint("launch-constraint.plist")

        try:
            codesign.validate_constraint(["launch.plist", "library.plist"])
        except codesign.BatchError as error:
            for path, failure in error.failures:
                print(f"{path}: {failure}")
        ```
    """
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
    """Reads the signature of the target as a `Signature`, changing nothing.

    Maps to `--display`. A single path gives one `Signature`: identifier, signing flags,
    hashes, the certificate chain, entitlements and more. A sequence gives a `list` of
    them, in input order. `Signature.raw` and `Signature.field` reach whatever the typed
    fields don't.

    Given a sequence, each target is read on its own by default, so one call reports
    every target that failed, as `BatchError`. The signatures of the targets that did
    read are dropped with it. `per_target=False` runs one `codesign` instead: it stops
    at the first target it rejects, and the entitlements of every target stay `None`.

    Args:
        target: The path to read, or a sequence of paths.
        per_target: Runs one `codesign` per target, concurrently, instead of one for all
            of them. Ignored for a single path. The default, `None`, is `True` for a
            sequence. With `False` one run stops at the first target it rejects.
        architecture: Reads this slice of a universal binary, e.g. `"arm64"` or
            `"x86_64"`. Without it a universal binary is reported whole, as
            `FormatKind.MACHO_UNIVERSAL`. A slice the binary doesn't have fails with
            `CodesignFailedError` (`--architecture`).
        bundle_version: Reads this version of a versioned bundle instead of `Current`. A
            version the bundle doesn't have fails with `CodesignFailedError`
            (`--bundle-version`).
        deep: Lists the code nested in a bundle, in `Signature.nested`. Only the items
            directly inside the bundle are listed, and their own signatures aren't read
            (`--deep`).
        signature_slot: Reads this `SignatureSlot` when the code carries two. Code with
            one signature has only `FIRST`; asking for `SECOND` raises
            `NoSignatureError` (`--signature-slot`).
        detached: Reads the signature from a detached signature file instead of from the
            code (`--detached`).

    Returns:
        A `Signature` for a single path, a `list[Signature]` for a sequence.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        CodesignFailedError: The target is unsigned (exit code 1). With one `codesign`
            over several targets, `stderr` also holds the reports of the targets
            before it.
        NoSignatureError: The `signature_slot` holds no signature.
        UnexpectedOutputError: A report or the entitlements couldn't be read.
        BatchError: Every target that failed, each with its own error. With
            `per_target=False`, the first target `codesign` rejects raises its own error
            instead.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`).

    Example:
        ```python
        from signers import codesign

        signature = codesign.display("MyApp.app")
        print(signature.identifier, signature.cd_hash)
        if signature.signature is None:
            print("signed ad hoc")
        if codesign.SigningFlags.RUNTIME in signature.code_directory.flags:
            print("hardened runtime")

        # The entitlements are a plain dict, or None if the target has none.
        entitlements = codesign.display("mytool").entitlements or {}
        print(entitlements.get("com.apple.security.get-task-allow", False))

        ls, cat = codesign.display(["/bin/ls", "/bin/cat"])
        ```
    """
    targets, single = _normalize(target)
    native = _call(
        _native.codesign_display,
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
def requirements(target: StrPath) -> list[Requirement]: ...  # pyright: ignore[reportOverlappingOverload]
@overload
def requirements(target: Sequence[StrPath]) -> list[list[Requirement]]: ...
def requirements(
    target: StrPath | Sequence[StrPath],
) -> list[Requirement] | list[list[Requirement]]:
    """Reads the requirements of the signature of the target (`--display -r-`).

    A single path gives a `list` of `Requirement`, in the order `codesign` keeps them,
    which is not the order given to `sign`'s `requirements` when signing. A requirement
    the signature doesn't embed, but the system supplies, is marked `implicit`. The list
    is empty when `codesign` prints none. `display` reports only how many requirements
    there are, in `Signature.internal_requirements`.

    Given a sequence, each target is read on its own, concurrently, and every one that
    failed is reported together as `BatchError`. The result is then one list of
    requirements per target. `codesign` prints the requirements of all targets together,
    with nothing to tell which target a line belongs to, so this action always runs one
    `codesign` per target and has no `per_target`.

    Args:
        target: The path to read, or a sequence of paths.

    Returns:
        A `list[Requirement]` for a single path, a `list[list[Requirement]]` for a
        sequence.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        CodesignFailedError: The target is unsigned (exit code 1).
        UnexpectedOutputError: A line couldn't be read as a requirement.
        BatchError: With a sequence, every target that failed, each with its own error.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`).

    Example:
        ```python
        from signers import codesign

        for requirement in codesign.requirements("MyApp.app"):
            if requirement.kind is codesign.RequirementKind.DESIGNATED:
                print(requirement.expression)

        # Tell the requirements a signature carries from the system's defaults.
        ls, cat = codesign.requirements(["/bin/ls", "/bin/cat"])
        embedded = [r for r in ls + cat if not r.implicit]
        ```
    """
    targets, single = _normalize(target)
    native = _call(_native.codesign_requirements, targets)
    return _requirements(native, single)


@overload
def extract_certificates(  # pyright: ignore[reportOverlappingOverload]
    target: StrPath, *, save_to: StrPath | None = None
) -> list[Certificate]: ...
@overload
def extract_certificates(
    target: Sequence[StrPath], *, save_to: StrPath | None = None
) -> list[list[Certificate]]: ...
def extract_certificates(
    target: StrPath | Sequence[StrPath], *, save_to: StrPath | None = None
) -> list[Certificate] | list[list[Certificate]]:
    """Reads the certificate chain that signed the target, leaf first.

    Maps to `--extract-certificates`. A single path gives a `list` of `Certificate`, the
    signing certificate first and the root last. A target signed ad hoc has none, so its
    list is empty. A sequence gives one list per target.

    Given a sequence, each target is read on its own, concurrently, and every one that
    failed is reported together as `BatchError`. One `codesign` over several targets
    would write every chain to the same files, so this action always runs one per target
    and has no `per_target`.

    Args:
        target: The path to read, or a sequence of paths.
        save_to: Also writes each target's chain as a PEM file in this directory. The
            file is named after the target, `MyApp.app` into `MyApp.app.pem`, and holds
            the chain leaf first, so `openssl` reads it as it is. A name already taken,
            by an earlier target of the same run or by a file that was there before,
            gets a number instead: `MyApp.app2.pem`, `MyApp.app3.pem`. A file is never
            overwritten. Targets that share a name are numbered in no fixed order. A
            target with an ad hoc signature has no certificates and gets no file. The
            directory is created, with its parents, only when at least one file is to be
            written. The files of the targets that were read stay when another target of
            the same run fails.

    Returns:
        A `list[Certificate]` for a single path, a `list[list[Certificate]]` for a
        sequence.

    Raises:
        TypeError: `target` is neither a path nor a sequence of paths.
        NoTargetsError: `target` is an empty sequence.
        EmptyTargetError: A target is an empty path.
        TargetNotFoundError: A target doesn't exist.
        TargetAccessError: Whether a target exists couldn't be checked.
        IoError: A file or directory couldn't be read or written, also when the system's
            temporary directory can't be used.
        CodesignFailedError: The target is unsigned (exit code 1).
        BatchError: With a sequence, every target that failed, each with its own error.
        CodesignNotFoundError: No `codesign` was found on `PATH`.
        CodesignError: `codesign` couldn't start or was killed (`SpawnError`,
            `RunError`, `TerminatedError`).

    Example:
        ```python
        from signers import codesign

        chain = codesign.extract_certificates("MyApp.app")
        if chain:
            print(f"signed with a certificate of {len(chain[0].der)} bytes")
        else:
            print("signed ad hoc")

        # Save the chains of two apps as PEM files in certs/.
        a, b = codesign.extract_certificates(["A.app", "B.app"], save_to="certs")
        ```
    """
    targets, single = _normalize(target)
    native = _call(
        _native.codesign_extract_certificates, targets, save_to=_path(save_to)
    )
    return _certificates(native, single)
