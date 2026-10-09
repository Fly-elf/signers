from typing import TypedDict

class NativeError(Exception): ...

class SignOptions(TypedDict):
    identifier: str | None
    requirements: str | None
    prefix: str | None
    keychain: str | None
    entitlements: str | None
    force_library_entitlements: bool
    generate_entitlement_der: bool
    options: int | None
    runtime_version: str | None
    launch_constraint_self: str | None
    launch_constraint_parent: str | None
    launch_constraint_responsible: str | None
    library_constraint: str | None
    enforce_constraint_validity: bool
    force: bool
    deep: bool
    preserve_metadata: int | None
    page_size: int | None
    timestamp: str | None
    bundle_version: str | None
    strip_disallowed_xattrs: bool
    single_threaded_signing: bool
    dry_run: bool
    detached: str | None
    detached_database: bool
    file_list: str | None

def codesign_remove_signature(
    target: str | list[str],
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None: ...
def codesign_sign(
    target: str | list[str],
    identity: str,
    options: SignOptions,
    *,
    per_target: bool | None = None,
) -> None: ...
def codesign_sign_adhoc(
    target: str | list[str],
    options: SignOptions,
    *,
    per_target: bool | None = None,
) -> None: ...
def codesign_sign_for_distribution(
    target: str | list[str],
    identity: str,
    options: SignOptions,
    *,
    per_target: bool | None = None,
) -> None: ...
