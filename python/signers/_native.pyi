class NativeError(Exception): ...

def codesign_remove_signature(
    target: str | list[str],
    *,
    per_target: bool | None = None,
    bundle_version: str | None = None,
) -> None: ...
