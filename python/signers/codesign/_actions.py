from collections.abc import Sequence
from typing import overload

from .. import _native
from .._errors import _call
from .._targets import StrPath, _normalize


@overload
def remove_signature(target: StrPath, *, bundle_version: str | None = None) -> None: ...
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
    targets, _ = _normalize(target, per_target)
    _call(
        _native.codesign_remove_signature,
        targets,
        per_target=per_target,
        bundle_version=bundle_version,
    )
