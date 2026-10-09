import os
from collections.abc import Sequence
from typing import TypeAlias, cast

__all__ = ["StrPath", "_normalize"]

StrPath: TypeAlias = str | os.PathLike[str]


def _normalize(
    target: StrPath | Sequence[StrPath], per_target: bool | None
) -> tuple[str | list[str], bool]:
    if isinstance(target, (str, os.PathLike)):
        if per_target is not None:
            raise TypeError("per_target needs a sequence of targets")
        return os.fspath(target), True
    if not isinstance(cast(object, target), Sequence):
        raise TypeError(
            "target must be a path or a sequence of paths, "
            f"not {type(target).__name__}"
        )
    return [os.fspath(t) for t in target], False
