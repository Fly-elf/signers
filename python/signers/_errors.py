import enum
from collections.abc import Callable
from dataclasses import dataclass
from errno import ENOENT
from pathlib import Path
from typing import Any, TypeVar, cast

from . import _native

__all__ = [
    "BatchError",
    "Change",
    "CodesignError",
    "CodesignFailedError",
    "CodesignNotFoundError",
    "ConstraintInvalidError",
    "EmptyTargetError",
    "IoError",
    "NoSignatureError",
    "NoTargetsError",
    "RequirementUnsatisfiedError",
    "ResourceChange",
    "RunError",
    "SharedOutputPerTargetError",
    "SignersError",
    "SpawnError",
    "StdioPathError",
    "TargetAccessError",
    "TargetNotFoundError",
    "TerminatedError",
    "UnexpectedOutputError",
    "VerificationFailedError",
    "_call",
    "_from_native",
]

T = TypeVar("T")


class SignersError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class NoTargetsError(SignersError, ValueError):
    pass


class EmptyTargetError(SignersError, ValueError):
    index: int

    def __init__(self, message: str, *, index: int) -> None:
        super().__init__(message)
        self.index = index


class TargetNotFoundError(SignersError, FileNotFoundError):
    path: Path

    def __init__(self, message: str, *, path: Path) -> None:
        FileNotFoundError.__init__(self, ENOENT, message, path)
        self.path = path

    def __str__(self) -> str:
        return str(self.strerror)


class TargetAccessError(SignersError, OSError):
    path: Path

    def __init__(self, message: str, *, path: Path, errno: int | None) -> None:
        OSError.__init__(self, errno, message, path)
        self.path = path

    def __str__(self) -> str:
        return str(self.strerror)


class IoError(SignersError, OSError):
    path: Path

    def __init__(self, message: str, *, path: Path, errno: int | None) -> None:
        OSError.__init__(self, errno, message, path)
        self.path = path

    def __str__(self) -> str:
        return str(self.strerror)


class StdioPathError(SignersError, ValueError):
    option: str

    def __init__(self, message: str, *, option: str) -> None:
        super().__init__(message)
        self.option = option


class SharedOutputPerTargetError(SignersError, ValueError):
    option: str

    def __init__(self, message: str, *, option: str) -> None:
        super().__init__(message)
        self.option = option


class BatchError(SignersError):
    failures: tuple[tuple[Path, SignersError], ...]

    def __init__(
        self, message: str, *, failures: tuple[tuple[Path, SignersError], ...]
    ) -> None:
        super().__init__(message)
        self.failures = failures


class CodesignError(SignersError):
    pass


class CodesignNotFoundError(CodesignError, FileNotFoundError):
    def __init__(self, message: str) -> None:
        FileNotFoundError.__init__(self, ENOENT, message)

    def __str__(self) -> str:
        return str(self.strerror)


class SpawnError(CodesignError, OSError):
    def __init__(self, message: str, *, errno: int | None) -> None:
        OSError.__init__(self, errno, message)

    def __str__(self) -> str:
        return str(self.strerror)


class RunError(CodesignError, OSError):
    def __init__(self, message: str, *, errno: int | None) -> None:
        OSError.__init__(self, errno, message)

    def __str__(self) -> str:
        return str(self.strerror)


class CodesignFailedError(CodesignError):
    code: int
    stdout: str
    stderr: str

    def __init__(self, message: str, *, code: int, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.code = code
        self.stdout = stdout
        self.stderr = stderr


class TerminatedError(CodesignError):
    signal: int | None
    stdout: str
    stderr: str

    def __init__(
        self, message: str, *, signal: int | None, stdout: str, stderr: str
    ) -> None:
        super().__init__(message)
        self.signal = signal
        self.stdout = stdout
        self.stderr = stderr


class UnexpectedOutputError(CodesignError):
    detail: str

    def __init__(self, message: str, *, detail: str) -> None:
        super().__init__(message)
        self.detail = detail


class Change(enum.Enum):
    ADDED = "added"
    MODIFIED = "modified"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class ResourceChange:
    change: Change
    path: Path


class VerificationFailedError(CodesignError):
    stdout: str
    stderr: str
    resources: tuple[ResourceChange, ...]

    def __init__(
        self,
        message: str,
        *,
        stdout: str,
        stderr: str,
        resources: tuple[ResourceChange, ...],
    ) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.resources = resources


class RequirementUnsatisfiedError(CodesignError):
    stdout: str
    stderr: str

    def __init__(self, message: str, *, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class ConstraintInvalidError(CodesignError):
    stdout: str
    stderr: str

    def __init__(self, message: str, *, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class NoSignatureError(CodesignError):
    stdout: str
    stderr: str

    def __init__(self, message: str, *, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


def _from_native(payload: dict[str, object]) -> SignersError:
    p = cast(dict[str, Any], payload)
    kind = p["kind"]
    message: str = p["message"]

    if p.get("codesign"):
        match kind:
            case "NotFound":
                return CodesignNotFoundError(message)
            case "Spawn":
                return SpawnError(message, errno=p["errno"])
            case "Run":
                return RunError(message, errno=p["errno"])
            case "Failed":
                return CodesignFailedError(
                    message, code=p["code"], stdout=p["stdout"], stderr=p["stderr"]
                )
            case "Terminated":
                return TerminatedError(
                    message, signal=p["signal"], stdout=p["stdout"], stderr=p["stderr"]
                )
            case "UnexpectedOutput":
                return UnexpectedOutputError(message, detail=p["detail"])
            case "VerificationFailed":
                resources = tuple(
                    ResourceChange(Change[r["change"].upper()], Path(r["path"]))
                    for r in p["resources"]
                )
                return VerificationFailedError(
                    message, stdout=p["stdout"], stderr=p["stderr"], resources=resources
                )
            case "RequirementUnsatisfied":
                return RequirementUnsatisfiedError(
                    message, stdout=p["stdout"], stderr=p["stderr"]
                )
            case "ConstraintInvalid":
                return ConstraintInvalidError(
                    message, stdout=p["stdout"], stderr=p["stderr"]
                )
            case "NoSignature":
                return NoSignatureError(message, stdout=p["stdout"], stderr=p["stderr"])
            case _:
                return CodesignError(message)

    match kind:
        case "NoTargets":
            return NoTargetsError(message)
        case "EmptyTarget":
            return EmptyTargetError(message, index=p["index"])
        case "TargetNotFound":
            return TargetNotFoundError(message, path=Path(p["path"]))
        case "TargetAccess":
            return TargetAccessError(message, path=Path(p["path"]), errno=p["errno"])
        case "Io":
            return IoError(message, path=Path(p["path"]), errno=p["errno"])
        case "StdioPath":
            return StdioPathError(message, option=p["option"])
        case "SharedOutputPerTarget":
            return SharedOutputPerTargetError(message, option=p["option"])
        case "Batch":
            failures = tuple(
                (Path(path), _from_native(failure)) for path, failure in p["failures"]
            )
            return BatchError(message, failures=failures)
        case _:
            return SignersError(message)


def _call(fn: Callable[..., T], /, *args: object, **kwargs: object) -> T:
    try:
        return fn(*args, **kwargs)
    except _native.NativeError as e:
        raise _from_native(e.args[0]) from None
