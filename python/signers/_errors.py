import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from errno import ENOENT
from pathlib import Path
from typing import Any, TypeVar, cast

from . import _native

__all__ = [
    "BatchError",
    "Change",
    "CodesignError",
    "CodesignNotFoundError",
    "ConstraintInvalidError",
    "EmptyTargetError",
    "IoError",
    "NoSignatureError",
    "NoTargetsError",
    "PathAccessError",
    "PathNotFoundError",
    "ProcessError",
    "ProcessFailedError",
    "RequirementUnsatisfiedError",
    "ResourceChange",
    "RunError",
    "SharedOutputPerTargetError",
    "SignersError",
    "SpawnError",
    "StdioPathError",
    "ToolNotFoundError",
    "UnexpectedOutputError",
    "VerificationFailedError",
    "_acall",
    "_call",
    "_from_native",
]

T = TypeVar("T")


# Exceptions rebuild themselves as `cls(*args)`, but these constructors take keyword-only
# attributes, so the default pickling fails.
def _restore(
    cls: type["SignersError"], args: tuple[Any, ...], state: dict[str, Any]
) -> "SignersError":
    error = cls.__new__(cls, *args)
    super(SignersError, error).__init__(*args)
    error.__dict__.update(state)
    return error


class SignersError(Exception):
    """Base class of every error that an action raises.

    `str(error)` is the message. Catch it to handle any failure of an action. Mistakes
    in the call itself, such as a target that is not a path, raise Python's own
    `TypeError` instead. Some subclasses are also built-in exceptions (`ValueError`,
    `FileNotFoundError`, `OSError`), so code that catches those keeps working.

    Every error can be pickled with its attributes, so it crosses `multiprocessing` and
    `ProcessPoolExecutor` intact.

    Example:
        ```python
        from signers import codesign

        try:
            codesign.sign_adhoc("mytool", force=True)
        except codesign.PathNotFoundError as error:
            print(f"no such file: {error.path}")
        except codesign.SignersError as error:
            print(error)
        ```
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __reduce__(self) -> tuple[Any, ...]:
        _, args, *rest = super().__reduce__()
        return _restore, (type(self), args, (rest[0] if rest else None) or {})


class NoTargetsError(SignersError, ValueError):
    """No target was given: an empty list or tuple.

    Also a `ValueError`.
    """


class EmptyTargetError(SignersError, ValueError):
    """A target is an empty path.

    Only the first empty path is reported. Also a `ValueError`.

    Attributes:
        index: Position of the empty path; 0 for a single target.
    """

    index: int

    def __init__(self, message: str, *, index: int) -> None:
        super().__init__(message)
        self.index = index


class PathNotFoundError(SignersError, FileNotFoundError):
    """A target doesn't exist.

    Also a `FileNotFoundError`.

    Attributes:
        path: The missing target. `errno` is `ENOENT` and `filename` is the same path.
    """

    path: Path

    def __init__(self, message: str, *, path: Path) -> None:
        FileNotFoundError.__init__(self, ENOENT, message, path)
        self.path = path

    def __str__(self) -> str:
        return str(self.strerror)


class PathAccessError(SignersError, OSError):
    """Whether a target exists couldn't be checked.

    The usual cause is a parent directory that denies access. Also an `OSError`.

    Attributes:
        path: The target.
        errno: The error code, if the system gave one.
    """

    path: Path

    def __init__(self, message: str, *, path: Path, errno: int | None) -> None:
        OSError.__init__(self, errno, message, path)
        self.path = path

    def __str__(self) -> str:
        return str(self.strerror)


class IoError(SignersError, OSError):
    """A file or directory couldn't be read, created or written.

    `extract_certificates` raises it, for the system's temporary directory, for the
    files it reads back and for the ones `save_to` writes. It never changes a target.
    Raised while a target is read in a run per target, it is collected in `BatchError`.
    Also an `OSError`.

    Attributes:
        path: The file or directory involved.
        errno: The error code, if the system gave one.
    """

    path: Path

    def __init__(self, message: str, *, path: Path, errno: int | None) -> None:
        OSError.__init__(self, errno, message, path)
        self.path = path

    def __str__(self) -> str:
        return str(self.strerror)


class StdioPathError(SignersError, ValueError):
    """An option was given `"-"`, which would mean standard input or output.

    On the command line `"-"` stands for a standard stream. `codesign` gets none here,
    so pass a file path instead. Also a `ValueError`.

    Attributes:
        option: The keyword argument: `"file_list"`, `"requirements"` or
            `"test_requirement_file"`.
    """

    option: str

    def __init__(self, message: str, *, option: str) -> None:
        super().__init__(message)
        self.option = option


class SharedOutputPerTargetError(SignersError, ValueError):
    """An option that writes one shared file was combined with `per_target=True`.

    One process per target would make every process write that same file. Also a
    `ValueError`.

    Attributes:
        option: The keyword argument: `"file_list"` or `"detached"`.
    """

    option: str

    def __init__(self, message: str, *, option: str) -> None:
        super().__init__(message)
        self.option = option


class BatchError(SignersError):
    """Some targets failed in a run per target, each with its own error.

    Every target was tried, so the ones not listed succeeded. A target for which
    `codesign` couldn't start is listed with its spawn error. One failing target is enough to
    get this error rather than its own. The results of the targets that did succeed are
    dropped, `display`'s signatures included.

    Example:
        ```python
        from signers import codesign

        try:
            codesign.verify(["A.app", "B.app"], deep=True)
        except codesign.BatchError as error:
            for path, failure in error.failures:
                print(f"{path}: {failure}")
        ```

    Attributes:
        failures: The failed targets and their errors, in input order.
    """

    failures: tuple[tuple[Path, SignersError], ...]

    def __init__(
        self, message: str, *, failures: tuple[tuple[Path, SignersError], ...]
    ) -> None:
        super().__init__(message)
        self.failures = failures


class CodesignError(SignersError):
    """Base class of what only `codesign` reports.

    That is a missing executable (`CodesignNotFoundError`) and the verdicts of `verify`,
    `validate_constraint` and `display`. Any other failure of its process is a
    `ProcessError`.
    """


class CodesignNotFoundError(CodesignError, FileNotFoundError):
    """No `codesign` was found on `PATH`.

    `codesign` ships with macOS in `/usr/bin`. This error usually means `PATH` leaves
    out `/usr/bin`, or the system isn't macOS. It stands in for `ToolNotFoundError` to
    carry that hint. Also a `FileNotFoundError`.
    """

    def __init__(self, message: str) -> None:
        FileNotFoundError.__init__(self, ENOENT, message)

    def __str__(self) -> str:
        return str(self.strerror)


class ProcessError(SignersError):
    """Base class of the failures of an external tool's process.

    The tool couldn't run, exited non-zero, or printed what this package can't read.
    Every tool an action wraps reports these through a subclass of this one. For
    `codesign` that is every failure of its process except a missing executable, which
    is `CodesignNotFoundError`.

    Attributes:
        program: The executable that was run, e.g. `"codesign"`.
    """

    program: str

    def __init__(self, message: str, *, program: str) -> None:
        super().__init__(message)
        self.program = program


class ToolNotFoundError(ProcessError, FileNotFoundError):
    """No executable called `program` was found on `PATH`.

    Also a `FileNotFoundError`.
    """

    def __init__(self, message: str, *, program: str) -> None:
        FileNotFoundError.__init__(self, ENOENT, message)
        self.program = program

    def __str__(self) -> str:
        return str(self.strerror)


class SpawnError(ProcessError, OSError):
    """`program` was found but couldn't start, e.g. because it isn't executable.

    Also raised when the runtime that drives the process can't be created. Also an
    `OSError`.
    """

    def __init__(self, message: str, *, program: str, errno: int | None) -> None:
        OSError.__init__(self, errno, message)
        self.program = program

    def __str__(self) -> str:
        return str(self.strerror)


class RunError(ProcessError, OSError):
    """Waiting for `program` or reading its output failed.

    The outcome is unknown, so the targets may or may not have changed. Also an
    `OSError`.
    """

    def __init__(self, message: str, *, program: str, errno: int | None) -> None:
        OSError.__init__(self, errno, message)
        self.program = program

    def __str__(self) -> str:
        return str(self.strerror)


class ProcessFailedError(ProcessError):
    """`program` exited with a non-zero code, or was killed by a signal.

    When one run covers several targets, the targets before the rejected one have
    already changed. See `signers.codesign`.

    Attributes:
        returncode: The exit code, or minus the signal number if a signal killed
            `program` (`-9` for `SIGKILL`), as `subprocess` reports it.
        stdout: What `program` printed on standard output, trimmed.
        stderr: Its diagnostics, trimmed. Only this is part of the message.
    """

    returncode: int
    stdout: str
    stderr: str

    def __init__(
        self, message: str, *, program: str, returncode: int, stdout: str, stderr: str
    ) -> None:
        super().__init__(message, program=program)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class UnexpectedOutputError(ProcessError):
    """`program` exited 0, but its output couldn't be read as the action's result.

    Attributes:
        detail: What didn't match, e.g. the number of results against the number of
            targets.
        stdout: What the run printed on standard output, trimmed. With one run over
            several targets it covers all of them. It isn't part of the message.
        stderr: What the run printed on standard error, trimmed. With one run over
            several targets it covers all of them.
    """

    detail: str
    stdout: str
    stderr: str

    def __init__(
        self, message: str, *, program: str, detail: str, stdout: str, stderr: str
    ) -> None:
        super().__init__(message, program=program)
        self.detail = detail
        self.stdout = stdout
        self.stderr = stderr


class Change(enum.Enum):
    """How a sealed resource differs from what the signature sealed."""

    ADDED = "added"
    """The bundle holds a file the signature doesn't cover."""
    MODIFIED = "modified"
    """The file's contents differ from what was sealed."""
    MISSING = "missing"
    """A sealed file is gone."""


@dataclass(frozen=True, slots=True)
class ResourceChange:
    """A sealed resource that `verify` found altered.

    It is found in `VerificationFailedError.resources`.
    """

    change: Change
    """How the resource differs from what the signature sealed."""
    path: Path
    """Absolute path, canonical: a temporary directory shows as `/private/var/...`.

    Read from `codesign`'s text output, so bytes that aren't valid UTF-8 become
    `U+FFFD`.
    """


class VerificationFailedError(CodesignError):
    """`verify` found the target's signature wanting.

    The signature is invalid or modified, the target is unsigned, or the text given as
    `test_requirement` doesn't compile.

    Example:
        ```python
        from signers import codesign

        try:
            codesign.verify("MyApp.app", check_designated_requirement=True)
        except codesign.VerificationFailedError as error:
            for resource in error.resources:
                if resource.change is codesign.Change.MODIFIED:
                    print(f"tampered: {resource.path}")
        ```

    Attributes:
        stdout: What `codesign` printed on standard output, trimmed.
        stderr: Its diagnostics, trimmed. Only this is part of the message.
        resources: The sealed resources that were altered, in the order `codesign`
            printed them, which can differ from run to run. Filled only with
            `check_designated_requirement`; empty when the damage is to nested code (see
            `deep`) or when nothing was altered.
    """

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
    """`verify` found a valid signature on code that doesn't meet the requirement.

    The requirement is the `test_requirement` text or file or, with
    `check_designated_requirement`, the code's own.

    Attributes:
        stdout: What `codesign` printed on standard output, trimmed.
        stderr: Its diagnostics, trimmed. Only this is part of the message.
    """

    stdout: str
    stderr: str

    def __init__(self, message: str, *, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class ConstraintInvalidError(CodesignError):
    """`validate_constraint` found a constraint that isn't valid.

    The plist has an unknown key or is empty. On macOS 27 `codesign` exits 0 and prints
    "Constraint validation failed" even for a valid plist, so a plist is rejected only
    when `codesign` also reports an error for it.

    Attributes:
        stdout: What `codesign` printed on standard output, trimmed.
        stderr: Its diagnostics, trimmed. Only this is part of the message.
    """

    stdout: str
    stderr: str

    def __init__(self, message: str, *, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class NoSignatureError(CodesignError):
    """`display` found no signature in the `signature_slot` it was asked for.

    Code with one signature has nothing in the second slot. `codesign` exits 0 for it
    and reports `no signature`, so this error is raised instead of returning an empty
    `Signature`. Unsigned code is a different failure: `ProcessFailedError`.

    Attributes:
        stdout: What `codesign` printed on standard output during the whole run,
            trimmed.
        stderr: Its diagnostics during the whole run, trimmed; with one run over several
            targets they also cover targets that read fine. Only this is part of the
            message.
    """

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

    if p.get("process"):
        program: str = p["program"]
        match kind:
            case "NotFound":
                return ToolNotFoundError(message, program=program)
            case "Spawn":
                return SpawnError(message, program=program, errno=p["errno"])
            case "Run":
                return RunError(message, program=program, errno=p["errno"])
            case "Failed":
                return ProcessFailedError(
                    message,
                    program=program,
                    returncode=p["returncode"],
                    stdout=p["stdout"],
                    stderr=p["stderr"],
                )
            case "UnexpectedOutput":
                return UnexpectedOutputError(
                    message,
                    program=program,
                    detail=p["detail"],
                    stdout=p["stdout"],
                    stderr=p["stderr"],
                )
            case _:
                return ProcessError(message, program=program)

    if p.get("codesign"):
        match kind:
            case "NotFound":
                return CodesignNotFoundError(message)
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
        case "PathNotFound":
            return PathNotFoundError(message, path=Path(p["path"]))
        case "PathAccess":
            return PathAccessError(message, path=Path(p["path"]), errno=p["errno"])
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


async def _acall(
    fn: Callable[..., Awaitable[T]], /, *args: object, **kwargs: object
) -> T:
    try:
        return await fn(*args, **kwargs)
    except _native.NativeError as e:
        raise _from_native(e.args[0]) from None
