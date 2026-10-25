# The variants no bridged action can trigger yet are built from the payload the
# extension sends; the Rust side of that payload is pinned in `python/src/error.rs`.
# pyright: reportPrivateUsage=false

import errno
from pathlib import Path

import pytest

import signers
from signers import _native
from signers._errors import _call, _from_native


@pytest.mark.parametrize(
    ("payload", "cls", "attributes"),
    [
        ({"kind": "NoTargets"}, signers.NoTargetsError, {}),
        ({"kind": "EmptyTarget", "index": 3}, signers.EmptyTargetError, {"index": 3}),
        ({"kind": "PathNotFound", "path": "/t/a"}, signers.PathNotFoundError, {"path": Path("/t/a"), "errno": errno.ENOENT}),
        ({"kind": "PathAccess", "path": "/t/a", "errno": 13}, signers.PathAccessError, {"path": Path("/t/a"), "errno": 13}),
        ({"kind": "Io", "path": "/t/a", "errno": None}, signers.IoError, {"path": Path("/t/a"), "errno": None}),
        ({"kind": "StdioPath", "option": "file_list"}, signers.StdioPathError, {"option": "file_list"}),
        ({"kind": "SharedOutputPerTarget", "option": "detached"}, signers.SharedOutputPerTargetError, {"option": "detached"}),
        ({"kind": "NotFound", "codesign": True}, signers.CodesignNotFoundError, {"errno": errno.ENOENT}),
        ({"kind": "NotFound", "process": True, "program": "pkgutil"}, signers.ToolNotFoundError, {"program": "pkgutil", "errno": errno.ENOENT}),
        ({"kind": "Spawn", "process": True, "program": "codesign", "errno": 1}, signers.SpawnError, {"program": "codesign", "errno": 1}),
        ({"kind": "Run", "process": True, "program": "codesign", "errno": None}, signers.RunError, {"program": "codesign", "errno": None}),
        (
            {"kind": "Failed", "process": True, "program": "codesign", "returncode": 3, "stdout": "o", "stderr": "e"},
            signers.ProcessFailedError,
            {"program": "codesign", "returncode": 3, "stdout": "o", "stderr": "e"},
        ),
        (
            {"kind": "Failed", "process": True, "program": "codesign", "returncode": -9, "stdout": "o", "stderr": "e"},
            signers.ProcessFailedError,
            {"program": "codesign", "returncode": -9, "stdout": "o", "stderr": "e"},
        ),
        (
            {"kind": "UnexpectedOutput", "process": True, "program": "codesign", "detail": "d", "stdout": "o", "stderr": "e"},
            signers.UnexpectedOutputError,
            {"program": "codesign", "detail": "d", "stdout": "o", "stderr": "e"},
        ),
        ({"kind": "Other", "process": True, "program": "pkgutil"}, signers.ProcessError, {"program": "pkgutil"}),
        ({"kind": "FutureVariant", "process": True, "program": "pkgutil"}, signers.ProcessError, {"program": "pkgutil"}),
        (
            {"kind": "RequirementUnsatisfied", "codesign": True, "stdout": "o", "stderr": "e"},
            signers.RequirementUnsatisfiedError,
            {"stdout": "o", "stderr": "e"},
        ),
        (
            {"kind": "ConstraintInvalid", "codesign": True, "stdout": "o", "stderr": "e"},
            signers.ConstraintInvalidError,
            {"stdout": "o", "stderr": "e"},
        ),
        (
            {"kind": "NoSignature", "codesign": True, "stdout": "o", "stderr": "e"},
            signers.NoSignatureError,
            {"stdout": "o", "stderr": "e"},
        ),
        ({"kind": "Other"}, signers.SignersError, {}),
        ({"kind": "Other", "codesign": True}, signers.CodesignError, {}),
        ({"kind": "FutureVariant"}, signers.SignersError, {}),
        ({"kind": "FutureVariant", "codesign": True}, signers.CodesignError, {}),
    ],
)
def test_from_native_builds_the_class_with_its_attributes(
    payload: dict[str, object], cls: type[signers.SignersError], attributes: dict[str, object]
) -> None:
    error = _from_native({**payload, "message": "the message"})

    assert type(error) is cls
    assert str(error) == "the message"
    for name, value in attributes.items():
        assert getattr(error, name) == value, name
        assert type(getattr(error, name)) is type(value), name


def test_from_native_converts_verification_resources() -> None:
    error = _from_native(
        {
            "kind": "VerificationFailed",
            "codesign": True,
            "message": "m",
            "stdout": "o",
            "stderr": "e",
            "resources": [
                {"change": "Added", "path": "/t/new"},
                {"change": "Modified", "path": "/t/changed"},
                {"change": "Missing", "path": "/t/gone"},
            ],
        }
    )

    assert isinstance(error, signers.VerificationFailedError)
    assert error.resources == (
        signers.ResourceChange(change=signers.Change.ADDED, path=Path("/t/new")),
        signers.ResourceChange(change=signers.Change.MODIFIED, path=Path("/t/changed")),
        signers.ResourceChange(change=signers.Change.MISSING, path=Path("/t/gone")),
    )
    with pytest.raises(AttributeError):
        error.resources[0].path = Path("/t/other")  # pyright: ignore[reportAttributeAccessIssue]


def test_from_native_builds_batch_failures_recursively_in_order() -> None:
    error = _from_native(
        {
            "kind": "Batch",
            "message": "2 failed",
            "failures": [
                (
                    "/t/a",
                    {"kind": "Failed", "process": True, "program": "codesign", "message": "a", "returncode": 1, "stdout": "", "stderr": "e"},
                ),
                ("/t/b", {"kind": "Batch", "message": "b", "failures": [("/t/c", {"kind": "NoTargets", "message": "c"})]}),
            ],
        }
    )

    assert isinstance(error, signers.BatchError)
    assert [(path, type(e)) for path, e in error.failures] == [
        (Path("/t/a"), signers.ProcessFailedError),
        (Path("/t/b"), signers.BatchError),
    ]
    nested = error.failures[1][1]
    assert isinstance(nested, signers.BatchError)
    assert [(path, type(e), str(e)) for path, e in nested.failures] == [(Path("/t/c"), signers.NoTargetsError, "c")]


def test_call_raises_the_mapped_error_without_the_native_one_chained() -> None:
    def fails() -> None:
        raise _native.NativeError({"kind": "EmptyTarget", "message": "m", "index": 0})

    with pytest.raises(signers.EmptyTargetError) as raised:
        _call(fails)

    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__


def test_process_errors_are_not_codesign_errors() -> None:
    for cls in (
        signers.ToolNotFoundError,
        signers.SpawnError,
        signers.RunError,
        signers.ProcessFailedError,
        signers.UnexpectedOutputError,
    ):
        assert issubclass(cls, signers.ProcessError), cls
        assert issubclass(cls, signers.SignersError), cls
        assert not issubclass(cls, signers.CodesignError), cls
    assert not issubclass(signers.ProcessError, signers.CodesignError)
    assert not issubclass(signers.CodesignNotFoundError, signers.ProcessError)


def test_the_builtin_bases_of_the_process_errors_are_kept() -> None:
    assert issubclass(signers.ToolNotFoundError, FileNotFoundError)
    assert issubclass(signers.SpawnError, OSError)
    assert issubclass(signers.RunError, OSError)
    assert issubclass(signers.PathNotFoundError, FileNotFoundError)
    assert issubclass(signers.PathAccessError, OSError)


def test_a_missing_tool_reads_as_its_message_and_names_the_program() -> None:
    error = _from_native({"kind": "NotFound", "process": True, "program": "pkgutil", "message": "`pkgutil` was not found on PATH"})

    assert isinstance(error, FileNotFoundError)
    assert not isinstance(error, signers.CodesignNotFoundError)
    assert str(error) == "`pkgutil` was not found on PATH"
    assert error.errno == errno.ENOENT


def test_the_codesign_not_found_stays_its_own_class() -> None:
    error = _from_native({"kind": "NotFound", "codesign": True, "message": "m"})

    assert type(error) is signers.CodesignNotFoundError
    assert isinstance(error, signers.CodesignError)
    assert not isinstance(error, signers.ProcessError)


def test_the_process_errors_are_reached_through_the_codesign_module() -> None:
    from signers import codesign

    for name in (
        "ProcessError",
        "ToolNotFoundError",
        "SpawnError",
        "RunError",
        "ProcessFailedError",
        "UnexpectedOutputError",
        "PathNotFoundError",
        "PathAccessError",
    ):
        assert getattr(codesign, name) is getattr(signers, name), name
    for name in ("CodesignFailedError", "TargetNotFoundError", "TargetAccessError"):
        assert not hasattr(signers, name), name
        assert not hasattr(codesign, name), name
