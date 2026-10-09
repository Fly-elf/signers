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
        ({"kind": "TargetNotFound", "path": "/t/a"}, signers.TargetNotFoundError, {"path": Path("/t/a"), "errno": errno.ENOENT}),
        ({"kind": "TargetAccess", "path": "/t/a", "errno": 13}, signers.TargetAccessError, {"path": Path("/t/a"), "errno": 13}),
        ({"kind": "Io", "path": "/t/a", "errno": None}, signers.IoError, {"path": Path("/t/a"), "errno": None}),
        ({"kind": "StdioPath", "option": "file_list"}, signers.StdioPathError, {"option": "file_list"}),
        ({"kind": "SharedOutputPerTarget", "option": "detached"}, signers.SharedOutputPerTargetError, {"option": "detached"}),
        ({"kind": "NotFound", "codesign": True}, signers.CodesignNotFoundError, {"errno": errno.ENOENT}),
        ({"kind": "Spawn", "codesign": True, "errno": 1}, signers.SpawnError, {"errno": 1}),
        ({"kind": "Run", "codesign": True, "errno": None}, signers.RunError, {"errno": None}),
        (
            {"kind": "Failed", "codesign": True, "code": 3, "stdout": "o", "stderr": "e"},
            signers.CodesignFailedError,
            {"code": 3, "stdout": "o", "stderr": "e"},
        ),
        (
            {"kind": "Terminated", "codesign": True, "signal": 9, "stdout": "o", "stderr": "e"},
            signers.TerminatedError,
            {"signal": 9, "stdout": "o", "stderr": "e"},
        ),
        (
            {"kind": "Terminated", "codesign": True, "signal": None, "stdout": "", "stderr": ""},
            signers.TerminatedError,
            {"signal": None},
        ),
        ({"kind": "UnexpectedOutput", "codesign": True, "detail": "d"}, signers.UnexpectedOutputError, {"detail": "d"}),
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
                ("/t/a", {"kind": "Failed", "codesign": True, "message": "a", "code": 1, "stdout": "", "stderr": "e"}),
                ("/t/b", {"kind": "Batch", "message": "b", "failures": [("/t/c", {"kind": "NoTargets", "message": "c"})]}),
            ],
        }
    )

    assert isinstance(error, signers.BatchError)
    assert [(path, type(e)) for path, e in error.failures] == [
        (Path("/t/a"), signers.CodesignFailedError),
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
