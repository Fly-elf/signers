# pyright: reportPrivateUsage=false

import pickle
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import signers
from signers._errors import _from_native

P = Path("/t/a")
PROC = {"program": "codesign"}
STREAMS = {"stdout": "o", "stderr": "e"}
RESOURCE = signers.ResourceChange(signers.Change.MODIFIED, P)

# One line per class; a new keyword argument is added to its entry.
INSTANCES: list[tuple[type[signers.SignersError], dict[str, Any]]] = [
    (signers.SignersError, {}),
    (signers.NoTargetsError, {}),
    (signers.EmptyTargetError, {"index": 2}),
    (signers.PathNotFoundError, {"path": P}),
    (signers.PathAccessError, {"path": P, "errno": 13}),
    (signers.PathAccessError, {"path": P, "errno": None}),
    (signers.IoError, {"path": P, "errno": 5}),
    (signers.StdioPathError, {"option": "file_list"}),
    (signers.SharedOutputPerTargetError, {"option": "detached"}),
    (signers.CodesignError, {}),
    (signers.CodesignNotFoundError, {}),
    (signers.ProcessError, PROC),
    (signers.ToolNotFoundError, PROC),
    (signers.SpawnError, {**PROC, "errno": 13}),
    (signers.RunError, {**PROC, "errno": None}),
    (signers.ProcessFailedError, {**PROC, "code": 3, **STREAMS}),
    (signers.TerminatedError, {**PROC, "signal": 9, **STREAMS}),
    (signers.UnexpectedOutputError, {**PROC, "detail": "d"}),
    (signers.VerificationFailedError, {**STREAMS, "resources": (RESOURCE,)}),
    (signers.RequirementUnsatisfiedError, STREAMS),
    (signers.ConstraintInvalidError, STREAMS),
    (signers.NoSignatureError, STREAMS),
]


def make(cls: type[signers.SignersError], kwargs: dict[str, Any]) -> signers.SignersError:
    return cls("message", **kwargs)


def snapshot(error: BaseException) -> dict[str, Any]:
    """Everything observable on an error; nested errors are snapshotted too."""

    def value(v: Any) -> Any:
        match v:
            case BaseException():
                return snapshot(v)
            case tuple() | list():
                return [value(i) for i in v]  # pyright: ignore[reportUnknownVariableType]
            case _:
                return v

    state = {k: value(v) for k, v in vars(error).items()}
    extra = {
        k: getattr(error, k, None) for k in ("errno", "strerror", "filename")
    }
    return {
        "type": type(error),
        "str": str(error),
        "args": value(error.args),
        **state,
        **extra,
    }


@pytest.mark.parametrize(
    ("cls", "kwargs"), INSTANCES, ids=[f"{c.__name__}-{i}" for i, (c, _) in enumerate(INSTANCES)]
)
def test_exception_survives_a_pickle_round_trip(
    cls: type[signers.SignersError], kwargs: dict[str, Any]
) -> None:
    error = make(cls, kwargs)
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        restored = pickle.loads(pickle.dumps(error, protocol))
        assert snapshot(restored) == snapshot(error)


def test_every_exception_class_is_covered() -> None:
    covered = {cls for cls, _ in INSTANCES} | {signers.BatchError}
    public = {
        v
        for v in vars(signers).values()
        if isinstance(v, type) and issubclass(v, signers.SignersError)
    }
    assert public <= covered


def test_nested_batch_error_keeps_its_failures() -> None:
    failures = (
        (Path("/t/a"), make(signers.PathNotFoundError, {"path": P})),
        (Path("/t/b"), make(signers.ProcessFailedError, {**PROC, "code": 1, **STREAMS})),
    )
    error = signers.BatchError("message", failures=failures)
    restored = pickle.loads(pickle.dumps(error))
    assert isinstance(restored, signers.BatchError)
    assert [(p, type(e), str(e)) for p, e in restored.failures] == [
        (p, type(e), str(e)) for p, e in failures
    ]
    missing = restored.failures[0][1]
    assert isinstance(missing, signers.PathNotFoundError)
    assert (missing.path, missing.errno) == (P, 2)
    assert snapshot(restored) == snapshot(error)


def _raise_not_found() -> None:
    raise _from_native({"kind": "PathNotFound", "message": "no such file", "path": "/t/a"})


def test_process_pool_re_raises_the_original_exception() -> None:
    with ProcessPoolExecutor(max_workers=1) as pool:
        with pytest.raises(signers.PathNotFoundError) as info:
            pool.submit(_raise_not_found).result()
    assert info.value.path == P
    assert str(info.value) == "no such file"
