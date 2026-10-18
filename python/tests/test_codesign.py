"""Target shapes and the errors raised by real calls, through `remove_signature` and `sign_adhoc`."""

import errno
import os
from pathlib import Path

import pytest

import signers
from signers import codesign
from .conftest import Workspace, is_signed


def test_remove_signature_strips_a_single_target_given_as_str_or_path(workspace: Workspace) -> None:
    by_str, by_path = workspace.adhoc_signed("-leading dash and spaces"), workspace.adhoc_signed("path")

    assert codesign.remove_signature(str(by_str)) is None
    assert codesign.remove_signature(by_path) is None

    assert not is_signed(by_str) and not is_signed(by_path)


def test_remove_signature_strips_every_target_of_a_sequence(workspace: Workspace) -> None:
    for per_target in (None, False, True):
        targets = (workspace.adhoc_signed(f"a-{per_target}"), str(workspace.adhoc_signed(f"b-{per_target}")))

        result = codesign.remove_signature(targets, per_target=per_target)

        assert result is None
        assert not is_signed(Path(targets[0]))
        assert not is_signed(Path(targets[1]))


def test_remove_signature_ignores_per_target_for_a_single_target(workspace: Workspace) -> None:
    first, second = workspace.adhoc_signed("first"), workspace.adhoc_signed("second")

    assert codesign.remove_signature(first, per_target=True) is None
    assert codesign.remove_signature(str(second), per_target=False) is None

    assert not is_signed(first) and not is_signed(second)


def test_remove_signature_bundle_version_reaches_codesign(workspace: Workspace) -> None:
    bundle = workspace.versioned_framework("Hello", ("A", "B"))

    codesign.remove_signature(bundle, bundle_version="B")

    assert not is_signed(bundle, bundle_version="B")
    assert is_signed(bundle, bundle_version="A")


def test_invalid_targets_raise_type_error() -> None:
    for target in (1, None, [1], b"hello"):
        with pytest.raises(TypeError):
            codesign.remove_signature(target)  # pyright: ignore[reportArgumentType, reportCallIssue]


def test_codesign_rejecting_a_target_raises_process_failed_error(workspace: Workspace) -> None:
    rejected = workspace.plain_dir("plain")

    with pytest.raises(signers.ProcessFailedError) as raised:
        codesign.remove_signature(rejected)

    error = raised.value
    assert isinstance(error, signers.ProcessError)
    assert not isinstance(error, signers.CodesignError)
    assert error.program == "codesign"
    assert error.code == 1
    assert "bundle format unrecognized" in error.stderr
    assert isinstance(error.stdout, str)
    assert "bundle format unrecognized" in str(error)


def test_per_target_failures_come_back_in_a_batch_error_in_input_order(workspace: Workspace) -> None:
    first = workspace.plain_dir("first")
    signed = workspace.adhoc_signed("hello")
    last = workspace.plain_dir("last")

    with pytest.raises(signers.BatchError) as raised:
        codesign.remove_signature([first, signed, last], per_target=True)

    failures = raised.value.failures
    assert isinstance(failures, tuple)
    assert [path for path, _ in failures] == [first, last]
    for path, error in failures:
        assert isinstance(path, Path)
        assert isinstance(error, signers.ProcessFailedError)
        assert error.program == "codesign"
        assert error.code == 1
        assert str(path) in str(raised.value)


def test_no_targets_raises_no_targets_error() -> None:
    with pytest.raises(signers.NoTargetsError) as raised:
        codesign.remove_signature([])

    assert isinstance(raised.value, ValueError)


def test_an_empty_path_raises_empty_target_error_with_its_index(workspace: Workspace) -> None:
    signed = workspace.adhoc_signed("hello")

    with pytest.raises(signers.EmptyTargetError) as raised:
        codesign.remove_signature([signed, ""])

    assert raised.value.index == 1
    assert isinstance(raised.value, ValueError)


def test_a_missing_path_raises_path_not_found_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(signers.PathNotFoundError) as raised:
        codesign.remove_signature(missing)

    error = raised.value
    assert isinstance(error, FileNotFoundError)
    assert error.path == missing
    assert isinstance(error.path, Path)
    assert error.errno == errno.ENOENT
    assert error.filename == missing
    assert str(error) == f"path does not exist: {missing}"


def test_an_unreadable_parent_raises_path_access_error(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    locked = tmp_path / "locked"
    locked.mkdir()
    target = locked / "hello"
    target.touch()
    locked.chmod(0)
    try:
        with pytest.raises(signers.PathAccessError) as raised:
            codesign.remove_signature(target)
    finally:
        locked.chmod(0o755)

    error = raised.value
    assert isinstance(error, OSError)
    assert error.path == target
    assert error.errno == errno.EACCES
    assert str(error).startswith(f"could not access {target}: ")


def _stand_in(workspace: Workspace, monkeypatch: pytest.MonkeyPatch, script: str | None, *, executable: bool = True) -> None:
    """Puts a `codesign` made of `script` first on `PATH`; with `None`, an empty directory instead."""
    bin_dir = workspace.join("bin")
    bin_dir.mkdir()
    if script is not None:
        stand_in = bin_dir / "codesign"
        stand_in.write_text(f"#!/bin/sh\n{script}\n")
        stand_in.chmod(0o755 if executable else 0o644)
    monkeypatch.setenv("PATH", str(bin_dir))


def test_a_missing_codesign_raises_codesign_not_found_error(workspace: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    target = workspace.unsigned("hello")
    _stand_in(workspace, monkeypatch, None)

    with pytest.raises(signers.CodesignNotFoundError) as raised:
        codesign.sign_adhoc(target)

    error = raised.value
    assert isinstance(error, signers.CodesignError)
    assert not isinstance(error, signers.ProcessError)
    assert isinstance(error, FileNotFoundError)
    assert "/usr/bin" in str(error)


def test_a_missing_codesign_stops_a_per_target_batch_alone(workspace: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    targets = [workspace.unsigned("a"), workspace.unsigned("b")]
    _stand_in(workspace, monkeypatch, None)

    with pytest.raises(signers.CodesignNotFoundError):
        codesign.sign_adhoc(targets, per_target=True)


def test_a_codesign_that_cannot_start_raises_spawn_error(workspace: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    targets = [workspace.unsigned("a"), workspace.unsigned("b")]
    _stand_in(workspace, monkeypatch, "exit 0", executable=False)

    for per_target in (False, True):
        with pytest.raises(signers.SpawnError) as raised:
            codesign.sign_adhoc(targets, per_target=per_target)

        error = raised.value
        assert isinstance(error, signers.ProcessError)
        assert isinstance(error, OSError)
        assert error.program == "codesign"
        assert error.errno == errno.EACCES


def test_a_codesign_killed_by_a_signal_raises_terminated_error(workspace: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    target = workspace.unsigned("hello")
    _stand_in(workspace, monkeypatch, "echo partial; echo warning >&2; kill -9 $$")

    with pytest.raises(signers.TerminatedError) as raised:
        codesign.sign_adhoc(target)

    error = raised.value
    assert isinstance(error, signers.ProcessError)
    assert error.program == "codesign"
    assert error.signal == 9
    assert error.stdout == "partial"
    assert error.stderr == "warning"


def test_an_unreadable_report_raises_unexpected_output_error(workspace: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    target = workspace.unsigned("hello")
    _stand_in(workspace, monkeypatch, "exit 0")

    with pytest.raises(signers.UnexpectedOutputError) as raised:
        codesign.display(target)

    error = raised.value
    assert isinstance(error, signers.ProcessError)
    assert error.program == "codesign"
    assert error.detail
    assert error.detail in str(error)
