import errno
import os
from pathlib import Path

import pytest

import signers
from signers import codesign
from .conftest import Workspace, is_signed


@pytest.mark.parametrize("as_path", [False, True], ids=["str", "Path"])
def test_remove_signature_strips_a_single_target(workspace: Workspace, as_path: bool) -> None:
    target = workspace.adhoc_signed("hello")

    result = codesign.remove_signature(target if as_path else str(target))

    assert result is None
    assert not is_signed(target)


@pytest.mark.parametrize("per_target", [None, False, True])
def test_remove_signature_strips_every_target_of_a_sequence(
    workspace: Workspace, per_target: bool | None
) -> None:
    targets = (workspace.adhoc_signed("a"), str(workspace.adhoc_signed("b")))

    result = codesign.remove_signature(targets, per_target=per_target)

    assert result is None
    assert not is_signed(Path(targets[0]))
    assert not is_signed(Path(targets[1]))


@pytest.mark.parametrize("per_target", [True, False])
@pytest.mark.parametrize("as_path", [False, True], ids=["str", "Path"])
def test_remove_signature_ignores_per_target_for_a_single_target(
    workspace: Workspace, as_path: bool, per_target: bool
) -> None:
    target = workspace.adhoc_signed("hello")

    result = codesign.remove_signature(target if as_path else str(target), per_target=per_target)

    assert result is None
    assert not is_signed(target)


def test_remove_signature_passes_awkward_paths_through_unchanged(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("-leading dash and spaces")

    codesign.remove_signature(target)

    assert not is_signed(target)


def test_remove_signature_bundle_version_selects_the_version(workspace: Workspace) -> None:
    bundle = workspace.versioned_framework("Hello", ("A", "B"))

    codesign.remove_signature(bundle, bundle_version="B")

    assert not is_signed(bundle, bundle_version="B")
    assert is_signed(bundle, bundle_version="A")


def test_remove_signature_shared_run_fails_as_one_codesign_error(workspace: Workspace) -> None:
    signed = workspace.adhoc_signed("hello")
    rejected = workspace.plain_dir("plain")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.remove_signature([signed, rejected], per_target=False)

    assert raised.value.code == 1
    assert "bundle format unrecognized" in raised.value.stderr


def test_remove_signature_per_target_collects_failures_in_input_order(workspace: Workspace) -> None:
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
        assert isinstance(error, signers.CodesignFailedError)
        assert error.code == 1
        assert str(path) in str(raised.value)
        assert str(error) in str(raised.value)
    assert not is_signed(signed), "the target that succeeded was not stripped"


def test_no_targets_raises_no_targets_error() -> None:
    with pytest.raises(signers.NoTargetsError) as raised:
        codesign.remove_signature([])

    assert isinstance(raised.value, ValueError)
    assert str(raised.value)


def test_an_empty_path_raises_empty_target_error_with_its_index(workspace: Workspace) -> None:
    signed = workspace.adhoc_signed("hello")

    with pytest.raises(signers.EmptyTargetError) as raised:
        codesign.remove_signature([signed, ""])

    assert raised.value.index == 1
    assert isinstance(raised.value, ValueError)
    assert is_signed(signed), "a refused call still ran codesign"


def test_a_missing_path_raises_target_not_found_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(signers.TargetNotFoundError) as raised:
        codesign.remove_signature(missing)

    error = raised.value
    assert isinstance(error, FileNotFoundError)
    assert error.path == missing
    assert isinstance(error.path, Path)
    assert error.errno == errno.ENOENT
    assert error.filename == missing
    assert str(missing) in str(error)


def test_a_missing_path_in_a_per_target_batch_is_refused_before_any_run(workspace: Workspace) -> None:
    signed = workspace.adhoc_signed("hello")
    missing = workspace.root / "missing"

    with pytest.raises(signers.TargetNotFoundError) as raised:
        codesign.remove_signature([signed, missing], per_target=True)

    assert raised.value.path == missing
    assert is_signed(signed)


def test_an_unreadable_parent_raises_target_access_error(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    locked = tmp_path / "locked"
    locked.mkdir()
    target = locked / "hello"
    target.touch()
    locked.chmod(0)
    try:
        with pytest.raises(signers.TargetAccessError) as raised:
            codesign.remove_signature(target)
    finally:
        locked.chmod(0o755)

    error = raised.value
    assert isinstance(error, OSError)
    assert error.path == target
    assert error.errno == errno.EACCES
    assert str(target) in str(error)


def test_codesign_rejecting_a_target_raises_codesign_failed_error(workspace: Workspace) -> None:
    rejected = workspace.plain_dir("plain")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.remove_signature(rejected)

    error = raised.value
    assert isinstance(error, signers.CodesignError)
    assert error.code == 1
    assert "bundle format unrecognized" in error.stderr
    assert isinstance(error.stdout, str)
    assert "bundle format unrecognized" in str(error)


@pytest.mark.parametrize("target", [1, None, [1], b"hello"], ids=["int", "None", "int element", "bytes"])
def test_invalid_targets_raise_type_error(target: object) -> None:
    with pytest.raises(TypeError):
        codesign.remove_signature(target)  # pyright: ignore[reportArgumentType, reportCallIssue]
