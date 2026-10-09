# Checked by pyright, never run: pins the types the IDE sees. A rejected call
# carries an ignore comment, which pyright reports once the call is accepted.
# pyright: reportUnnecessaryTypeIgnoreComment=true

from pathlib import Path
from typing import assert_type

import signers
from signers import codesign


def remove_signature() -> None:
    assert_type(codesign.remove_signature("a"), None)
    assert_type(codesign.remove_signature(Path("a"), bundle_version="B"), None)
    assert_type(codesign.remove_signature(["a", Path("b")]), None)
    assert_type(codesign.remove_signature(("a",), per_target=True, bundle_version="B"), None)

    codesign.remove_signature(Path("a"), per_target=True)  # pyright: ignore[reportArgumentType]
    codesign.remove_signature(1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.remove_signature(b"a")  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.remove_signature(["a"], bundle_version=1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.remove_signature(["a"], True)  # pyright: ignore[reportCallIssue]
    codesign.remove_signature(["a"], force=True)  # pyright: ignore[reportCallIssue]


def errors(error: Exception) -> None:
    if isinstance(error, signers.BatchError):
        assert_type(error.failures, tuple[tuple[Path, signers.SignersError], ...])
    if isinstance(error, signers.EmptyTargetError):
        assert_type(error.index, int)
    if isinstance(error, signers.TargetNotFoundError):
        assert_type(error.path, Path)
    if isinstance(error, signers.StdioPathError):
        assert_type(error.option, str)
    if isinstance(error, signers.CodesignFailedError):
        assert_type(error.code, int)
        assert_type(error.stderr, str)
    if isinstance(error, signers.TerminatedError):
        assert_type(error.signal, int | None)
    if isinstance(error, signers.UnexpectedOutputError):
        assert_type(error.detail, str)
    if isinstance(error, signers.VerificationFailedError):
        assert_type(error.resources, tuple[signers.ResourceChange, ...])
        assert_type(error.resources[0].change, signers.Change)
        assert_type(error.resources[0].path, Path)
