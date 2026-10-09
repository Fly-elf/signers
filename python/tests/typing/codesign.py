# Checked by pyright, never run: pins the types the IDE sees. A rejected call
# carries an ignore comment, which pyright reports once the call is accepted.
# pyright: reportUnnecessaryTypeIgnoreComment=true

from pathlib import Path
from typing import assert_type

import signers
from signers import codesign
from signers.codesign import (
    Certificate,
    Platform,
    PreserveMetadata,
    Requirement,
    RequirementKind,
    Signature,
    SignatureSlot,
    SigningFlags,
    Strict,
    Timestamp,
)


def remove_signature() -> None:
    assert_type(codesign.remove_signature("a"), None)
    assert_type(codesign.remove_signature(Path("a"), bundle_version="B"), None)
    assert_type(codesign.remove_signature(["a", Path("b")]), None)
    assert_type(codesign.remove_signature(("a",), per_target=True, bundle_version="B"), None)
    assert_type(codesign.remove_signature("a", per_target=True), None)
    assert_type(codesign.remove_signature(Path("a"), per_target=False), None)

    codesign.remove_signature(1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.remove_signature(b"a")  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.remove_signature(["a"], bundle_version=1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.remove_signature(["a"], True)  # pyright: ignore[reportCallIssue]
    codesign.remove_signature(["a"], force=True)  # pyright: ignore[reportCallIssue]


def sign() -> None:
    assert_type(codesign.sign("a", "-"), None)
    assert_type(codesign.sign(Path("a"), "Developer ID", keychain=Path("k"), force=True), None)
    assert_type(codesign.sign(["a", Path("b")], "-", per_target=True), None)
    assert_type(codesign.sign("a", "-", per_target=True), None)
    assert_type(codesign.sign_adhoc(("a",), identifier="id", page_size=4096), None)
    assert_type(codesign.sign_adhoc(Path("a"), per_target=False, file_list="list.txt"), None)
    assert_type(codesign.sign_for_distribution("a", "-", options=SigningFlags.RUNTIME | SigningFlags.HARD), None)
    assert_type(codesign.sign_for_distribution(["a"], "-", timestamp=Timestamp.DISABLED), None)
    assert_type(codesign.sign_adhoc("a", timestamp="http://timestamp.example"), None)
    assert_type(codesign.sign_adhoc("a", preserve_metadata=PreserveMetadata.IDENTIFIER), None)
    assert_type(codesign.sign_adhoc("a", options=None, timestamp=None, preserve_metadata=None), None)

    codesign.sign("a")  # pyright: ignore[reportCallIssue]
    codesign.sign_adhoc("a", "-")  # pyright: ignore[reportCallIssue]
    codesign.sign_adhoc(1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", force=1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", page_size="4096")  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", options=0x100)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", options=PreserveMetadata.FLAGS)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", preserve_metadata=SigningFlags.RUNTIME)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", timestamp=True)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", detached=1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", requirements=Path("r"))  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.sign_adhoc("a", display=True)  # pyright: ignore[reportCallIssue]
    codesign.sign_adhoc("a", True)  # pyright: ignore[reportCallIssue]
    codesign.sign_for_distribution("a")  # pyright: ignore[reportCallIssue]


def verify() -> None:
    assert_type(codesign.verify("a"), None)
    assert_type(codesign.verify(Path("a"), deep=True, strict=Strict.ALL, signature_slot=SignatureSlot.SECOND), None)
    assert_type(codesign.verify(["a", Path("b")], per_target=True, test_requirement="anchor apple"), None)
    assert_type(codesign.verify("a", test_requirement_file=Path("r"), detached="d", architecture="arm64"), None)
    assert_type(codesign.validate_constraint("a.plist"), None)
    assert_type(codesign.validate_constraint([Path("a.plist")], per_target=True), None)

    codesign.verify("a", strict=True)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.verify("a", strict="ALL")  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.verify("a", signature_slot=Strict.ALL)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.verify("a", force=True)  # pyright: ignore[reportCallIssue]
    codesign.verify(1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.validate_constraint("a.plist", deep=True)  # pyright: ignore[reportCallIssue]


def display() -> None:
    assert_type(codesign.display("a"), Signature)
    assert_type(codesign.display(Path("a"), per_target=True, deep=True), Signature)
    assert_type(codesign.display(["a", Path("b")]), list[Signature])
    assert_type(codesign.display(("a",), per_target=False, signature_slot=SignatureSlot.FIRST), list[Signature])

    codesign.display("a", detached=1)  # pyright: ignore[reportCallIssue, reportArgumentType]
    codesign.display("a", force=True)  # pyright: ignore[reportCallIssue]

    signature = codesign.display("a")
    assert_type(signature.executable, Path)
    assert_type(signature.signature is None, bool)
    assert_type(signature.platform, Platform | int | None)
    assert_type(signature.code_directory.flags, SigningFlags)
    assert_type(signature.code_directory.hashes.code, int)
    assert_type(signature.entitlements, dict[str, object] | None)
    assert_type(signature.field("Identifier"), str | None)
    signature.identifier = "x"  # pyright: ignore[reportAttributeAccessIssue]


def requirements() -> None:
    assert_type(codesign.requirements("a"), list[Requirement])
    assert_type(codesign.requirements(Path("a")), list[Requirement])
    assert_type(codesign.requirements(["a", Path("b")]), list[list[Requirement]])
    assert_type(codesign.extract_certificates("a"), list[Certificate])
    assert_type(codesign.extract_certificates(Path("a"), save_to="dir"), list[Certificate])
    assert_type(codesign.extract_certificates(["a"], save_to=Path("dir")), list[list[Certificate]])

    codesign.requirements("a", per_target=True)  # pyright: ignore[reportCallIssue]
    codesign.extract_certificates("a", per_target=True)  # pyright: ignore[reportCallIssue]
    codesign.extract_certificates("a", save_to=1)  # pyright: ignore[reportCallIssue, reportArgumentType]

    requirement = codesign.requirements("a")[0]
    assert_type(requirement.kind, RequirementKind | str)
    assert_type(requirement.implicit, bool)
    assert_type(codesign.extract_certificates("a")[0].der, bytes)


def option_types() -> None:
    assert_type(SigningFlags.RUNTIME | SigningFlags.HARD, SigningFlags)
    assert_type(PreserveMetadata.IDENTIFIER | PreserveMetadata.FLAGS, PreserveMetadata)
    SigningFlags.RUNTIME | PreserveMetadata.FLAGS  # pyright: ignore[reportOperatorIssue, reportUnusedExpression]


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
