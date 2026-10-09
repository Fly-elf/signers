"""`verify` and `validate_constraint`: the kwargs reach `codesign` and its verdicts map to the exceptions."""

import platform

import pytest

import signers
from signers import codesign
from signers.codesign import SignatureSlot, Strict
from .conftest import Signature, Workspace, codesign as real_codesign, fixture


def test_verify_returns_none_for_a_valid_signature(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")

    assert codesign.verify(target) is None
    assert codesign.verify(str(target)) is None
    assert codesign.verify([target, target]) is None


def test_verify_passes_every_option_to_codesign(workspace: Workspace) -> None:
    framework = workspace.versioned_framework("Hello", ("A", "B"))
    identifier = Signature(framework, "--bundle-version", "B").identifier

    for strict in Strict:
        result = codesign.verify(
            framework,
            deep=True,
            strict=strict,
            ignore_resources=False,
            architecture=platform.machine(),
            bundle_version="B",
            check_designated_requirement=True,
            test_requirement=f'identifier "{identifier}"',
            signature_slot=SignatureSlot.FIRST,
        )

        assert result is None


def test_verify_test_requirement_file_reads_the_requirement_from_a_file(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")
    requirement = workspace.join("requirement.txt")
    requirement.write_text(f'identifier "{Signature(target).identifier}"\n')

    assert codesign.verify(target, test_requirement_file=requirement) is None

    requirement.write_text('identifier "nope"\n')
    with pytest.raises(signers.RequirementUnsatisfiedError):
        codesign.verify(target, test_requirement_file=requirement)


def test_verify_detached_reads_the_signature_from_a_file(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    detached = workspace.join("hello.sig")
    run = real_codesign("--sign", "-", "--detached", detached, target)
    assert run.returncode == 0, run.stderr

    assert codesign.verify(target, detached=detached) is None


def test_verify_rejects_both_requirement_sources_before_running_codesign(workspace: Workspace) -> None:
    with pytest.raises(TypeError, match="mutually exclusive"):
        codesign.verify(
            workspace.join("missing"), test_requirement="anchor apple", test_requirement_file="r.txt"
        )


def test_verify_raises_verification_failed_for_a_tampered_binary(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")
    with target.open("ab") as binary:
        binary.write(b"\0")

    with pytest.raises(signers.VerificationFailedError) as raised:
        codesign.verify(target)

    assert raised.value.resources == ()


def test_validate_constraint_returns_none_for_valid_plists_and_raises_for_a_bad_one() -> None:
    assert codesign.validate_constraint(fixture("constraint-team.plist")) is None
    assert codesign.validate_constraint([fixture("constraint-team.plist"), fixture("constraint-and.plist")]) is None

    with pytest.raises(signers.ConstraintInvalidError):
        codesign.validate_constraint(fixture("bad-constraint.plist"))
