"""`verify` and `validate_constraint`: the kwargs reach `codesign` and its verdicts map to the exceptions."""

import platform

import pytest

import signers
from signers import codesign
from signers.codesign import SignatureSlot, Strict
from .conftest import Signature, Workspace, codesign as real_codesign, fixture


def test_verify_accepts_a_valid_signature_and_returns_none(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")

    assert codesign.verify(target) is None
    assert codesign.verify(str(target)) is None


def test_verify_passes_every_option_to_codesign(workspace: Workspace) -> None:
    framework = workspace.versioned_framework("Hello", ("A", "B"))

    result = codesign.verify(
        framework,
        deep=True,
        strict=Strict.ALL,
        ignore_resources=False,
        architecture=platform.machine(),
        bundle_version="B",
        check_designated_requirement=True,
        test_requirement=f'identifier "{Signature(framework, "--bundle-version", "B").identifier}"',
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


def test_verify_checks_every_target_of_a_sequence(workspace: Workspace) -> None:
    targets = [workspace.adhoc_signed("a"), workspace.adhoc_signed("b")]

    assert codesign.verify(targets) is None
    assert codesign.verify(targets, per_target=True) is None


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


def test_verify_failure_lists_the_changed_resources(workspace: Workspace) -> None:
    app = workspace.app_bundle("Hello")
    resources = app / "Contents/Resources"
    resources.mkdir()
    (resources / "changed").write_text("before")
    (resources / "gone").write_text("before")
    run = real_codesign("--sign", "-", app)
    assert run.returncode == 0, run.stderr
    (resources / "changed").write_text("after")
    (resources / "gone").unlink()
    (resources / "new").write_text("new")

    with pytest.raises(signers.VerificationFailedError) as raised:
        codesign.verify(app, check_designated_requirement=True)

    changes = {(r.change, r.path.resolve()) for r in raised.value.resources}
    assert changes == {
        (signers.Change.MODIFIED, (resources / "changed").resolve()),
        (signers.Change.MISSING, (resources / "gone").resolve()),
        (signers.Change.ADDED, (resources / "new").resolve()),
    }


def test_verify_raises_requirement_unsatisfied_for_a_requirement_the_code_fails(
    workspace: Workspace,
) -> None:
    target = workspace.adhoc_signed("hello")

    with pytest.raises(signers.RequirementUnsatisfiedError):
        codesign.verify(target, test_requirement='identifier "nope"')


def test_verify_collects_failures_of_a_sequence_in_a_batch_error(workspace: Workspace) -> None:
    good = workspace.adhoc_signed("good")
    bad = workspace.adhoc_signed("bad")
    with bad.open("ab") as binary:
        binary.write(b"\0")

    with pytest.raises(signers.BatchError) as raised:
        codesign.verify([good, bad], per_target=True)

    [(path, error)] = raised.value.failures
    assert path == bad
    assert isinstance(error, signers.VerificationFailedError)


def test_validate_constraint_accepts_a_valid_plist_and_returns_none() -> None:
    assert codesign.validate_constraint(fixture("constraint-team.plist")) is None
    assert codesign.validate_constraint([fixture("constraint-team.plist"), fixture("constraint-and.plist")]) is None


def test_validate_constraint_raises_constraint_invalid_for_a_bad_plist() -> None:
    with pytest.raises(signers.ConstraintInvalidError):
        codesign.validate_constraint(fixture("bad-constraint.plist"))

