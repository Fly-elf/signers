"""`codesign.aio`: each awaitable reaches the real `codesign`, results and errors match the sync functions."""

import asyncio
import inspect
from collections.abc import Awaitable
from typing import TypeVar

import pytest

import signers
from signers import codesign
from signers.codesign import (
    Certificate,
    Requirement,
    Signature,
    SigningFlags,
    aio,
)
from .conftest import ADHOC, Signature as Report, Workspace, assert_valid, fixture, is_signed

APPLE_SIGNED = "/usr/bin/true"
ACTIONS = (
    "remove_signature",
    "sign",
    "sign_adhoc",
    "sign_for_distribution",
    "verify",
    "validate_constraint",
    "display",
    "requirements",
    "extract_certificates",
)

T = TypeVar("T")


def run(awaitable: Awaitable[T]) -> T:
    """Drives one awaitable on a fresh event loop."""

    async def main() -> T:
        return await awaitable

    return asyncio.run(main())


def test_aio_exports_the_nine_actions_as_coroutine_functions_with_the_sync_signatures() -> None:
    assert sorted(aio.__all__) == sorted(ACTIONS)
    for name in ACTIONS:
        assert inspect.iscoroutinefunction(getattr(aio, name)), name
        assert inspect.signature(getattr(aio, name)) == inspect.signature(getattr(codesign, name)), name


def test_remove_signature_strips_a_target_and_a_sequence(workspace: Workspace) -> None:
    single = workspace.adhoc_signed("single")
    many = [workspace.adhoc_signed("a"), workspace.adhoc_signed("b")]

    assert run(aio.remove_signature(single)) is None
    assert run(aio.remove_signature(many, per_target=True)) is None

    assert not any(is_signed(path) for path in [single, *many])


def test_sign_applies_its_kwargs_to_the_real_signature(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    result = run(aio.sign(target, "-", identifier="com.example.aio", options=SigningFlags.RUNTIME, force=True))

    assert result is None
    report = Report(target)
    assert report.identifier == "com.example.aio"
    assert report.flags == ADHOC | SigningFlags.RUNTIME.value
    assert_valid(target)


def test_sign_adhoc_signs_a_target_and_every_target_of_a_sequence(workspace: Workspace) -> None:
    single = workspace.unsigned("single")
    many = [workspace.unsigned("a"), workspace.unsigned("b")]

    assert run(aio.sign_adhoc(single, identifier="com.example.single")) is None
    assert run(aio.sign_adhoc(many, per_target=True, force=True)) is None

    assert Report(single).identifier == "com.example.single"
    for path in many:
        assert_valid(path)


def test_sign_for_distribution_applies_the_distribution_preset(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    assert run(aio.sign_for_distribution(target, "-")) is None

    assert Report(target).flags == ADHOC | SigningFlags.RUNTIME.value


def test_verify_returns_none_for_valid_signatures(workspace: Workspace) -> None:
    single = workspace.adhoc_signed("single")
    many = [workspace.adhoc_signed("a"), workspace.adhoc_signed("b")]

    assert run(aio.verify(single, strict=codesign.Strict.ALL)) is None
    assert run(aio.verify(many)) is None


def test_verify_raises_the_mapped_exception_when_awaited(workspace: Workspace) -> None:
    with pytest.raises(signers.TargetNotFoundError) as raised:
        run(aio.verify(workspace.join("missing")))

    assert raised.value.path == workspace.join("missing")


def test_verify_collects_the_failures_of_a_sequence_in_a_batch_error(workspace: Workspace) -> None:
    good = workspace.adhoc_signed("good")
    bad = workspace.adhoc_signed("bad")
    with bad.open("ab") as binary:
        binary.write(b"\0")

    with pytest.raises(signers.BatchError) as raised:
        run(aio.verify([good, bad], per_target=True))

    [(path, error)] = raised.value.failures
    assert path == bad
    assert isinstance(error, signers.VerificationFailedError)


def test_argument_errors_surface_when_the_call_is_awaited(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")

    awaitable = aio.verify(target, test_requirement="anchor apple", test_requirement_file="r.txt")

    with pytest.raises(TypeError):
        run(awaitable)


def test_validate_constraint_accepts_and_rejects_plists() -> None:
    assert run(aio.validate_constraint(fixture("constraint-team.plist"))) is None
    assert run(aio.validate_constraint([fixture("constraint-team.plist"), fixture("constraint-and.plist")])) is None

    with pytest.raises(signers.ConstraintInvalidError):
        run(aio.validate_constraint(fixture("bad-constraint.plist")))


def test_display_returns_a_signature_for_a_path_and_a_list_for_a_sequence(workspace: Workspace) -> None:
    a, b = workspace.adhoc_signed("a"), workspace.adhoc_signed("b")

    one = run(aio.display(a))
    many = run(aio.display([a, b]))

    assert isinstance(one, Signature)
    assert one.identifier == Report(a).identifier
    assert isinstance(many, list) and len(many) == 2
    assert [s.identifier for s in many] == [Report(a).identifier, Report(b).identifier]


def test_requirements_returns_one_list_for_a_path_and_one_per_target_for_a_sequence(
    workspace: Workspace,
) -> None:
    adhoc = workspace.adhoc_signed("hello")

    one = run(aio.requirements(APPLE_SIGNED))
    many = run(aio.requirements([APPLE_SIGNED, adhoc]))

    assert [r.expression for r in one] == ['identifier "com.apple.true" and anchor apple']
    assert all(isinstance(r, Requirement) for r in one)
    assert [[r.implicit for r in chain] for chain in many] == [[False], [True]]


def test_extract_certificates_returns_the_chain_in_the_same_shapes(workspace: Workspace) -> None:
    one = run(aio.extract_certificates(APPLE_SIGNED))
    many = run(aio.extract_certificates([APPLE_SIGNED, workspace.adhoc_signed("hello")]))

    assert len(one) == 3 and all(isinstance(c, Certificate) for c in one)
    assert many == [one, []]


def test_concurrent_calls_run_side_by_side_and_keep_their_own_results(workspace: Workspace) -> None:
    a, b = workspace.unsigned("a"), workspace.unsigned("b")

    async def main() -> tuple[None, None, Signature, Signature]:
        signed = await asyncio.gather(
            aio.sign_adhoc(a, identifier="com.example.a"),
            aio.sign_adhoc(b, identifier="com.example.b"),
        )
        shown = await asyncio.gather(aio.display(a), aio.display(b))
        return (*signed, *shown)

    _, _, shown_a, shown_b = asyncio.run(main())

    assert (shown_a.identifier, shown_b.identifier) == ("com.example.a", "com.example.b")


def test_cancelling_a_call_raises_cancelled_error_and_leaves_the_loop_usable(workspace: Workspace) -> None:
    cancelled = workspace.unsigned("cancelled")
    other = workspace.adhoc_signed("other")

    async def main() -> Signature:
        task = asyncio.create_task(aio.sign_adhoc(cancelled, force=True))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()
        return await aio.display(other)

    assert asyncio.run(main()).identifier == Report(other).identifier

