"""`requirements` and `extract_certificates`: results compared with what `codesign` itself prints and writes."""

# pyright: reportPrivateUsage=false

from pathlib import Path

from signers import codesign
from signers.codesign import Certificate, Requirement, RequirementKind
from .conftest import Workspace, codesign as real_codesign, designated_requirement

APPLE_SIGNED = "/usr/bin/true"


def test_requirements_lists_the_designated_requirement() -> None:
    [requirement] = codesign.requirements(APPLE_SIGNED)

    assert requirement.kind is RequirementKind.DESIGNATED
    assert requirement.expression == 'identifier "com.apple.true" and anchor apple'
    assert requirement.implicit is False


def test_requirements_marks_the_one_codesign_derives_as_implicit(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")

    [requirement] = codesign.requirements(target)

    assert requirement.implicit is True
    assert requirement.expression in designated_requirement(target)


def test_requirements_returns_one_list_per_target(workspace: Workspace) -> None:
    chains = codesign.requirements([APPLE_SIGNED, workspace.adhoc_signed("hello")])

    assert [len(chain) for chain in chains] == [1, 1]
    assert [chain[0].implicit for chain in chains] == [False, True]


def test_requirement_from_native_keeps_an_unknown_kind_as_text() -> None:
    known = {"kind": "GUEST", "expression": "anchor apple", "implicit": False}
    unknown = {"kind": {"other": "future"}, "expression": "e", "implicit": True}

    assert Requirement._from_native(known).kind is RequirementKind.GUEST
    assert Requirement._from_native(unknown) == Requirement("future", "e", True)


def test_extract_certificates_returns_the_chain_codesign_writes(workspace: Workspace) -> None:
    prefix = workspace.join("cert")
    run = real_codesign("-d", f"--extract-certificates={prefix}", APPLE_SIGNED)
    assert run.returncode == 0, run.stderr
    expected = [Path(f"{prefix}{i}").read_bytes() for i in range(3)]

    certificates = codesign.extract_certificates(APPLE_SIGNED)

    assert certificates == [Certificate(der) for der in expected]


def test_extract_certificates_of_an_ad_hoc_signature_is_empty(workspace: Workspace) -> None:
    assert codesign.extract_certificates(workspace.adhoc_signed("hello")) == []


def test_extract_certificates_save_to_writes_the_pem_chain(workspace: Workspace) -> None:
    folder = workspace.join("pem")
    folder.mkdir()

    codesign.extract_certificates(APPLE_SIGNED, save_to=folder)

    assert "BEGIN CERTIFICATE" in (folder / "true.pem").read_text()


def test_extract_certificates_returns_one_list_per_target(workspace: Workspace) -> None:
    chains = codesign.extract_certificates([APPLE_SIGNED, workspace.adhoc_signed("hello")])

    assert [len(chain) for chain in chains] == [3, 0]
