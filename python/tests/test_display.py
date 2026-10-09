"""`display` and the `Signature` types: values read back through `codesign -d`, and every conversion branch."""

# pyright: reportPrivateUsage=false

import copy
import dataclasses
import platform
from typing import Any

import pytest

import signers
from signers import _native, codesign
from signers.codesign import (
    CertificateSignature,
    Constraints,
    Format,
    FormatKind,
    HashType,
    Location,
    OsVersion,
    Platform,
    Signature,
    SignatureSlot,
    SigningFlags,
)
from .conftest import Signature as Report, Workspace, codesign as real_codesign, fixture

APPLE_SIGNED = "/usr/bin/true"
_THIN = {"kind": "MACHO_THIN", "archs": ["arm64"], "app": None, "executable": None, "other": None}


def _native_dict(path: str) -> dict[str, Any]:
    """The plain dict the extension hands to Python for a signed binary."""
    return _native.codesign_display(
        path,
        {"architecture": None, "bundle_version": None, "deep": False, "signature_slot": None, "detached": None},
        per_target=None,
    )


def test_display_reads_an_adhoc_signature_as_codesign_reports_it(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")
    report = Report(target)

    signature = codesign.display(target)

    assert isinstance(signature, Signature)
    assert signature.signature is None
    assert signature.code_directory.flags.value == report.flags
    assert signature.identifier == report.identifier
    assert signature.field("Identifier") == report.identifier
    assert signature.executable.resolve() == target.resolve()
    assert signature.format.kind is FormatKind.MACHO_THIN
    assert signature.entitlements is None
    assert report.field("Hash type") == "sha256 size=32" and signature.hash_type is HashType.SHA256


def test_display_reads_an_apple_signed_binary() -> None:
    signature = codesign.display(APPLE_SIGNED)

    assert isinstance(signature.signature, CertificateSignature)
    assert signature.signature.authorities[0] == "macOS Software Signing"
    assert signature.platform_identifier is not None
    assert signature.platform is Platform.MAC_OS
    assert signature.code_directory.location is Location.EMBEDDED
    assert isinstance(signature.min_os, OsVersion)
    assert signature.format.kind is FormatKind.MACHO_UNIVERSAL and len(signature.format.archs) > 1


def test_display_passes_every_option_to_codesign(workspace: Workspace) -> None:
    framework = workspace.versioned_framework("Hello", ("A", "B"))

    signature = codesign.display(
        framework,
        architecture=platform.machine(),
        bundle_version="B",
        deep=True,
        signature_slot=SignatureSlot.FIRST,
    )

    assert signature.executable.name == "Hello"
    assert signature.identifier == Report(framework, "--bundle-version", "B").identifier

    thin = codesign.display(APPLE_SIGNED, architecture="arm64e")
    assert thin.format == Format(FormatKind.MACHO_THIN, archs=("arm64e",))


def test_display_detached_reads_the_signature_from_a_file(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    detached = workspace.join("hello.sig")
    run = real_codesign("--sign", "-", "--detached", detached, target)
    assert run.returncode == 0, run.stderr

    signature = codesign.display(target, detached=detached)

    assert signature.code_directory.location is Location.EXPLICIT_DETACHED
    assert signature.code_directory.flags.value == Report(target, "--detached", str(detached)).flags


def test_display_reads_bundle_resources_and_entitlements(workspace: Workspace) -> None:
    app = workspace.app_bundle("Hello")
    codesign.sign_adhoc(
        app,
        entitlements=fixture("entitlements.plist"),
        launch_constraint_self=fixture("launch-constraint.plist"),
    )

    signature = codesign.display(app)

    assert signature.format.kind is FormatKind.BUNDLE and signature.format.app is True
    assert signature.format.executable is not None
    assert signature.format.executable.kind is FormatKind.MACHO_THIN
    assert signature.info_plist is not None and signature.sealed_resources is not None
    assert signature.entitlements == {
        "com.apple.security.cs.allow-jit": True,
        "com.apple.security.get-task-allow": True,
    }
    assert signature.constraints == Constraints.LAUNCH_SELF


def test_display_lists_one_signature_per_target(workspace: Workspace) -> None:
    targets = [workspace.adhoc_signed("a"), APPLE_SIGNED]

    signatures = codesign.display(targets)
    unshared = codesign.display(targets, per_target=True)

    assert [s.signature is None for s in signatures] == [True, False]
    assert [s.identifier for s in unshared] == [s.identifier for s in signatures]


def test_display_raises_no_signature_for_a_slot_the_code_lacks() -> None:
    with pytest.raises(signers.NoSignatureError):
        codesign.display("/bin/ls", signature_slot=SignatureSlot.SECOND)


def test_display_raises_codesign_failed_for_unsigned_code(workspace: Workspace) -> None:
    with pytest.raises(signers.CodesignFailedError, match="not signed"):
        codesign.display(workspace.unsigned("hello"))


def test_signature_is_a_frozen_value_that_hides_the_raw_report() -> None:
    signature = codesign.display(APPLE_SIGNED)

    with pytest.raises(dataclasses.FrozenInstanceError):
        signature.identifier = "x"  # pyright: ignore[reportAttributeAccessIssue]
    assert signature.raw not in repr(signature)
    assert signature == Signature._from_native(_native_dict(APPLE_SIGNED))


def test_field_returns_the_first_exact_key_and_strips_a_carriage_return() -> None:
    raw = "Identifier=a\r\nIdentifier=b\nIdentifier2=c\nno separator\nAuthority=x=y"
    signature = dataclasses.replace(codesign.display(APPLE_SIGNED), raw=raw)

    assert signature.field("Identifier") == "a"
    assert signature.field("Identifier2") == "c"
    assert signature.field("Authority") == "x=y"
    assert signature.field("Missing") is None
    assert signature.field("no separator") is None


def test_from_native_keeps_the_raw_value_of_every_catch_all() -> None:
    d = copy.deepcopy(_native_dict(APPLE_SIGNED))
    d["code_directory"]["location"] = {"other": "somewhere"}
    d["code_directory"]["flags"] = 0x2 | 0x1_0000 | 0x4000_0000
    d["platform"] = {"other": 99}
    d["hash_type"] = {"other": "SHA512"}
    d["hash_choices"] = ["SHA256", {"other": "SHA512"}]
    d["cd_hashes"][0]["algorithm"] = {"other": "SHA512"}
    d["constraints"] = 0b1010
    d["min_os"] = None
    d["signature"] = None

    signature = Signature._from_native(d)

    assert signature.code_directory.location == "somewhere"
    assert SigningFlags.RUNTIME in signature.code_directory.flags
    assert signature.code_directory.flags.value == 0x2 | 0x1_0000 | 0x4000_0000
    assert signature.platform == 99
    assert signature.hash_type == "SHA512"
    assert signature.hash_choices == (HashType.SHA256, "SHA512")
    assert signature.cd_hashes[0].algorithm == "SHA512"
    assert signature.signature is None and signature.min_os is None
    assert signature.constraints == Constraints.LAUNCH_PARENT | Constraints.LIBRARY_LOAD

    d["signature"] = {"size": 4, "authorities": [None, "Apple Root CA"]}
    assert Signature._from_native(d).signature == CertificateSignature(4, (None, "Apple Root CA"))


@pytest.mark.parametrize(
    ("native", "expected"),
    [
        ({"kind": "MACHO_THIN", "archs": ["arm64"]}, Format(FormatKind.MACHO_THIN, archs=("arm64",))),
        ({"kind": "MACHO_UNIVERSAL", "archs": ["x86_64", "arm64"]}, Format(FormatKind.MACHO_UNIVERSAL, archs=("x86_64", "arm64"))),
        ({"kind": "OTHER", "other": "Weird"}, Format(FormatKind.OTHER, other="Weird")),
        ({"kind": "GENERIC"}, Format(FormatKind.GENERIC)),
        (
            {"kind": "BUNDLE", "app": False, "executable": _THIN},
            Format(FormatKind.BUNDLE, app=False, executable=Format(FormatKind.MACHO_THIN, archs=("arm64",))),
        ),
    ],
)
def test_format_from_native_maps_each_shape(native: dict[str, Any], expected: Format) -> None:
    complete: dict[str, Any] = {"archs": [], "app": None, "executable": None, "other": None, **native}

    assert Format._from_native(complete) == expected

