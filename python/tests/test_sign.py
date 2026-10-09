"""The signing actions: each kwarg has to reach `codesign`, checked by reading the result back with it."""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import signers
from signers import codesign
from signers.codesign import PreserveMetadata, SigningFlags, Timestamp
from .conftest import (
    ADHOC,
    Identity,
    Signature,
    Workspace,
    assert_valid,
    designated_requirement,
    entitlements,
    fixture,
    is_signed,
)

Signer = Callable[..., None]


def _sign(target: Any, **kwargs: Any) -> None:
    codesign.sign(target, "-", **kwargs)


def _sign_for_distribution(target: Any, **kwargs: Any) -> None:
    codesign.sign_for_distribution(target, "-", **kwargs)


SIGNERS: dict[str, Signer] = {
    "sign": _sign,
    "sign_adhoc": codesign.sign_adhoc,
    "sign_for_distribution": _sign_for_distribution,
}


@pytest.fixture(params=SIGNERS)
def any_signer(request: pytest.FixtureRequest) -> Signer:
    return SIGNERS[request.param]


def test_every_signer_reaches_codesign_with_its_options(workspace: Workspace, any_signer: Signer) -> None:
    by_str = workspace.unsigned("-leading dash and spaces")
    by_path = workspace.unsigned("path")

    results = [
        any_signer(
            target,
            identifier="com.example.forwarded",
            entitlements=fixture("entitlements.plist"),
            page_size=4096,
        )
        for target in (str(by_str), by_path)
    ]

    assert results == [None, None]
    for target in (by_str, by_path):
        assert_valid(target)
        signature = Signature(target)
        assert signature.identifier == "com.example.forwarded"
        assert signature.page_size == 4096
        assert "allow-jit" in entitlements(target)


def test_a_sequence_of_targets_is_signed_whatever_per_target_says(workspace: Workspace) -> None:
    for per_target in (None, False, True):
        first, second = workspace.unsigned(f"first-{per_target}"), workspace.unsigned(f"second-{per_target}")

        result = codesign.sign_adhoc([first, str(second)], per_target=per_target, identifier="com.example.each")

        assert result is None
        for target in (first, second):
            assert Signature(target).identifier == "com.example.each"


def test_per_target_is_ignored_for_a_single_target(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, per_target=True)
    codesign.sign_adhoc(str(target), per_target=False, force=True)

    assert_valid(target)


def test_a_fully_loaded_call_reaches_codesign_option_by_option(workspace: Workspace) -> None:
    target = workspace.presigned("hello", "-i", "com.example.previous")
    listing = workspace.join("signed.txt")
    requirement = 'designated => identifier "com.example.constrained"'
    constraint = fixture("launch-constraint.plist")

    codesign.sign_adhoc(
        target,
        identifier="com.example.constrained",
        requirements=f"={requirement}",
        keychain="/nonexistent/does-not.keychain",
        entitlements=fixture("entitlements.plist"),
        generate_entitlement_der=True,
        force_library_entitlements=True,
        options=SigningFlags.RUNTIME | SigningFlags.KILL | SigningFlags.HARD,
        runtime_version="13.1",
        launch_constraint_self=constraint,
        launch_constraint_parent=constraint,
        launch_constraint_responsible=constraint,
        library_constraint=constraint,
        force=True,
        preserve_metadata=PreserveMetadata(0),
        page_size=4096,
        timestamp=Timestamp.DISABLED,
        strip_disallowed_xattrs=True,
        single_threaded_signing=True,
        file_list=listing,
    )

    assert_valid(target)
    signature = Signature(target)
    assert signature.identifier == "com.example.constrained"
    assert signature.flags == ADHOC | SigningFlags.HARD.value | SigningFlags.KILL.value | SigningFlags.RUNTIME.value
    assert signature.runtime_version == "13.1.0"
    assert signature.page_size == 4096
    for kind in ("Self Launch", "Parent Launch", "Responsible Launch", "Library Load"):
        assert signature.has_constraint(kind), kind
    assert "allow-jit" in entitlements(target)
    assert designated_requirement(target) == requirement
    assert target.resolve() in {Path(line) for line in listing.read_text().splitlines()}


def test_prefix_and_a_requirements_file_reach_codesign(workspace: Workspace) -> None:
    prefixed, required = workspace.unsigned("hello"), workspace.unsigned("required")
    requirement = 'designated => identifier "com.example.from-file"'
    source = workspace.join("requirements.txt")
    source.write_text(requirement)

    codesign.sign_adhoc(prefixed, prefix="com.example.")
    codesign.sign_adhoc(required, identifier="com.example.from-file", requirements=str(source))

    assert Signature(prefixed).identifier == "com.example.hello"
    assert designated_requirement(required) == requirement


def test_enforce_constraint_validity_reaches_codesign(workspace: Workspace) -> None:
    tolerated, rejected = workspace.unsigned("tolerated"), workspace.unsigned("rejected")

    codesign.sign_adhoc(tolerated, launch_constraint_self=fixture("bad-constraint.plist"))
    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc(
            rejected, launch_constraint_self=fixture("bad-constraint.plist"), enforce_constraint_validity=True
        )

    assert "bogus-key-xyz" in raised.value.stderr
    assert not is_signed(rejected)


def test_bundle_version_and_deep_reach_codesign(workspace: Workspace) -> None:
    bundle = workspace.framework("Hello", ("A", "B"))

    codesign.sign_adhoc(bundle, bundle_version="B", deep=True, identifier="com.example.versioned")

    assert (bundle / "Versions/B/_CodeSignature/CodeResources").is_file()
    assert not (bundle / "Versions/A/_CodeSignature").exists()
    assert Signature(bundle, "--bundle-version", "B").identifier == "com.example.versioned"


def test_dry_run_and_detached_reach_codesign(workspace: Workspace) -> None:
    dry, split = workspace.unsigned("dry"), workspace.unsigned("split")
    never, detached = workspace.join("never.sig"), workspace.join("split.sig")

    codesign.sign_adhoc(dry, dry_run=True, detached=never)
    codesign.sign_adhoc(split, detached=detached)

    assert not is_signed(dry) and not never.exists()
    assert not is_signed(split) and detached.is_file()


@pytest.mark.skipif(os.geteuid() == 0, reason="as root this would write to the system's signature database")
def test_detached_database_reaches_codesign(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc(target, detached_database=True)

    assert "cannot access a database" in raised.value.stderr


def test_each_signing_flag_lands_on_the_bit_it_names(workspace: Workspace) -> None:
    for flag in SigningFlags:
        target = workspace.unsigned(f"flag-{flag.name}")

        codesign.sign_adhoc(target, options=flag)

        assert Signature(target).flags == ADHOC | flag.value, flag.name


def _identifier_kept(path: Path) -> bool:
    return Signature(path).identifier == "com.example.original"


def _entitlements_kept(path: Path) -> bool:
    return "allow-jit" in entitlements(path)


def _requirements_kept(path: Path) -> bool:
    return "com.example.original" in designated_requirement(path)


def _flags_kept(path: Path) -> bool:
    return "kill" in Signature(path).flag_names


def _runtime_kept(path: Path) -> bool:
    return Signature(path).runtime_version == "13.1.0"


def _launch_constraints_kept(path: Path) -> bool:
    return Signature(path).has_constraint("Self Launch")


def _library_constraints_kept(path: Path) -> bool:
    return Signature(path).has_constraint("Library Load")


_CONSTRAINT = str(fixture("launch-constraint.plist"))


# The extension rebuilds the flag with `from_bits_truncate`: a member whose value drifts from the
# Rust bit would be dropped silently, so each one is checked against the metadata it names.
_PRESERVED: list[tuple[PreserveMetadata, list[str], Callable[[Path], bool]]] = [
    (PreserveMetadata.IDENTIFIER, ["-i", "com.example.original"], _identifier_kept),
    (PreserveMetadata.ENTITLEMENTS, ["--entitlements", str(fixture("entitlements.plist"))], _entitlements_kept),
    (PreserveMetadata.REQUIREMENTS, ['-r=designated => identifier "com.example.original"'], _requirements_kept),
    (PreserveMetadata.FLAGS, ["-o", "kill"], _flags_kept),
    (PreserveMetadata.RUNTIME, ["-o", "runtime", "--runtime-version", "13.1"], _runtime_kept),
    (PreserveMetadata.LAUNCH_CONSTRAINTS, ["--launch-constraint-self", _CONSTRAINT], _launch_constraints_kept),
    (PreserveMetadata.LIBRARY_CONSTRAINTS, ["--library-constraint", _CONSTRAINT], _library_constraints_kept),
]


def test_each_preserve_metadata_flag_lands_on_the_metadata_it_names(workspace: Workspace) -> None:
    for flag, presign, preserved in _PRESERVED:
        kept = workspace.presigned(f"kept-{flag.name}", *presign)
        discarded = workspace.presigned(f"discarded-{flag.name}", *presign)
        assert preserved(kept), f"{flag.name}: the pre-signed fixture lacks the metadata"

        codesign.sign_adhoc(kept, force=True, preserve_metadata=flag)
        codesign.sign_adhoc(discarded, force=True)

        assert preserved(kept), flag.name
        assert not preserved(discarded), flag.name


def test_every_timestamp_form_reaches_codesign_as_one_argument(workspace: Workspace) -> None:
    for timestamp in (Timestamp.ENABLED, Timestamp.DISABLED, "http://127.0.0.1:9"):
        target = workspace.unsigned(f"hello-{timestamp}".replace("/", "_"))

        codesign.sign_adhoc(target, timestamp=timestamp)

        assert_valid(target)


@pytest.mark.keychain
def test_a_certificate_identity_is_looked_up_in_the_given_keychain(
    workspace: Workspace, identity: Identity
) -> None:
    target = workspace.unsigned("hello")

    codesign.sign(target, identity.name, keychain=identity.keychain, timestamp=Timestamp.DISABLED)

    assert_valid(target)
    assert Signature(target).authority == identity.name
