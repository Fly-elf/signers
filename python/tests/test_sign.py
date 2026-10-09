"""The signing actions: each kwarg has to reach `codesign`, checked by reading the result back with it."""

import os
import subprocess
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
    output_of,
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


def test_the_public_names_are_exported() -> None:
    for name in ("sign", "sign_adhoc", "sign_for_distribution", "SigningFlags", "PreserveMetadata", "Timestamp"):
        assert name in codesign.__all__
        assert hasattr(codesign, name)


@pytest.mark.parametrize("as_path", [False, True], ids=["str", "Path"])
def test_a_single_target_is_signed_and_the_result_is_none(
    workspace: Workspace, any_signer: Signer, as_path: bool
) -> None:
    target = workspace.unsigned("hello")

    result = any_signer(target if as_path else str(target))

    assert result is None
    assert_valid(target)
    assert output_of(target) == "hello, signers"


def test_every_function_forwards_its_options_to_codesign(workspace: Workspace, any_signer: Signer) -> None:
    target = workspace.unsigned("hello")

    any_signer(
        target,
        identifier="com.example.forwarded",
        entitlements=fixture("entitlements.plist"),
        page_size=4096,
    )

    signature = Signature(target)
    assert signature.identifier == "com.example.forwarded"
    assert signature.page_size == 4096
    assert "allow-jit" in entitlements(target)


def test_sign_adhoc_and_the_adhoc_identity_make_the_same_signature(workspace: Workspace) -> None:
    by_identity = workspace.unsigned("by-identity")
    adhoc = workspace.unsigned("adhoc")

    codesign.sign(by_identity, "-", identifier="com.example.same")
    codesign.sign_adhoc(adhoc, identifier="com.example.same")

    assert Signature(by_identity).flags == Signature(adhoc).flags == ADHOC
    assert Signature(by_identity).field("CDHash") == Signature(adhoc).field("CDHash")


def test_awkward_paths_reach_codesign_unchanged(workspace: Workspace) -> None:
    target = workspace.unsigned("-leading dash and spaces")

    codesign.sign_adhoc(target)

    assert_valid(target)


# --- targets ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", [list, tuple], ids=["list", "tuple"])
@pytest.mark.parametrize("per_target", [None, False, True])
def test_every_target_of_a_sequence_is_signed(
    workspace: Workspace, any_signer: Signer, shape: type, per_target: bool | None
) -> None:
    first, second = workspace.unsigned("first"), workspace.unsigned("second")

    result = any_signer(shape([first, str(second)]), per_target=per_target, identifier="com.example.each")

    assert result is None
    for target in (first, second):
        assert_valid(target)
        assert Signature(target).identifier == "com.example.each"


@pytest.mark.parametrize("per_target", [True, False])
def test_per_target_is_ignored_for_a_single_target(workspace: Workspace, any_signer: Signer, per_target: bool) -> None:
    target = workspace.unsigned("hello")

    any_signer(target, per_target=per_target)
    any_signer(str(target), per_target=per_target, force=True)

    assert_valid(target)


def test_a_shared_run_stops_at_the_target_codesign_refuses(workspace: Workspace) -> None:
    refused = workspace.plain_dir("not-a-bundle")
    after = workspace.unsigned("after")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc([refused, after])

    assert "bundle format unrecognized" in raised.value.stderr
    assert not is_signed(after)


def test_per_target_collects_the_refused_targets_in_input_order(workspace: Workspace) -> None:
    first = workspace.plain_dir("first")
    signed = workspace.unsigned("signed")
    last = workspace.plain_dir("last")

    with pytest.raises(signers.BatchError) as raised:
        codesign.sign_adhoc([first, signed, last], per_target=True)

    failures = raised.value.failures
    assert [path for path, _ in failures] == [first, last]
    for _, error in failures:
        assert isinstance(error, signers.CodesignFailedError)
        assert "bundle format unrecognized" in error.stderr
    assert_valid(signed)


def test_no_targets_raises_no_targets_error() -> None:
    with pytest.raises(signers.NoTargetsError):
        codesign.sign_adhoc([])


def test_an_empty_path_raises_empty_target_error_before_anything_is_signed(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    with pytest.raises(signers.EmptyTargetError) as raised:
        codesign.sign_adhoc([target, ""])

    assert raised.value.index == 1
    assert not is_signed(target)


def test_a_missing_path_raises_target_not_found_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(signers.TargetNotFoundError) as raised:
        codesign.sign_adhoc(missing)

    assert raised.value.path == missing


@pytest.mark.parametrize("target", [1, None, [1], b"hello"], ids=["int", "None", "int element", "bytes"])
def test_invalid_targets_raise_type_error(target: object) -> None:
    with pytest.raises(TypeError):
        codesign.sign_adhoc(target)  # pyright: ignore[reportArgumentType, reportCallIssue]


# --- option by option ------------------------------------------------------------------------------------------


def test_identifier_names_the_signature(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, identifier="com.example.explicit")

    assert Signature(target).identifier == "com.example.explicit"


def test_prefix_completes_a_derived_identifier(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, prefix="com.example.")

    assert Signature(target).identifier == "com.example.hello"


def test_requirements_given_as_source_are_embedded(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    requirement = 'designated => identifier "com.example.required"'

    codesign.sign_adhoc(target, identifier="com.example.required", requirements=f"={requirement}")

    assert designated_requirement(target) == requirement


def test_requirements_given_as_a_path_are_read_from_the_file(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    requirement = 'designated => identifier "com.example.from-file"'
    source = workspace.join("requirements.txt")
    source.write_text(requirement)

    codesign.sign_adhoc(target, identifier="com.example.from-file", requirements=str(source))

    assert designated_requirement(target) == requirement


def test_entitlements_are_embedded(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, entitlements=fixture("entitlements.plist"))

    assert "allow-jit" in entitlements(target)


def test_a_library_keeps_its_entitlements_only_when_forced(workspace: Workspace) -> None:
    dropped = workspace.unsigned_dylib("dropped.dylib")
    forced = workspace.unsigned_dylib("forced.dylib")

    codesign.sign_adhoc(dropped, entitlements=fixture("entitlements.plist"))
    codesign.sign_adhoc(forced, entitlements=fixture("entitlements.plist"), force_library_entitlements=True)

    assert entitlements(dropped) == ""
    assert "allow-jit" in entitlements(forced)


def test_the_der_and_threading_switches_are_accepted(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(
        target,
        entitlements=fixture("entitlements.plist"),
        generate_entitlement_der=True,
        single_threaded_signing=True,
    )

    assert_valid(target)
    assert "allow-jit" in entitlements(target)


@pytest.mark.parametrize("flag", list(SigningFlags), ids=lambda flag: flag.name)
def test_each_signing_flag_seals_the_bit_it_names(workspace: Workspace, flag: SigningFlags) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, options=flag)

    assert Signature(target).flags == ADHOC | flag.value


def test_combined_signing_flags_are_sealed_together(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, options=SigningFlags.RUNTIME | SigningFlags.KILL)

    signature = Signature(target)
    assert signature.flag_names == ["adhoc", "kill", "runtime"]
    assert signature.flags == ADHOC | SigningFlags.KILL.value | SigningFlags.RUNTIME.value


def test_empty_signing_flags_seal_no_flag(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, options=SigningFlags(0))

    assert Signature(target).flags == ADHOC


def test_the_runtime_version_is_sealed(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, options=SigningFlags.RUNTIME, runtime_version="13.1")

    assert Signature(target).runtime_version == "13.1.0"


@pytest.mark.parametrize(
    ("option", "kind"),
    [
        ("launch_constraint_self", "Self Launch"),
        ("launch_constraint_parent", "Parent Launch"),
        ("launch_constraint_responsible", "Responsible Launch"),
        ("library_constraint", "Library Load"),
    ],
)
def test_each_constraint_is_embedded_as_its_own_kind(workspace: Workspace, option: str, kind: str) -> None:
    target = workspace.unsigned("hello")

    kwargs: dict[str, Any] = {option: fixture("launch-constraint.plist")}

    codesign.sign_adhoc(target, **kwargs)

    signature = Signature(target)
    assert signature.has_constraint(kind)
    others = {"Self Launch", "Parent Launch", "Responsible Launch", "Library Load"} - {kind}
    assert not any(signature.has_constraint(other) for other in others)


def test_constraint_validity_is_only_enforced_on_request(workspace: Workspace) -> None:
    tolerated, rejected = workspace.unsigned("tolerated"), workspace.unsigned("rejected")

    codesign.sign_adhoc(tolerated, launch_constraint_self=fixture("bad-constraint.plist"))
    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc(
            rejected, launch_constraint_self=fixture("bad-constraint.plist"), enforce_constraint_validity=True
        )

    assert_valid(tolerated)
    assert "bogus-key-xyz" in raised.value.stderr
    assert not is_signed(rejected)


def test_signing_an_already_signed_target_needs_force(workspace: Workspace) -> None:
    target = workspace.adhoc_signed("hello")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc(target, identifier="com.example.first")
    codesign.sign_adhoc(target, identifier="com.example.second", force=True)

    assert "already signed" in raised.value.stderr
    assert Signature(target).identifier == "com.example.second"


def test_deep_signs_a_bundle(workspace: Workspace) -> None:
    bundle = workspace.app_bundle("Deep")

    codesign.sign_adhoc(bundle, deep=True, identifier="com.example.deep")

    assert_valid(bundle)
    assert Signature(bundle).identifier == "com.example.deep"


def test_a_bundle_version_selects_which_version_to_sign(workspace: Workspace) -> None:
    bundle = workspace.framework("Hello", ("A", "B"))

    codesign.sign_adhoc(bundle, bundle_version="B", identifier="com.example.versioned")

    assert (bundle / "Versions/B/_CodeSignature/CodeResources").is_file()
    assert not (bundle / "Versions/A/_CodeSignature").exists()
    assert Signature(bundle, "--bundle-version", "B").identifier == "com.example.versioned"


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


@pytest.mark.parametrize(
    ("flag", "presign", "preserved"),
    [
        (PreserveMetadata.IDENTIFIER, ["-i", "com.example.original"], _identifier_kept),
        (PreserveMetadata.ENTITLEMENTS, ["--entitlements", str(fixture("entitlements.plist"))], _entitlements_kept),
        (PreserveMetadata.REQUIREMENTS, ['-r=designated => identifier "com.example.original"'], _requirements_kept),
        (PreserveMetadata.FLAGS, ["-o", "kill"], _flags_kept),
        (PreserveMetadata.RUNTIME, ["-o", "runtime", "--runtime-version", "13.1"], _runtime_kept),
        (PreserveMetadata.LAUNCH_CONSTRAINTS, ["--launch-constraint-self", _CONSTRAINT], _launch_constraints_kept),
        (PreserveMetadata.LIBRARY_CONSTRAINTS, ["--library-constraint", _CONSTRAINT], _library_constraints_kept),
    ],
    ids=lambda value: value.name if isinstance(value, PreserveMetadata) else "",
)
def test_each_preserved_kind_survives_a_forced_re_sign_only_when_asked(
    workspace: Workspace,
    flag: PreserveMetadata,
    presign: list[str],
    preserved: Callable[[Path], bool],
) -> None:
    kept = workspace.presigned("kept", *presign)
    discarded = workspace.presigned("discarded", *presign)
    assert preserved(kept), "the pre-signed fixture lacks the metadata"

    codesign.sign_adhoc(kept, force=True, preserve_metadata=flag)
    codesign.sign_adhoc(discarded, force=True)

    assert preserved(kept)
    assert not preserved(discarded)


def test_every_preserve_metadata_kind_is_accepted_together(workspace: Workspace) -> None:
    target = workspace.presigned("hello", "-i", "com.example.original")

    everything = PreserveMetadata(0)
    for kind in PreserveMetadata:
        everything |= kind

    codesign.sign_adhoc(target, force=True, preserve_metadata=everything)

    assert Signature(target).identifier == "com.example.original"


def test_empty_preserve_metadata_preserves_nothing(workspace: Workspace) -> None:
    target = workspace.presigned("hello", "-i", "com.example.original")

    codesign.sign_adhoc(target, force=True, preserve_metadata=PreserveMetadata(0))

    assert Signature(target).identifier != "com.example.original"


@pytest.mark.parametrize("size", [4096, 16384])
def test_page_size_sets_the_signing_granularity(workspace: Workspace, size: int) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, page_size=size)

    assert Signature(target).page_size == size


@pytest.mark.parametrize(
    "timestamp",
    [Timestamp.ENABLED, Timestamp.DISABLED, "http://127.0.0.1:9"],
    ids=["enabled", "disabled", "server url"],
)
def test_every_timestamp_form_reaches_codesign_as_one_argument(workspace: Workspace, timestamp: Timestamp | str) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, timestamp=timestamp)

    assert_valid(target)
    assert Signature(target).timestamp is None, "an ad hoc signature is never timestamped"


def test_disallowed_xattrs_are_stripped_only_on_request(workspace: Workspace) -> None:
    kept, stripped = workspace.unsigned("kept"), workspace.unsigned("stripped")
    for target in (kept, stripped):
        subprocess.run(["xattr", "-w", "com.apple.ResourceFork", "detritus", target], check=True)

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc(kept)
    codesign.sign_adhoc(stripped, strip_disallowed_xattrs=True)

    assert "detritus not allowed" in raised.value.stderr
    assert_valid(stripped)
    names = subprocess.run(["xattr", stripped], capture_output=True, text=True, check=True).stdout.split()
    assert "com.apple.ResourceFork" not in names


def test_a_dry_run_signs_nothing_and_writes_no_detached_signature(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    detached = workspace.join("hello.sig")

    codesign.sign_adhoc(target, dry_run=True, detached=detached)

    assert not is_signed(target)
    assert not detached.exists()


def test_a_detached_signature_leaves_the_target_untouched(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    detached = workspace.join("hello.sig")

    codesign.sign_adhoc(target, detached=detached)

    assert not is_signed(target)
    assert detached.is_file()
    verified = subprocess.run(
        ["/usr/bin/codesign", "-v", "--detached", detached, target], capture_output=True, text=True
    )
    assert verified.returncode == 0, verified.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="as root this would write to the system's signature database")
def test_a_detached_database_signature_needs_root(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign_adhoc(target, detached_database=True)

    assert "cannot access a database" in raised.value.stderr
    assert not is_signed(target)


def test_the_file_list_records_what_was_signed(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")
    listing = workspace.join("signed.txt")

    codesign.sign_adhoc(target, file_list=listing)

    assert target.resolve() in {Path(line) for line in listing.read_text().splitlines()}


def test_a_keychain_hint_does_not_get_in_the_way_of_an_adhoc_signature(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_adhoc(target, keychain="/nonexistent/does-not.keychain")

    assert_valid(target)


def test_a_fully_loaded_call_renders_a_command_codesign_accepts(workspace: Workspace) -> None:
    target = workspace.presigned("hello", "-i", "com.example.previous")
    listing = workspace.join("signed.txt")
    requirement = 'designated => identifier "com.example.constrained"'

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
        launch_constraint_self=fixture("launch-constraint.plist"),
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
    assert signature.has_constraint("Self Launch")
    assert "allow-jit" in entitlements(target)
    assert designated_requirement(target) == requirement
    assert listing.read_text()
    assert output_of(target) == "hello, signers"


# --- presets ---------------------------------------------------------------------------------------------------


def test_the_distribution_preset_seals_the_runtime_flag(workspace: Workspace) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_for_distribution(target, "-")

    assert Signature(target).flags == ADHOC | SigningFlags.RUNTIME.value


def test_options_replace_the_distribution_preset(workspace: Workspace) -> None:
    replaced, emptied = workspace.unsigned("replaced"), workspace.unsigned("emptied")

    codesign.sign_for_distribution(replaced, "-", options=SigningFlags.KILL)
    codesign.sign_for_distribution(emptied, "-", options=SigningFlags(0))

    assert Signature(replaced).flags == ADHOC | SigningFlags.KILL.value
    assert Signature(emptied).flags == ADHOC


# --- errors raised before codesign runs ------------------------------------------------------------------------


@pytest.mark.parametrize("option", ["file_list", "requirements"])
def test_a_dash_for_a_stdio_option_raises_stdio_path_error(
    workspace: Workspace, any_signer: Signer, option: str
) -> None:
    target = workspace.unsigned("hello")

    with pytest.raises(signers.StdioPathError) as raised:
        any_signer(target, **{option: "-"})

    assert raised.value.option == option
    assert isinstance(raised.value, ValueError)
    assert not is_signed(target)


def _output(option: str, path: Path) -> dict[str, Any]:
    return {option: path}


@pytest.mark.parametrize("option", ["detached", "file_list"])
def test_a_shared_output_with_per_target_raises_shared_output_per_target_error(
    workspace: Workspace, option: str
) -> None:
    first, second = workspace.unsigned("first"), workspace.unsigned("second")

    with pytest.raises(signers.SharedOutputPerTargetError) as raised:
        codesign.sign_adhoc([first, second], per_target=True, **_output(option, workspace.join("out")))

    assert raised.value.option == option
    assert isinstance(raised.value, ValueError)
    assert not is_signed(first)
    assert not is_signed(second)


@pytest.mark.parametrize("option", ["detached", "file_list"])
def test_a_shared_output_is_fine_for_a_single_target_with_per_target(workspace: Workspace, option: str) -> None:
    target = workspace.unsigned("hello")
    output = workspace.join("out")

    codesign.sign_adhoc(target, per_target=True, **_output(option, output))

    assert output.is_file()


def test_a_shared_output_is_fine_for_a_shared_run(workspace: Workspace) -> None:
    first, second = workspace.unsigned("first"), workspace.unsigned("second")
    listing = workspace.join("signed.txt")

    codesign.sign_adhoc([first, second], per_target=False, file_list=listing)

    assert len(listing.read_text().splitlines()) == 2


# --- real identity (groups: keychain, network) -----------------------------------------------------------------


@pytest.mark.keychain
def test_a_certificate_signature_names_its_signer(workspace: Workspace, identity: Identity) -> None:
    target = workspace.unsigned("hello")

    codesign.sign(target, identity.name, keychain=identity.keychain, timestamp=Timestamp.DISABLED)

    assert_valid(target)
    signature = Signature(target)
    assert signature.authority == identity.name
    assert signature.flags & ADHOC == 0, "signed ad hoc"


@pytest.mark.keychain
def test_the_identity_is_looked_up_in_the_given_keychain(workspace: Workspace, identity: Identity) -> None:
    unfound, found = workspace.unsigned("unfound"), workspace.unsigned("found")

    with pytest.raises(signers.CodesignFailedError) as raised:
        codesign.sign(unfound, identity.name)
    codesign.sign(found, identity.name, keychain=identity.keychain, timestamp=Timestamp.DISABLED)

    assert "no identity found" in raised.value.stderr
    assert not is_signed(unfound)
    assert Signature(found).authority == identity.name


@pytest.mark.keychain
def test_the_distribution_preset_with_an_identity_can_drop_the_timestamp(
    workspace: Workspace, identity: Identity
) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_for_distribution(target, identity.name, keychain=identity.keychain, timestamp=Timestamp.DISABLED)

    signature = Signature(target)
    assert signature.timestamp is None
    assert signature.flags == SigningFlags.RUNTIME.value
    assert signature.authority == identity.name


@pytest.mark.keychain
@pytest.mark.network
@pytest.mark.parametrize("timestamp", [Timestamp.ENABLED, "http://timestamp.apple.com/ts01"], ids=["enabled", "server url"])
def test_a_certificate_signature_can_be_timestamped(
    workspace: Workspace, identity: Identity, timestamp: Timestamp | str
) -> None:
    target = workspace.unsigned("hello")

    codesign.sign(target, identity.name, keychain=identity.keychain, timestamp=timestamp)

    assert Signature(target).timestamp is not None


@pytest.mark.keychain
@pytest.mark.network
def test_the_distribution_preset_is_timestamped_and_hardened(workspace: Workspace, identity: Identity) -> None:
    target = workspace.unsigned("hello")

    codesign.sign_for_distribution(target, identity.name, keychain=identity.keychain)

    signature = Signature(target)
    assert signature.timestamp is not None, signature.raw
    assert signature.flags == SigningFlags.RUNTIME.value


# --- option types ----------------------------------------------------------------------------------------------


def test_signing_flags_keep_the_bits_codesign_reports_without_a_member() -> None:
    reported = SigningFlags(0x2 | 0x1_0000)

    assert reported.value == 0x2 | 0x1_0000
    assert SigningFlags.RUNTIME in reported


def test_timestamp_members_are_named_after_the_rust_variants() -> None:
    assert [member.name for member in Timestamp] == ["ENABLED", "DISABLED"]


def test_the_member_names_match_the_rust_flags() -> None:
    assert [m.name for m in SigningFlags] == ["HOST", "HARD", "KILL", "EXPIRES", "LIBRARY", "RUNTIME", "LINKER_SIGNED"]
    assert [m.name for m in PreserveMetadata] == [
        "IDENTIFIER",
        "ENTITLEMENTS",
        "REQUIREMENTS",
        "FLAGS",
        "RUNTIME",
        "LAUNCH_CONSTRAINTS",
        "LIBRARY_CONSTRAINTS",
    ]
