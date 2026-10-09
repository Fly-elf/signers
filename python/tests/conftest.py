"""Fixtures shared by the Python tests: a compiled Mach-O and the real `codesign`.

Every check goes through `/usr/bin/codesign` itself, never through `signers`.
"""

import itertools
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CODESIGN = "/usr/bin/codesign"
ADHOC = 0x2

_GROUPS = ("keychain", "network")

_INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>{name}</string>
	<key>CFBundleIdentifier</key>
	<string>com.example.{name}</string>
	<key>CFBundleName</key>
	<string>{name}</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
</dict>
</plist>
"""


def codesign(*args: str | os.PathLike[str]) -> subprocess.CompletedProcess[str]:
    """Runs the real `codesign` with `args`, capturing its output.

    >>> codesign("-dv", path).stderr
    """
    return subprocess.run([CODESIGN, *args], capture_output=True, text=True)


def is_signed(path: Path, *, bundle_version: str | None = None) -> bool:
    """Whether `codesign -d` finds a signature on `path` (or on one version of a bundle).

    Fails rather than guessing when `codesign` rejects the path for another reason.
    """
    selector = ["--bundle-version", bundle_version] if bundle_version else []
    run = codesign("-d", *selector, path)
    if run.returncode == 0:
        return True
    assert "code object is not signed at all" in run.stderr, run.stderr
    return False


class Workspace:
    """A throwaway directory to copy the fixture into."""

    def __init__(self, root: Path, hello: Path, dylib: Path) -> None:
        self.root = root
        self._hello = hello
        self._dylib = dylib

    def adhoc_signed(self, name: str) -> Path:
        """A copy of the fixture carrying a fresh ad hoc signature."""
        path = self.root / name
        shutil.copyfile(self._hello, path)
        path.chmod(0o755)
        run = codesign("--sign", "-", "--force", path)
        assert run.returncode == 0, run.stderr
        return path

    def plain_dir(self, name: str) -> Path:
        """A plain directory, which `codesign --remove-signature` exits 1 on."""
        path = self.root / name
        path.mkdir()
        return path

    def join(self, name: str) -> Path:
        return self.root / name

    def unsigned(self, name: str) -> Path:
        """A copy of the fixture carrying no signature at all (the linker's is stripped)."""
        return self._unsigned_copy_of(self._hello, name)

    def unsigned_dylib(self, name: str) -> Path:
        """An unsigned copy of the fixture built as a dynamic library."""
        return self._unsigned_copy_of(self._dylib, name)

    def presigned(self, name: str, *args: str | os.PathLike[str]) -> Path:
        """An unsigned copy signed ad hoc by the real `codesign` with extra `args`."""
        path = self.unsigned(name)
        run = codesign("--sign", "-", *args, path)
        assert run.returncode == 0, run.stderr
        return path

    def app_bundle(self, name: str) -> Path:
        """A minimal unsigned `<name>.app` declaring `com.example.<name>`."""
        bundle = self.root / f"{name}.app"
        (bundle / "Contents/MacOS").mkdir(parents=True)
        shutil.copyfile(self._hello, bundle / "Contents/MacOS" / name)
        (bundle / "Contents/Info.plist").write_text(
            _INFO_PLIST.format(name=name).replace("FMWK", "APPL")
        )
        return bundle

    def framework(self, name: str, versions: tuple[str, ...] = ("A",)) -> Path:
        """An unsigned `<name>.framework` with each of `versions`; `Current` points at the first."""
        bundle = self.root / f"{name}.framework"
        for version in versions:
            resources = bundle / "Versions" / version / "Resources"
            resources.mkdir(parents=True)
            shutil.copyfile(self._hello, resources.parent / name)
            (resources / "Info.plist").write_text(_INFO_PLIST.format(name=name))
        (bundle / "Versions" / "Current").symlink_to(versions[0])
        (bundle / name).symlink_to(f"Versions/Current/{name}")
        (bundle / "Resources").symlink_to("Versions/Current/Resources")
        return bundle

    def versioned_framework(self, name: str, versions: tuple[str, ...]) -> Path:
        """`<name>.framework` with each of `versions` ad hoc signed; `Current` points at the first."""
        bundle = self.framework(name, versions)
        for version in versions:
            run = codesign("--sign", "-", "--bundle-version", version, bundle)
            assert run.returncode == 0, run.stderr
        return bundle

    def _unsigned_copy_of(self, source: Path, name: str) -> Path:
        path = self.root / name
        shutil.copyfile(source, path)
        path.chmod(0o755)
        run = codesign("--remove-signature", path)
        assert run.returncode == 0, run.stderr
        return path


class Signature:
    """The `codesign -dvvvv` report of a signed path, read through the real `codesign`."""

    def __init__(self, path: Path, *extra: str) -> None:
        run = codesign("-dvvvv", *extra, path)
        assert run.returncode == 0, run.stderr
        self.raw = run.stderr.strip()

    def field(self, key: str) -> str | None:
        """The value of the first `key=value` line, e.g. `Identifier` or `Page size`."""
        for line in self.raw.splitlines():
            name, sep, value = line.partition("=")
            if sep and name == key:
                return value
        return None

    @property
    def identifier(self) -> str | None:
        return self.field("Identifier")

    @property
    def authority(self) -> str | None:
        return self.field("Authority")

    @property
    def timestamp(self) -> str | None:
        return self.field("Timestamp")

    @property
    def runtime_version(self) -> str | None:
        return self.field("Runtime Version")

    @property
    def page_size(self) -> int | None:
        size = self.field("Page size")
        assert size is not None, self.raw
        return None if size == "none" else int(size)

    def has_constraint(self, kind: str) -> bool:
        """Whether the report lists `Has <kind> Constraints` (`Self`, `Parent`, `Responsible`, `Library Load`)."""
        return f"Has {kind} Constraints" in (line.strip() for line in self.raw.splitlines())

    @property
    def flags(self) -> int:
        """The CodeDirectory flags, from `flags=0x10002(adhoc,runtime)`."""
        directory = next(l for l in self.raw.splitlines() if l.startswith("CodeDirectory "))
        token = next(t for t in directory.split() if t.startswith("flags="))
        return int(token.removeprefix("flags=").split("(")[0], 16)

    @property
    def flag_names(self) -> list[str]:
        directory = next(l for l in self.raw.splitlines() if l.startswith("CodeDirectory "))
        token = next(t for t in directory.split() if t.startswith("flags="))
        names = token.partition("(")[2].partition(")")[0]
        return [n for n in names.split(",") if n and n != "none"]


def assert_valid(path: Path) -> None:
    """Asserts `codesign --verify --strict --deep` accepts `path`."""
    run = codesign("--verify", "--strict", "--deep", "-vvv", path)
    assert run.returncode == 0, f"{path} carries no valid signature: {run.stderr.strip()}"


def entitlements(path: Path) -> str:
    """The entitlements embedded in `path` as XML, empty when there are none."""
    run = codesign("-d", "--entitlements", "-", "--xml", path)
    assert run.returncode == 0, run.stderr
    return run.stdout


def designated_requirement(path: Path) -> str:
    run = codesign("-d", "-r-", path)
    assert run.returncode == 0, run.stderr
    return run.stdout.strip()


def output_of(path: Path) -> str:
    """Runs the signed executable: proof that signing left a working binary."""
    run = subprocess.run([path], capture_output=True, text=True, check=True)
    return run.stdout.strip()


def fixture(name: str) -> Path:
    """A file of `tests/fixtures/`."""
    return REPO / "tests/fixtures" / name


def pytest_configure(config: pytest.Config) -> None:
    for group in _GROUPS:
        config.addinivalue_line("markers", f"{group}: needs the test group `{group}`")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skips the tests of a group not named in `SIGNERS_TEST_GROUPS` (comma separated).

    `SIGNERS_TEST_GROUPS=keychain,network uv run pytest` runs them all.
    """
    enabled = {g.strip() for g in os.environ.get("SIGNERS_TEST_GROUPS", "").split(",")}
    for item in items:
        needed = [g for g in _GROUPS if item.get_closest_marker(g)]
        if not all(g in enabled for g in needed):
            item.add_marker(pytest.mark.skip(reason=f"test groups: {', '.join(needed)}"))


class Identity:
    """A throwaway self-signed code-signing identity in a keychain of its own.

    The keychain is off the search list, so `codesign` only finds the identity through
    `keychain=`; the user's keychain is never touched.
    """

    _PASSWORD = "signers"
    _counter = itertools.count()

    def __init__(self, directory: Path) -> None:
        self.name = f"signers-test-{os.getpid()}-{next(self._counter)}"
        self.keychain = directory / "signers-test.keychain-db"
        config = directory / "cert.cnf"
        config.write_text(
            f"[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
            f"[dn]\nCN = {self.name}\n"
            "[ext]\nbasicConstraints = critical, CA:false\n"
            "keyUsage = critical, digitalSignature\n"
            "extendedKeyUsage = critical, codeSigning\n"
        )
        key, cert, p12 = directory / "key.pem", directory / "cert.pem", directory / "identity.p12"
        self._run("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                  "-config", config, "-keyout", key, "-out", cert)
        self._run("/usr/bin/openssl", "pkcs12", "-export", "-passout", f"pass:{self._PASSWORD}",
                  "-inkey", key, "-in", cert, "-out", p12)
        self._run("security", "create-keychain", "-p", self._PASSWORD, self.keychain)
        self._run("security", "unlock-keychain", "-p", self._PASSWORD, self.keychain)
        self._run("security", "set-keychain-settings", self.keychain)
        self._run("security", "import", p12, "-k", self.keychain, "-P", self._PASSWORD,
                  "-T", CODESIGN)
        self._run("security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
                  "-s", "-k", self._PASSWORD, self.keychain)

    def delete(self) -> None:
        subprocess.run(["security", "delete-keychain", self.keychain], capture_output=True)

    @staticmethod
    def _run(*args: str | os.PathLike[str]) -> None:
        run = subprocess.run(args, capture_output=True, text=True)
        assert run.returncode == 0, f"could not set up an identity ({args}): {run.stderr.strip()}"


@pytest.fixture(scope="session")
def hello(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """`tests/fixtures/hello.c` compiled once per session for the host architecture."""
    out = tmp_path_factory.mktemp("fixtures") / "hello"
    subprocess.run(["cc", "-o", out, REPO / "tests/fixtures/hello.c"], check=True)
    return out


@pytest.fixture(scope="session")
def hello_dylib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The same source built as a dynamic library."""
    out = tmp_path_factory.mktemp("fixtures-dylib") / "hello.dylib"
    subprocess.run(["cc", "-dynamiclib", "-o", out, REPO / "tests/fixtures/hello.c"], check=True)
    return out


@pytest.fixture
def workspace(tmp_path: Path, hello: Path, hello_dylib: Path) -> Workspace:
    return Workspace(tmp_path, hello, hello_dylib)


@pytest.fixture
def identity(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Identity]:
    """A fresh `Identity`, deleted afterwards. Only tests of the `keychain` group use it."""
    created = Identity(tmp_path_factory.mktemp("identity"))
    try:
        yield created
    finally:
        created.delete()
