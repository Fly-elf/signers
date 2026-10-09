"""Fixtures shared by the Python tests: a compiled Mach-O and the real `codesign`.

Every check goes through `/usr/bin/codesign` itself, never through `signers`.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CODESIGN = "/usr/bin/codesign"

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

    def __init__(self, root: Path, hello: Path) -> None:
        self.root = root
        self._hello = hello

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

    def versioned_framework(self, name: str, versions: tuple[str, ...]) -> Path:
        """`<name>.framework` with each of `versions` ad hoc signed; `Current` points at the first."""
        bundle = self.root / f"{name}.framework"
        for version in versions:
            resources = bundle / "Versions" / version / "Resources"
            resources.mkdir(parents=True)
            shutil.copyfile(self._hello, resources.parent / name)
            (resources / "Info.plist").write_text(_INFO_PLIST.format(name=name))
        (bundle / "Versions" / "Current").symlink_to(versions[0])
        (bundle / name).symlink_to(f"Versions/Current/{name}")
        (bundle / "Resources").symlink_to("Versions/Current/Resources")
        for version in versions:
            run = codesign("--sign", "-", "--bundle-version", version, bundle)
            assert run.returncode == 0, run.stderr
        return bundle


@pytest.fixture(scope="session")
def hello(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """`tests/fixtures/hello.c` compiled once per session for the host architecture."""
    out = tmp_path_factory.mktemp("fixtures") / "hello"
    subprocess.run(["cc", "-o", out, REPO / "tests/fixtures/hello.c"], check=True)
    return out


@pytest.fixture
def workspace(tmp_path: Path, hello: Path) -> Workspace:
    return Workspace(tmp_path, hello)
