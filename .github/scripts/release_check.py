"""Checks that the repository is ready to release its workspace version.

Usage: python3 .github/scripts/release_check.py [--tag vX.Y.Z] [--notes-out FILE]

Run from the repository root. Prints every problem found and exits 1, or exits 0
silently. `--tag` also checks the tag and that its commit is on `origin/main`.
`--notes-out` writes the version's CHANGELOG section, the release notes, to FILE.
"""

import argparse
import datetime
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_URL = "https://github.com/Fly-elf/signers"
PINNED_LINK = re.compile(
    r"github\.com/Fly-elf/signers/(?:tree|blob)/v"
    r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)/"
)
LINK_REFERENCE = re.compile(r"^\[[^\]]+\]:\s")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag")
    parser.add_argument("--notes-out", type=Path)
    args = parser.parse_args()

    try:
        with open("Cargo.toml", "rb") as f:
            version = tomllib.load(f)["workspace"]["package"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError) as e:
        print(f"Cargo.toml: no [workspace.package] version ({e!r})", file=sys.stderr)
        return 1

    failures: list[str] = []
    if args.tag is not None:
        failures += check_tag(args.tag, version)
    notes, changelog_failures = check_changelog(version)
    failures += changelog_failures
    failures += check_pinned_links(version)
    if args.notes_out is not None:
        if notes:
            args.notes_out.write_text(notes + "\n", encoding="utf-8")
        elif notes is not None:
            failures.append(f"CHANGELOG.md: the section of {version} is empty")

    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


def check_tag(tag: str, version: str) -> list[str]:
    failures: list[str] = []
    if tag != f"v{version}":
        failures.append(f"tag {tag} does not match the workspace version {version} (expected v{version})")
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"],
        capture_output=True,
        text=True,
    )
    if ancestry.returncode == 1:
        failures.append(f"tag {tag}: its commit is not on origin/main")
    elif ancestry.returncode != 0:
        failures.append(f"tag {tag}: cannot check it against origin/main: {ancestry.stderr.strip()}")
    return failures


def check_changelog(version: str) -> tuple[str | None, list[str]]:
    try:
        lines = Path("CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return None, [f"CHANGELOG.md: cannot read it ({e.strerror})"]

    failures: list[str] = []
    reference = f"[{version}]: {REPO_URL}/releases/tag/v{version}"
    if not any(line.strip() == reference for line in lines):
        failures.append(f"CHANGELOG.md: missing the link reference `{reference}`")

    heading = re.compile(rf"^## \[{re.escape(version)}\] - (.*?)\s*$")
    found = next(((i, m) for i, line in enumerate(lines) if (m := heading.match(line))), None)
    if found is None:
        failures.append(f"CHANGELOG.md: missing the heading `## [{version}] - YYYY-MM-DD`")
        return None, failures
    start, date = found[0], found[1].group(1)
    if not is_iso_date(date):
        failures.append(f"CHANGELOG.md:{start + 1}: `{date}` is not a YYYY-MM-DD date")

    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    body = [line for line in lines[start + 1 : end] if not LINK_REFERENCE.match(line)]
    return "\n".join(body).strip(), failures


def is_iso_date(text: str) -> bool:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return False
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def check_pinned_links(version: str) -> list[str]:
    files = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    failures: list[str] = []
    for name in files.decode().split("\0"):
        if not name or name == "CHANGELOG.md":
            continue
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for match in PINNED_LINK.finditer(line):
                if match.group(1) != version:
                    failures.append(f"{name}:{number}: link pinned to v{match.group(1)}, expected v{version}")
    return failures


if __name__ == "__main__":
    sys.exit(main())
