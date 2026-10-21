"""Turns the inputs of the test workflows into the runner and the test group flags.

Usage: python3 .github/scripts/test_plan.py --macos 27 --keychain true [--network true]

Prints `key=value` lines, the format of `$GITHUB_OUTPUT`: `runner`, `rustflags`,
`rustflags_network` (the same plus the `network` group when `--network` is true) and
`pytest_groups` (comma separated, as `SIGNERS_TEST_GROUPS` expects).
Exits 1 on a macOS version without a runner.
"""

import argparse
import sys

RUNNERS = {26: "macos-26", 27: "xcode-27"}
# A group is on from the macOS version in its key onwards.
VERSION_GROUPS = {27: "macos27"}
BOOLEANS = ("true", "false")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--macos", required=True)
    parser.add_argument("--keychain", required=True, choices=BOOLEANS)
    parser.add_argument("--network", default="false", choices=BOOLEANS)
    args = parser.parse_args()

    versions = {str(version): version for version in RUNNERS}
    version = versions.get(args.macos)
    if version is None:
        valid = ", ".join(versions)
        print(f"unsupported macOS version {args.macos!r}, expected one of: {valid}", file=sys.stderr)
        return 1

    groups = ["keychain"] if args.keychain == "true" else []
    groups += [group for since, group in sorted(VERSION_GROUPS.items()) if version >= since]
    network_groups = groups + ["network"] if args.network == "true" else groups

    print(f"runner={RUNNERS[version]}")
    print(f"rustflags={rustflags(groups)}")
    print(f"rustflags_network={rustflags(network_groups)}")
    print(f"pytest_groups={','.join(groups)}")
    return 0


def rustflags(groups: list[str]) -> str:
    return " ".join(f'--cfg signers_test="{group}"' for group in groups)


if __name__ == "__main__":
    sys.exit(main())
