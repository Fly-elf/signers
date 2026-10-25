# Contributing to signers

## How the crate is shaped

Each signing tool has one public module, named after the tool, that maps it fairly faithfully. Its actions
and their options come from the tool's own operations and flags, each action offers only the flags its
operation honours, and every action runs the real executable. Nothing in the API is shared across tools, and
tools are not interchangeable. A new tool is a new module in the same style.

## Requirements

- macOS.
- The latest stable Rust.
- The Xcode Command Line Tools, for the integration tests: they build their fixtures with `cc`. The library
  itself needs only `/usr/bin/codesign`.
- [`uv`](https://docs.astral.sh/uv/), for the Python package.

## Building from source

```sh
cargo build --all-features
```

For Python, build the extension into the project's virtual environment, development tools included:

```sh
uv run maturin develop
```

## Running the tests

```sh
cargo test
```

This runs the unit and integration tests. The integration tests sign real files and check the result with
the real `codesign`.

Tests that need more than a plain macOS belong to opt-in groups. They are ignored by default, and listed as
`ignored, test group: …`. Enable them with the `signers_test` cfg:

```sh
RUSTFLAGS='--cfg signers_test="keychain" --cfg signers_test="network"' cargo test
```

To run one group, pass only its `--cfg`.

- `keychain`: creates a throwaway self-signed identity in a temporary keychain, using the system `openssl`
  and `security`. On macOS 27 the keychain stays off the search list; on macOS 26 `codesign` needs it there,
  so it is added for the identity's lifetime and removed afterwards. The keychain is deleted at the end and
  your own keychains are not touched.
- `network`: reaches Apple's timestamp server.
- `macos27`: needs the `codesign` of macOS 27 or later (`--signature-slot`, total and chosen signature lines,
  the exclusive `--keychain` lookup). Groups of a newer macOS are named `macosNN`.

Changing `RUSTFLAGS` rebuilds all dependencies.

For Python:

```sh
uv run pytest
uv run pyright
```

`pytest` covers the bridge between Python and Rust; the library's behaviour is tested in Rust. `pyright`
checks the types. The Python test groups are enabled with `SIGNERS_TEST_GROUPS`, for example
`SIGNERS_TEST_GROUPS=keychain,macos27 uv run pytest`.

## Workflows

- `ci.yml`: on pushes to `main` and `dev` and on pull requests. Runs fmt, clippy, the MSRV build, docs, the
  Rust tests and the Python tests, all on macOS 27.
- `tests.yml` and `python.yml`: the Rust and the Python test suites. `ci.yml` and `release.yml` call them,
  and you can run them by hand with a macOS version (27 or 26) and the test groups to enable (`keychain`;
  `network` and `network-required` for Rust). macOS 26 is the check against the previous macOS and never
  runs on a push. The runner labels are `xcode-27` for macOS 27 and `macos-26` for macOS 26.
- `release.yml`: on `v*` tags. Runs the tests, builds the wheels and the source distribution, then publishes.

To run a suite by hand, for example on macOS 26 (manual runs may work only once the workflow is on the
default branch):

```sh
gh workflow run tests.yml -f macos=26
```

## Pull requests

Pull requests are welcome. Before opening one, run `cargo fmt`, make sure
`cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean, and check that the tests pass.

## License

`signers` is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by
you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or
conditions.
