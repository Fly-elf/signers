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
  and `security`. The keychain stays off the search list and is deleted afterwards; your keychains are not
  touched.
- `network`: reaches Apple's timestamp server.
- `macos27`: needs the `codesign` of macOS 27 or later (`--signature-slot`, total and chosen signature lines).

Changing `RUSTFLAGS` rebuilds all dependencies.

For Python:

```sh
uv run pytest
uv run pyright
```

`pytest` covers the bridge between Python and Rust; the library's behaviour is tested in Rust. `pyright`
checks the types.

## Pull requests

Pull requests are welcome. Before opening one, run `cargo fmt`, make sure
`cargo clippy --all-targets --all-features -- -D warnings` is clean, and check that the tests pass.

## License

`signers` is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by
you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or
conditions.
