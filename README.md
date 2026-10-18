# signers

[![crates.io](https://img.shields.io/crates/v/signers.svg)](https://crates.io/crates/signers) [![docs.rs](https://img.shields.io/docsrs/signers)](https://docs.rs/signers) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Fly-elf/signers)

`signers` is a typed front-end for code signing tools, usable from async or blocking Rust and from Python.
It runs the real tool and gives each of its operations a small API that only accepts the options that
operation honours. It is meant for scripting and automating signing: re-signing binaries after patching
them, or signing as a step of build tooling.

Supported tools: `codesign` (macOS). Planned: `productsign`, and `pkgutil` for checking signatures.

```rust
use signers::codesign;

// Re-sign a binary after patching it: `force` replaces the signature the patch broke.
codesign::sign_adhoc("patched.dylib").force(true).await?;
```

Complete examples for Rust (async and blocking) and Python (sync and asyncio) are in
[`examples/`](https://github.com/Fly-elf/signers/tree/v0.1.0/examples).

## Installation

`signers` runs on macOS only.

Rust: the async API comes with the default `async` feature.

```sh
cargo add signers
```

The `blocking` feature adds `signers::codesign::blocking`, alongside the async API.

```sh
cargo add signers --features blocking
```

Python: 3.11 or later.

```sh
pip install signers
```

To build from a checkout, see [CONTRIBUTING.md](https://github.com/Fly-elf/signers/blob/main/CONTRIBUTING.md).
