# signers

Simple, ergonomic Rust bindings for macOS code signing.

`signers` wraps macOS binary code-signing behind a single, hard-to-misuse API, with two
interchangeable backends:

- **`codesign`** — the macOS `codesign` CLI, via subprocess.
- **`rcodesign`** — the [`apple-codesign`](https://crates.io/crates/apple-codesign) crate, used
  natively. No external binary, no Xcode Command Line Tools required, works cross-platform.

Pick whichever backend fits your environment — both expose the same API.

> 🚧 **Early development.** The usage example below reflects the intended API design; nothing
> is implemented yet. See [Status](#status) for where things currently stand.

## Why

Built for scripting and automating code signing — e.g. re-signing binaries after patching them
in reverse-engineering or build-tooling workflows — without hand-rolling subprocess calls or
learning the two underlying tools' CLIs.

## Usage (planned API)

```rust
use signers::codesign::Codesign;

Codesign::sign("MyApp.app")
    .force(true)
    .deep(true)
    .identity("-")
    .await?;

let status = Codesign::verify("MyApp.app").await?;
```

The API is primarily async. An optional blocking variant will be available under `blocking` submodules

## Backends

|                | `codesign`                    | `rcodesign`                     |
|----------------|--------------------------------|----------------------------------|
| Implementation | subprocess (macOS `codesign`) | native (`apple-codesign` crate)  |
| Platforms      | macOS only                    | macOS, Linux, Windows            |
| Requires       | Xcode Command Line Tools      | nothing extra                    |

Both backends are always available — no feature flag needed to choose between them.

## Installation

Not yet published on crates.io.

## Status

Early development, built one feature at a time:

- [x] Project setup
- [ ] `codesign` async API
- [ ] `codesign` blocking API
- [ ] `rcodesign` blocking API
- [ ] `rcodesign` async API
- [ ] Python bindings

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.