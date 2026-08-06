# signers

Manage macOS binary code-signing with a simple Rust API.
- `async` first, with an optional `blocking` API
- Multiplatform with no external dependency, via `rcodesign`
- Python API

Built on top of two backends:

|                | `codesign`                     | `rcodesign`                                                              |
|----------------|--------------------------------|--------------------------------------------------------------------------|
| Platforms      | macOS only                     | macOS, Linux, Windows                                                    |
| Requires       | Xcode Command Line Tools       | nothing extra                                                            |
| Implementation | subprocess — the macOS [`codesign`](https://keith.github.io/xcode-man-pages/codesign.1.html) binary | native — the [`apple-codesign`](https://crates.io/crates/apple-codesign) crate |

> 🚧 **Early development.** Signing and removing signatures work on the `codesign` backend;
> everything else is still on the way. See [Status](#status).

## Installation

Not yet published on crates.io.

## Usage

Both backends expose a set of actions (`sign`, `verify`, ...), each configurable through its own
builder options. Every action needs at least one target (see `IntoTargets`) and only runs once
you `.await` it.

### Codesign
Wraps the macOS `codesign` utility one-to-one — if you know how to use it, you already know what
a builder will do. The API has the same default options as the utility.

```rust
// Ad-hoc signature, replacing whatever was there before.
Codesign::sign(vec!["MyApp.app", "MyLib.dylib"], "-")
    .force(true)
    .await?;

// Signing for distribution
Codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    .entitlements("MyApp.entitlements")
    .options(SigningFlags::RUNTIME) // the hardened runtime, needed to notarize
    .timestamp(Timestamp::Enabled)
    .force(true)
    .await?;

// Stripping a signature, e.g. before patching the Mach-O it no longer matches.
// Re-signing needs no removal first: `sign` with `force` replaces in one step.
Codesign::remove_signature("MyApp.app").await?;
```

### Rcodesign
Exposes the `apple-codesign` crate with an API in the same style as `codesign`'s, easier to use
than the crate on its own.

*(Examples once the backend is implemented — see [Status](#status).)*

## Status
The project is in early development, so most of the features don't work yet.
- [x] `codesign` async API — signing, removing signatures
- [ ] `codesign` async API — verifying
- [ ] `codesign` blocking API
- [ ] `rcodesign` blocking API
- [ ] `rcodesign` async API
- [ ] Python bindings

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.