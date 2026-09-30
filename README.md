# signers

Sign, re-sign and strip code signatures on macOS, from async Rust.

`signers` runs Apple's `codesign` tool through a typed builder. Each action offers only the options
`codesign` honours for it, and nothing runs until you `.await` it.

```rust
use signers::Codesign;

// Re-sign a binary after patching it: `force` replaces the signature the patch broke.
Codesign::sign_adhoc("patched.dylib").force(true).await?;

// Sign an app for notarization: hardened runtime and a secure timestamp.
Codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    .entitlements("MyApp.entitlements")
    .await?;

// Remove signatures, several targets in one run.
Codesign::remove_signature(vec!["mytool", "libfoo.dylib"]).await?;
```

## Requirements

- macOS, which ships `codesign`.
- A Tokio runtime with I/O enabled, such as `#[tokio::main]`.

## Installation

Not published on crates.io yet.

## Status

Early development: the API may still change.

- [x] `codesign` backend, async: `sign`, `remove_signature`
- [ ] `codesign` backend, async: `verify`, then `display` and the other operations
- [ ] Blocking API
- [ ] `rcodesign` backend: native, through the [`apple-codesign`](https://crates.io/crates/apple-codesign)
      crate, on any OS
- [ ] Python bindings

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
