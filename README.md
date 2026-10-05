# signers

Sign, re-sign, strip, verify and inspect code signatures on macOS, from async or blocking Rust.

`signers` runs Apple's `codesign` tool through a typed builder. Each action offers only the options
`codesign` honours for it, and nothing runs until you `.await` it, or call `.run()` in the blocking
API. The target decides the result: one path gives one value, a `Vec` or slice gives a `Vec`, an array
gives an array.

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

Read signatures back:

```rust
use signers::{Codesign, CodesignError, Error};

// Verify, optionally against a requirement.
match Codesign::verify("mytool").deep(true).test_requirement("anchor apple").await {
    Ok(()) => println!("signed by Apple"),
    Err(Error::Codesign(CodesignError::RequirementUnsatisfied { .. })) => println!("not by Apple"),
    Err(error) => return Err(error),
}

// Read the signature: one `Signature` per target, a fixed-size array for an array.
let [ls, cat] = Codesign::display(["/bin/ls", "/bin/cat"]).await?;
println!("{} {}", ls.cd_hash, cat.cd_hash);

// Embedded requirements.
for requirement in Codesign::internal_requirements("MyApp.app").await? {
    println!("{:?}: {}", requirement.kind, requirement.expression);
}

// Certificate chains, leaf first; `save_to` also writes them as PEM files.
let chains = Codesign::extract_certificates(vec!["A.app", "B.app"]).save_to("certs").await?;

// Check launch and library constraint plists.
Codesign::validate_constraint("launch-constraint.plist").await?;
```

## Several targets

Given a `Vec`, slice or array, `.per_target(true)` runs one `codesign` per target, concurrently. Every
target runs, and the failures come together in `Error::Batch`:

```rust
match Codesign::verify(vec!["a.app", "b.app"]).per_target(true).await {
    Ok(_) => {}
    Err(Error::Batch(failures)) => {
        for (path, error) in &failures {
            eprintln!("{}: {error}", path.display());
        }
    }
    Err(error) => return Err(error),
}
```

Reading actions default to per target. `sign` and `remove_signature` default to one run for all targets.

## Blocking API

With the `blocking` feature, `signers::blocking::Codesign` has the same actions and options, makes the
same checks, returns the same errors and result shapes, and `.run()` takes the place of `.await`:

```rust
use signers::blocking::Codesign;

Codesign::sign_adhoc("patched.dylib").force(true).run()?;
let [ls, cat] = Codesign::display(["/bin/ls", "/bin/cat"]).run()?;
```

Each `.run()` builds a single-threaded Tokio runtime for the call and drops it before returning, so the
caller needs none, and `per_target` still runs concurrently. Calling `.run()` inside a Tokio runtime
panics: async code uses `signers::Codesign`.

## Requirements

- macOS, which ships `codesign`.
- For the async API, a Tokio runtime with I/O enabled, such as `#[tokio::main]`.

## Installation

Not published on crates.io yet. Until then, depend on the Git repository. The async API is the
default `async` feature:

```toml
[dependencies]
signers = { git = "https://github.com/Fly-elf/signers" }
```

The `blocking` feature adds the blocking API, alongside the async one, and Tokio's `rt`:

```toml
[dependencies]
signers = { git = "https://github.com/Fly-elf/signers", features = ["blocking"] }
```

## Status

Early development: the API may still change.

- [x] `codesign` backend, async: `sign`, `remove_signature`, `verify`, `display`,
      `internal_requirements`, `extract_certificates`, `validate_constraint`
- [x] `codesign` backend, blocking: the same actions, behind the `blocking` feature
- [ ] `rcodesign` backend: native, through the [`apple-codesign`](https://crates.io/crates/apple-codesign)
      crate, on any OS
- [ ] Python bindings

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
