# signers

Sign, re-sign, strip, verify and inspect code signatures on macOS, from async or blocking Rust, or from Python.

`signers` runs Apple's `codesign` tool. Each action is a function that returns a typed builder, which
offers only the options `codesign` honours for that action. Nothing runs until you `.await` it, or call
`.run()` in the blocking API. The target decides the result: one path gives one value, a `Vec` or slice gives a `Vec`, an array
gives an array.

```rust
use signers::codesign;

// Re-sign a binary after patching it: `force` replaces the signature the patch broke.
codesign::sign_adhoc("patched.dylib").force(true).await?;

// Sign an app for notarization: hardened runtime and a secure timestamp.
codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    .entitlements("MyApp.entitlements")
    .await?;

// Remove signatures, several targets in one run.
codesign::remove_signature(vec!["mytool", "libfoo.dylib"]).await?;
```

Read signatures back:

```rust
use signers::{CodesignError, Error, codesign};

// Verify, optionally against a requirement.
match codesign::verify("mytool").deep(true).test_requirement("anchor apple").await {
    Ok(()) => println!("signed by Apple"),
    Err(Error::Codesign(CodesignError::RequirementUnsatisfied { .. })) => println!("not by Apple"),
    Err(error) => return Err(error),
}

// Read the signature: one `Signature` per target, a fixed-size array for an array.
let [ls, cat] = codesign::display(["/bin/ls", "/bin/cat"]).await?;
println!("{} {}", ls.cd_hash, cat.cd_hash);

// Embedded requirements.
for requirement in codesign::requirements("MyApp.app").await? {
    println!("{:?}: {}", requirement.kind, requirement.expression);
}

// Certificate chains, leaf first; `save_to` also writes them as PEM files.
let chains = codesign::extract_certificates(vec!["A.app", "B.app"]).save_to("certs").await?;

// Check launch and library constraint plists.
codesign::validate_constraint("launch-constraint.plist").await?;
```

## Several targets

Given a `Vec`, slice or array, `.per_target(true)` runs one `codesign` per target, concurrently. Every
target runs, and the failures come together in `Error::Batch`:

```rust
match codesign::verify(vec!["a.app", "b.app"]).per_target(true).await {
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

With the `blocking` feature, `signers::codesign::blocking` has the same functions and options, makes
the same checks, returns the same errors and result shapes, and `.run()` takes the place of `.await`:

```rust
use signers::codesign::blocking;

blocking::sign_adhoc("patched.dylib").force(true).run()?;
let [ls, cat] = blocking::display(["/bin/ls", "/bin/cat"]).run()?;
```

Each `.run()` builds a single-threaded Tokio runtime for the call and drops it before returning, so the
caller needs none, and `per_target` still runs concurrently. Calling `.run()` inside a Tokio runtime
panics: async code uses the functions of `signers::codesign`.

## Python

The same actions are available from Python, with options as keyword arguments:

```python
from signers import codesign

# Re-sign after patching, then seal the hardened runtime into an app's signature.
codesign.sign_adhoc("patched.dylib", force=True)
codesign.sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)",
              options=codesign.SigningFlags.RUNTIME)

# One path gives one value, a sequence gives a list, even with a single element.
signature = codesign.display("/bin/ls")
signatures = codesign.display(["/bin/ls", "/bin/cat"])

try:
    codesign.verify(["a.app", "b.app"], deep=True)
except codesign.BatchError as error:
    for path, failure in error.failures:
        print(f"{path}: {failure}")
```

Actions that sign, remove or check return `None`; `per_target` is ignored for a single path. Calls
block until `codesign` finishes (there is no async API in Python), and the package is typed, so
options and results complete in the IDE and show up in `help()`.

## Requirements

- macOS, which ships `codesign`.
- For the async API, a Tokio runtime with I/O enabled, such as `#[tokio::main]`.
- For the Python bindings, Python 3.11 or later.

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

For Python, install from the Git repository. It builds from source, so it needs a Rust toolchain
(`cargo`); it is not on PyPI yet:

```sh
pip install git+https://github.com/Fly-elf/signers
```

## Status

Early development: the API may still change.

- [x] `codesign` backend, async: `sign`, `remove_signature`, `verify`, `display`,
      `requirements`, `extract_certificates`, `validate_constraint`
- [x] `codesign` backend, blocking: the same actions, behind the `blocking` feature
- [ ] `rcodesign` backend: native, through the [`apple-codesign`](https://crates.io/crates/apple-codesign)
      crate, on any OS
- [x] Python bindings: `codesign` backend, sync

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
