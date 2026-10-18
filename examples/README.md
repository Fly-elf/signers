# Examples

Complete programs that show the API, in Rust and in Python. Edit the paths and identities in them before
running: they are placeholders.

## codesign

| Use case | Rust | Python |
|---|---|---|
| Re-sign a patched binary, keeping its identifier and entitlements | [`resign_patched.rs`](rust/codesign/resign_patched.rs) (blocking: `display`, `verify`, `sign_adhoc`, `preserve_metadata`) | [`resign_patched.py`](python/codesign/resign_patched.py) (sync) |
| Triage binaries and bundles: signer, entitlements, requirements, verdict | [`inspect.rs`](rust/codesign/inspect.rs) (async: `display`, `requirements`, `verify`, `extract_certificates`) | [`inspect_targets.py`](python/codesign/inspect_targets.py) (asyncio) |
| Sign an app bundle in a build step, nested code first | [`sign_bundle.rs`](rust/codesign/sign_bundle.rs) (blocking: `sign`, `entitlements`, `options`, `timestamp`, `verify`) | [`sign_bundle.py`](python/codesign/sign_bundle.py) (sync) |
| Sign an app for distribution with a Developer ID | [`sign_for_distribution.rs`](rust/codesign/sign_for_distribution.rs) (async: `sign_for_distribution`, `verify`, `test_requirement`, `display`) | [`sign_for_distribution.py`](python/codesign/sign_for_distribution.py) (asyncio) |

How to run them: [Rust](rust/README.md), [Python](python/README.md). The Python twin of `inspect.rs` is not
named `inspect.py`, which would shadow the standard library module of that name when run as a script.

### Getting a signing identity

Ad hoc signing (`"-"`) needs no identity and is enough to run code on your own Mac. For a real one:

- List the identities in your keychains with `security find-identity -v -p codesigning`.
- A free "Apple Development" certificate comes from Xcode, in Settings > Accounts > Manage Certificates.
- A self-signed code-signing certificate comes from Keychain Access, in Certificate Assistant > Create a
  Certificate. It is good for local use only.
- A "Developer ID Application" certificate, which distribution outside the Mac App Store needs, comes with
  the paid Apple Developer Program.
