# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added

- `codesign` module (macOS), wrapping `codesign`, looked up on `PATH`: `sign`, `sign_adhoc`,
  `sign_for_distribution`, `verify`, `display`, `requirements`, `extract_certificates`, `remove_signature`,
  `validate_constraint`.
- Targets as one path, a `Vec`/slice or an array; `per_target` runs one `codesign` per target, concurrently.
- Async API (default `async` feature, Tokio) and a blocking mirror in `codesign::blocking` (`blocking` feature).
- `tracing` events for each run.
- Python package `signers` (Python 3.11+): typed sync API in `signers.codesign`, asyncio in
  `signers.codesign.aio`, Rust log events forwarded to `logging`.

[Unreleased]: https://github.com/Fly-elf/signers/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Fly-elf/signers/releases/tag/v0.1.0
