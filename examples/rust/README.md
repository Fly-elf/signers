# Rust examples

Run one from the root of the repository:

```sh
cargo run --example codesign_resign_patched
```

The name is `codesign_` followed by the file's name in [`codesign/`](codesign). The examples are placeholders
that show the API, so edit their paths and identities first. See the [index](../README.md) for what each one
does.

## Async and blocking

Each example uses the async API or the blocking one, whichever reads better for its job. They are the same
functions: the blocking ones live in `codesign::blocking` and end with `.run()` instead of `.await`. The
blocking API needs the `blocking` feature, which the examples already build with.

```rust
codesign::sign_adhoc("a").force(true).await?;           // async
codesign::blocking::sign_adhoc("a").force(true).run()?; // blocking
```
