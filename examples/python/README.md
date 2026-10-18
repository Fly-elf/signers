# Python examples

Install the package first, either from GitHub (needs `cargo`, it builds from source):

```sh
pip install git+https://github.com/Fly-elf/signers
```

or from a checkout of the repository:

```sh
uv run maturin develop
```

Then run an example:

```sh
python examples/python/codesign/resign_patched.py
```

The examples are placeholders that show the API, so edit their paths and identities first. See the
[index](../README.md) for what each one does.

## Sync and asyncio

Each example uses the synchronous API or the asyncio one, whichever reads better for its job. They have the
same signatures: the asyncio ones live in `signers.codesign.aio` and are awaited.

```python
codesign.sign_adhoc("a", force=True)            # sync
await codesign.aio.sign_adhoc("a", force=True)  # asyncio
```
