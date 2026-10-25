"""Backend that runs Apple's `codesign` tool, so it works on macOS only.

Each action is a function that takes the targets, then its options as keyword-only
arguments. `codesign` ships with macOS in `/usr/bin` and is looked up on `PATH` each
time an action runs.

```python
from signers import codesign

codesign.sign_adhoc("patched.dylib", force=True)
ls, cat = codesign.display(["/bin/ls", "/bin/cat"])
print(ls.identifier, cat.identifier)
```

An option you leave out keeps `codesign`'s default: `None` for a value, `False` for a
flag. Passing `False` leaves a flag out too, so a variable can switch it.

Targets are a path (`str` or any `os.PathLike`) or a sequence of paths (a list, a
tuple...). A `str` is always one path, never a sequence of characters. What an action
returns follows the targets: the action's result for a single path, a `list` of
results for a sequence, even one with a single element. Every path is kept, order and
duplicates too, and a path starting with `-` is never read as an option.

Complete scripts for the common jobs:

- [Re-signing a patched binary](https://github.com/Fly-elf/signers/blob/v0.1.0/examples/python/codesign/resign_patched.py), keeping its identifier and
  entitlements.
- [Inspecting several targets](https://github.com/Fly-elf/signers/blob/v0.1.0/examples/python/codesign/inspect_targets.py) at once: signature, requirements and
  verification (asyncio).
- [Signing an app bundle](https://github.com/Fly-elf/signers/blob/v0.1.0/examples/python/codesign/sign_bundle.py), nested code first.
- [Signing for distribution](https://github.com/Fly-elf/signers/blob/v0.1.0/examples/python/codesign/sign_for_distribution.py) and checking the result (asyncio).

Actions:

- `sign`, `sign_adhoc`, `sign_for_distribution`: sign the targets.
- `remove_signature`: strips the signatures.
- `verify`: checks the signatures.
- `validate_constraint`: checks launch and library constraint plists.
- `display`: reads a `Signature`.
- `requirements`: reads the `Requirement`s of a signature.
- `extract_certificates`: reads the `Certificate` chain of a signature.

The ones that sign, remove or check return `None`, for one path and for a sequence
alike: they succeed, or they raise.

Calls block until `codesign` finishes and release the GIL meanwhile, so threads can
run several at once. In asyncio code, use `codesign.aio` instead: the same actions as
awaitables, which let the event loop run while `codesign` does.

Before starting `codesign`, an action checks, in this order:

1. that the options can be honoured, else `StdioPathError`, or `IoError` if
   `extract_certificates` can't use the system's temporary directory;
2. with `per_target=True`, that no option writes one shared file, else
   `SharedOutputPerTargetError`;
3. that there is a target at all, else `NoTargetsError`;
4. that no target is an empty path, else `EmptyTargetError`;
5. that every target exists, else `PathNotFoundError` or `PathAccessError`.

So far no target has been touched. Then `codesign` runs:

- once over all the targets, for a single path and by default for the actions that
  change them (`sign` and its presets, `remove_signature`). It stops at the first
  target it rejects: the targets before that one have already been changed, the ones
  after it haven't.
- once per target, with `per_target=True`, which is the default for the actions that
  only read them. Every target runs, and the failures come together as `BatchError`,
  including the targets for which `codesign` couldn't start. Only if it can't start for
  any target (`CodesignNotFoundError`, `SpawnError`) is that error raised alone instead.

What `codesign` does wrong raises a `ProcessError` with `program` `"codesign"`: it
couldn't start or be waited on (`SpawnError`, `RunError`), it exited non-zero or was
killed by a signal (`ProcessFailedError`), or its output couldn't be read
(`UnexpectedOutputError`). A missing executable is the exception: it raises
`CodesignNotFoundError`, which adds a hint about `/usr/bin`. The other `CodesignError`
subclasses are the verdicts of `verify`, `validate_constraint` and `display`.

`per_target` is ignored for a single path, which always runs one `codesign`.
`requirements` and `extract_certificates` have no `per_target`: they always run one
`codesign` per target.

The exceptions and the other public types are also available here, the same classes
as in `signers`: `codesign.BatchError`, `codesign.SigningFlags`, `codesign.Change`...
"""

from . import aio as aio
from ._actions import (
    display,
    extract_certificates,
    remove_signature,
    requirements,
    sign,
    sign_adhoc,
    sign_for_distribution,
    validate_constraint,
    verify,
)
from .._errors import (
    BatchError,
    Change,
    CodesignError,
    CodesignNotFoundError,
    ConstraintInvalidError,
    EmptyTargetError,
    IoError,
    NoSignatureError,
    NoTargetsError,
    PathAccessError,
    PathNotFoundError,
    ProcessError,
    ProcessFailedError,
    RequirementUnsatisfiedError,
    ResourceChange,
    RunError,
    SharedOutputPerTargetError,
    SignersError,
    SpawnError,
    StdioPathError,
    ToolNotFoundError,
    UnexpectedOutputError,
    VerificationFailedError,
)
from ._options import PreserveMetadata, SignatureSlot, SigningFlags, Strict, Timestamp
from ._types import (
    CdHash,
    Certificate,
    CertificateSignature,
    CmsDigest,
    CodeDirectory,
    CodeHashes,
    Constraints,
    ExecutableSegment,
    Format,
    FormatKind,
    HashType,
    Location,
    OsVersion,
    Platform,
    Requirement,
    RequirementKind,
    RequirementsSummary,
    SealedResources,
    Signature,
)

__all__ = [
    "BatchError",
    "CdHash",
    "Certificate",
    "CertificateSignature",
    "Change",
    "CmsDigest",
    "CodeDirectory",
    "CodeHashes",
    "CodesignError",
    "CodesignNotFoundError",
    "ConstraintInvalidError",
    "Constraints",
    "EmptyTargetError",
    "ExecutableSegment",
    "Format",
    "FormatKind",
    "HashType",
    "IoError",
    "Location",
    "NoSignatureError",
    "NoTargetsError",
    "OsVersion",
    "PathAccessError",
    "PathNotFoundError",
    "Platform",
    "PreserveMetadata",
    "ProcessError",
    "ProcessFailedError",
    "Requirement",
    "RequirementKind",
    "RequirementUnsatisfiedError",
    "RequirementsSummary",
    "ResourceChange",
    "RunError",
    "SealedResources",
    "SharedOutputPerTargetError",
    "Signature",
    "SignatureSlot",
    "SignersError",
    "SigningFlags",
    "SpawnError",
    "StdioPathError",
    "Strict",
    "Timestamp",
    "ToolNotFoundError",
    "UnexpectedOutputError",
    "VerificationFailedError",
    "aio",
    "display",
    "extract_certificates",
    "remove_signature",
    "requirements",
    "sign",
    "sign_adhoc",
    "sign_for_distribution",
    "validate_constraint",
    "verify",
]
