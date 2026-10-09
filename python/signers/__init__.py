"""Sign, re-sign and strip code signatures on macOS.

`signers.codesign` runs Apple's `codesign` tool, which ships with macOS. Call the
function of an action with the targets, then pass its options as keyword arguments:

```python
from signers import codesign

# Re-sign a binary after patching it: `force` replaces the signature the patch broke.
codesign.sign_adhoc("patched.dylib", force=True)

# Sign an app for notarization: hardened runtime and a secure timestamp.
codesign.sign_for_distribution(
    "MyApp.app",
    "Developer ID Application: Jane Doe (A1B2C3D4E5)",
    entitlements="MyApp.entitlements",
)
```

A call blocks until `codesign` finishes. A failure raises a subclass of
`SignersError`; the package is typed, so the options and results show up in the IDE.

Where to go next:

- `signers.codesign`: the actions, what they check before running anything, and
  running one `codesign` per target of a sequence.
- `SignersError`: what can fail, and the attributes each error carries.
"""

from importlib.metadata import version

from ._errors import (
    BatchError,
    Change,
    CodesignError,
    CodesignFailedError,
    CodesignNotFoundError,
    ConstraintInvalidError,
    EmptyTargetError,
    IoError,
    NoSignatureError,
    NoTargetsError,
    RequirementUnsatisfiedError,
    ResourceChange,
    RunError,
    SharedOutputPerTargetError,
    SignersError,
    SpawnError,
    StdioPathError,
    TargetAccessError,
    TargetNotFoundError,
    TerminatedError,
    UnexpectedOutputError,
    VerificationFailedError,
)

__version__ = version("signers")
"""The installed version of the package."""

__all__ = [
    "BatchError",
    "Change",
    "CodesignError",
    "CodesignFailedError",
    "CodesignNotFoundError",
    "ConstraintInvalidError",
    "EmptyTargetError",
    "IoError",
    "NoSignatureError",
    "NoTargetsError",
    "RequirementUnsatisfiedError",
    "ResourceChange",
    "RunError",
    "SharedOutputPerTargetError",
    "SignersError",
    "SpawnError",
    "StdioPathError",
    "TargetAccessError",
    "TargetNotFoundError",
    "TerminatedError",
    "UnexpectedOutputError",
    "VerificationFailedError",
    "__version__",
]
