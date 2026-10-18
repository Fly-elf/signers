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

`import signers` also loads `signers.codesign`, so `signers.codesign.sign_adhoc(...)`
works without a second import.

Events from the Rust side go to the standard `logging` module, under the single logger
`signers`, at debug and trace level (`DEBUG`, and level 5 for trace). Debug events report
each tool being spawned and exiting; trace events add the tool's output. Configure them
through `logging.getLogger("signers")`. Lowering the level of that logger after events
have been emitted needs a call to `refresh_log_levels`; raising it takes effect at once.

Where to go next:

- `signers.codesign`: the actions, what they check before running anything, and
  running one `codesign` per target of a sequence.
- `SignersError`: what can fail, and the attributes each error carries.
- `refresh_log_levels`: applying a lowered `signers` logger level.
"""

from importlib.metadata import version

from ._errors import (
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
    TerminatedError,
    ToolNotFoundError,
    UnexpectedOutputError,
    VerificationFailedError,
)
from ._logging import refresh_log_levels

from . import codesign as codesign

__version__ = version("signers")
"""The installed version of the package."""

__all__ = [
    "BatchError",
    "Change",
    "CodesignError",
    "CodesignNotFoundError",
    "ConstraintInvalidError",
    "EmptyTargetError",
    "IoError",
    "NoSignatureError",
    "NoTargetsError",
    "PathAccessError",
    "PathNotFoundError",
    "ProcessError",
    "ProcessFailedError",
    "RequirementUnsatisfiedError",
    "ResourceChange",
    "RunError",
    "SharedOutputPerTargetError",
    "SignersError",
    "SpawnError",
    "StdioPathError",
    "TerminatedError",
    "ToolNotFoundError",
    "UnexpectedOutputError",
    "VerificationFailedError",
    "__version__",
    "codesign",
    "refresh_log_levels",
]
