import logging

from . import _native

logging.getLogger("signers").addHandler(logging.NullHandler())


def refresh_log_levels() -> None:
    """Make the Rust side re-read the levels of the `signers` loggers.

    Needed only after you lower the level of a `signers` logger once events have been
    emitted, for example from `INFO` to `DEBUG`: the previous level is cached and the
    new one is ignored until you call this. Raising a level takes effect at once.

    Example:
        ```python
        import logging
        import signers

        logging.basicConfig(level=logging.WARNING)
        signers.codesign.sign_adhoc("a.dylib")

        # Debug output is wanted from here on.
        logging.getLogger("signers").setLevel(logging.DEBUG)
        signers.refresh_log_levels()
        signers.codesign.sign_adhoc("b.dylib")
        ```
    """
    _native.refresh_log_levels()
