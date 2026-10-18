import logging

from . import _native

logging.getLogger("signers").addHandler(logging.NullHandler())


def refresh_log_levels() -> None:
    """Re-read the Python logger levels that the Rust side has cached."""
    _native.refresh_log_levels()
