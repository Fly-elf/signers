# Checked by pyright, never run: pins the types the IDE sees. A rejected call
# carries an ignore comment, which pyright reports once the call is accepted.
# pyright: reportUnnecessaryTypeIgnoreComment=true

from typing import assert_type

import signers
from signers import refresh_log_levels


def refresh() -> None:
    assert_type(signers.refresh_log_levels(), None)
    assert_type(refresh_log_levels(), None)

    signers.refresh_log_levels(1)  # pyright: ignore[reportCallIssue]
    signers.refresh_log_levels(level=1)  # pyright: ignore[reportCallIssue]
