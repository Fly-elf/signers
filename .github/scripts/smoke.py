"""Smoke-tests an installed `signers` package against the real `codesign`.

Usage: python .github/scripts/smoke.py (from outside the repository, so the installed package is imported)
"""

import asyncio

import signers
import signers.codesign.aio
from signers import codesign

TARGET = "/usr/bin/true"
IDENTIFIER = "com.apple.true"


async def display_async() -> str:
    return (await codesign.aio.display(TARGET)).identifier


codesign.verify(TARGET)
assert codesign.display(TARGET).identifier == IDENTIFIER
assert asyncio.run(display_async()) == IDENTIFIER
print(f"ok: signers from {signers.__file__}")
