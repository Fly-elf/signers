"""The Rust -> `logging` bridge: events arrive on the `signers` logger, levels are cached until refreshed."""

import asyncio
import logging
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import signers
from signers import codesign
from signers.codesign import aio
from .conftest import Workspace

TRACE = 5
DEBUG = logging.DEBUG


class Records(logging.Handler):
    """Collects every record that reaches the `signers` logger tree."""

    def __init__(self) -> None:
        super().__init__(level=1)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def from_rust(self) -> list[logging.LogRecord]:
        return [r for r in self.records if r.name == "signers"]


@pytest.fixture
def records() -> Iterator[Records]:
    """A collector on `signers`, with levels re-read before and after: the cache outlives tests."""
    logger = logging.getLogger("signers")
    handler = Records()
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(1)
    signers.refresh_log_levels()
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
        signers.refresh_log_levels()


def test_the_events_of_a_run_reach_the_signers_logger_with_their_levels(records: Records, workspace: Workspace) -> None:
    codesign.sign_adhoc(workspace.unsigned("t"), force=True)

    assert [(r.getMessage().split()[0], r.levelno) for r in records.from_rust()] == [
        ("spawning", DEBUG),
        ("exited", DEBUG),
        ("output", TRACE),
    ]


def test_the_async_path_delivers_the_record_too(records: Records, workspace: Workspace) -> None:
    asyncio.run(aio.sign_adhoc(workspace.unsigned("t"), force=True))

    assert [r.levelno for r in records.from_rust()] == [DEBUG, DEBUG, TRACE]


def test_the_blocking_path_run_off_the_main_thread_delivers_the_record(records: Records, workspace: Workspace) -> None:
    target = workspace.unsigned("t")

    async def main() -> None:
        await asyncio.to_thread(codesign.sign_adhoc, target, force=True)

    asyncio.run(main())

    assert records.from_rust()


def test_a_level_raised_by_a_logger_hides_the_event(records: Records, workspace: Workspace) -> None:
    logging.getLogger("signers").setLevel(logging.WARNING)
    signers.refresh_log_levels()

    codesign.sign_adhoc(workspace.unsigned("t"), force=True)

    assert records.from_rust() == []


def test_a_lowered_level_has_no_effect_on_a_cached_logger_until_refreshed(records: Records, workspace: Workspace) -> None:
    logger = logging.getLogger("signers")
    logger.setLevel(logging.WARNING)
    signers.refresh_log_levels()
    codesign.sign_adhoc(workspace.unsigned("a"), force=True)
    assert records.from_rust() == []

    logger.setLevel(1)
    codesign.sign_adhoc(workspace.unsigned("b"), force=True)
    assert records.from_rust() == []

    signers.refresh_log_levels()
    codesign.sign_adhoc(workspace.unsigned("c"), force=True)
    assert records.from_rust()


def test_refresh_log_levels_can_be_called_repeatedly_and_returns_none() -> None:
    assert signers.refresh_log_levels() is None
    assert signers.refresh_log_levels() is None


def test_refresh_log_levels_is_exported_from_the_package() -> None:
    assert "refresh_log_levels" in signers.__all__
    assert callable(signers.refresh_log_levels)


def test_the_signers_logger_has_a_null_handler() -> None:
    handlers = logging.getLogger("signers").handlers

    assert any(type(h) is logging.NullHandler for h in handlers)


def test_a_fresh_interpreter_imports_and_refreshes_before_any_event() -> None:
    script = "import signers; signers.refresh_log_levels(); print('ok')"
    run = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True)

    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "ok"


def test_a_fresh_interpreter_without_logging_config_prints_nothing(tmp_path: Path, hello: Path) -> None:
    target = tmp_path / "t"
    target.write_bytes(hello.read_bytes())
    target.chmod(0o755)
    script = (
        "import logging, sys, signers;"
        "logging.getLogger('signers').setLevel(1);"
        "signers.codesign.sign_adhoc(sys.argv[1], force=True)"
    )
    run = subprocess.run([sys.executable, "-I", "-c", script, str(target)], capture_output=True, text=True)

    assert run.returncode == 0, run.stderr
    assert run.stderr == ""
