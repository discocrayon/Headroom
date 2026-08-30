"""
Restore the process-wide state a handful of tests mutate.

Two things in this package are global rather than per-test, and both were
being left dirty for whatever ran next. Measured over the whole suite with a
snapshot-and-compare fixture: four tests leak, in exactly these two ways.

`headroom.log_context` keeps the account name in a `threading.local`, and
`tests/test_log_context.py` sets it on the main thread. Every test after that
one sees `payments_111111111111` as its thread's account, so anything
asserting on a log record's `[account]` field is reading a value the test
before it chose. Three tests in `TestRunChecksPool` spawn a thread purely to
get away from it, and say so in their docstrings.

`configure_logging` installs `AccountContextFilter` and Headroom's format on
every handler on the root logger. Under pytest those handlers belong to
pytest -- `LogCaptureHandler` and the live-log handlers -- so the one test
that calls it for real re-formats `caplog` output for the rest of the
session.

Restoring is unconditional rather than conditional on having detected a
change: it costs a list copy per test, and a fixture that only sometimes runs
its restore is a fixture whose restore is only sometimes tested.
"""

import logging
from typing import Iterator

import pytest

from headroom.log_context import _CONTEXT


@pytest.fixture(autouse=True)
def restore_process_wide_state() -> Iterator[None]:
    """
    Hand every test the root logger and account context it started with.

    The account context is deleted rather than reset to `NO_ACCOUNT`, because
    unset is the state a fresh thread is in and `-` is not: `AccountContextFilter`
    reads them the same, but a test that asserts `set_account` cleared up after
    itself passes by construction if the attribute was already there.
    """
    root = logging.getLogger()
    level = root.level
    handlers = list(root.handlers)
    filters_and_formatters = [(handler, list(handler.filters), handler.formatter) for handler in handlers]

    yield

    if hasattr(_CONTEXT, "account"):
        del _CONTEXT.account

    root.setLevel(level)
    root.handlers[:] = handlers
    for handler, handler_filters, formatter in filters_and_formatters:
        handler.filters[:] = handler_filters
        handler.setFormatter(formatter)
