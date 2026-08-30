"""Tests for the autouse fixture in conftest.py."""

import logging

from headroom.log_context import AccountContextFilter, LOG_FORMAT, _CONTEXT, configure_logging, set_account


class TestRestoreProcessWideState:
    """
    Pin the restore by dirtying the state and reading it back next test.

    Two tests rather than one, because the fixture runs between tests and
    there is no other vantage point from which to see it work. pytest
    collects in definition order within a module, so the second runs after
    the first; the pair fails as soon as the fixture stops restoring, which
    is the whole contract.

    The pollution is the real thing both times -- `set_account` and
    `configure_logging` as production calls them -- so this cannot pass while
    the fixture only handles a stand-in.
    """

    def test_a_test_may_leave_the_global_state_dirty(self) -> None:
        """Set the account context and install Headroom's log format."""
        set_account("payments_111111111111")
        configure_logging()

        assert _CONTEXT.account == "payments_111111111111"
        assert any(
            isinstance(log_filter, AccountContextFilter)
            for handler in logging.getLogger().handlers
            for log_filter in handler.filters
        )

    def test_the_next_test_starts_clean(self) -> None:
        """The account is unset again and no handler carries the filter."""
        assert not hasattr(_CONTEXT, "account")

        handlers = logging.getLogger().handlers
        assert not any(
            isinstance(log_filter, AccountContextFilter)
            for handler in handlers
            for log_filter in handler.filters
        )
        assert not any(
            handler.formatter is not None and handler.formatter._fmt == LOG_FORMAT
            for handler in handlers
        )
