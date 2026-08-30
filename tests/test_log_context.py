"""
Tests for headroom.log_context module.
"""

import io
import logging
import threading

from typing import List

from headroom.log_context import NO_ACCOUNT, AccountContextFilter, configure_logging, set_account


def _bare_record() -> logging.LogRecord:
    """Build a log record with no account attribute."""
    return logging.LogRecord(
        name="headroom.aws.sqs",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Analyzing SQS queues in eu-west-1",
        args=(),
        exc_info=None,
    )


class TestAccountContextFilter:
    """Test that log records carry the account of the emitting thread."""

    def test_record_carries_the_account_this_thread_set(self) -> None:
        """The filter stamps the record with this thread's account."""
        set_account("payments_111111111111")
        record = _bare_record()

        assert AccountContextFilter().filter(record) is True
        assert record.account == "payments_111111111111"  # type: ignore[attr-defined]

    def test_record_outside_a_worker_gets_a_placeholder(self) -> None:
        """
        Records emitted before any account is set still format.

        The formatter interpolates %(account)s unconditionally, so the
        attribute has to exist even for startup, configuration, and teardown
        records. The check runs on its own thread because thread-local context
        set by an earlier test would otherwise leak into it.
        """
        captured: List[str] = []

        def emit_without_context() -> None:
            record = _bare_record()
            AccountContextFilter().filter(record)
            captured.append(record.account)  # type: ignore[attr-defined]

        thread = threading.Thread(target=emit_without_context)
        thread.start()
        thread.join(timeout=5)

        assert captured == [NO_ACCOUNT]

    def test_each_thread_sees_only_its_own_account(self) -> None:
        """
        Context is thread-local, so concurrent workers do not overwrite
        each other's account.
        """
        seen: dict[str, str] = {}
        ready = threading.Barrier(2, timeout=5)

        def worker(identifier: str) -> None:
            set_account(identifier)
            ready.wait()
            record = _bare_record()
            AccountContextFilter().filter(record)
            seen[identifier] = record.account  # type: ignore[attr-defined]

        threads = [
            threading.Thread(target=worker, args=("a_111111111111",)),
            threading.Thread(target=worker, args=("b_222222222222",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        assert seen == {
            "a_111111111111": "a_111111111111",
            "b_222222222222": "b_222222222222",
        }


class TestConfigureLogging:
    """Test what configure_logging installs, and that repeating it is safe."""

    def test_an_empty_root_gets_a_handler_rather_than_nothing(self) -> None:
        """
        With no root handler yet, configure_logging installs one.

        Iterating an empty handler list installs nothing, and says nothing
        about it. The `[account]` field is then gone for the rest of the
        process: whichever `logging.basicConfig` runs next fits the root
        logger with the default format and no filter, and every later record
        formats without complaint and without the account.

        The only thing keeping that list non-empty today is `analysis.py`
        calling `basicConfig` at import time together with `main.py` importing
        it at module scope -- an invariant nothing states or enforces, and one
        that deferring the heavy `analysis` import to cut startup cost would
        quietly break.

        The other test in this class pre-installs a NullHandler, which is
        exactly what keeps it off this path.

        The root logger's handler list and level are process-global and
        shared with pytest, so this puts both back. Emptying the handler list
        is what lets configure_logging's basicConfig take its one effective
        branch, and that branch raises the level as well as installing the
        handler.
        """
        root_logger = logging.getLogger()
        preexisting_handlers = list(root_logger.handlers)
        preexisting_level = root_logger.level
        root_logger.handlers = []
        set_account("payments_111111111111")

        try:
            configure_logging()

            installed = list(root_logger.handlers)
            assert installed

            for handler in installed:
                assert any(
                    isinstance(installed_filter, AccountContextFilter)
                    for installed_filter in handler.filters
                )
                assert handler.formatter is not None

                record = _bare_record()
                assert handler.filter(record)
                assert handler.formatter.format(record) == (
                    "INFO:headroom.aws.sqs:[payments_111111111111] Analyzing SQS queues in eu-west-1"
                )
        finally:
            root_logger.handlers = preexisting_handlers
            root_logger.setLevel(preexisting_level)

    def test_an_empty_root_is_left_logging_at_info(self) -> None:
        """
        configure_logging must set the level, not only install the handler.

        basicConfig reaches root.setLevel only inside the branch it takes when
        the root handler list is empty, and only when it was passed a level.
        Called with no level it installs a handler and leaves root at WARNING
        -- and disarms every later basicConfig, which is a no-op once a
        handler exists. Headroom reports progress at INFO, so that combination
        silences the run while still printing errors.

        Root is reset to WARNING here because that is where a fresh
        interpreter starts. The suite has already imported `headroom.analysis`,
        which raises it to INFO at import time, so without the reset this would
        be asserting against that import rather than against this function.
        """
        root_logger = logging.getLogger()
        preexisting_handlers = list(root_logger.handlers)
        preexisting_level = root_logger.level
        root_logger.handlers = []
        root_logger.setLevel(logging.WARNING)

        try:
            configure_logging()

            assert root_logger.isEnabledFor(logging.INFO)
        finally:
            root_logger.handlers = preexisting_handlers
            root_logger.setLevel(preexisting_level)

    def test_a_record_from_a_child_logger_arrives_stamped(self) -> None:
        """
        The one test that exercises level, propagation, filter, and format
        together.

        Every other test in this class calls `handler.filter` and
        `formatter.format` by hand. That shows the pieces work; it cannot show
        they are wired to each other, and it cannot see the level at all,
        because neither call consults it. This emits through a child logger
        the way `headroom/aws/` does and reads what the root handler wrote.

        The expected line is the format string filled in by hand, not built
        from LOG_FORMAT, so a change to the format has to be made here too.
        """
        root_logger = logging.getLogger()
        preexisting_handlers = list(root_logger.handlers)
        preexisting_level = root_logger.level
        root_logger.handlers = []
        root_logger.setLevel(logging.WARNING)

        try:
            configure_logging()

            installed = root_logger.handlers[0]
            assert isinstance(installed, logging.StreamHandler)
            captured = io.StringIO()
            installed.setStream(captured)
            set_account("payments_111111111111")

            logging.getLogger("headroom.aws.sqs").info("Analyzing SQS queues in eu-west-1")

            assert captured.getvalue() == (
                "INFO:headroom.aws.sqs:[payments_111111111111] "
                "Analyzing SQS queues in eu-west-1\n"
            )
        finally:
            root_logger.handlers = preexisting_handlers
            root_logger.setLevel(preexisting_level)
            set_account(NO_ACCOUNT)

    def test_repeat_calls_leave_one_account_filter_on_the_handler(self) -> None:
        """
        A second call must not install a second filter.

        main() calls configure_logging() once, but nothing enforces that.
        Handler.addFilter dedups by identity, not by class, so a fresh
        AccountContextFilter() built on every call would never be recognized
        as a duplicate. The check runs against a handler of its own, and
        restores every pre-existing handler's filters and formatter
        afterwards, so it cannot leak state into the process's real root
        handler for a later test to inherit.
        """
        root_logger = logging.getLogger()
        preexisting_handlers = list(root_logger.handlers)
        original_filters = {handler: list(handler.filters) for handler in preexisting_handlers}
        original_formatters = {handler: handler.formatter for handler in preexisting_handlers}

        probe_handler = logging.NullHandler()
        root_logger.addHandler(probe_handler)
        try:
            configure_logging()
            configure_logging()

            account_filters = [
                installed_filter
                for installed_filter in probe_handler.filters
                if isinstance(installed_filter, AccountContextFilter)
            ]
            assert len(account_filters) == 1
        finally:
            root_logger.removeHandler(probe_handler)
            for handler in preexisting_handlers:
                handler.filters = original_filters[handler]
                handler.formatter = original_formatters[handler]
