"""
Tests for headroom.log_context module.
"""

import logging
import threading

from typing import List

from headroom.log_context import NO_ACCOUNT, AccountContextFilter, set_account


class TestAccountContextFilter:
    """Test that log records carry the account of the emitting thread."""

    @staticmethod
    def _record() -> logging.LogRecord:
        """Build a bare log record with no account attribute."""
        return logging.LogRecord(
            name="headroom.aws.sqs",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Analyzing SQS queues in eu-west-1",
            args=(),
            exc_info=None,
        )

    def test_record_carries_the_account_this_thread_set(self) -> None:
        """The filter stamps the record with this thread's account."""
        set_account("payments_111111111111")
        record = self._record()

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
            record = self._record()
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
            record = self._record()
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
