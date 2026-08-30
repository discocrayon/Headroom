"""
Thread-local account context for log records.

Headroom analyzes accounts concurrently, so records from different accounts
interleave in the output. Most of the log calls in `headroom/aws/` name only a
region or a resource, which is ambiguous the moment more than one account is in
flight. Rather than edit all of them, a filter stamps every record with the
account its thread is working on.
"""

import logging
import threading

__all__ = ["AccountContextFilter", "configure_logging", "set_account"]

# Shown for records emitted outside a worker: startup, configuration, teardown.
NO_ACCOUNT = "-"

LOG_FORMAT = "%(levelname)s:%(name)s:[%(account)s] %(message)s"

_CONTEXT = threading.local()


def set_account(account_identifier: str) -> None:
    """
    Record which account the calling thread is analyzing.

    Args:
        account_identifier: Formatted account identifier for log records
    """
    _CONTEXT.account = account_identifier


class AccountContextFilter(logging.Filter):
    """
    Stamp every log record with the account its thread is analyzing.

    Installed on the handler rather than on a logger. A logger's filters see
    only records logged directly to that logger, not records propagated up from
    child loggers, so a logger-level filter would leave most records without the
    attribute the formatter interpolates.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Add the calling thread's account to the record.

        Args:
            record: Record about to be formatted

        Returns:
            True, always: this filter annotates records, it never drops them
        """
        record.account = getattr(_CONTEXT, "account", NO_ACCOUNT)
        return True


_ACCOUNT_FILTER = AccountContextFilter()


def configure_logging() -> None:
    """
    Install the account filter and format on the root handler.

    `basicConfig` does two things here, and both matter only when the root
    logger has no handler yet -- the branch it takes in a fresh process, and
    the only branch that does anything at all, since it returns early once a
    handler exists.

    It installs a handler, so the loop below has something to configure.
    Iterating an empty list installed nothing and said nothing about it, and
    the next `basicConfig` to run would then fit the root logger with the
    default format and no filter, dropping the `[account]` field from every
    record for the rest of the process.

    It also sets the level, which is this module's single source for it.
    CPython reaches `root.setLevel` only inside that same empty-handler
    branch and only when a level was passed, so calling this with no level
    would leave the root logger at WARNING -- and, having installed a
    handler, make every later `basicConfig` a no-op that cannot raise it.
    Headroom reports progress at INFO, so the run would go quiet while still
    printing errors.

    `main` calls this once, but nothing about the function requires that.
    Repeat calls are harmless: `_ACCOUNT_FILTER` is a module-level singleton,
    and `Handler.addFilter` dedups by identity, so passing the same instance
    on a later call is a no-op rather than a second filter.
    """
    logging.basicConfig(level=logging.INFO)

    for handler in logging.getLogger().handlers:
        handler.addFilter(_ACCOUNT_FILTER)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
