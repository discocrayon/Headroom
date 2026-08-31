"""
Shared AWS helper utilities for region discovery and pagination.
"""

from collections.abc import Iterator
from functools import wraps
from threading import Lock
from typing import Any, Callable, List, Sequence, Set, Tuple, TypeVar
from weakref import WeakKeyDictionary

from boto3.session import Session
from botocore.client import BaseClient
from mypy_boto3_ec2.client import EC2Client

__all__ = ["get_all_regions", "memoize_per_session", "paginate"]

_REGION_MEMO: WeakKeyDictionary[Session, list[str]] = WeakKeyDictionary()
_REGION_MEMO_LOCK = Lock()


def get_all_regions(session: Session) -> Sequence[str]:
    """
    Return the AWS regions that are enabled for the account.

    `describe_regions` is deliberately called with no arguments. The default
    response contains only regions the account has enabled -- those with an
    OptInStatus of `opt-in-not-required` or `opted-in` -- and omits every
    `not-opted-in` region.

    Do not pass `AllRegions=True`. It adds disabled regions to the result, and
    since every caller builds a per-region client from this list, each disabled
    region would become a doomed API call against a region the account cannot
    use. Headroom has no interest in analyzing a region that cannot hold
    resources. `test_only_enabled_regions_are_requested` pins this.

    Note that an enabled region does not guarantee the service is available
    there; handling a missing regional endpoint is the caller's concern.

    The result is memoized per session. Eleven functions call this, one per
    region-sweeping analyzer and four of them in `aws/ec2.py`, and the answer
    cannot change within a run, so ten of the eleven calls an account makes
    are pure latency. `deny_service_confused_deputy` re-invokes six analyzers
    that another check also calls, four of which sweep regions, but
    `memoize_per_session` absorbs whichever of each pair runs second -- so the
    count stays eleven whatever order the registry yields the checks in, and
    which of the two checks reaches here is not worth asserting.

    The memo is keyed on the session object itself, never on an account ID or
    name. That is what keeps one account's region list out of another account's
    results. Entries live in a WeakKeyDictionary, so an account's entry goes
    when its worker drops the session and nothing accumulates across a
    300-account run.

    An account that raises is the exception, and it applies to all three of
    Headroom's per-session memos. Its worker's exception is stored on its
    future, the traceback pins the worker's frame, and the frame holds the
    session -- so the entry outlives the worker and is released only when
    `run_checks`'s own frame goes. On the normal path that is when it
    returns; on the failure path it does not return at all, and the frame is
    pinned by the propagating traceback until whatever caught it lets go. What bounds that is
    how many accounts are in flight when the abort lands, so
    `max_account_workers` rather than the size of the organization, which is
    why the ceiling `MAX_ACCOUNT_WORKERS` states still holds on the failure
    path.

    The lock is released across the `describe_regions` call rather than held.
    Holding it would serialize every worker behind one account's region
    lookup. The lock exists only because the WeakKeyDictionary is shared
    between workers; the entry itself is uncontended, since one worker owns a
    session. Two threads filling it would cost a duplicate API call and
    nothing else -- the value written is a fresh list either way.

    Callers cannot mutate what this returns. It is the cached list itself,
    not a copy, so sorting or filtering it in place would change the region
    list every later check for this account reads; the return type is
    `Sequence`, which has no such method, so strict mypy rejects the attempt
    at the call site rather than leaving the rule to a docstring.
    """
    with _REGION_MEMO_LOCK:
        cached = _REGION_MEMO.get(session)

    if cached is not None:
        return cached

    ec2_client: EC2Client = session.client("ec2")
    response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in response["Regions"]]

    with _REGION_MEMO_LOCK:
        _REGION_MEMO[session] = regions

    return regions


_Result = TypeVar("_Result")


def memoize_per_session(
    analyzer: Callable[[Session, Set[str], str], List[_Result]]
) -> Callable[[Session, Set[str], str], Sequence[_Result]]:
    """
    Serve a resource-policy analysis once per account instead of twice.

    Six analyzers have two callers each: their own third-party-access check,
    and `deny_service_confused_deputy`, which re-reads the same policies for
    the source guards on them. Four of the six sweep every enabled region, so
    an account pays 4 x 17 region probes for policies it has already read --
    the same waste the four identical EC2 sweeps were, arriving by a
    different route.

    The memo is keyed on the session object itself, never on an account ID or
    name. That is what keeps one account's resource policies out of another
    account's allowlist. Entries live in a `WeakKeyDictionary`, so an
    account's entry goes when its worker drops the session -- except on the
    failure path, for the reason `get_all_regions` gives above. These are the
    largest of the three memos, holding every bucket, key, and role policy in
    the account, which is what makes that bound worth having.

    A session is sufficient as the whole key only because `org_account_ids`
    and `org_id` are fixed for a run. Rather than trust that silently, a
    second call for the same session carrying different values raises: being
    served the first call's answer to a different question would be both
    plausible and wrong.

    That guard cannot fire in a real run, and it is not the cross-account
    check it resembles. `discover_organization` captures both values once,
    and `run_checks` threads them unchanged into every account, so the
    comparison is always between two copies of one thing; only a direct
    caller can trip it. The failure it does not catch is the one that would
    matter: one session reaching two accounts carries identical organization
    arguments and would be served the first account's policies in silence.
    Nothing here can see that, because the analyzer signature carries no
    account identity. What rules it out is one session per worker and one
    worker per account, upstream in `run_checks`.

    Nothing here checks that upstream property at runtime either, and a
    thread-identity check on the memo entry is the obvious thing to reach for
    -- it would not close it. The pool reuses its worker threads across
    accounts, so two accounts sharing one session can be two accounts on one
    thread, and the check passes. What does close it is asserting the thing
    itself:
    `TestRunChecksPool.test_the_real_registry_runs_every_check_per_account_across_workers`
    runs the whole registry with four workers and asserts every check of one
    account saw one session, and no session reached two accounts.

    The lock is released across the analyzer call rather than held, for the
    reason `get_all_regions` gives above: holding it would serialize every
    worker behind one account's policy sweep, and the entry is uncontended.

    Callers cannot mutate what this returns. It is the cached list itself,
    not a copy, so sorting or filtering it in place would change what the
    other check for this account reads. The decorated function is typed as
    returning `Sequence`, so strict mypy rejects the attempt even though the
    analyzer it wraps still returns a list.

    Args:
        analyzer: A `(session, org_account_ids, org_id)` analysis function

    Returns:
        The same function, answering repeat calls for a session from memory
    """
    memo: WeakKeyDictionary[Session, Tuple[frozenset[str], str, List[_Result]]] = WeakKeyDictionary()
    lock = Lock()

    @wraps(analyzer)
    def memoized(session: Session, org_account_ids: Set[str], org_id: str) -> List[_Result]:
        with lock:
            entry = memo.get(session)

        if entry is not None:
            cached_account_ids, cached_org_id, cached_results = entry
            if cached_account_ids != org_account_ids or cached_org_id != org_id:
                raise RuntimeError(
                    f"{analyzer.__name__} was called twice for one session with different "
                    "organization arguments. The memo is keyed on the session alone, so the "
                    "second call would have been served the first call's results."
                )
            return cached_results

        results = analyzer(session, org_account_ids, org_id)

        with lock:
            memo[session] = (frozenset(org_account_ids), org_id, results)

        return results

    # Exposed so tests can assert the entry is released with its session, and
    # so `test_every_doubly_called_analyzer_is_memoized` can tell a decorated
    # analyzer from one that quietly lost the decorator.
    setattr(memoized, "session_memo", memo)

    return memoized


def paginate(
    client: BaseClient,
    operation_name: str,
    **operation_kwargs: Any
) -> Iterator[dict[str, Any]]:
    """
    Yield pages for a paginated AWS API operation.
    """
    paginator = client.get_paginator(operation_name)
    for page in paginator.paginate(**operation_kwargs):
        yield page
