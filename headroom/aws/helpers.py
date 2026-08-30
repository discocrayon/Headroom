"""
Shared AWS helper utilities for region discovery and pagination.
"""

from collections.abc import Iterator
from functools import wraps
from threading import Lock
from typing import Any, Callable, List, Set, Tuple, TypeVar
from weakref import WeakKeyDictionary

from boto3.session import Session
from botocore.client import BaseClient
from mypy_boto3_ec2.client import EC2Client

__all__ = ["get_all_regions", "memoize_per_session", "paginate"]

_REGION_MEMO: WeakKeyDictionary[Session, list[str]] = WeakKeyDictionary()
_REGION_MEMO_LOCK = Lock()


def get_all_regions(session: Session) -> list[str]:
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

    The result is memoized per session. Eleven calls reach this function for
    each account -- one per region-sweeping analyzer, four of them in
    `aws/ec2.py` -- and the answer cannot change within a run, so the other
    ten are pure latency. `deny_service_confused_deputy` adds no twelfth:
    its copies of the four shared analyzers are absorbed a layer up, by
    `memoize_per_session`, and never reach here at all.

    The memo is keyed on the session object itself, never on an account ID or
    name. That is what keeps one account's region list out of another account's
    results. Entries live in a WeakKeyDictionary, so an account's entry is
    released as soon as its worker drops the session and nothing accumulates
    across a 300-account run.

    The lock is released across the `describe_regions` call rather than held.
    Holding it would serialize every worker behind one account's region lookup.
    Two threads cannot race to fill the same entry because each session belongs
    to exactly one worker; the lock exists only because the outer
    WeakKeyDictionary is shared between workers.

    Callers must not mutate what this returns. It is the cached list itself,
    not a copy, so sorting or filtering it in place changes the region list
    every later check for this account reads.
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
) -> Callable[[Session, Set[str], str], List[_Result]]:
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
    account's entry is released as soon as its worker drops the session; these
    entries hold every bucket, key, and role policy in the account, so
    retaining them past the worker would move the pool's memory ceiling away
    from where `MAX_ACCOUNT_WORKERS` says it is.

    A session is sufficient as the whole key only because `org_account_ids`
    and `org_id` are fixed for a run. Rather than trust that silently, a
    second call for the same session carrying different values raises: being
    served the first call's answer to a different question would be both
    plausible and wrong.

    The lock is released across the analyzer call rather than held. Holding it
    would serialize every worker behind one account's policy sweep. Two
    threads cannot race to fill the same entry because each session belongs to
    exactly one worker; the lock exists only because the `WeakKeyDictionary`
    is shared between workers.

    Callers must not mutate what this returns. It is the cached list itself,
    not a copy, so sorting or filtering it in place changes what the other
    check for this account reads.

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
