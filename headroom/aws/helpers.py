"""
Shared AWS helper utilities for region discovery and pagination.
"""

from collections.abc import Iterator
from threading import Lock
from typing import Any
from weakref import WeakKeyDictionary

from boto3.session import Session
from botocore.client import BaseClient
from mypy_boto3_ec2.client import EC2Client

__all__ = ["get_all_regions", "paginate"]

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

    The result is memoized per session. Eleven checks each ask for the region
    list and the answer cannot change within a run, so the other ten calls are
    pure latency.

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
