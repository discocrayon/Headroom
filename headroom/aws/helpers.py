"""
Shared AWS helper utilities for region discovery and pagination.
"""

from collections.abc import Iterator
from typing import Any

from boto3.session import Session
from botocore.client import BaseClient
from mypy_boto3_ec2.client import EC2Client

__all__ = ["get_all_regions", "paginate"]


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
    """
    ec2_client: EC2Client = session.client("ec2")
    response = ec2_client.describe_regions()
    return [region["RegionName"] for region in response["Regions"]]


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
