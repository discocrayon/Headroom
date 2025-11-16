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
    Return the list of AWS region names available to the account.
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

