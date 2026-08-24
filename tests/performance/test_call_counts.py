"""
Call-count contracts for the per-account memos.

These pin the savings from caching the region list and the EC2 instance list.
They assert counts rather than wall clock, so they cannot flake, and they fail
the day a new check reintroduces a redundant sweep.
"""

from typing import Any, Dict, List
from unittest.mock import MagicMock

from headroom.aws.ec2 import (
    get_ec2_ami_owner_analysis,
    get_ec2_imds_hop_limit_analysis,
    get_ec2_imds_v1_analysis,
    get_ec2_public_ip_analysis,
)
from headroom.aws.helpers import get_all_regions

REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-2"]


def _session(pages: List[Dict[str, Any]]) -> MagicMock:
    """Build a mock session serving `pages` from every region."""
    client = MagicMock()
    client.describe_regions.return_value = {
        "Regions": [{"RegionName": region} for region in REGIONS]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    client.get_paginator.return_value = paginator
    session = MagicMock()
    session.client.return_value = client
    return session


class TestCallCounts:
    """Pin the per-account AWS call counts the memos are there to reduce."""

    def test_region_list_costs_one_call_however_many_checks_ask(self) -> None:
        """
        Eleven checks ask for the region list; one describe_regions results.

        Before the memo this was eleven calls per account.
        """
        session = _session([{"Reservations": []}])

        for _ in range(11):
            get_all_regions(session)

        assert session.client.return_value.describe_regions.call_count == 1

    def test_four_ec2_checks_describe_each_region_once(self) -> None:
        """
        Four checks over three regions issue three describe_instances calls.

        Before the memo this was twelve: each check swept every region
        independently with an identical call.
        """
        session = _session([{"Reservations": []}])

        get_ec2_imds_v1_analysis(session)
        get_ec2_public_ip_analysis(session)
        get_ec2_imds_hop_limit_analysis(session)
        get_ec2_ami_owner_analysis(session)

        paginator = session.client.return_value.get_paginator
        describe_instances_calls = [
            call for call in paginator.call_args_list
            if call.args and call.args[0] == "describe_instances"
        ]
        assert len(describe_instances_calls) == len(REGIONS)
