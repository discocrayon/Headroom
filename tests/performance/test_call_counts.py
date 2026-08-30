"""
Call-count contracts for the per-account memos.

These pin the savings from caching the region list, the EC2 instance list, and
the six resource-policy analyses shared with `deny_service_confused_deputy`.
They assert counts rather than wall clock, so they cannot flake.

They are memo unit tests, not registry-driven regression guards, and the
distinction matters because it is easy to read them as the latter. Each
assertion hand-enumerates what it drives -- `range(11)` here, a literal
`SHARED_ANALYZERS` list below -- so a check registered tomorrow is outside
every one of them. Measured: registering a twelfth check that asks for the
region list twice and sweeps every region twice leaves this file green, and so
does adding a seventh doubly-called, region-sweeping, unmemoized analyzer to
`deny_service_confused_deputy`. Driving them from `get_all_check_classes`
would close that; nothing does today.

What they do catch is regression in the other direction: disabling either memo
fails the matching test, and an analyzer that loses its decorator fails the
third.
"""

from typing import Any, Callable, Dict, List, Set
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from headroom.aws.ec2 import (
    get_ec2_ami_owner_analysis,
    get_ec2_imds_hop_limit_analysis,
    get_ec2_imds_v1_analysis,
    get_ec2_public_ip_analysis,
)
from headroom.aws.ecr import analyze_ecr_policies
from headroom.aws.helpers import get_all_regions
from headroom.aws.iam.roles import analyze_iam_roles_trust_policies
from headroom.aws.kms import analyze_kms_key_policies
from headroom.aws.s3 import analyze_s3_bucket_policies
from headroom.aws.secretsmanager import analyze_secrets_manager_policies
from headroom.aws.sqs import analyze_sqs_queue_policies

ORG_ACCOUNT_IDS = {"111111111111"}
ORG_ID = "o-11111111"

# The analyzers `deny_service_confused_deputy` shares with a third-party-access
# check, each therefore invoked twice per account.
SHARED_ANALYZERS: List[Callable[[MagicMock, Set[str], str], List[Any]]] = [
    analyze_ecr_policies,
    analyze_iam_roles_trust_policies,
    analyze_kms_key_policies,
    analyze_s3_bucket_policies,
    analyze_secrets_manager_policies,
    analyze_sqs_queue_policies,
]

REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-2"]


def _session(pages: List[Dict[str, Any]]) -> MagicMock:
    """Build a mock session serving `pages` from every region."""
    client = MagicMock()
    client.describe_regions.return_value = {
        "Regions": [{"RegionName": region} for region in REGIONS]
    }
    client.list_buckets.return_value = {"Buckets": []}
    client.list_queues.return_value = {}
    # An unconfigured MagicMock hands get_registry_policy's return value to
    # json.loads(); ECR reports "no registry policy" as this error instead.
    registry_error: Any = {"Error": {"Code": "RegistryPolicyNotFoundException"}}
    client.get_registry_policy.side_effect = ClientError(
        registry_error, "GetRegistryPolicy"
    )
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

    def test_the_shared_analyzers_read_an_account_once_for_both_callers(self) -> None:
        """
        Six analyzers have two callers each and still cost one read.

        `deny_service_confused_deputy` re-reads ECR, KMS, S3, Secrets Manager,
        SQS, and IAM role trust policies after each of those resources' own
        third-party-access check has already read them. Four of the six sweep
        every enabled region, so before the memo an account paid four extra
        region sweeps -- the same waste as the four identical EC2 sweeps
        above, reintroduced by a check added later.

        Clients are the unit because they are what a sweep builds: one per
        region per sweeping analyzer, plus one global client each for S3 and
        IAM.

        Both the floor and the delta are asserted, and they catch different
        things. The floor is derived from the shape above rather than
        captured from the run: three regions times the four regional
        analyzers, one global client each for S3 and IAM, and one EC2 client
        for the `describe_regions` that fills the region memo. Fifteen.
        Without it the second assertion compares the run against itself, so
        two redundant clients built inside one sweep stay green because both
        passes pay them.

        The delta is the memo's own contract: removing a decorator from any
        of the six fails it. Neither half is registry-driven -- the list is
        hand-maintained, so a seventh doubly-called analyzer has to be added
        here to be covered.
        """
        session = _session([{}])

        for analyzer in SHARED_ANALYZERS:
            analyzer(session, ORG_ACCOUNT_IDS, ORG_ID)

        after_the_first_caller = session.client.call_count

        # 4 regional analyzers x 3 regions, + S3 and IAM global, + the EC2
        # client get_all_regions builds for describe_regions.
        assert after_the_first_caller == 15

        for analyzer in SHARED_ANALYZERS:
            analyzer(session, ORG_ACCOUNT_IDS, ORG_ID)

        assert session.client.call_count == after_the_first_caller
