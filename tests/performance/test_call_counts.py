"""
Call-count contracts for the per-account memos.

These pin the savings from caching the region list, the EC2 instance list, and
the six resource-policy analyses shared with `deny_service_confused_deputy`.
They assert counts rather than wall clock, so they cannot flake.

The first three are memo unit tests, not registry-driven regression guards,
and the distinction matters because it is easy to read them as the latter.
Each hand-enumerates what it drives -- `range(11)` in the first, a literal
`SHARED_ANALYZERS` list in the third -- so a check registered tomorrow is
outside all three. Measured: registering a twelfth check that asks for the
region list twice and sweeps every region twice leaves those three green, and
so does adding a seventh doubly-called, region-sweeping, unmemoized analyzer
to `deny_service_confused_deputy`. What they do catch is regression in the
other direction: disabling either memo fails the matching test, and an
analyzer that loses its decorator fails the third.

`TestNoCheckRepeatsAnother` is the registry-driven one, and it is what covers
the check registered tomorrow. It drives `get_all_check_classes()` and asserts
a single invariant -- no `(service, region, operation)` triple is issued twice
in one account's run -- so it needs no edit when a check is added. Measured
against the same twelfth check: it fails with
`eks ap-southeast-2 list_clusters x3` while the three above stay green.
"""

from collections import Counter, defaultdict
from typing import Any, Callable, DefaultDict, Dict, List, Set, Tuple
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
from headroom.checks.registry import get_all_check_classes

ORG_ACCOUNT_IDS = {"111111111111"}
ORG_ID = "o-11111111"

# One AWS API call, as the repeat guard counts it: which client issued it
# and what it asked for. Region is "" for a global service.
Operation = Tuple[str, str, str]

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


class _RecordingClient:
    """
    A stand-in boto3 client that logs the operation names asked of it.

    Every listing comes back empty, which is what keeps the log to entry
    points: a per-resource follow-up like `get_bucket_policy` needs a bucket
    to exist, and those are not what the memos deduplicate.
    """

    def __init__(self, service: str, region: str, log: List[Operation]) -> None:
        self._service = service
        self._region = region
        self._log_to = log

    def _log(self, operation: str) -> None:
        self._log_to.append((self._service, self._region, operation))

    def get_paginator(self, operation_name: str) -> MagicMock:
        """Log the paginated operation and hand back an empty page."""
        self._log(operation_name)
        paginator = MagicMock()
        paginator.paginate.return_value = [_empty_response()]
        return paginator

    def describe_regions(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Report the three regions every sweep below walks."""
        self._log("describe_regions")
        return {"Regions": [{"RegionName": region} for region in REGIONS]}

    def get_registry_policy(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Report no registry policy the way ECR reports it: as an error."""
        self._log("get_registry_policy")
        registry_error: Any = {"Error": {"Code": "RegistryPolicyNotFoundException"}}
        raise ClientError(registry_error, "GetRegistryPolicy")

    def __getattr__(self, operation_name: str) -> Callable[..., Any]:
        """Log any other operation and return an empty response."""
        def call(*args: Any, **kwargs: Any) -> DefaultDict[str, Any]:
            self._log(operation_name)
            return _empty_response()
        return call


def _empty_response() -> DefaultDict[str, Any]:
    """An empty response every key of which reads as an empty list."""
    return defaultdict(list)


class TestNoCheckRepeatsAnother:
    """Pin the memo contract across the whole registry rather than a list."""

    def test_no_operation_is_issued_twice_for_one_account(self) -> None:
        """
        Run every registered check against one session; nothing repeats.

        The three assertions above are memo unit tests: each hand-enumerates
        what it drives, so a check registered tomorrow that asks for the
        region list twice and sweeps every region twice leaves all of them
        green. This is the guard that does not need editing when a check is
        added, because the registry supplies the scope.

        The invariant is one line: across one account's whole run, no
        `(service, region, operation)` triple is issued twice. That is the
        memo contract restated, and unlike a call-count floor it does not
        grow when a check for a new service arrives -- a new API is a new
        triple, not a repeat. It fires exactly when one check re-reads what
        another already read.

        Measured on the registry as it stands: 35 operations, 35 distinct.
        Two of those checks issue nothing at all -- once
        `deny_service_confused_deputy` has swept SQS and IAM role trust
        policies, `deny_sqs_third_party_access` and
        `deny_sts_third_party_assumerole` are served entirely from the memo.
        Which check pays is registry order; that no triple repeats is not.
        """
        operations: List[Operation] = []

        def build_client(service_name: str, region_name: str = "") -> _RecordingClient:
            return _RecordingClient(service_name, region_name, operations)

        session = MagicMock()
        session.client.side_effect = build_client

        for check_class in get_all_check_classes():
            check_class(
                check_name=check_class.CHECK_NAME,
                account_name="account-0",
                account_id="111111111111",
                results_dir="/dev/null",
                org_account_ids=ORG_ACCOUNT_IDS,
                org_id=ORG_ID,
                exclude_account_ids=False,
            ).analyze(session)

        repeated = sorted(
            f"{service} {region or 'global'} {operation} x{count}"
            for (service, region, operation), count in Counter(operations).items()
            if count > 1
        )

        assert repeated == []
        assert operations, "no check issued an operation; the harness is not exercising them"
