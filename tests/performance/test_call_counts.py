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

`TestOrganizationsIsReadOnce` is a third contract, not a per-account memo: it
pins the one-time organization read that replaced four independent ones. One
test counts the management-role assumptions and discovery calls a run makes;
the other drives a real discovery against a recording client, hands the
resulting snapshot to every projection and to the org-info render, and
asserts the client sees no further call. Together they cover both ways the
property could regress: an added call site, or a consumer that re-reads
instead of reusing what discovery captured.
"""

from collections import Counter, defaultdict
from typing import Any, Callable, DefaultDict, Dict, List, Sequence, Set, Tuple
from unittest.mock import MagicMock, Mock, patch

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
from headroom.aws.organization_snapshot import discover_organization
from headroom.aws.s3 import analyze_s3_bucket_policies
from headroom.aws.secretsmanager import analyze_secrets_manager_policies
from headroom.aws.sqs import analyze_sqs_queue_policies
from headroom.checks.registry import get_all_check_classes
from headroom.config import AccountTagLayout, HeadroomConfig
from headroom.main import main
from headroom.terraform.generate_org_info import render_terraform_org_info
from headroom.types import OrganizationHierarchy, OrganizationSnapshot

ORG_ACCOUNT_IDS = {"111111111111"}
ORG_ID = "o-11111111111"

# One AWS API call, as the repeat guard counts it: which client issued it
# and what it asked for. Region is "" for a global service.
Operation = Tuple[str, str, str]

# The analyzers `deny_service_confused_deputy` shares with a third-party-access
# check, each therefore invoked twice per account.
SHARED_ANALYZERS: List[Callable[[MagicMock, Set[str], str], Sequence[Any]]] = [
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

        `deny_service_confused_deputy` shares six analyzers with the
        resource-specific third-party-access checks, and which of a pair pays
        is registry order rather than design. It runs fourteenth of sixteen,
        so ECR, KMS, S3 and Secrets Manager are already in the memo by the
        time it asks; SQS and IAM role trust policies it reads first, and
        `deny_sqs_third_party_access` and `deny_sts_third_party_assumerole`
        are the ones served from memory. Four of the six sweep every enabled
        region, so before the memo an account paid four extra region sweeps --
        the same waste as the four identical EC2 sweeps above, reintroduced by
        a check added later.

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
        session = _session([_empty_response()])

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

    Every listing comes back empty, which keeps the log to entry points. That
    is the boundary rather than a shortcut. A per-resource follow-up like
    `get_bucket_policy` is issued from inside one analyzer, and the memo
    already guarantees that analyzer runs at most once per account, so the
    only way one could repeat is two analyzers reading the same resource --
    and that requires repeating the listing that found it, which is an entry
    point this does log. Filling the listings would make the stand-in
    service-aware, hand-enumerating a response shape per service, which is
    the property this class exists to avoid.
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

        Measured on the registry as it stands: 35 operations, 35 distinct,
        and five of the sixteen checks issue nothing at all. Three are EC2:
        `deny_ec2_ami_owner` sweeps first and fills the instance memo, so
        `deny_ec2_imds_hop_limit`, `deny_ec2_imds_v1` and
        `deny_ec2_public_ip` reach AWS not at all. The other two are
        `deny_sqs_third_party_access` and `deny_sts_third_party_assumerole`,
        served from the analyzer memo once `deny_service_confused_deputy` has
        swept SQS and IAM role trust policies. Which check pays is registry
        order; that no triple repeats is not.
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


class _RecordingOrganizationsClient(Mock):
    """
    An Organizations client that logs every operation asked of it.

    Subclasses `Mock` rather than standing alone: `discover_organization`
    types its client parameter as the real boto3-stubs `OrganizationsClient`,
    a concrete class not a protocol, so an unrelated plain class fails mypy's
    argument check. A `Mock` subclass is what the two AWS-side call sites of
    this pattern already use for the same reason -- `_org_client` in
    `tests/test_aws_organization_snapshot.py` and its similarly-named sibling
    in `tests/test_aws_organization.py`. `get_paginator` and
    `describe_organization` are overridden below; every other attribute this
    client is asked for resolves through Mock's own auto-attribute behavior.
    """
    ACCOUNTS: List[Dict[str, str]] = [
        {"Id": "111111111111", "Name": "management", "Status": "ACTIVE"},
        {"Id": "222222222222", "Name": "payments", "Status": "ACTIVE"},
    ]

    def __init__(self) -> None:
        super().__init__()
        self.operations: List[str] = []

    def get_paginator(self, operation_name: str) -> Mock:
        """Log the paginated operation and hand back this fixture's pages."""
        self.operations.append(operation_name)
        paginator = Mock()

        def paginate_op(**kwargs: str) -> List[Dict[str, Any]]:
            if operation_name == "list_accounts":
                return [{"Accounts": self.ACCOUNTS}]
            if operation_name == "list_roots":
                return [{"Roots": [{"Id": "r-1111"}]}]
            if operation_name == "list_tags_for_resource":
                return [{"Tags": []}]
            if operation_name == "list_organizational_units_for_parent":
                return [{"OrganizationalUnits": []}]
            return [{"Accounts": self.ACCOUNTS if kwargs["ParentId"] == "r-1111" else []}]

        paginator.paginate.side_effect = paginate_op
        return paginator

    def describe_organization(self) -> Dict[str, Any]:
        """Log the call and report the one organization this fixture has."""
        self.operations.append("describe_organization")
        return {"Organization": {"Id": ORG_ID}}


def _snapshot_config() -> HeadroomConfig:
    """A configuration whose management account is the first fixture account."""
    return HeadroomConfig(
        management_account_id="111111111111",
        security_analysis_account_id="222222222222",
        use_account_name_from_tags=False,
        account_tag_layout=AccountTagLayout(environment="Env", name="Name", owner="Owner"),
    )


class TestOrganizationsIsReadOnce:
    """One run, one management assumption, one discovery pass."""

    def test_main_assumes_management_and_discovers_exactly_once(self) -> None:
        """
        A run used to assume the management role four times and enumerate the
        organization twice, from four call sites that could each see a
        different organization.
        """
        snapshot = OrganizationSnapshot(
            organization_id=ORG_ID,
            member_account_ids=frozenset({"111111111111"}),
            analyzable_accounts=(),
            hierarchy=OrganizationHierarchy(
                root_id="r-1111", organizational_units={}, accounts={}
            ),
        )

        with patch("headroom.main.get_security_analysis_session") as security, \
             patch("headroom.main.get_management_account_session") as management, \
             patch("headroom.main.discover_organization", return_value=snapshot) as discover, \
             patch("headroom.main.perform_analysis"), \
             patch("headroom.main.parse_cli_args"), \
             patch("headroom.main.load_yaml_config"), \
             patch("headroom.main.setup_configuration", return_value=_snapshot_config()), \
             patch("headroom.main.handle_scp_workflow", return_value=[]), \
             patch("headroom.main.handle_rcp_workflow", return_value=[]), \
             patch("headroom.main.compile_terraform_plan"), \
             patch("headroom.main.apply_terraform_plan"):
            main()

        assert security.call_count == 1
        assert management.call_count == 1
        assert discover.call_count == 1

    def test_reusing_the_snapshot_reads_no_more_organizations_data(self) -> None:
        """
        Every projection and the org-info render come from what was captured.
        A consumer that refreshed would reintroduce the inconsistency.

        The expected value below is a literal, not a copy of
        `org_client.operations` taken right after discovery. Nothing between
        that capture and an assertion against it could ever add an
        operation -- the four projection reads are plain attribute access on
        a frozen dataclass, and `render_terraform_org_info` takes no
        client -- so a captured-copy comparison would hold no matter what
        discovery read or what a consumer read afterward: it would compare
        the list to itself. The literal is this fixture's whole call log,
        hand-traced against `discover_organization`: one
        `describe_organization`, one paginated `list_accounts`, one
        `list_roots`, one OU traversal of the fixture's single parent (the
        root) -- `list_organizational_units_for_parent` then
        `list_accounts_for_parent`, each once, not the twice a recursive
        traversal used to cost -- and one `list_tags_for_resource`, because
        `management` is excluded from analysis and only `payments` is
        tagged. A regression in discovery's count or order changes this
        list; a consumer that re-reads Organizations appends to it.
        """
        org_client = _RecordingOrganizationsClient()
        snapshot = discover_organization(_snapshot_config(), org_client)

        _ = snapshot.organization_id
        _ = snapshot.member_account_ids
        _ = snapshot.analyzable_accounts
        _ = snapshot.hierarchy
        render_terraform_org_info(snapshot.hierarchy)

        assert org_client.operations == [
            "describe_organization",
            "list_accounts",
            "list_roots",
            "list_organizational_units_for_parent",
            "list_accounts_for_parent",
            "list_tags_for_resource",
        ]
