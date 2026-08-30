"""Tests for the deny_service_confused_deputy RCP check."""

import tempfile
from typing import Any, Dict, Iterator, List
from unittest.mock import MagicMock, patch

import pytest

from headroom.aws.policy_documents import (
    ServicePrincipalSource,
    unreadable_service_principal_source,
)
from headroom.checks.rcps.deny_service_confused_deputy import (
    DenyServiceConfusedDeputyCheck,
)
from tests.constants import ORG_ID

ORG_ACCOUNTS = {"111111111111"}
THIRD_PARTY = "999999999999"

ANALYZERS = [
    "analyze_ecr_policies",
    "analyze_kms_key_policies",
    "analyze_s3_bucket_policies",
    "analyze_secrets_manager_policies",
    "analyze_sqs_queue_policies",
    "analyze_iam_roles_trust_policies",
]

# One out-of-organization account per analyzer, deliberately not in ascending
# order, so an assertion on the allowlist pins the sort as well as the union.
ACCOUNT_BY_ANALYZER = {
    "analyze_ecr_policies": "777777777777",
    "analyze_kms_key_policies": "222222222222",
    "analyze_s3_bucket_policies": "666666666666",
    "analyze_secrets_manager_policies": "333333333333",
    "analyze_sqs_queue_policies": "555555555555",
    "analyze_iam_roles_trust_policies": "444444444444",
}


@pytest.fixture
def temp_results_dir() -> Iterator[str]:
    """Provide a throwaway results directory."""
    with tempfile.TemporaryDirectory() as directory:
        yield directory


def _source(
    service: str = "sns.amazonaws.com",
    accounts: List[str] | None = None,
    has_condition: bool = True,
    wildcard: bool = False,
) -> ServicePrincipalSource:
    """Build one ServicePrincipalSource with sensible defaults."""
    return ServicePrincipalSource(
        service_principal=service,
        source_account_ids=accounts if accounts is not None else [],
        has_source_condition=has_condition,
        has_wildcard_source=wildcard,
    )


def _sqs_analysis(sources: List[ServicePrincipalSource]) -> MagicMock:
    """Build a stand-in SQS analysis carrying the given sources."""
    analysis = MagicMock()
    analysis.service_principal_sources = sources
    analysis.queue_arn = "arn:aws:sqs:us-west-2:111111111111:a-queue"
    analysis.region = "us-west-2"
    return analysis


def _run(temp_results_dir: str, sqs_sources: List[ServicePrincipalSource]) -> Dict[str, Any]:
    """
    Execute the check with only SQS returning findings.

    Returns the results payload the check wrote.
    """
    module = "headroom.checks.rcps.deny_service_confused_deputy"
    check = DenyServiceConfusedDeputyCheck(
        check_name="deny_service_confused_deputy",
        account_name="test-account",
        account_id="111111111111",
        results_dir=temp_results_dir,
        org_account_ids=ORG_ACCOUNTS,
        org_id=ORG_ID,
    )

    with patch(f"{module}.analyze_sqs_queue_policies") as mock_sqs:
        mock_sqs.return_value = [_sqs_analysis(sqs_sources)]

        patches = [
            patch(f"{module}.{name}", return_value=[])
            for name in ANALYZERS
            if name != "analyze_sqs_queue_policies"
        ]
        for entered in patches:
            entered.start()
        try:
            # write_check_results is imported by headroom/checks/base.py:17,
            # so that is where it must be patched
            with patch("headroom.checks.base.write_check_results") as mock_write:
                check.execute(MagicMock())
        finally:
            for entered in patches:
                entered.stop()

    results_data: Dict[str, Any] = mock_write.call_args[1]["results_data"]
    return results_data


def _analysis(**fields: Any) -> MagicMock:
    """Build a stand-in analysis carrying the given attributes."""
    analysis = MagicMock()
    for name, value in fields.items():
        setattr(analysis, name, value)
    return analysis


def _run_many(
    temp_results_dir: str,
    analyses_by_analyzer: Dict[str, List[MagicMock]],
) -> Dict[str, Any]:
    """
    Execute the check with several analyzers each returning findings.

    Any analyzer the mapping does not name returns nothing.

    Returns the results payload the check wrote.
    """
    module = "headroom.checks.rcps.deny_service_confused_deputy"
    check = DenyServiceConfusedDeputyCheck(
        check_name="deny_service_confused_deputy",
        account_name="test-account",
        account_id="111111111111",
        results_dir=temp_results_dir,
        org_account_ids=ORG_ACCOUNTS,
        org_id=ORG_ID,
    )

    patches = [
        patch(f"{module}.{name}", return_value=analyses_by_analyzer.get(name, []))
        for name in ANALYZERS
    ]
    for entered in patches:
        entered.start()
    try:
        with patch("headroom.checks.base.write_check_results") as mock_write:
            check.execute(MagicMock())
    finally:
        for entered in patches:
            entered.stop()

    results_data: Dict[str, Any] = mock_write.call_args[1]["results_data"]
    return results_data


def _run_single_analyzer(
    temp_results_dir: str, analyzer_name: str, analysis: MagicMock
) -> Dict[str, Any]:
    """
    Execute the check with only the named analyzer returning a finding.

    The other five analyzers return nothing, isolating which analyzer fed
    the resulting finding.

    Returns the results payload the check wrote.
    """
    return _run_many(temp_results_dir, {analyzer_name: [analysis]})


class TestServiceConfusedDeputyCheck:
    """Test categorization, filtering, and summary fields."""

    def test_third_party_source_reaches_the_allowlist(
        self, temp_results_dir: str
    ) -> None:
        """A guarded out-of-org source is what the allowlist carries."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        assert data["summary"]["unique_third_party_accounts"] == [THIRD_PARTY]
        assert data["summary"]["third_party_account_count"] == 1

    def test_a_guarded_source_is_not_a_violation(
        self, temp_results_dir: str
    ) -> None:
        """An expressible source costs the account no RCP coverage."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        assert data["summary"]["violations"] == 0

    def test_a_wildcard_source_is_a_violation(
        self, temp_results_dir: str
    ) -> None:
        """No allowlist can express an unbounded source set."""
        data = _run(temp_results_dir, [_source(wildcard=True)])

        assert data["summary"]["violations"] == 1

    def test_unguarded_sources_reach_nothing(
        self, temp_results_dir: str
    ) -> None:
        """
        An unguarded service principal produces no finding.

        The policy names no account, so there is none to allowlist and
        none to report. Listing these would put every service role trust
        policy in the account into the results. The trust is still within
        the statement's reach once deployed, which the rollout guidance
        covers with CloudTrail rather than with this output.
        """
        data = _run(temp_results_dir, [_source(has_condition=False)])

        assert data["summary"]["violations"] == 0
        assert data["summary"]["unique_third_party_accounts"] == []
        assert data["compliant_instances"] == []

    def test_two_findings_union_their_accounts(
        self, temp_results_dir: str
    ) -> None:
        """
        The allowlist is the union across every finding, sorted.

        This value decides whether a production integration keeps working
        once the Deny is deployed, so the accumulation across findings is
        pinned rather than left to inspection.
        """
        data = _run(temp_results_dir, [
            _source(accounts=["999999999999", "888888888888"]),
            _source(service="events.amazonaws.com", accounts=["999999999999", "777777777777"]),
        ])

        assert data["summary"]["unique_third_party_accounts"] == [
            "777777777777",
            "888888888888",
            "999999999999",
        ]
        assert data["summary"]["third_party_account_count"] == 3

    def test_a_mixed_guard_both_allowlists_and_violates(
        self, temp_results_dir: str
    ) -> None:
        """
        One statement can occupy two disposition rows at once.

        `aws:SourceAccount` holding `["*", "999999999999"]` resolves the
        out-of-organization account and sets the wildcard flag. The account
        is unioned into the allowlist before the wildcard branch runs, so
        the finding contributes an allowlist entry and files a violation.
        The violation governs: the statement is withheld from the account
        regardless of what it contributed.
        """
        data = _run(temp_results_dir, [
            _source(accounts=[THIRD_PARTY], wildcard=True)
        ])

        assert data["summary"]["unique_third_party_accounts"] == [THIRD_PARTY]
        assert data["summary"]["violations"] == 1
        assert data["violations"][0]["source_account_ids"] == [THIRD_PARTY]
        assert data["violations"][0]["has_wildcard_source"] is True

    def test_a_read_failure_is_a_violation(
        self, temp_results_dir: str
    ) -> None:
        """
        A guard nobody could read withholds the statement.

        The shared parser records the failure rather than raising, so the
        six pre-existing checks that share its analyzers keep running. This
        check turns the record into a violation, which is what stops a Deny
        from deploying against an allowlist that could not be computed.
        """
        data = _run(temp_results_dir, [
            unreadable_service_principal_source("aws:SourceAccount under StringNotEquals does not pin the source")
        ])

        assert data["summary"]["violations"] == 1
        assert data["summary"]["unique_third_party_accounts"] == []

        violation = data["violations"][0]
        assert violation["read_failure"] == "aws:SourceAccount under StringNotEquals does not pin the source"
        assert violation["service_principal"] is None

    def test_a_readable_finding_records_no_read_failure(
        self, temp_results_dir: str
    ) -> None:
        """The failure field is null on every finding the parser could read."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        assert data["compliant_instances"][0]["read_failure"] is None

    def test_the_finding_names_its_resource(
        self, temp_results_dir: str
    ) -> None:
        """A finding without its resource cannot be acted on."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        # The base _build_results_data names this key compliant_instances
        finding = data["compliant_instances"][0]
        assert finding["resource_type"] == "sqs"
        assert finding["resource_identifier"].endswith("a-queue")
        assert finding["region"] == "us-west-2"
        assert finding["service_principal"] == "sns.amazonaws.com"
        assert finding["source_account_ids"] == [THIRD_PARTY]


class TestTheAllowlistAccumulatesAcrossTheEstate:
    """
    `unique_third_party_accounts` is the union over every resource found.

    It becomes the deployed statement's `aws:SourceAccount` allowlist, so an
    account dropped here is a working integration the RCP denies on apply.
    Every other test in this file feeds a single analyzer a single resource;
    these pin the accumulation across the six loops in `analyze()` and across
    resources within one loop.
    """

    def test_every_analyzer_contributes_to_one_allowlist(
        self, temp_results_dir: str
    ) -> None:
        """
        All six analyzers' accounts land in one sorted allowlist.

        The analysis carries every identifier field, so one stand-in serves
        whichever analyzer is reading it.
        """
        data = _run_many(temp_results_dir, {
            name: [_analysis(
                service_principal_sources=[_source(accounts=[account])],
                repository_name="a-repo",
                key_id="a-key",
                bucket_name="a-bucket",
                secret_name="a-secret",
                queue_arn="arn:aws:sqs:us-west-2:111111111111:a-queue",
                role_name="a-role",
                region="us-west-2",
            )]
            for name, account in ACCOUNT_BY_ANALYZER.items()
        })

        assert data["summary"]["unique_third_party_accounts"] == [
            "222222222222",
            "333333333333",
            "444444444444",
            "555555555555",
            "666666666666",
            "777777777777",
        ]
        assert data["summary"]["third_party_account_count"] == 6
        assert len(data["compliant_instances"]) == 6

    def test_two_resources_from_one_analyzer_both_contribute(
        self, temp_results_dir: str
    ) -> None:
        """
        One analyzer returning two resources contributes both accounts.

        `test_two_findings_union_their_accounts` puts two sources on a
        single queue; this puts one source on each of two queues, which is
        the other way a single loop accumulates.
        """
        data = _run_many(temp_results_dir, {
            "analyze_sqs_queue_policies": [
                _analysis(
                    service_principal_sources=[_source(accounts=["888888888888"])],
                    queue_arn="arn:aws:sqs:us-west-2:111111111111:first-queue",
                    region="us-west-2",
                ),
                _analysis(
                    service_principal_sources=[_source(accounts=["222222222222"])],
                    queue_arn="arn:aws:sqs:us-west-2:111111111111:second-queue",
                    region="us-west-2",
                ),
            ],
        })

        assert data["summary"]["unique_third_party_accounts"] == [
            "222222222222",
            "888888888888",
        ]
        assert [
            finding["resource_identifier"]
            for finding in data["compliant_instances"]
        ] == [
            "arn:aws:sqs:us-west-2:111111111111:first-queue",
            "arn:aws:sqs:us-west-2:111111111111:second-queue",
        ]

    def test_the_same_account_from_two_analyzers_appears_once(
        self, temp_results_dir: str
    ) -> None:
        """
        One third party reached through two services is one allowlist entry.

        The allowlist is keyed on the account, not on the resource that
        exposed it, so a vendor holding both a repository and a role costs
        the statement one entry while still being reported twice.
        """
        data = _run_many(temp_results_dir, {
            "analyze_ecr_policies": [_analysis(
                service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                repository_name="a-repo",
                region="us-east-1",
            )],
            "analyze_iam_roles_trust_policies": [_analysis(
                service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                role_name="a-role",
            )],
        })

        assert data["summary"]["unique_third_party_accounts"] == [THIRD_PARTY]
        assert data["summary"]["third_party_account_count"] == 1
        assert len(data["compliant_instances"]) == 2


class TestEveryAnalyzerFeedsTheCheck:
    """Each of the six analyzers must reach analyze()'s findings list."""

    def test_ecr_finding_names_its_repository(self, temp_results_dir: str) -> None:
        """A repository policy's finding names that repository."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            repository_name="a-repo",
            region="us-east-1",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_ecr_policies", analysis)

        finding = data["compliant_instances"][0]
        assert finding["resource_type"] == "ecr"
        assert finding["resource_identifier"] == "a-repo"
        assert finding["region"] == "us-east-1"

    def test_ecr_registry_policy_falls_back_to_registry(
        self, temp_results_dir: str
    ) -> None:
        """A registry policy names no repository, so the finding says so."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            repository_name=None,
            region="us-east-1",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_ecr_policies", analysis)

        finding = data["compliant_instances"][0]
        assert finding["resource_identifier"] == "registry"

    def test_kms_finding_names_its_key(self, temp_results_dir: str) -> None:
        """A key policy's finding names that key."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            key_id="a-key",
            region="us-east-1",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_kms_key_policies", analysis)

        finding = data["compliant_instances"][0]
        assert finding["resource_type"] == "kms"
        assert finding["resource_identifier"] == "a-key"
        assert finding["region"] == "us-east-1"

    def test_s3_finding_names_its_bucket_with_no_region(
        self, temp_results_dir: str
    ) -> None:
        """A bucket policy's finding names that bucket; S3 is global."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            bucket_name="a-bucket",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_s3_bucket_policies", analysis)

        finding = data["compliant_instances"][0]
        assert finding["resource_type"] == "s3"
        assert finding["resource_identifier"] == "a-bucket"
        assert finding["region"] is None

    def test_secretsmanager_finding_names_its_secret_with_no_region(
        self, temp_results_dir: str
    ) -> None:
        """A secret policy's finding names that secret; Secrets Manager is global."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            secret_name="a-secret",
        )
        data = _run_single_analyzer(
            temp_results_dir, "analyze_secrets_manager_policies", analysis
        )

        finding = data["compliant_instances"][0]
        assert finding["resource_type"] == "secretsmanager"
        assert finding["resource_identifier"] == "a-secret"
        assert finding["region"] is None

    def test_iam_finding_names_its_role_with_no_region(
        self, temp_results_dir: str
    ) -> None:
        """A trust policy's finding names that role; IAM is global."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            role_name="a-role",
        )
        data = _run_single_analyzer(
            temp_results_dir, "analyze_iam_roles_trust_policies", analysis
        )

        finding = data["compliant_instances"][0]
        assert finding["resource_type"] == "iam"
        assert finding["resource_identifier"] == "a-role"
        assert finding["region"] is None
