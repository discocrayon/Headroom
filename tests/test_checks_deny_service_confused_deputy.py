"""Tests for the deny_service_confused_deputy RCP check."""

import ast
import inspect
import json
import tempfile
import textwrap
from typing import Dict, Iterator, List, cast
from unittest.mock import MagicMock, patch

import pytest

from headroom.aws.policy_documents import (
    ServicePrincipalSource,
    unreadable_service_principal_source,
)
from headroom.checks.rcps.deny_service_confused_deputy import (
    DenyServiceConfusedDeputyCheck,
)
from headroom.types import JsonDict
from tests.constants import ORG_ID
from tests.test_aws_helpers import analyzers_producing_service_principal_sources

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


def _summary(data: JsonDict) -> JsonDict:
    """The summary block of a result document the check wrote."""
    return cast(JsonDict, data["summary"])


def _entries(data: JsonDict, key: str) -> List[JsonDict]:
    """One of the entry lists of a result document the check wrote."""
    return cast(List[JsonDict], data[key])


def _run(temp_results_dir: str, sqs_sources: List[ServicePrincipalSource]) -> JsonDict:
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

    results_data: JsonDict = mock_write.call_args[1]["results_data"]
    return results_data


def _analysis(**fields: object) -> MagicMock:
    """
    Build a stand-in analysis carrying exactly the given attributes.

    A read of any attribute the caller did not name raises, so a stand-in
    cannot pass a test by handing the check a `MagicMock` where the check
    reads a real field.
    """
    return MagicMock(spec_set=list(fields), **fields)


def _run_many(
    temp_results_dir: str,
    analyses_by_analyzer: Dict[str, List[MagicMock]],
) -> JsonDict:
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

    results_data: JsonDict = mock_write.call_args[1]["results_data"]
    return results_data


def _sqs_session(policy: JsonDict) -> MagicMock:
    """
    Build a boto3 session stand-in serving one queue carrying the policy.

    The real SQS analyzer and the shared source reader run against it, so a
    check executed with this session pins the path from policy document to
    finding with nothing in between replaced.
    """
    session = MagicMock()
    ec2_client = MagicMock()
    sqs_client = MagicMock()
    session.client.side_effect = lambda service, **kwargs: {
        "ec2": ec2_client,
        "sqs": sqs_client,
    }[service]
    ec2_client.describe_regions.return_value = {
        "Regions": [{"RegionName": "us-west-2"}]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"QueueUrls": ["https://sqs.us-west-2.amazonaws.com/111111111111/a-queue"]}
    ]
    sqs_client.get_paginator.return_value = paginator
    sqs_client.get_queue_attributes.return_value = {
        "Attributes": {
            "Policy": json.dumps(policy),
            "QueueArn": "arn:aws:sqs:us-west-2:111111111111:a-queue",
        }
    }
    return session


def _run_sqs_policy(temp_results_dir: str, policy: JsonDict) -> JsonDict:
    """
    Execute the check with the real SQS analyzer reading one queue policy.

    The other five analyzers return nothing.

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
        patch(f"{module}.{name}", return_value=[])
        for name in ANALYZERS
        if name != "analyze_sqs_queue_policies"
    ]
    for entered in patches:
        entered.start()
    try:
        with patch("headroom.checks.base.write_check_results") as mock_write:
            check.execute(_sqs_session(policy))
    finally:
        for entered in patches:
            entered.stop()

    results_data: JsonDict = mock_write.call_args[1]["results_data"]
    return results_data


def _run_single_analyzer(
    temp_results_dir: str, analyzer_name: str, analysis: MagicMock
) -> JsonDict:
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

        assert _summary(data)["unique_third_party_accounts"] == [THIRD_PARTY]
        assert _summary(data)["third_party_account_count"] == 1

    def test_a_guarded_source_is_not_a_violation(
        self, temp_results_dir: str
    ) -> None:
        """An expressible source costs the account no RCP coverage."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        assert _summary(data)["violations"] == 0

    def test_a_wildcard_source_is_a_violation(
        self, temp_results_dir: str
    ) -> None:
        """No allowlist can express an unbounded source set."""
        data = _run(temp_results_dir, [_source(wildcard=True)])

        assert _summary(data)["violations"] == 1

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

        assert _summary(data)["violations"] == 0
        assert _summary(data)["unique_third_party_accounts"] == []
        assert _entries(data, "compliant_instances") == []

    def test_analyze_keeps_exactly_what_the_shared_predicate_accepts(
        self, temp_results_dir: str
    ) -> None:
        """
        The check does not restate the retention rule; it delegates.

        `is_actionable_service_principal_source` is the per-source predicate
        the five filtering adapters apply with `any`, and this check filters
        every source through that same predicate. Forcing the predicate both
        ways is what shows the check keeps no second copy of the rule: a
        source the real predicate accepts is dropped when the predicate says
        no, and one the real predicate drops is kept when it says yes.
        """
        predicate = (
            "headroom.checks.rcps.deny_service_confused_deputy"
            ".is_actionable_service_principal_source"
        )

        with patch(predicate, return_value=False):
            rejected = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        assert rejected["violations"] == []
        assert rejected["compliant_instances"] == []

        with patch(predicate, return_value=True):
            accepted = _run(temp_results_dir, [_source(accounts=[], has_condition=False)])

        assert len(_entries(accepted, "compliant_instances")) == 1

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

        assert _summary(data)["unique_third_party_accounts"] == [
            "777777777777",
            "888888888888",
            "999999999999",
        ]
        assert _summary(data)["third_party_account_count"] == 3

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

        assert _summary(data)["unique_third_party_accounts"] == [THIRD_PARTY]
        assert _summary(data)["violations"] == 1
        assert _entries(data, "violations")[0]["source_account_ids"] == [THIRD_PARTY]
        assert _entries(data, "violations")[0]["has_wildcard_source"] is True

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

        assert _summary(data)["violations"] == 1
        assert _summary(data)["unique_third_party_accounts"] == []

        violation = _entries(data, "violations")[0]
        assert violation["read_failure"] == "aws:SourceAccount under StringNotEquals does not pin the source"
        assert violation["service_principal"] is None

    def test_a_wildcard_source_is_counted_as_one(
        self, temp_results_dir: str
    ) -> None:
        """
        The wildcard cause is counted apart from the violation total.

        `sources_with_wildcard_source` isolates the guards an allowlist can
        never express, so a rollout can tell this cause apart from a failed
        read without re-deriving it from the violation list. The zero on
        the failed-read count here pins that the two causes are not
        conflated.
        """
        data = _run(temp_results_dir, [_source(wildcard=True)])

        assert _summary(data)["sources_with_wildcard_source"] == 1
        assert _summary(data)["sources_with_failed_read"] == 0

    def test_a_failed_read_is_counted_as_one(
        self, temp_results_dir: str
    ) -> None:
        """
        The failed-read cause is counted apart from the wildcard cause.

        `sources_with_failed_read` isolates guards the parser could not
        read at all, which is a different reason to withhold the statement
        than a guard the parser read but could not express as an
        allowlist. The zero on the wildcard count here pins that the two
        causes are not conflated.
        """
        data = _run(temp_results_dir, [
            unreadable_service_principal_source(
                "aws:SourceAccount under StringNotEquals does not pin the source"
            )
        ])

        assert _summary(data)["sources_with_failed_read"] == 1
        assert _summary(data)["sources_with_wildcard_source"] == 0

    def test_the_two_causes_partition_the_violations(
        self, temp_results_dir: str
    ) -> None:
        """
        The two per-cause counts add up to the violation total, with no overlap.

        `unreadable_service_principal_source` is the real constructor for a
        failed read, and it hardcodes `has_wildcard_source=False`, so a
        failed read never also carries a wildcard. That is what lets the
        two counts partition the violations rather than merely bound them.
        """
        data = _run(temp_results_dir, [
            _source(wildcard=True),
            unreadable_service_principal_source(
                "aws:SourceAccount under StringNotEquals does not pin the source"
            ),
            _source(accounts=[THIRD_PARTY]),
        ])

        summary = _summary(data)
        assert summary["violations"] == 2
        assert summary["sources_with_wildcard_source"] == 1
        assert summary["sources_with_failed_read"] == 1
        assert summary["sources_with_wildcard_source"] + summary["sources_with_failed_read"] == summary["violations"]

    def test_a_source_with_both_causes_is_counted_once(
        self, temp_results_dir: str
    ) -> None:
        """
        A source carrying both causes is counted under exactly one of them.

        No constructor builds a source with both flags, so this fixture is
        the case the partition must survive by construction rather than by
        convention. A failed read names the cause, because the guard is
        unknown, which subsumes what a wildcard would say.
        """
        data = _run(temp_results_dir, [
            ServicePrincipalSource(
                service_principal=None,
                source_account_ids=[],
                has_source_condition=False,
                has_wildcard_source=True,
                read_failure="could not be read",
            ),
        ])

        summary = _summary(data)
        assert summary["violations"] == 1
        assert summary["sources_with_failed_read"] == 1
        assert summary["sources_with_wildcard_source"] == 0

    def test_an_if_exists_guard_on_a_source_arn_is_counted_as_a_wildcard(
        self, temp_results_dir: str
    ) -> None:
        """
        An `...IfExists` guard on `aws:SourceArn` is a wildcard source.

        The guard names its source precisely, yet `ArnEqualsIfExists` is
        also satisfied by a request carrying no `aws:SourceArn` at all, and
        the deployed statement's `Null` clause spares that case only for
        `aws:SourceAccount`. That is the second `has_wildcard_source` row
        of the Decision table, and `sources_with_wildcard_source` counts it
        alongside the first.
        """
        data = _run_sqs_policy(temp_results_dir, {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-west-2:111111111111:a-queue",
                    "Condition": {"ArnEqualsIfExists": {
                        "aws:SourceArn": "arn:aws:sns:us-west-2:999999999999:a-topic"
                    }},
                },
            ],
        })

        assert _summary(data)["violations"] == 1
        assert _summary(data)["sources_with_wildcard_source"] == 1

    def test_a_foreign_organization_scope_is_counted_as_a_wildcard(
        self, temp_results_dir: str
    ) -> None:
        """
        An organization scope naming another organization is a wildcard source.

        The allowlist holds account IDs, and another organization's accounts
        are not knowable from here, so the guard names a source set no
        allowlist can enumerate. That is the first `has_wildcard_source` row
        of the Decision table, which `sources_with_wildcard_source` counts.
        """
        data = _run_sqs_policy(temp_results_dir, {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-west-2:111111111111:a-queue",
                    "Condition": {"StringEquals": {
                        "aws:SourceOrgID": "o-22222222222"
                    }},
                },
            ],
        })

        assert _summary(data)["violations"] == 1
        assert _summary(data)["sources_with_wildcard_source"] == 1

    def test_a_wildcard_guard_counts_one_entry_per_service_principal(
        self, temp_results_dir: str
    ) -> None:
        """
        A readable statement counts one entry per service principal it names.

        One Condition block guards every principal in its statement, so a
        statement trusting three services under one guard no allowlist can
        express is three entries: `sources_with_wildcard_source` counts
        service principals, not statements. The single queue carrying them
        is still one resource.
        """
        data = _run_sqs_policy(temp_results_dir, {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": [
                        "sns.amazonaws.com",
                        "events.amazonaws.com",
                        "s3.amazonaws.com",
                    ]},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-west-2:111111111111:a-queue",
                    "Condition": {"ArnEqualsIfExists": {
                        "aws:SourceArn": "arn:aws:sns:us-west-2:999999999999:a-topic"
                    }},
                },
            ],
        })

        summary = _summary(data)
        assert summary["violations"] == 3
        assert summary["sources_with_wildcard_source"] == 3
        assert summary["sources_with_failed_read"] == 0
        assert summary["resources_with_actionable_source"] == 1

    def test_a_failed_read_counts_one_entry_per_statement(
        self, temp_results_dir: str
    ) -> None:
        """
        An unreadable statement counts one entry, whatever it trusts.

        The reader resolves all three service principals first, then reads
        the guard, which raises; the error is caught at statement scope, so
        the resolved principals are discarded and one entry stands for the
        whole statement. That is why the same three-service statement
        yields one entry rather than three: `sources_with_failed_read`
        counts statements, not the service principals they name.
        """
        data = _run_sqs_policy(temp_results_dir, {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": [
                        "sns.amazonaws.com",
                        "events.amazonaws.com",
                        "s3.amazonaws.com",
                    ]},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-west-2:111111111111:a-queue",
                    "Condition": {"StringNotEquals": {
                        "aws:SourceAccount": THIRD_PARTY
                    }},
                },
            ],
        })

        summary = _summary(data)
        assert summary["violations"] == 1
        assert summary["sources_with_failed_read"] == 1
        assert summary["sources_with_wildcard_source"] == 0

    def test_a_readable_finding_records_no_read_failure(
        self, temp_results_dir: str
    ) -> None:
        """The failure field is null on every finding the parser could read."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        assert _entries(data, "compliant_instances")[0]["read_failure"] is None

    def test_a_source_pinned_only_on_a_deny_statement_is_not_recorded(
        self, temp_results_dir: str
    ) -> None:
        """
        An unguarded Allow to the service beside a Deny pinning the source.

        No adapter reads a Deny, so the account the pair permits reaches
        nothing, and the deployed statement denies the driver the policy
        named. This pins limitation 1 of the specification; lifting it is
        standing intent, and doing so flips this test.
        """
        data = _run_sqs_policy(temp_results_dir, {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-west-2:111111111111:a-queue",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-west-2:111111111111:a-queue",
                    "Condition": {"StringNotEquals": {"aws:SourceAccount": THIRD_PARTY}},
                },
            ],
        })

        assert _summary(data)["unique_third_party_accounts"] == []
        assert _summary(data)["violations"] == 0

    def test_the_finding_names_its_resource(
        self, temp_results_dir: str
    ) -> None:
        """A finding without its resource cannot be acted on."""
        data = _run(temp_results_dir, [_source(accounts=[THIRD_PARTY])])

        # The base _build_results_data names this key compliant_instances
        finding = _entries(data, "compliant_instances")[0]
        assert finding["resource_type"] == "sqs"
        assert finding["resource_identifier"] == "arn:aws:sqs:us-west-2:111111111111:a-queue"
        assert finding["region"] == "us-west-2"
        assert finding["service_principal"] == "sns.amazonaws.com"
        assert finding["source_account_ids"] == [THIRD_PARTY]

    def test_two_sources_on_one_resource_count_one_resource(
        self, temp_results_dir: str
    ) -> None:
        """
        Two sources trusted by one queue produce two findings, one resource.

        `resources_with_actionable_source` counts the queue once, not the
        two sources on it. The two-entry `compliant_instances` asserted
        alongside is what shows that difference.
        """
        data = _run(temp_results_dir, [
            _source(accounts=[THIRD_PARTY]),
            _source(service="events.amazonaws.com", accounts=["888888888888"]),
        ])

        assert len(_entries(data, "compliant_instances")) == 2
        assert _summary(data)["resources_with_actionable_source"] == 1

    def test_a_resource_with_only_violations_is_counted(
        self, temp_results_dir: str
    ) -> None:
        """
        A resource whose only finding is a violation still arrived.

        `resources_with_actionable_source` counts distinct resources over
        the violation entries as well as the compliant ones. This fixture's
        one finding is a wildcard source, which is a violation and leaves
        `compliant_instances` empty, so no compliant entry is left to mask
        a count taken over the wrong list.
        """
        data = _run(temp_results_dir, [_source(wildcard=True)])

        assert len(_entries(data, "violations")) == 1
        assert len(_entries(data, "compliant_instances")) == 0
        assert _summary(data)["resources_with_actionable_source"] == 1


class TestTheAllowlistAccumulatesAcrossTheEstate:
    """
    `unique_third_party_accounts` is the union over every resource found,
    and `resources_with_actionable_source` is the distinct count of them.

    The union becomes the deployed statement's `aws:SourceAccount` allowlist,
    so an account dropped here is a working integration the RCP denies on
    apply. Every other test in this file feeds a single analyzer a single
    resource; these pin the accumulation across the six loops in `analyze()`
    and across resources within one loop, and the three components of the
    resource key, each by a pair of resources that differ in that one alone.
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
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/a-repo",
                key_id="a-key",
                bucket_name="a-bucket",
                secret_name="a-secret",
                queue_arn="arn:aws:sqs:us-west-2:111111111111:a-queue",
                role_name="a-role",
                region="us-west-2",
            )]
            for name, account in ACCOUNT_BY_ANALYZER.items()
        })

        assert _summary(data)["unique_third_party_accounts"] == [
            "222222222222",
            "333333333333",
            "444444444444",
            "555555555555",
            "666666666666",
            "777777777777",
        ]
        assert _summary(data)["third_party_account_count"] == 6
        assert len(_entries(data, "compliant_instances")) == 6
        assert _summary(data)["resources_with_actionable_source"] == 6

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

        assert _summary(data)["unique_third_party_accounts"] == [
            "222222222222",
            "888888888888",
        ]
        assert [
            finding["resource_identifier"]
            for finding in _entries(data, "compliant_instances")
        ] == [
            "arn:aws:sqs:us-west-2:111111111111:first-queue",
            "arn:aws:sqs:us-west-2:111111111111:second-queue",
        ]

    def test_replica_secrets_in_two_regions_count_two_resources(
        self, temp_results_dir: str
    ) -> None:
        """
        Two replicas sharing a secret name are two resources, not one.

        Limitation 3 of
        spec/checks/rcps/deny_secrets_manager_third_party_access.md: a
        replica secret is enumerated once per region it replicates to, so
        one logical secret produces several findings that share a name.
        Keying on region as well as identifier is what keeps them apart.
        """
        data = _run_many(temp_results_dir, {
            "analyze_secrets_manager_policies": [
                _analysis(
                    service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                    secret_name="a-secret",
                    region="us-east-1",
                ),
                _analysis(
                    service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                    secret_name="a-secret",
                    region="us-west-2",
                ),
            ],
        })

        assert _summary(data)["resources_with_actionable_source"] == 2
        assert len(_entries(data, "compliant_instances")) == 2
        assert {
            entry["region"] for entry in _entries(data, "compliant_instances")
        } == {"us-east-1", "us-west-2"}
        assert {
            entry["resource_identifier"] for entry in _entries(data, "compliant_instances")
        } == {"a-secret"}

    def test_a_bucket_and_a_role_sharing_a_name_count_two_resources(
        self, temp_results_dir: str
    ) -> None:
        """
        A bucket and a role sharing a name are two resources, not one.

        S3 and IAM are both global, so each finding carries `region`
        None, and the two stand-ins here also share the identifier
        "shared-name". `resource_type` is the only field left to tell
        them apart, which is what this pins.
        """
        data = _run_many(temp_results_dir, {
            "analyze_s3_bucket_policies": [_analysis(
                service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                bucket_name="shared-name",
            )],
            "analyze_iam_roles_trust_policies": [_analysis(
                service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                role_name="shared-name",
            )],
        })

        assert len(_entries(data, "compliant_instances")) == 2
        assert _summary(data)["resources_with_actionable_source"] == 2

    def test_two_queues_in_one_region_count_two_resources(
        self, temp_results_dir: str
    ) -> None:
        """
        Two queues in one region are two resources, not one.

        They share `resource_type` and `region`; `resource_identifier` is
        the one component of the resource key left to tell them apart,
        which is what this pins.
        """
        data = _run_many(temp_results_dir, {
            "analyze_sqs_queue_policies": [
                _analysis(
                    service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                    queue_arn="arn:aws:sqs:us-west-2:111111111111:first-queue",
                    region="us-west-2",
                ),
                _analysis(
                    service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                    queue_arn="arn:aws:sqs:us-west-2:111111111111:second-queue",
                    region="us-west-2",
                ),
            ],
        })

        assert len(_entries(data, "compliant_instances")) == 2
        assert _summary(data)["resources_with_actionable_source"] == 2

    def test_a_repository_named_registry_is_not_the_registry(
        self, temp_results_dir: str
    ) -> None:
        """
        A repository may be named `registry`, and it is not the registry.

        Keying an ECR finding on the repository ARN keeps such a repository
        apart from the region's registry policy, which has no ARN and falls
        back to the literal `registry`. No ARN can equal that string, so the
        two are two resources however the repository is named.
        """
        data = _run_many(temp_results_dir, {
            "analyze_ecr_policies": [
                _analysis(
                    service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                    repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/registry",
                    region="us-east-1",
                ),
                _analysis(
                    service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                    repository_arn=None,
                    region="us-east-1",
                ),
            ],
        })

        assert _summary(data)["resources_with_actionable_source"] == 2
        assert {
            entry["resource_identifier"]
            for entry in _entries(data, "compliant_instances")
        } == {
            "registry",
            "arn:aws:ecr:us-east-1:111111111111:repository/registry",
        }

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
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/a-repo",
                region="us-east-1",
            )],
            "analyze_iam_roles_trust_policies": [_analysis(
                service_principal_sources=[_source(accounts=[THIRD_PARTY])],
                role_name="a-role",
            )],
        })

        assert _summary(data)["unique_third_party_accounts"] == [THIRD_PARTY]
        assert _summary(data)["third_party_account_count"] == 1
        assert len(_entries(data, "compliant_instances")) == 2


class TestEveryAnalyzerFeedsTheCheck:
    """Each of the six analyzers must reach analyze()'s findings list."""

    def test_ecr_finding_names_its_repository(self, temp_results_dir: str) -> None:
        """
        A repository policy's finding names that repository by ARN, which no
        registry policy can share.
        """
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/a-repo",
            region="us-east-1",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_ecr_policies", analysis)

        finding = _entries(data, "compliant_instances")[0]
        assert finding["resource_type"] == "ecr"
        assert finding["resource_identifier"] == "arn:aws:ecr:us-east-1:111111111111:repository/a-repo"
        assert finding["region"] == "us-east-1"

    def test_ecr_registry_policy_falls_back_to_registry(
        self, temp_results_dir: str
    ) -> None:
        """A registry policy names no repository, so the finding says so."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            repository_arn=None,
            region="us-east-1",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_ecr_policies", analysis)

        finding = _entries(data, "compliant_instances")[0]
        assert finding["resource_identifier"] == "registry"

    def test_kms_finding_names_its_key(self, temp_results_dir: str) -> None:
        """A key policy's finding names that key."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            key_id="a-key",
            region="us-east-1",
        )
        data = _run_single_analyzer(temp_results_dir, "analyze_kms_key_policies", analysis)

        finding = _entries(data, "compliant_instances")[0]
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

        finding = _entries(data, "compliant_instances")[0]
        assert finding["resource_type"] == "s3"
        assert finding["resource_identifier"] == "a-bucket"
        assert finding["region"] is None

    def test_secretsmanager_finding_names_its_secret_with_its_region(
        self, temp_results_dir: str
    ) -> None:
        """A secret policy's finding names that secret and its region; Secrets Manager is regional."""
        analysis = _analysis(
            service_principal_sources=[_source(accounts=[THIRD_PARTY])],
            secret_name="a-secret",
            region="us-east-1",
        )
        data = _run_single_analyzer(
            temp_results_dir, "analyze_secrets_manager_policies", analysis
        )

        finding = _entries(data, "compliant_instances")[0]
        assert finding["resource_type"] == "secretsmanager"
        assert finding["resource_identifier"] == "a-secret"
        assert finding["region"] == "us-east-1"

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

        finding = _entries(data, "compliant_instances")[0]
        assert finding["resource_type"] == "iam"
        assert finding["resource_identifier"] == "a-role"
        assert finding["region"] is None

    def test_confused_deputy_reads_every_analyzer_producing_sources(self) -> None:
        """
        Every analyzer that records source guards is called by the check.

        The six loops in `analyze` are hand-written on purpose; this is what
        fails by name when a module in `SHARED_ANALYZER_MODULES`, in
        `tests/test_aws_helpers.py`, gains an analyzer producing
        `service_principal_sources` that `analyze` does not call.
        """
        source = textwrap.dedent(inspect.getsource(DenyServiceConfusedDeputyCheck.analyze))
        called = {
            node.func.id
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

        unread = sorted(
            analyzer.__name__
            for analyzer in analyzers_producing_service_principal_sources()
            if analyzer.__name__ not in called
        )

        assert unread == []
