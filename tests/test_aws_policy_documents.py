"""
Tests for headroom.aws.policy_documents module.
"""

from typing import Any, Dict, List

import pytest

from headroom.aws.policy_documents import (
    MalformedPolicyError,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_service_principal_sources,
    unreadable_service_principal_source,
)
from headroom.types import JsonDict


class TestNormalizeStatements:
    def test_list_of_statements_is_returned_unchanged(self) -> None:
        """A Statement list passes through as-is."""
        first = {"Effect": "Allow", "Principal": {"AWS": "999999999999"}}
        second = {"Effect": "Deny", "Principal": "*"}
        policy: JsonDict = {"Version": "2012-10-17", "Statement": [first, second]}

        assert normalize_statements(policy, "Bucket 'example'") == [first, second]

    def test_lone_statement_object_becomes_a_one_element_list(self) -> None:
        """
        IAM accepts a lone statement object, so it reads as one statement.

        Returning an empty list here would report the policy as granting
        nothing, and iterating the object directly yields its keys as
        strings, which crashes on the first `statement.get`.
        """
        statement = {"Effect": "Allow", "Principal": {"AWS": "999999999999"}}
        policy: JsonDict = {"Version": "2012-10-17", "Statement": statement}

        assert normalize_statements(policy, "Bucket 'example'") == [statement]

    def test_missing_statement_key_is_no_statements(self) -> None:
        """A document with no Statement key grants nothing."""
        policy: JsonDict = {"Version": "2012-10-17"}

        assert normalize_statements(policy, "Bucket 'example'") == []

    def test_statement_string_raises(self) -> None:
        """A string Statement is malformed, and guessing at it is unsafe."""
        policy: JsonDict = {"Version": "2012-10-17", "Statement": "Allow"}

        with pytest.raises(MalformedPolicyError) as exc_info:
            normalize_statements(policy, "Bucket 'example'")

        message = str(exc_info.value)
        assert "Bucket 'example'" in message
        assert "Statement of type str" in message

    def test_statement_null_raises(self) -> None:
        """A null Statement is malformed for the same reason."""
        policy: JsonDict = {"Version": "2012-10-17", "Statement": None}

        with pytest.raises(MalformedPolicyError, match="Statement of type NoneType"):
            normalize_statements(policy, "Key 'example-key' in us-east-1")


class TestHasNotPrincipal:
    def test_not_principal_is_reported(self) -> None:
        """A statement naming NotPrincipal reaches everyone it excludes."""
        statement = {
            "Effect": "Allow",
            "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "s3:GetObject",
        }

        assert has_not_principal(statement) is True

    def test_ordinary_principal_is_not_reported(self) -> None:
        """A Principal names who it grants to, so the analyzer can read it."""
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "s3:GetObject",
        }

        assert has_not_principal(statement) is False

    def test_both_elements_is_reported(self) -> None:
        """
        Carrying both is invalid IAM, and the answer still errs toward blocking.

        Letting the Principal half stand alone would report a narrow grant
        for a statement whose reach is everyone outside the exclusion list.
        """
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "NotPrincipal": {"AWS": "arn:aws:iam::888888888888:root"},
            "Action": "s3:GetObject",
        }

        assert has_not_principal(statement) is True


class TestServicePrincipalSources:
    """Test read_service_principal_sources against every disposition."""
    ORG_ACCOUNTS = {"111111111111"}
    ORG_ID = "o-example12345"
    WHERE = "Bucket 'a-bucket'"

    @staticmethod
    def _statement(principal: Any, condition: Any = None) -> Dict[str, Any]:
        """Build one Allow statement, optionally with a Condition block."""
        statement: Dict[str, Any] = {
            "Effect": "Allow",
            "Principal": principal,
            "Action": "s3:PutObject",
        }
        if condition is not None:
            statement["Condition"] = condition
        return statement

    def test_no_service_principal_reports_nothing(self) -> None:
        """A statement naming only AWS principals has no service source."""
        statement = self._statement({"AWS": "arn:aws:iam::999999999999:root"})

        assert read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        ) == []

    def test_unguarded_service_principal_is_recorded_not_allowlisted(self) -> None:
        """
        A Service principal with no source key names no account to permit.

        The policy pins nothing, so there is nothing for the allowlist to
        carry. The trust is still within the statement's reach - the
        calling service populates aws:SourceAccount itself - which is why
        the rollout guidance sends the operator to CloudTrail for the
        drivers this read cannot see.
        """
        statement = self._statement({"Service": "sns.amazonaws.com"})

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert len(sources) == 1
        assert sources[0].service_principal == "sns.amazonaws.com"
        assert sources[0].source_account_ids == []
        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_in_org_source_account_is_not_allowlisted(self) -> None:
        """A source already inside the organization needs no allowlist entry."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "111111111111"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == []
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_out_of_org_source_account_reaches_the_allowlist(self) -> None:
        """A third-party source is what the allowlist exists to carry."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_wildcard_source is False

    def test_condition_keys_are_matched_case_insensitively(self) -> None:
        """IAM matches condition key names without regard to case."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:sourceaccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]

    def test_source_arn_yields_its_account(self) -> None:
        """aws:SourceArn is the more common pin, and carries the account."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"ArnLike": {
                "aws:SourceArn": "arn:aws:sns:us-west-2:999999999999:a-topic"
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_wildcard_source is False

    def test_wildcard_source_account_cannot_be_expressed(self) -> None:
        """An unbounded source set is what withholds the statement."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceAccount": "*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True
        assert sources[0].source_account_ids == []

    def test_wildcard_account_in_source_arn_cannot_be_expressed(self) -> None:
        """An ARN whose account field is a wildcard names no account."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-west-2:*:a-topic"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bucket_arn_alone_cannot_be_expressed(self) -> None:
        """
        S3 ARNs carry no account field at all.

        `arn:aws:s3:::a-bucket` never identifies whose bucket drove the
        call, which is why AWS pairs aws:SourceArn with aws:SourceAccount.
        """
        statement = self._statement(
            {"Service": "s3.amazonaws.com"},
            {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::a-bucket"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bucket_arn_resolves_through_its_companion_source_account(self) -> None:
        """The companion key is what makes an accountless ARN readable."""
        statement = self._statement(
            {"Service": "s3.amazonaws.com"},
            {
                "ArnLike": {"aws:SourceArn": "arn:aws:s3:::a-bucket"},
                "StringEquals": {"aws:SourceAccount": "999999999999"},
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_wildcard_source is False

    def test_every_service_principal_in_one_statement_is_reported(self) -> None:
        """One Condition block guards every service the statement names."""
        statement = self._statement(
            {"Service": ["sns.amazonaws.com", "events.amazonaws.com"]},
            {"StringEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert [source.service_principal for source in sources] == [
            "sns.amazonaws.com",
            "events.amazonaws.com",
        ]
        assert all(s.source_account_ids == ["999999999999"] for s in sources)

    def test_aws_and_service_principals_together_report_only_the_service(self) -> None:
        """The AWS principal path is untouched by this reader."""
        statement = self._statement(
            {
                "AWS": "arn:aws:iam::999999999999:root",
                "Service": "sns.amazonaws.com",
            }
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert len(sources) == 1
        assert sources[0].service_principal == "sns.amazonaws.com"

    def test_source_org_id_naming_this_organization_needs_no_allowlist(self) -> None:
        """
        A guard pinned to our own organization is a perfect guard.

        The deployed statement exempts a source carrying this
        organization's ID, so the resource needs no allowlist entry and is
        not a violation. This is AWS's own recommended service principal
        guard, and treating it as unreadable withheld the statement from
        every other resource in the account.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceOrgID": self.ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].source_account_ids == []
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_source_org_id_naming_another_organization_is_unenumerable(self) -> None:
        """
        A foreign organization names accounts no allowlist can carry.

        The allowlist holds account IDs, and the accounts of another
        organization are not knowable from here, so the statement is
        withheld rather than deployed against an allowlist that cannot
        cover them.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceOrgID": "o-notours98765"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is True

    def test_wildcarded_source_org_id_is_not_read_as_this_organization(self) -> None:
        """
        A trailing wildcard on our own ID also matches other organizations.

        `o-example12345*` matches this organization and every organization
        whose ID extends that prefix, so reading it as ours would deploy
        the statement against sources it does not cover.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgID": f"{self.ORG_ID}*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_source_org_paths_inside_this_organization_needs_no_allowlist(self) -> None:
        """An organization path carries the organization ID as its first element."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {
                "aws:SourceOrgPaths": f"{self.ORG_ID}/r-ab12/ou-ab12-11111111/"
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_source_org_paths_below_this_organization_needs_no_allowlist(self) -> None:
        """A wildcard below our own organization stays inside it."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": f"{self.ORG_ID}/*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is False

    def test_source_org_paths_in_another_organization_is_unenumerable(self) -> None:
        """A path rooted in a foreign organization is no more enumerable than its ID."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": "o-notours98765/*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bare_wildcard_source_org_paths_is_unenumerable(self) -> None:
        """A path of `*` matches every organization, so it names no organization."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": "*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_one_foreign_organization_scope_among_several_is_enough(self) -> None:
        """Any scope the allowlist cannot cover withholds the statement."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {
                "aws:SourceOrgID": [self.ORG_ID, "o-notours98765"]
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_organization_scope_key_case_is_ignored(self) -> None:
        """IAM matches condition key names without regard to case."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:sourceorgid": self.ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_negated_operator_on_an_organization_scope_is_recorded(self) -> None:
        """The operator gate covers the organization keys too."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringNotEquals": {"aws:SourceOrgID": "o-notours98765"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "StringNotEquals" in sources[0].read_failure

    def test_negated_operator_on_a_source_key_is_recorded(self) -> None:
        """A negated operator excludes rather than permits; it is no guard."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringNotEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "StringNotEquals" in sources[0].read_failure

    def test_malformed_source_account_is_recorded(self) -> None:
        """A source account that is neither an ID nor a wildcard is unreadable."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "not-an-account"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "not-an-account" in sources[0].read_failure

    def test_non_string_source_condition_value_is_recorded(self) -> None:
        """A source key holding neither a string nor a list is unreadable."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": 123}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "int" in sources[0].read_failure

    def test_a_readable_statement_records_no_failure(self) -> None:
        """The failure field stays None on every guard the parser can read."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None

    def test_unrelated_conditions_are_ignored(self) -> None:
        """Only the four source keys are read; everything else passes by."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SecureTransport": "true"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_operator_with_non_mapping_entries_is_ignored(self) -> None:
        """An operator whose value is not itself a mapping guards nothing."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"Bool": "true"},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_wildcard_principal_string_reports_nothing(self) -> None:
        """`Principal: "*"` is not a dict and names no service."""
        assert read_service_principal_sources(
            self._statement("*"), self.ORG_ACCOUNTS, self.ORG_ID, self.WHERE
        ) == []


class TestHasActionableServicePrincipalSource:
    """Test has_actionable_service_principal_source against every disposition."""

    @staticmethod
    def _source(
        source_account_ids: List[str], has_wildcard_source: bool
    ) -> ServicePrincipalSource:
        """Build one service principal source with the fields under test."""
        return ServicePrincipalSource(
            service_principal="sns.amazonaws.com",
            source_account_ids=source_account_ids,
            has_source_condition=True,
            has_wildcard_source=has_wildcard_source,
        )

    def test_a_failed_read_is_actionable(self) -> None:
        """
        A resource whose guard could not be read must reach the check.

        Dropping it would leave the confused deputy statement to deploy
        against an allowlist nobody could compute.
        """
        sources = [unreadable_service_principal_source("could not be read")]

        assert has_actionable_service_principal_source(sources) is True

    def test_an_unguarded_source_is_not_actionable(self) -> None:
        """An unguarded trust would bury the sources that matter."""
        sources = [
            ServicePrincipalSource(
                service_principal="sns.amazonaws.com",
                source_account_ids=[],
                has_source_condition=False,
                has_wildcard_source=False,
            )
        ]

        assert has_actionable_service_principal_source(sources) is False

    def test_an_out_of_org_account_id_is_actionable(self) -> None:
        """A source naming an out-of-organization account is worth keeping."""
        sources = [self._source(["999999999999"], False)]

        assert has_actionable_service_principal_source(sources) is True

    def test_a_wildcard_guard_is_actionable(self) -> None:
        """A guard no allowlist can express is worth keeping, even unresolved."""
        sources = [self._source([], True)]

        assert has_actionable_service_principal_source(sources) is True

    def test_no_sources_is_not_actionable(self) -> None:
        """A statement naming no service principal has nothing worth keeping."""
        assert has_actionable_service_principal_source([]) is False
