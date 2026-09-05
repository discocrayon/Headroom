"""
Tests for headroom.aws.policy_documents module.
"""

import ast
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, cast

import pytest

import headroom

from headroom.aws.policy_documents import (
    CONFINING_OPERATORS,
    MalformedPolicyError,
    PrincipalElement,
    PrincipalReading,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    SOURCE_GUARD_IF_EXISTS_OPERATORS,
    SOURCE_GUARD_OPERATORS,
    TRUST_POLICY_PRINCIPAL_TYPES,
    UnknownPrincipalTypeError,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_actions,
    normalize_statements,
    _read_principal,
    read_service_principal_sources,
    read_statement_principals,
    unreadable_service_principal_source,
)
from headroom.enums import PolicyService
from headroom.types import JsonDict
from tests.constants import ORG_ID


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


class TestNormalizeActions:
    def test_an_action_that_is_neither_string_nor_list_raises(self) -> None:
        """
        A malformed Action is a document AWS could not have stored.

        IAM accepts a string or an array of strings and nothing else, so
        anything else means Headroom has misread the document. Two analyzers
        used to answer an empty set, recording the resource as granting no
        action at all, which is the fallback CONVENTIONS.md forbids and a
        verdict nobody measured.
        """
        with pytest.raises(TypeError) as exc_info:
            normalize_actions(None)  # type: ignore[arg-type]

        assert "NoneType" in str(exc_info.value)

    def test_a_string_is_one_action(self) -> None:
        """A lone action is stored as a bare string."""
        assert normalize_actions("s3:GetObject") == {"s3:GetObject"}

    def test_a_list_is_every_action_it_names(self) -> None:
        """An array grants each action in it."""
        assert normalize_actions(["sqs:SendMessage", "sqs:ReceiveMessage"]) == {
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
        }

    def test_an_empty_list_is_no_actions(self) -> None:
        """
        A statement with no Action key reaches this as the empty default.

        Every caller passes `statement.get("Action", [])`, so this is the
        ordinary path for a statement that names none, not a malformed one.
        """
        assert normalize_actions([]) == set()

    def test_a_dict_raises_rather_than_reading_its_keys(self) -> None:
        """
        An object Action must not be read as the set of its keys.

        `set({"unexpected": "shape"})` is `{"unexpected"}`, so two analyzers
        used to record a key name as though it were an IAM action.
        """
        with pytest.raises(TypeError, match="Expected str or list"):
            normalize_actions({"unexpected": "shape"})  # type: ignore[arg-type]


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

    def test_a_not_principal_statement_is_not_confined_by_its_condition(self) -> None:
        """
        NotPrincipal blocks before any Condition is read, and that is deliberate.

        Every adapter records the wildcard and moves to the next statement
        the moment this reports true, so no principal reader runs here and
        the confining clause below is never consulted. NotPrincipal states
        who is excluded rather than who is admitted, and a bound read off a
        statement whose reach is stated by exclusion would be an inference
        rather than a reading. Leaving it a blocker withholds the RCP, which
        breaks nothing.
        """
        statement = {
            "Effect": "Allow",
            "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "s3:GetObject",
            "Condition": {
                "StringEquals": {"aws:PrincipalAccount": ["111111111111", "222222222222"]},
            },
        }

        assert has_not_principal(statement) is True


class TestServicePrincipalSources:
    """Test read_service_principal_sources against every disposition."""
    ORG_ACCOUNTS = {"111111111111"}
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            {"StringEquals": {"aws:SourceOrgID": ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            {"StringEquals": {"aws:SourceOrgID": "o-22222222222"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is True

    def test_wildcarded_source_org_id_is_not_read_as_this_organization(self) -> None:
        """
        A trailing wildcard on our own ID also matches other organizations.

        `o-11111111111*` matches this organization and every organization
        whose ID extends that prefix, so reading it as ours would deploy
        the statement against sources it does not cover.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgID": f"{ORG_ID}*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_source_org_paths_inside_this_organization_needs_no_allowlist(self) -> None:
        """An organization path carries the organization ID as its first element."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {
                "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/"
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_source_org_paths_below_this_organization_needs_no_allowlist(self) -> None:
        """A wildcard below our own organization stays inside it."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": f"{ORG_ID}/*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is False

    def test_source_org_paths_in_another_organization_is_unenumerable(self) -> None:
        """A path rooted in a foreign organization is no more enumerable than its ID."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": "o-22222222222/*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bare_wildcard_source_org_paths_is_unenumerable(self) -> None:
        """A path of `*` matches every organization, so it names no organization."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": "*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_one_foreign_organization_scope_among_several_is_enough(self) -> None:
        """Any scope the allowlist cannot cover withholds the statement."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {
                "aws:SourceOrgID": [ORG_ID, "o-22222222222"]
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_organization_scope_key_case_is_ignored(self) -> None:
        """IAM matches condition key names without regard to case."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:sourceorgid": ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_negated_operator_on_an_organization_scope_is_recorded(self) -> None:
        """The operator gate covers the organization keys too."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringNotEquals": {"aws:SourceOrgID": "o-22222222222"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None

    def test_unrelated_conditions_are_ignored(self) -> None:
        """Only the four source keys are read; everything else passes by."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SecureTransport": "true"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
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
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_wildcard_principal_string_reports_nothing(self) -> None:
        """`Principal: "*"` under no source key names no service and no source."""
        assert read_service_principal_sources(
            self._statement("*"), self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        ) == []

    def test_a_wildcard_principal_narrowed_by_a_source_arn_is_a_source(self) -> None:
        """
        AWS's cross-account SNS-to-SQS queue policy is `Principal: "*"`
        pinned by `aws:SourceArn` to the topic. Only a service call carries
        a source key, so the guard names who the grant is for even though
        the Principal element does not, and the topic's account belongs in
        the allowlist.
        """
        sources = read_service_principal_sources(
            self._statement(
                "*",
                {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:us-west-2:999999999999:a-topic"}},
            ),
            self.ORG_ACCOUNTS,
            ORG_ID,
            self.WHERE,
        )

        assert len(sources) == 1
        assert sources[0].service_principal == "*"
        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_a_wildcard_under_the_aws_key_is_read_the_same_way(self) -> None:
        """`{"AWS": "*"}` is the same wildcard, and reads as the same source."""
        sources = read_service_principal_sources(
            self._statement(
                {"AWS": "*"},
                {"StringEquals": {"aws:SourceAccount": "999999999999"}},
            ),
            self.ORG_ACCOUNTS,
            ORG_ID,
            self.WHERE,
        )

        assert len(sources) == 1
        assert sources[0].service_principal == "*"
        assert sources[0].source_account_ids == ["999999999999"]

    def test_a_wildcard_narrowed_only_by_unrelated_keys_reports_nothing(self) -> None:
        """
        `Principal: "*"` under `aws:PrincipalOrgID` alone is the data
        perimeter idiom, not a service grant. No source key, no source.
        """
        assert read_service_principal_sources(
            self._statement(
                "*",
                {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}},
            ),
            self.ORG_ACCOUNTS,
            ORG_ID,
            self.WHERE,
        ) == []

    def test_a_wildcard_under_an_unreadable_guard_is_a_read_failure(self) -> None:
        """
        A wildcard's guard is read by the same rules as a service's. A
        negated operator on a source key pins nothing, so the read fails
        and the statement is withheld rather than read as no guard.
        """
        sources = read_service_principal_sources(
            self._statement(
                "*",
                {"StringNotEquals": {"aws:SourceAccount": "999999999999"}},
            ),
            self.ORG_ACCOUNTS,
            ORG_ID,
            self.WHERE,
        )

        assert len(sources) == 1
        assert sources[0].read_failure is not None
        assert "StringNotEquals" in sources[0].read_failure

    def test_the_failure_text_names_the_guard_not_a_service_principal(self) -> None:
        """
        The same guards are read under a wildcard principal as under a
        Service one, so the text that explains a failed read must describe
        the guard and not assert a principal type the statement does not
        carry.
        """
        sources = read_service_principal_sources(
            self._statement(
                "*",
                {"StringNotEquals": {"aws:SourceAccount": "999999999999"}},
            ),
            self.ORG_ACCOUNTS,
            ORG_ID,
            self.WHERE,
        )

        assert sources[0].read_failure is not None
        assert sources[0].read_failure.startswith(
            "Bucket 'a-bucket' has a source guard with 'aws:SourceAccount' "
            "under operator 'StringNotEquals'"
        )

    @pytest.mark.parametrize("set_operator", ["ForAnyValue", "ForAllValues"])
    @pytest.mark.parametrize("string_operator", ["StringEquals", "StringLike"])
    def test_aws_published_org_paths_form_reads_as_a_guard(
        self, set_operator: str, string_operator: str
    ) -> None:
        """
        aws:SourceOrgPaths is multivalued, so AWS requires a set operator.

        The eight bare operators were the whole whitelist, so every form the
        AWS Security Blog publishes came back as a read failure, which the
        confused-deputy check files as a violation and which withholds the
        statement from the account. The only accepted form was the bare one
        AWS says not to write for a multivalued key.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "Null": {"aws:SourceOrgPaths": "false"},
                f"{set_operator}:{string_operator}": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert len(sources) == 1
        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_for_all_values_without_a_null_companion_permits_an_absent_key(self) -> None:
        """
        ForAllValues is satisfied by a request carrying no values at all.

        That is why AWS's own examples pair it with Null <key> = "false":
        the Null clause is what forbids the empty case. Without the
        companion the resource policy permits a sourceless request that the
        guard appears to constrain, so the statement has to be withheld
        rather than deployed over it.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "ForAllValues:StringLike": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_for_any_value_without_a_null_companion_does_not(self) -> None:
        """
        ForAnyValue is false on an absent key, so it needs no companion.

        Setting the flag for both set operators would withhold the
        statement from every account using the safe one, which is the
        opposite error and just as wrong.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "ForAnyValue:StringLike": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_wildcard_source is False

    def test_a_prefixed_null_companion_closes_nothing(self) -> None:
        """
        Only a bare `Null` clause asserts a key present.

        `ForAllValues:Null` is not a policy AWS stores, and the pre-pass
        reads it as no assertion, so the ForAllValues guard beside it still
        permits the empty case. The pre-pass selects its clauses from the
        shared parse by the operator as written; matching on the base
        operator instead would let this prefixed spelling rescue the guard,
        and that mutation survived every other test here.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "ForAllValues:Null": {"aws:SourceOrgPaths": "false"},
                "ForAllValues:StringLike": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_wildcard_source is True

    @pytest.mark.parametrize(
        "asserted",
        [False, ["false"], [False]],
        ids=["json-bool", "one-element-list-of-string", "one-element-list-of-bool"],
    )
    def test_every_spelling_iam_stores_closes_the_empty_case(
        self, asserted: Any
    ) -> None:
        """
        The Null companion is not always spelled with the string "false".

        IAM's policy grammar makes quotation marks optional on a Boolean
        value, and defines a condition value as a list whose brackets may be
        dropped for a single entry. Both spellings are therefore stored, and
        reading either as no assertion turns AWS's own recommended
        aws:SourceOrgPaths guard into a wildcard that withholds the
        confused-deputy statement from the whole account.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "ForAllValues:StringLike": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
                "Null": {"aws:SourceOrgPaths": asserted},
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_wildcard_source is False

    @pytest.mark.parametrize(
        "not_asserted",
        ["true", True, "False", ["false", "true"], []],
        ids=["true-string", "true-bool", "capitalised", "two-entries", "empty-list"],
    )
    def test_anything_else_leaves_the_empty_case_open(
        self, not_asserted: Any
    ) -> None:
        """
        Only the two sanctioned spellings assert the key is present.

        "true" asserts the opposite. A capitalised "False" is not a form AWS
        documents for Null, which defines no case-insensitive variant, and a
        list of two entries asserts nothing coherent about one key. Reading
        any of them as the companion would clear an account whose guard
        still permits a sourceless request, which is the direction INV-01
        forbids.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "ForAllValues:StringLike": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
                "Null": {"aws:SourceOrgPaths": not_asserted},
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_an_unknown_set_operator_is_still_a_read_failure(self) -> None:
        """
        ForAnyValue and ForAllValues are the only two set operators AWS defines.

        Accepting a third by stripping any prefix would read a guard this
        parser does not understand as one it does.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {"ForSomeValues:StringLike": {"aws:SourceOrgPaths": ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None

    def test_a_null_clause_holding_a_non_mapping_is_a_read_failure(self) -> None:
        """
        A Null clause is documented as a mapping of keys to "true"/"false".

        A statement carrying "Null": "false" at the wrong nesting level is
        not that. Silently treating it as though it asserted nothing would
        compute a specific answer for data this parser cannot read, rather
        than record that the read failed.
        """
        statement = self._statement(
            {"Service": "cloudtrail.amazonaws.com"},
            {
                "Null": "false",
                "ForAllValues:StringLike": {
                    "aws:SourceOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
                },
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None


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


class TestReadPrincipal:
    def test_an_account_id_is_read_as_itself(self) -> None:
        """The shortened account-ID form names the account directly."""
        reading = _read_principal(
            {"AWS": "111111111111"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    def test_an_arn_yields_the_account_it_names(self) -> None:
        """The account segment of an ARN is the fifth colon-delimited field."""
        reading = _read_principal(
            {"AWS": "arn:aws:iam::222222222222:role/example"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"222222222222"}

    def test_a_service_linked_role_names_no_account_and_blocks_nothing(self) -> None:
        """
        A service-linked role is neither an account nor a blocker.

        RCPs do not impact the permissions of any service-linked role, so
        no statement Headroom generates can deny one and its account has no
        business in an allowlist. IAM reserves the `aws-service-role/` role
        path to AWS services, so the path identifies the role in any
        partition; the name is not consulted.
        """
        reading = _read_principal(
            {
                "AWS": [
                    "arn:aws:iam::222222222222:role/aws-service-role/"
                    "example.amazonaws.com/AWSServiceRoleForExample",
                    "arn:aws-cn:iam::222222222222:role/aws-service-role/"
                    "example.amazonaws.com.cn/AWSServiceRoleForExample",
                ]
            },
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    def test_a_role_named_like_a_service_role_outside_the_path_is_an_account(self) -> None:
        """Anyone can name a role AWSServiceRoleForExample; only the path is reserved."""
        reading = _read_principal(
            {"AWS": "arn:aws:iam::222222222222:role/AWSServiceRoleForExample"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"222222222222"}

    def test_a_bare_wildcard_is_a_wildcard_naming_no_account(self) -> None:
        """`Principal: "*"` reaches everyone, so it names nobody in particular."""
        reading = _read_principal(
            "*", RESOURCE_POLICY_PRINCIPAL_TYPES, "Queue 'example'"
        )

        assert reading.has_wildcard is True
        assert reading.account_ids == set()

    def test_a_service_principal_names_no_account(self) -> None:
        """A service principal is not an account and is not a blocker."""
        reading = _read_principal(
            {"Service": "s3.amazonaws.com"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    def test_a_federated_principal_names_no_account(self) -> None:
        """
        A SAML provider ARN carries twelve digits that are not the caller's.

        They name the account hosting the provider. Reading them as the
        principal's account would put a stranger's identity into an
        allowlist keyed on aws:PrincipalAccount.
        """
        reading = _read_principal(
            {"Federated": "arn:aws:iam::333333333333:saml-provider/Example"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.has_non_account_principals is True
        assert reading.account_ids == set()

    def test_a_canonical_user_names_no_account(self) -> None:
        """A canonical user ID is opaque; no allowlist can carry it."""
        reading = _read_principal(
            {"CanonicalUser": "d" * 64},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Bucket 'example'",
        )

        assert reading.has_non_account_principals is True
        assert reading.account_ids == set()

    def test_a_canonical_user_is_not_permitted_in_a_trust_policy(self) -> None:
        """
        Only S3 accepts a canonical user, and a trust policy is not S3's.

        Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
        """
        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            _read_principal(
                {"CanonicalUser": "d" * 64},
                TRUST_POLICY_PRINCIPAL_TYPES,
                "Role 'example'",
            )

        assert "Role 'example'" in str(exc_info.value)

    def test_a_key_aws_does_not_document_raises(self) -> None:
        """A key outside the documented four is a document Headroom cannot read."""
        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            _read_principal(
                {"Kerberos": "example"},
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'example'",
            )

        message = str(exc_info.value)
        assert "Kerberos" in message
        assert "Queue 'example'" in message

    def test_a_known_key_alongside_an_unknown_one_still_raises(self) -> None:
        """The readable half does not excuse the half nobody can read."""
        with pytest.raises(UnknownPrincipalTypeError):
            _read_principal(
                {"AWS": "111111111111", "Kerberos": "example"},
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'example'",
            )

    def test_a_list_of_accounts_yields_every_account(self) -> None:
        """An array of principals grants to each of them."""
        reading = _read_principal(
            {"AWS": ["111111111111", "arn:aws:iam::222222222222:root"]},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111", "222222222222"}

    def test_a_wildcard_inside_a_list_is_a_wildcard(self) -> None:
        """One wildcard entry opens the grant however many accounts follow it."""
        reading = _read_principal(
            {"AWS": ["111111111111", "*"]},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.account_ids == {"111111111111"}

    def test_an_account_and_a_federated_principal_report_both(self) -> None:
        """One statement can name a readable account and an unreadable one."""
        reading = _read_principal(
            {
                "AWS": "111111111111",
                "Federated": "arn:aws:iam::333333333333:saml-provider/Example",
            },
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_non_account_principals is True

    def test_an_sts_session_arn_resolves_to_its_account(self) -> None:
        """The service segment is unconstrained, so sts ARNs resolve."""
        reading = _read_principal(
            {"AWS": "arn:aws:sts::444444444444:assumed-role/Example/session"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"444444444444"}

    def test_an_unrecognizable_string_yields_no_account(self) -> None:
        """A principal that is neither an ARN nor an account ID names none."""
        reading = _read_principal(
            {"AWS": "not-an-arn"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is False

    def test_an_arn_naming_no_account_blocks_the_account(self) -> None:
        """
        An ARN whose account field is not an account ID is a blocker.

        CloudFront's origin access identity user carries the service's name
        where an account ID would be. It named no account, no wildcard, and
        no non-account type, so a bucket granting only an OAI was never
        recorded and its account cleared for the S3 RCP, which then denied
        every request the distribution made. No allowlist keyed on
        aws:PrincipalAccount can carry it, which is what the third fact
        records.
        """
        oai = "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E11111111111111"

        bare = _read_principal(
            oai, RESOURCE_POLICY_PRINCIPAL_TYPES, "Bucket 'example-bucket'"
        )
        keyed = _read_principal(
            {"AWS": oai}, RESOURCE_POLICY_PRINCIPAL_TYPES, "Bucket 'example-bucket'"
        )

        for reading in (bare, keyed):
            assert reading.account_ids == set()
            assert reading.has_wildcard is False
            assert reading.has_non_account_principals is True

    def test_a_unique_id_names_nothing_and_blocks_nothing(self) -> None:
        """
        A deleted principal's unique ID is a dead grant, not a blocker.

        AWS rewrites a Principal ARN to the entity's unique ID when the user
        or role it named is deleted, and documents that the entry then
        grants no one access: a replacement with the same name gets a new
        ID. Nothing lives behind it for an RCP to deny, so it names no
        account and is no non-account principal. It is the one account-less
        string that clears rather than blocks, pinned here beside the OAI
        so the two are never folded into one rule.
        """
        unique_id = "AROA11111111111111111"

        bare = _read_principal(
            unique_id, RESOURCE_POLICY_PRINCIPAL_TYPES, "Bucket 'example-bucket'"
        )
        keyed = _read_principal(
            {"AWS": unique_id}, RESOURCE_POLICY_PRINCIPAL_TYPES, "Bucket 'example-bucket'"
        )

        for reading in (bare, keyed):
            assert reading.account_ids == set()
            assert reading.has_wildcard is False
            assert reading.has_non_account_principals is False

    def test_a_bare_string_principal_names_no_non_account_type(self) -> None:
        """
        A bare-string Principal naming an account names no non-account type.

        `has_non_account_principals` is what blocks an account from a check:
        it means the policy grants to something an aws:PrincipalAccount
        allowlist cannot carry. An ARN naming an account is carried fine, so
        the third fact is False here; the one string form that sets it is
        pinned by `test_an_arn_naming_no_account_blocks_the_account`. Making
        the branch a constant True passes the rest of the suite, so nothing
        but this assertion stands between a one-word edit and every such
        resource blocking its account.
        """
        reading = _read_principal(
            "arn:aws:iam::111111111111:root",
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Bucket 'example-bucket'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    @pytest.mark.parametrize(
        "principal",
        [None, 123, True],
        ids=["null", "number", "bool"],
    )
    def test_a_principal_that_is_not_a_policy_element_names_the_resource(
        self, principal: object
    ) -> None:
        """
        A Principal that is neither string, list, nor object is malformed.

        Every caller hands this function a resource_description precisely so
        that a document it cannot read says which document. Reaching .keys()
        on a value that has none raised a bare AttributeError instead, and an
        operator reading that traceback learned the run died without learning
        which bucket, queue, key, secret, repository, or role did it.
        """
        with pytest.raises(MalformedPolicyError) as exc_info:
            _read_principal(
                cast(PrincipalElement, principal),
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'orders'",
            )

        message = str(exc_info.value)
        assert "Queue 'orders'" in message
        assert type(principal).__name__ in message


class TestReadStatementPrincipals:
    """
    `read_statement_principals` composes `_read_principal` with a statement's
    `Condition`.

    A Condition that enumerates the principals its statement reaches narrows
    the wildcard `_read_principal` would report. Everything it cannot
    enumerate leaves the wildcard standing, which withholds the RCP from the
    account and breaks nothing.
    """

    def _read(
        self,
        statement: JsonDict,
        policy_service: PolicyService = PolicyService.S3,
    ) -> PrincipalReading:
        """
        Read one statement's principals against this organization.

        Args:
            statement: The Allow statement to read
            policy_service: The service whose policy holds the statement,
                deciding which service-scoped condition keys can confine it.
                S3 recognizes none, so a caller that omits this reads
                exactly as it did before any service-scoped key existed

        Returns:
            What the statement's Principal names, narrowed by its Condition
        """
        return read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            policy_service,
            ORG_ID,
            "Bucket 'example'",
        )

    def _read_wildcard_under(
        self,
        condition: JsonDict,
        policy_service: PolicyService = PolicyService.S3,
    ) -> PrincipalReading:
        """
        Read a wildcard principal narrowed by one Condition block.

        Args:
            condition: The statement's Condition element
            policy_service: The service whose policy holds the statement,
                deciding which service-scoped condition keys can confine it.
                S3 recognizes none, so a caller that omits this reads
                exactly as it did before any service-scoped key existed

        Returns:
            What the statement's wildcard names, narrowed by that Condition
        """
        return self._read(
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Condition": condition,
            },
            policy_service,
        )

    def test_statement_principals_confined_by_principal_account(self) -> None:
        """A StringEquals on aws:PrincipalAccount enumerates who the wildcard reaches."""
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": ["111111111111", "222222222222"]},
        })

        assert reading.account_ids == {"111111111111", "222222222222"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_statement_principals_confining_key_is_matched_without_case(self) -> None:
        """IAM matches a condition key name without regard to case, and so does this."""
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:principalaccount": ["111111111111", "222222222222"]},
        })

        assert reading.account_ids == {"111111111111", "222222222222"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_statement_principals_confines_a_bare_string_wildcard(self) -> None:
        """A bare `Principal: "*"` is confined exactly as the `{"AWS": "*"}` form is."""
        reading = self._read({
            "Effect": "Allow",
            "Principal": "*",
            "Condition": {
                "StringEquals": {"aws:PrincipalAccount": ["111111111111", "222222222222"]},
            },
        })

        assert reading.account_ids == {"111111111111", "222222222222"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_statement_principals_confined_by_a_lone_account_string(self) -> None:
        """IAM accepts a lone string where a one-element list would do, and both confine."""
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": "111111111111"},
        })

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_statement_principals_with_one_unbounded_account_value_is_a_wildcard(self) -> None:
        """
        Values under one key are ORed, so one unbounded value unbounds the key.

        `11111111111*` matches ten accounts of this organization's and every
        account any other organization holds under the same prefix, so the
        clause enumerates nobody even though its companion value does.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": ["111111111111", "11111111111*"]},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_confined_by_this_organizations_id(self) -> None:
        """
        aws:PrincipalOrgID naming this organization bounds the statement.

        Every caller it admits is already in the organization, so the
        allowlist needs no entry for any of them.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalOrgID": ORG_ID},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalorgid"})

    def test_statement_principals_with_a_foreign_organization_id_is_a_wildcard(self) -> None:
        """
        Another organization's ID enumerates nobody this allowlist can hold.

        The allowlist carries account IDs, and another organization's member
        accounts are not knowable from here.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalOrgID": "o-22222222222"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_prefixed_organization_id_is_a_wildcard(self) -> None:
        """
        `o-11111111111*` names this organization and every one extending it.

        The comparison is exact, so the trailing wildcard reads as foreign.
        Reading it as ours would deploy an RCP against callers no scope here
        covers.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalOrgID": f"{ORG_ID}*"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_confined_by_this_organizations_paths(self) -> None:
        """
        aws:PrincipalOrgPaths carries the organization ID as its first segment.

        The key is multivalued, so AWS writes it under a set operator;
        ForAnyValue is the one this reader accepts.
        """
        reading = self._read_wildcard_under({
            "ForAnyValue:StringLike": {
                "aws:PrincipalOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
            },
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalorgpaths"})

    def test_statement_principals_with_a_foreign_organizations_paths_is_a_wildcard(self) -> None:
        """A path under another organization takes the same verdict as its bare ID."""
        reading = self._read_wildcard_under({
            "ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": "o-22222222222/r-1111/*"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_confined_by_a_service_linked_role_arn(self) -> None:
        """
        A service-linked role bounds the statement and names no account.

        RCPs do not impact a service-linked role, so no statement Headroom
        generates can deny one and its account is never a third party to
        preserve. The reserved role path decides that, not the account field.
        """
        reading = self._read_wildcard_under({
            "ArnEquals": {
                "aws:PrincipalArn": (
                    "arn:aws:iam::111111111111:role/aws-service-role/"
                    "autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
                ),
            },
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalarn"})

    def test_statement_principals_confined_by_a_role_arn_names_its_account(self) -> None:
        """An ordinary role ARN bounds the statement to the account it names."""
        reading = self._read_wildcard_under({
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::333333333333:role/Example"},
        })

        assert reading.account_ids == {"333333333333"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalarn"})

    def test_statement_principals_confined_by_an_arn_wildcarded_after_the_account(self) -> None:
        """
        A wildcard after the account field leaves the account pinned.

        `role/*` reaches every role in one account, and an allowlist keyed on
        that account preserves all of them.
        """
        reading = self._read_wildcard_under({
            "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::333333333333:role/*"},
        })

        assert reading.account_ids == {"333333333333"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalarn"})

    def test_statement_principals_with_a_wildcard_account_field_is_a_wildcard(self) -> None:
        """
        An ARN wildcarded in its account field reaches every account.

        The allowlist holds account IDs, so there is nothing to put in it.
        """
        reading = self._read_wildcard_under({
            "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Example"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_an_accountless_arn_is_a_wildcard(self) -> None:
        """
        CloudFront's origin access identity user carries no account at all.

        Its ARN holds the service's name where an account ID would be, so no
        allowlist keyed on aws:PrincipalAccount can carry it, exactly as
        _read_principal already reports for the same ARN in a Principal
        element.
        """
        reading = self._read_wildcard_under({
            "ArnEquals": {
                "aws:PrincipalArn": (
                    "arn:aws:iam::cloudfront:user/CloudFront Origin Access "
                    "Identity E11111111111111"
                ),
            },
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_unions_the_accounts_two_keys_bound(self) -> None:
        """
        Two confining keys contribute the union of their accounts, never the
        intersection.

        The two keys AND together, so the true caller set is the
        intersection - here, empty. An allowlist built from the intersection
        would omit an account the resource policy might still admit under a
        reading of the block this parser has not modelled, and the RCP would
        then deny it. The union costs an allowlist entry; the intersection
        costs an outage.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": ["444444444444"]},
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::555555555555:role/x"},
        })

        assert reading.account_ids == {"444444444444", "555555555555"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount", "aws:principalarn"})

    def test_statement_principals_confines_beside_an_unrelated_clause(self) -> None:
        """
        Condition keys AND together, so one bound is enough.

        `kms:GrantIsForAWSResource` narrows which calls the statement covers
        and says nothing about who makes them. The aws:PrincipalAccount
        clause beside it still enumerates every caller the statement can
        reach.
        """
        reading = self._read_wildcard_under(
            {
                "StringEquals": {"aws:PrincipalAccount": ["111111111111"]},
                "Bool": {"kms:GrantIsForAWSResource": "true"},
            },
            PolicyService.KMS,
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_statement_principals_confined_by_the_kms_caller_account(self) -> None:
        """
        kms:CallerAccount names the calling principal's account, so it bounds like
        aws:PrincipalAccount does.

        A KMS key policy is where the key is meaningful, and every request
        against the key carries it, so a StringEquals on it enumerates every
        caller the wildcard reaches.
        """
        reading = self._read_wildcard_under(
            {"StringEquals": {"kms:CallerAccount": "111111111111"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"kms:calleraccount"})

    def test_the_kms_caller_account_carries_an_out_of_organization_account(self) -> None:
        """
        An out-of-organization account the key names has to reach the allowlist.

        Stopping the wildcard from blocking without recording the account it
        was confined to would deploy an RCP that denies the very caller the
        key policy admits, which is an outage Headroom would have caused.
        """
        reading = self._read_wildcard_under(
            {"StringEquals": {"kms:CallerAccount": "333333333333"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == {"333333333333"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"kms:calleraccount"})

    @pytest.mark.parametrize("policy_service", [PolicyService.S3, PolicyService.STS])
    def test_caller_account_confines_only_in_a_kms_policy(
        self, policy_service: PolicyService
    ) -> None:
        """
        kms:CallerAccount is meaningful only where a KMS request carries it.

        In any other service's policy the clause names a key no request
        carries, so the statement grants nobody anything. Reading it as a
        bound would stop the wildcard blocking and put an account into an
        allowlist no policy ever granted, which is a widening error nothing
        downstream can catch.
        """
        reading = self._read_wildcard_under(
            {"StringEquals": {"kms:CallerAccount": "111111111111"}},
            policy_service,
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_via_service_beside_caller_account_is_not_what_confines(self) -> None:
        """
        kms:ViaService names the service a call came through, not who made it.

        Every principal in every account can call KMS through EC2, so the
        clause enumerates nobody however narrow it reads. Beside a caller
        account it is the caller account alone that proves the bound, and
        recording the via-service key as a second one would claim a proof
        the document does not carry.
        """
        via_service_alone = self._read_wildcard_under(
            {"StringEquals": {"kms:ViaService": "ec2.us-west-2.amazonaws.com"}},
            PolicyService.KMS,
        )

        assert via_service_alone.account_ids == set()
        assert via_service_alone.has_wildcard is True
        assert via_service_alone.confined_by == frozenset()

        beside_a_caller_account = self._read_wildcard_under(
            {
                "StringEquals": {
                    "kms:CallerAccount": "111111111111",
                    "kms:ViaService": "ec2.us-west-2.amazonaws.com",
                },
            },
            PolicyService.KMS,
        )

        assert beside_a_caller_account.account_ids == {"111111111111"}
        assert beside_a_caller_account.has_wildcard is False
        assert beside_a_caller_account.confined_by == frozenset({"kms:calleraccount"})

    def test_an_unmodelled_kms_key_does_not_confine_on_its_namespace(self) -> None:
        """
        The service gate is an explicit set of keys, not the service's namespace.

        kms:EncryptionContext:<key> is a real KMS condition key in a real KMS
        key policy, and its values are arbitrary strings a caller chose - an
        account ID is a perfectly ordinary one. It says nothing about who
        makes the request, so admitting it because its name starts `kms:`
        would confine the wildcard on a bound the document never stated and
        put an account no policy ever granted into the allowlist.
        """
        reading = self._read_wildcard_under(
            {"StringEquals": {"kms:EncryptionContext:owner": "111111111111"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_non_mapping_operator_is_a_wildcard(self) -> None:
        """
        An operator holding anything but a mapping of condition keys pins nobody.

        This reader answers every shape it cannot read with a wildcard rather
        than a raise, so a document IAM could not have stored costs coverage
        on one account instead of aborting the estate run.
        """
        reading = self._read_wildcard_under({"StringEquals": "not-a-mapping"})

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    @pytest.mark.parametrize("value", [
        {"nested": "object"},
        111111111111,
        [],
        ["111111111111", 111111111111],
    ])
    def test_statement_principals_with_an_unreadable_clause_value_is_a_wildcard(
        self, value: Any
    ) -> None:
        """
        A clause value that is not an enumeration of strings pins nobody.

        IAM stores a string or a list of strings and nothing else. An empty
        list is here too: whatever it means, it is not a list of principals
        this reader can name, and a shape this reader cannot name does not
        confine.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": value},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_reads_an_account_like_read_principal(self) -> None:
        """A named account is unaffected; there is no wildcard to confine."""
        statement: JsonDict = {"Effect": "Allow", "Principal": {"AWS": "111111111111"}}

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_no_condition_is_a_wildcard(self) -> None:
        """No Condition at all leaves a bare wildcard unconfined."""
        statement: JsonDict = {"Effect": "Allow", "Principal": "*"}

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_aws_wildcard_object_form_agrees(self) -> None:
        """The `{"AWS": "*"}` object form reads the same as the bare string."""
        statement: JsonDict = {"Effect": "Allow", "Principal": {"AWS": "*"}}

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_empty_condition_is_a_wildcard(self) -> None:
        """An empty Condition block enumerates nobody, so it confines nothing."""
        statement: JsonDict = {
            "Effect": "Allow",
            "Principal": "*",
            "Condition": {},
        }

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_an_irrelevant_key_is_a_wildcard(self) -> None:
        """`s3:prefix` narrows the grant, not the principal set, so it confines nothing."""
        statement: JsonDict = {
            "Effect": "Allow",
            "Principal": "*",
            "Condition": {"StringEquals": {"s3:prefix": "logs/"}},
        }

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_malformed_condition_does_not_raise(self) -> None:
        """A Condition shaped nothing like a mapping still resolves, not raises."""
        statement: JsonDict = {
            "Effect": "Allow",
            "Principal": "*",
            "Condition": "not-a-mapping",
        }

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_federated_keeps_non_account_principals(self) -> None:
        """A Federated principal is an identity-type blocker, not a wildcard, and stays unconfined."""
        statement: JsonDict = {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::111111111111:saml-provider/Example",
            },
        }

        reading = read_statement_principals(
            statement,
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            PolicyService.S3,
            ORG_ID,
            "Bucket 'example'",
        )

        assert reading.has_non_account_principals is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_an_if_exists_operator_is_a_wildcard(self) -> None:
        """
        StringEqualsIfExists is satisfied by a request that omits the key.

        An anonymous caller carries no aws:PrincipalAccount at all, so the
        clause holds for them and the wildcard still reaches the public
        internet. The clause enumerates who may call only when the key is
        there to compare.
        """
        reading = self._read_wildcard_under({
            "StringEqualsIfExists": {"aws:PrincipalAccount": ["111111111111"]},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_an_if_exists_arn_operator_is_a_wildcard(self) -> None:
        """
        The IfExists forms are rejected on aws:PrincipalArn too.

        Nothing about the key changes what the suffix does: the clause holds
        for a caller who carries no aws:PrincipalArn, so the role it names
        does not enumerate who the statement reaches, and its account is not
        an account the allowlist has to carry.
        """
        reading = self._read_wildcard_under({
            "ArnLikeIfExists": {"aws:PrincipalArn": "arn:aws:iam::333333333333:role/Example"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_an_if_exists_caller_account_is_a_wildcard(self) -> None:
        """
        The IfExists forms are rejected on a service-scoped key too.

        Being service-scoped buys the key no exemption from the operator
        rules: StringEqualsIfExists holds for a request that carries no
        kms:CallerAccount, so the account it names does not enumerate who
        the statement reaches.
        """
        reading = self._read_wildcard_under(
            {"StringEqualsIfExists": {"kms:CallerAccount": "111111111111"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_wildcarded_caller_account_is_a_wildcard(self) -> None:
        """
        A service-scoped account value is held to the twelve-digit rule too.

        `1111111111*` names a hundred accounts of this organization's and
        every account any other organization holds under the same prefix, so
        the clause enumerates nobody. Reading the value verbatim would put a
        string that is not an account ID into the allowlist.
        """
        reading = self._read_wildcard_under(
            {"StringEquals": {"kms:CallerAccount": "1111111111*"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_negated_account_operator_is_a_wildcard(self) -> None:
        """
        StringNotEquals excludes an account rather than bounding the statement.

        `StringNotEquals aws:PrincipalAccount = ["111111111111"]` admits every
        caller in every other account on earth. It says who may not call,
        which leaves everyone else, so it proves nothing about who may - and
        the one account it names is the one account the allowlist must not
        carry.
        """
        reading = self._read_wildcard_under({
            "StringNotEquals": {"aws:PrincipalAccount": ["111111111111"]},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_negated_arn_operator_is_a_wildcard(self) -> None:
        """
        ArnNotEquals excludes one role and admits every other principal alive.

        The account in the excluded ARN is the account the statement will not
        serve, so harvesting it would be exactly backwards.
        """
        reading = self._read_wildcard_under({
            "ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::333333333333:role/Example"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_for_all_values_operator_is_a_wildcard(self) -> None:
        """
        ForAllValues is satisfied when the request supplies no value at all.

        It asserts that every value the request carries for the key is in the
        list, and a request carrying none satisfies that vacuously. Only a
        companion `Null` clause closes the hole, and this reader runs no such
        rescue, so the wildcard stands.
        """
        reading = self._read_wildcard_under({
            "ForAllValues:StringEquals": {"aws:PrincipalAccount": ["111111111111"]},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_null_guarded_for_all_values_is_a_wildcard(self) -> None:
        """
        A companion Null clause does not rescue ForAllValues for this reader.

        `Null aws:PrincipalOrgPaths = "false"` is the clause AWS pairs with
        ForAllValues to forbid the empty case, and `_read_source_guards`
        honours it for a source guard. This reader runs no such rescue: it
        recognizes a bound only from an operator on its whitelist, so a
        rescued ForAllValues is read the same way an unrescued one is.
        """
        reading = self._read_wildcard_under({
            "ForAllValues:StringLike": {
                "aws:PrincipalOrgPaths": f"{ORG_ID}/r-1111/ou-1111-11111111/*"
            },
            "Null": {"aws:PrincipalOrgPaths": "false"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_an_unknown_set_operator_is_a_wildcard(self) -> None:
        """
        A set operator AWS does not define is read, not rejected with a raise.

        `_read_source_guards` raises on one, because a source guard read as
        absent puts the wrong account in the allowlist. Here an unread clause
        costs only coverage, so `ForSomeValues:`, a prefix IAM defines no
        meaning for, leaves the wildcard standing and the run continues.
        """
        reading = self._read_wildcard_under({
            "ForSomeValues:StringEquals": {"aws:PrincipalAccount": ["111111111111"]},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_boolean_operator_is_a_wildcard(self) -> None:
        """
        Bool compares a Boolean, so it pins no principal whatever it is given.

        The value here is shaped like an account ID on purpose: it leaves the
        operator as the only thing that can reject the clause, which is the
        rule this test is for. Absence from the whitelist is that rule, and
        nothing about the value is consulted first.
        """
        reading = self._read_wildcard_under({
            "Bool": {"aws:PrincipalAccount": "111111111111"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_null_operator_is_a_wildcard(self) -> None:
        """
        Null tests whether a key is present, so it enumerates nobody.

        `_read_source_guards` skips a Null clause by name, because it reads
        that clause separately. This reader needs no such case: Null is not
        on the whitelist, and that is the whole of it. The account-shaped
        value again leaves the operator as the only thing rejecting the
        clause.
        """
        reading = self._read_wildcard_under({
            "Null": {"aws:PrincipalAccount": "111111111111"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_source_account_is_a_wildcard(self) -> None:
        """
        aws:SourceAccount names who drove the call, not who made it.

        A service acting on another resource's behalf populates it with the
        account owning that resource, and the calling principal is the
        service. The key bounds which sources the statement serves and says
        nothing about which principals it admits, so the wildcard stands and
        the account it names is not one an aws:PrincipalAccount allowlist
        should carry.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:SourceAccount": ["111111111111"]},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_source_arn_account_never_reaches_the_allowlist(self) -> None:
        """
        The account in an aws:SourceArn is the originating resource's owner.

        An SNS topic, a bucket, or an alarm drives the call and a service
        makes it; the account in the ARN owns that resource and is routinely
        not the calling principal's. Harvesting it would write it into an
        aws:PrincipalAccount allowlist and hand it direct principal access
        the policy never gave. That widening breaks no workload, so nothing
        downstream would ever report it, and an assertion on the allowlist is
        the only thing that catches it.
        """
        reading = self._read_wildcard_under({
            "ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:666666666666:a-topic"},
        })

        assert "666666666666" not in reading.account_ids
        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_an_if_exists_guard_on_a_wildcard_stays_a_blocker(self) -> None:
        """
        ArnLikeIfExists on aws:SourceArn guards nothing a direct caller does.

        The key is absent on every call a service did not make, and IfExists
        is satisfied by an absent key, so this statement is a genuinely
        public grant wearing a guard's costume. Two separate rules refuse it,
        the operator being off the whitelist and the key naming no principal,
        and the wildcard has to survive either one of them being wrong.
        """
        reading = self._read_wildcard_under({
            "ArnLikeIfExists": {"aws:SourceArn": "arn:aws:sns:us-east-1:666666666666:a-topic"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_source_org_id_is_a_wildcard(self) -> None:
        """
        A source scope is not a principal scope, even naming this organization.

        aws:PrincipalOrgID naming this organization bounds the statement,
        because every caller it admits is a member account. aws:SourceOrgID
        constrains the organization owning the resource that drove the call,
        and any principal at all can drive a resource in this organization,
        so the statement still reaches callers no allowlist enumerates.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:SourceOrgID": ORG_ID},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_source_vpce_is_a_wildcard(self) -> None:
        """
        aws:SourceVpce pins the network path, not the caller on it.

        Every principal in every account that can reach the endpoint
        satisfies it, so the statement's reach is a network boundary rather
        than a list of accounts, and an allowlist of account IDs cannot
        express one.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:SourceVpce": "vpce-11111111111111111"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_date_operator_is_a_wildcard(self) -> None:
        """
        A date bound expires the grant; it does not narrow who holds it.

        Until the moment it names, every principal on earth is inside the
        statement's reach, and the RCP would be deployed the whole time. Two
        rules refuse it here, the operator whitelist and the unmodelled key,
        and neither is redundant: the operator decides on any key and the key
        decides under any operator.
        """
        reading = self._read_wildcard_under({
            "DateLessThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_with_a_mapping_clause_value_is_a_wildcard(self) -> None:
        """
        A mapping where IAM stores a string names no principal, and no raise.

        `_as_condition_values` answers this same shape on a source guard by
        raising, because a source read as empty leaves its account out of the
        allowlist. Here the cost of an unread value is coverage on one
        account, so the reader returns the wildcard and the estate run
        carries on. The mapping sits under aws:PrincipalArn, whose values go
        through a reader of their own, to pin that the shape is refused
        before any key ever sees it.
        """
        reading = self._read_wildcard_under({
            "ArnEquals": {
                "aws:PrincipalArn": {"arn": "arn:aws:iam::333333333333:role/Example"},
            },
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_statement_principals_confines_beside_a_negation_on_the_same_key(self) -> None:
        """
        A negation beside a bound on one key leaves the bound standing.

        Clauses in one Condition block AND together, so an added clause can
        only ever narrow the set of callers admitted. A negation therefore
        cannot widen past a clause that already bounds the statement, and
        ignoring it is safe in the only direction that matters. This
        particular pair admits nobody at all - the account must both be and
        not be 111111111111 - so recording it is over-wide by one entry and
        never under-wide by any.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": ["111111111111"]},
            "StringNotEquals": {"aws:PrincipalAccount": ["111111111111"]},
        })

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_the_negations_the_whitelist_omits_are_still_exactly_four(self) -> None:
        """
        The comment beside CONFINING_OPERATORS names four omitted negations.

        Nothing in the reader consults a negated operator: one confines by
        being on the whitelist, and every operator off it - negations
        included - leaves the wildcard standing. The comment names the four
        omissions so a reader can see they were weighed rather than missed,
        and a whitelist that grew a fifth operator while that list stayed at
        four would make the claim false. This derives the expectation by
        rewriting each whitelisted operator into its negation, the opposite
        of how the comment lists them by name, so the two can disagree.
        """
        negations_the_comment_names = {
            "ArnNotEquals",
            "ArnNotLike",
            "StringNotEquals",
            "StringNotLike",
        }

        derived_from_the_whitelist = {
            operator.replace("Equals", "NotEquals").replace("Like", "NotLike")
            for operator in CONFINING_OPERATORS
        }

        assert negations_the_comment_names == derived_from_the_whitelist

    def test_an_arn_operator_on_an_account_key_confines_nothing(self) -> None:
        """
        An ARN comparison against a key that holds no ARN proves no bound.

        `ArnEquals` compares six colon-delimited components; a twelve-digit
        account ID has one. What IAM makes of the pairing is not something
        this reader guesses at, and guessing wrong would put an account in
        an org-wide allowlist that no policy granted.
        """
        reading = self._read_wildcard_under({
            "ArnEquals": {"aws:PrincipalAccount": "222222222222"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_an_arn_operator_on_a_service_scoped_account_key_confines_nothing(self) -> None:
        """
        The pairing rule holds for kms:CallerAccount in its own service too.

        The service gate and the operator gate are separate: reaching the
        right service does not make an ARN comparison against an account ID
        readable.
        """
        reading = self._read_wildcard_under(
            {"ArnLike": {"kms:CallerAccount": "222222222222"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_an_arn_operator_on_an_organization_scope_confines_nothing(self) -> None:
        """An organization ID is not an ARN either, whichever ARN operator names it."""
        reading = self._read_wildcard_under({
            "ArnEquals": {"aws:PrincipalOrgID": ORG_ID},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_string_operator_on_principal_arn_confines(self) -> None:
        """
        aws:PrincipalArn takes the string operators as well as the ARN ones.

        `StringLike` against a role-name pattern is the ordinary way the key
        is written, so a rule admitting only ArnEquals and ArnLike on it
        would withhold the RCP from most of the accounts that use it.
        """
        reading = self._read_wildcard_under({
            "StringLike": {"aws:PrincipalArn": "arn:aws:iam::222222222222:role/vendor-*"},
        })

        assert reading.account_ids == {"222222222222"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalarn"})

    def test_a_named_principal_is_not_widened_by_its_condition(self) -> None:
        """
        A Condition narrows a wildcard; it never adds a caller.

        Condition clauses AND with the Principal element, so an account the
        Condition names and the Principal does not is reached by nobody.
        Joining it anyway writes an org-wide allowlist entry that exempts an
        account from the Deny without any grant behind it.
        """
        reading = self._read({
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Condition": {"StringEquals": {"aws:PrincipalAccount": "222222222222"}},
        })

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset()

    def test_a_clause_that_enumerates_nothing_does_not_unprove_a_proven_bound(self) -> None:
        """
        Clauses AND, so a second clause cannot widen past the first.

        `StringEquals` pinning one account and `StringLike` admitting any
        together admit that one account. Pooling both clauses' values under
        the key before judging it reads the pair as unbounded, which
        withholds an RCP the policy supports.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": "111111111111"},
            "StringLike": {"aws:PrincipalAccount": "*"},
        })

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_a_non_ascii_digit_run_is_not_an_account_id(self) -> None:
        """
        Twelve digits means twelve ASCII digits.

        AWS never validates a condition value, so a policy may carry any
        twelve characters Python's `\\d` accepts. Fullwidth digits reaching
        the allowlist fail the module's own `^[0-9]{12}$` check and take the
        whole Terraform plan down with them.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalAccount": "１２３４５６７８９０１２"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_non_ascii_digit_run_in_an_arn_account_field_is_not_an_account_id(self) -> None:
        """
        The ASCII rule holds for the account field of an aws:PrincipalArn value.

        The ARN pattern and the bare account pattern are two patterns for one
        twelve-digit rule, and a condition value reaches both unvalidated.
        """
        reading = self._read_wildcard_under({
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::１２３４５６７８９０１２:role/vendor"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_wildcard_under_string_equals_on_principal_arn_confines_nothing(self) -> None:
        """
        `StringEquals` matches exactly, so a `*` in its value is a literal star.

        No ARN carries one, so the clause admits nobody - the author meant
        `StringLike`. Reading it as a bound on the account would put that
        account in an org-wide allowlist no grant reaches; leaving the
        wildcard standing blocks the account until someone fixes the policy,
        which is the one way Headroom has to say the policy needs looking at.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalArn": "arn:aws:iam::222222222222:role/vendor-*"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_single_character_wildcard_under_string_equals_on_principal_arn_confines_nothing(self) -> None:
        """
        `?` is the other wildcard `StringLike` expands and `StringEquals` does not.

        The rule is the same as for `*`, and this pins the half of it that
        the `*` case alone cannot: a guard reading `*` and not `?` would pass
        that case and still mint the allowlist entry here.
        """
        reading = self._read_wildcard_under({
            "StringEquals": {"aws:PrincipalArn": "arn:aws:iam::222222222222:role/vendor-?"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_an_assumed_role_session_arn_on_principal_arn_confines_nothing(self) -> None:
        """
        aws:PrincipalArn holds the role's ARN for a role session, never the session's.

        AWS documents the key as the role ARN and says not to write the
        assumed-role session ARN as its value, so a value under
        `arn:<partition>:sts:` naming `assumed-role/` matches nobody under
        any operator - the author meant `arn:<partition>:iam::<account>:role/`.
        """
        reading = self._read_wildcard_under({
            "ArnLike": {"aws:PrincipalArn": "arn:aws:sts::222222222222:assumed-role/deploy/*"},
        })

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_federated_user_session_arn_on_principal_arn_confines(self) -> None:
        """
        The session-ARN rule reaches only `assumed-role/`, not the sts service.

        For a GetFederationToken session aws:PrincipalArn does hold the
        `federated-user/` ARN, so that value is a real bound on its account.
        This is the positive control on the rule above: a rule keyed on the
        service segment alone would turn this grant into a blocker.
        """
        reading = self._read_wildcard_under({
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:sts::222222222222:federated-user/vendor"},
        })

        assert reading.account_ids == {"222222222222"}
        assert reading.has_wildcard is False
        assert reading.confined_by == frozenset({"aws:principalarn"})

    def test_a_condition_key_with_a_non_ascii_character_confines_nothing(self) -> None:
        """
        A condition key is matched as ASCII, before case is folded.

        IAM has no non-ASCII condition key, so one matches nobody and its
        statement grants nothing. Python's `lower()` folds the Kelvin sign
        U+212A to `k`, which would read `\u212ams:CallerAccount` as the
        real key and mint an org-wide allowlist entry for an account no
        grant reaches.
        """
        reading = self._read_wildcard_under(
            {"StringEquals": {"\u212ams:CallerAccount": "222222222222"}},
            PolicyService.KMS,
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is True
        assert reading.confined_by == frozenset()

    def test_a_statement_with_neither_principal_nor_not_principal_aborts(self) -> None:
        """
        An Allow carrying neither element is a document AWS could not have stored.

        Every resource-policy and trust-policy statement AWS stores carries
        one of the two, so one carrying neither is a misread rather than a
        grant to nobody. The six analyzers once skipped it, each with its own
        read of the element; the reader now raises instead, naming the
        resource, exactly as it does for a Principal of the wrong type.
        """
        statement = {"Effect": "Allow", "Action": "s3:GetObject"}

        with pytest.raises(MalformedPolicyError, match="Bucket 'example-bucket' has an Allow statement carrying neither"):
            read_statement_principals(
                statement, RESOURCE_POLICY_PRINCIPAL_TYPES, PolicyService.S3, ORG_ID, "Bucket 'example-bucket'"
            )

    def test_the_reading_names_the_principal_types_the_element_carries(self) -> None:
        """
        The type keys are a fact of the reading, not of a raw look at the element.

        The trust-policy analyzer asks whether a statement names a `Federated`
        principal. It once answered that with its own read of the element,
        the last raw Principal read any analyzer wrote; the reading carries
        the element's type keys so that it need not.
        """
        statement = {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::222222222222:root",
                "Federated": "arn:aws:iam::222222222222:saml-provider/example-idp",
            },
            "Action": "sts:AssumeRoleWithSAML",
        }

        reading = read_statement_principals(
            statement, TRUST_POLICY_PRINCIPAL_TYPES, PolicyService.STS, ORG_ID, "Role 'example-role'"
        )

        assert reading.principal_types == frozenset({"AWS", "Federated"})

    def test_a_bare_string_principal_carries_no_type_key(self) -> None:
        """A wildcard written `"*"` names no principal type, so the reading names none."""
        statement = {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}

        reading = read_statement_principals(
            statement, TRUST_POLICY_PRINCIPAL_TYPES, PolicyService.STS, ORG_ID, "Role 'example-role'"
        )

        assert reading.principal_types == frozenset()

    def test_the_principal_types_survive_the_wildcard_rebuild(self) -> None:
        """
        A wildcard beside a Federated principal keeps both type keys.

        A statement whose Principal is a wildcard is rebuilt after its
        Condition is read, and the rebuild must carry the type keys across.
        Dropping them there left every other test green: the Federated tests
        all use a bare `{"Federated": ...}`, which takes the early return,
        and the trust-policy analyzer's Federated check would have gone
        blind on exactly the statement that names `*` beside the provider.
        """
        statement = {
            "Effect": "Allow",
            "Principal": {
                "AWS": "*",
                "Federated": "arn:aws:iam::222222222222:saml-provider/example-idp",
            },
            "Action": "sts:AssumeRole",
        }

        reading = read_statement_principals(
            statement, TRUST_POLICY_PRINCIPAL_TYPES, PolicyService.STS, ORG_ID, "Role 'example-role'"
        )

        assert reading.has_wildcard is True
        assert reading.principal_types == frozenset({"AWS", "Federated"})

    def test_a_null_principal_aborts_as_a_principal_of_the_wrong_type(self) -> None:
        """
        `Principal: null` is present, so it is not the missing-element case.

        The adapters' skip once swallowed it along with the empty forms. It
        reaches _read_principal now, which aborts on a Principal that is
        neither a string, a list, nor an object, as the spec row has always
        said it does.
        """
        statement = {"Effect": "Allow", "Principal": None, "Action": "s3:GetObject"}

        with pytest.raises(MalformedPolicyError, match="Bucket 'example-bucket' has a Principal of type NoneType"):
            read_statement_principals(
                statement, RESOURCE_POLICY_PRINCIPAL_TYPES, PolicyService.S3, ORG_ID, "Bucket 'example-bucket'"
            )

    @pytest.mark.parametrize("empty_principal", [{}, [], ""])
    def test_an_empty_principal_names_nobody(self, empty_principal: PrincipalElement) -> None:
        """
        A present but empty Principal reads as naming nobody, not as absent.

        `{}`, `[]`, and `""` all once fell to the adapters' falsy skip. They
        now reach the reader and contribute no account, no wildcard, and no
        type, which is the outcome the skip produced for them.
        """
        statement = {"Effect": "Allow", "Principal": empty_principal, "Action": "s3:GetObject"}

        reading = read_statement_principals(
            statement, RESOURCE_POLICY_PRINCIPAL_TYPES, PolicyService.S3, ORG_ID, "Bucket 'example-bucket'"
        )

        assert reading == PrincipalReading(account_ids=set(), has_wildcard=False, has_non_account_principals=False)


A_BARE_STRING_WILDCARD_UNDER_AN_ACCOUNT_LIST: JsonDict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowPartnerReads",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::example-bucket",
                "arn:aws:s3:::example-bucket/*",
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalAccount": ["111111111111", "222222222222"],
                },
            },
        },
    ],
}


TWO_OBJECT_FORM_WILDCARDS_UNDER_AN_ACCOUNT_LIST: JsonDict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowPartnerList",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example-exports",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalAccount": ["111111111111", "222222222222"],
                },
            },
        },
        {
            "Sid": "AllowPartnerGet",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": "arn:aws:s3:::example-exports/*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalAccount": ["111111111111", "222222222222"],
                },
            },
        },
    ],
}


A_ROOT_ARN_TWO_SERVICES_AND_A_WILDCARD_BOUND_TO_A_SERVICE_LINKED_ROLE: JsonDict = {
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [
        {
            "Sid": "EnableIAMUserPermissions",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Action": "kms:*",
            "Resource": "*",
        },
        {
            "Sid": "AllowLogDelivery",
            "Effect": "Allow",
            "Principal": {"Service": "delivery.logs.amazonaws.com"},
            "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
            "Resource": "*",
        },
        {
            "Sid": "AllowAttachmentOfPersistentResources",
            "Effect": "Allow",
            "Principal": {"Service": "autoscaling.amazonaws.com"},
            "Action": ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"],
            "Resource": "*",
            "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}},
        },
        {
            "Sid": "AllowServiceLinkedRoleUse",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:GenerateDataKey*",
                "kms:ReEncrypt*",
            ],
            "Resource": "*",
            "Condition": {
                "ArnEquals": {
                    "aws:PrincipalArn": (
                        "arn:aws:iam::111111111111:role/aws-service-role/"
                        "autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
                    ),
                },
            },
        },
    ],
}


A_SERVICE_PRINCIPAL_AND_A_WILDCARD_UNDER_THE_SAME_SOURCE_ARN: JsonDict = {
    "Version": "2012-10-17",
    "Id": "example-queue-policy",
    "Statement": [
        {
            "Sid": "AllowTopicDelivery",
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": "arn:aws:sqs:us-east-1:111111111111:example-queue",
            "Condition": {
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:sns:us-east-1:666666666666:a-topic",
                },
            },
        },
        {
            "Sid": "AllowTopicDeliveryTheConsoleWroteFirst",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sqs:SendMessage",
            "Resource": "arn:aws:sqs:us-east-1:111111111111:example-queue",
            "Condition": {
                "ArnLike": {
                    "aws:SourceArn": "arn:aws:sns:us-east-1:666666666666:a-topic",
                },
            },
        },
    ],
}


class TestWholeDocumentPrincipalReadings:
    """
    The reader against whole documents.

    `read_statement_principals` answers for one statement, and two rules no
    single-statement test can state appear only once every statement of a
    document has been read: the document's verdict is the OR of its
    statements, and two statements granting the same access can still reach
    opposite verdicts. The documents above are named for their shape,
    because shape is what the reader branches on; the service is consulted
    only for which service-scoped condition keys exist at all.
    """
    RESOURCE_DESCRIPTION = "Resource 'example'"

    def _read_every_statement(
        self,
        document: JsonDict,
        policy_service: PolicyService = PolicyService.S3,
    ) -> List[PrincipalReading]:
        """
        Read every statement of one document, in the document's own order.

        This is not the whole of what an adapter does. Every adapter gates
        on `Effect` and on `has_not_principal` before it calls the reader at
        all, and those gates are tested where they live. Every document
        read here must therefore be all-Allow with a Principal on each
        statement: a Deny statement would add a reading no adapter would
        ever take, and a statement without a Principal would raise, because
        the reader aborts on one rather than skipping it.

        Args:
            document: The policy document to read
            policy_service: The service whose policy this is, deciding which
                service-scoped condition keys can confine its statements. S3
                recognizes none, so a caller that omits this reads on the
                global keys alone

        Returns:
            One reading per statement, in the document's own order
        """
        return [
            read_statement_principals(
                statement,
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                policy_service,
                ORG_ID,
                self.RESOURCE_DESCRIPTION,
            )
            for statement in normalize_statements(document, self.RESOURCE_DESCRIPTION)
        ]

    def test_one_unconfined_wildcard_blocks_a_document_of_confined_ones(self) -> None:
        """
        Confinement is a property of a statement, never of the document.

        An adapter accumulates `has_wildcard` across a document with `or`, so
        one statement nothing bounds blocks the resource however many bounded
        statements sit beside it. Reading the document as confined because
        most of it is would generate an RCP that breaks the grant the last
        statement makes to everyone.
        """
        confined, unconfined = self._read_every_statement({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/partner/*",
                    "Condition": {
                        "StringEquals": {"aws:PrincipalAccount": "222222222222"},
                    },
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/public/*",
                },
            ],
        })

        assert confined.account_ids == {"222222222222"}
        assert confined.has_wildcard is False
        assert confined.has_non_account_principals is False
        assert confined.confined_by == frozenset({"aws:principalaccount"})
        assert unconfined.account_ids == set()
        assert unconfined.has_wildcard is True
        assert unconfined.has_non_account_principals is False
        assert unconfined.confined_by == frozenset()
        assert (confined.has_wildcard or unconfined.has_wildcard) is True

    def test_a_bare_string_wildcard_confines_on_the_accounts_it_names(self) -> None:
        """
        The bare-string principal is the same grant as the object form.

        A reader that recognized only `{"AWS": "*"}` would leave this
        document a blocker. That is the safe direction, but it withholds an
        RCP from an organization whose grant is already bounded to two
        accounts written right there in the statement.
        """
        [reading] = self._read_every_statement(A_BARE_STRING_WILDCARD_UNDER_AN_ACCOUNT_LIST)

        assert reading.account_ids == {"111111111111", "222222222222"}
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False
        assert reading.confined_by == frozenset({"aws:principalaccount"})

    def test_each_statement_of_a_split_grant_confines_on_its_own(self) -> None:
        """
        A document is confined only when every one of its statements is.

        The console wrote one grant as two statements, a bucket statement
        and an object statement, each carrying its own copy of the clause.
        The two differ only in their `Sid`, `Action`, and `Resource`, none
        of which the reader reads, so the two readings have to come back
        identical: a document does not become less confined merely by
        being written out statement by statement.
        """
        first, second = self._read_every_statement(TWO_OBJECT_FORM_WILDCARDS_UNDER_AN_ACCOUNT_LIST)

        assert first.account_ids == {"111111111111", "222222222222"}
        assert first.has_wildcard is False
        assert first.has_non_account_principals is False
        assert first.confined_by == frozenset({"aws:principalaccount"})
        assert second.account_ids == {"111111111111", "222222222222"}
        assert second.has_wildcard is False
        assert second.has_non_account_principals is False
        assert second.confined_by == frozenset({"aws:principalaccount"})

    def test_named_principals_beside_a_service_linked_role_leave_no_wildcard(self) -> None:
        """
        Four statements, four bounded readings, one account to preserve.

        Read under the one service that recognizes a service-scoped account
        key, so the third statement's `kms:` clause is offered every chance
        to confine and still confines nothing: it is not the modelled key,
        and a Service principal was never a wildcard for it to narrow. The
        last statement is the one its condition decides, and the
        service-linked role bounds it while naming nobody the allowlist has
        to carry, because an RCP does not impact one.
        """
        readings = self._read_every_statement(
            A_ROOT_ARN_TWO_SERVICES_AND_A_WILDCARD_BOUND_TO_A_SERVICE_LINKED_ROLE,
            PolicyService.KMS,
        )
        root, unconditioned_service, guarded_service, service_linked_role = readings

        assert root.account_ids == {"111111111111"}
        assert root.has_wildcard is False
        assert root.has_non_account_principals is False
        assert root.confined_by == frozenset()
        assert unconditioned_service.account_ids == set()
        assert unconditioned_service.has_wildcard is False
        assert unconditioned_service.has_non_account_principals is False
        assert unconditioned_service.confined_by == frozenset()
        assert guarded_service.account_ids == set()
        assert guarded_service.has_wildcard is False
        assert guarded_service.has_non_account_principals is False
        assert guarded_service.confined_by == frozenset()
        assert service_linked_role.account_ids == set()
        assert service_linked_role.has_wildcard is False
        assert service_linked_role.has_non_account_principals is False
        assert service_linked_role.confined_by == frozenset({"aws:principalarn"})

    def test_the_legacy_console_form_blocks_where_the_service_form_does_not(self) -> None:
        """
        Two statements granting one delivery, and only one of them is read.

        They are not the same statement written twice. The first names who
        may call, so nothing about it is a wildcard. The second names
        anybody at all and then says where the call has to have come from,
        which bounds the request rather than the caller: any principal whose
        request carries that source ARN is admitted. Reading the pair as one
        grant, on the strength of their granting the same action on the same
        queue to the same topic, would take the first statement's bound as
        the second's and generate an RCP that breaks a genuinely public one.
        """
        service_form, console_form = self._read_every_statement(
            A_SERVICE_PRINCIPAL_AND_A_WILDCARD_UNDER_THE_SAME_SOURCE_ARN,
        )

        assert service_form.account_ids == set()
        assert service_form.has_wildcard is False
        assert service_form.has_non_account_principals is False
        assert service_form.confined_by == frozenset()
        assert console_form.account_ids == set()
        assert console_form.has_wildcard is True
        assert console_form.has_non_account_principals is False
        assert console_form.confined_by == frozenset()
        assert service_form.has_wildcard != console_form.has_wildcard

    def test_no_account_in_a_source_arn_reaches_the_allowlist(self) -> None:
        """
        The account in an aws:SourceArn owns the topic, not the request.

        666666666666 owns the originating resource, and the credentials a
        service signs that request with are routinely another account's, so
        harvesting it would hand it direct principal access the policy never
        granted. Widening breaks no workload, so nothing downstream would
        ever report it and this assertion is the only thing that catches it.
        The ARN carries a well-formed twelve-digit account in the field an
        ARN reader reads, so the account arrives here whenever that reader
        is pointed at the key, rather than being turned away for a reason
        this test did not mean to rely on. Every per-field assertion the
        test above makes is restated below so that this test stands on its
        own; the assertion this test exists for is the last one, about the
        account.
        """
        service_form, console_form = self._read_every_statement(
            A_SERVICE_PRINCIPAL_AND_A_WILDCARD_UNDER_THE_SAME_SOURCE_ARN,
        )

        assert service_form.account_ids == set()
        assert service_form.has_wildcard is False
        assert service_form.has_non_account_principals is False
        assert service_form.confined_by == frozenset()
        assert console_form.account_ids == set()
        assert console_form.has_wildcard is True
        assert console_form.has_non_account_principals is False
        assert console_form.confined_by == frozenset()
        assert "666666666666" not in service_form.account_ids | console_form.account_ids


class TestPrincipalArnCoverage:
    """
    Every documented principal ARN form must yield its account ID.

    The analyzers once matched only `^arn:aws:iam::(\\d{12}):`, so STS session
    principals - which AWS documents as valid in a resource-based policy, and
    a role trust policy is one - and every non-commercial partition produced
    no account ID at all.
    """
    PARTNER = "999999999999"

    @pytest.mark.parametrize("principal", [
        "arn:aws:iam::999999999999:root",
        "arn:aws:iam::999999999999:role/vendor",
        "arn:aws:iam::999999999999:user/vendor",
        "arn:aws:sts::999999999999:assumed-role/vendor/session",
        "arn:aws:sts::999999999999:federated-user/vendor",
        "arn:aws-us-gov:iam::999999999999:role/vendor",
        "arn:aws-cn:iam::999999999999:role/vendor",
        "999999999999",
    ])
    def test_principal_yields_account_id(self, principal: str) -> None:
        """Each documented principal form resolves to its account."""
        reading = _read_principal(
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, "Role 'example'"
        )

        assert reading.account_ids == {self.PARTNER}

    def test_non_account_principal_yields_nothing(self) -> None:
        """A service principal carries no account ID."""
        reading = _read_principal(
            "ec2.amazonaws.com", RESOURCE_POLICY_PRINCIPAL_TYPES, "Role 'example'"
        )

        assert reading.account_ids == set()


class TestSourceGuardOperatorSemantics:
    """
    An IfExists operator guards only the key the deployed statement pins.

    A guard written with an ...IfExists operator also matches a request that
    omits the key. The generated statement exempts the key-absent case for
    exactly one key, aws:SourceAccount, through `Null aws:SourceAccount =
    "false"`. On every other key the resource policy therefore permits a call
    the deployed RCP denies, and the statement must be withheld from that
    account instead.
    """
    ORG_ID = "o-11111111111"
    ORG_ACCOUNT_IDS = frozenset({"222222222222"})

    def _read_one(self, operator: str, key: str, value: str) -> ServicePrincipalSource:
        """
        Read the source guard one operator and key put on a Service principal.

        Args:
            operator: The condition operator to write the guard under
            key: The source condition key
            value: The value the guard pins

        Returns:
            The single source entry the statement yields
        """
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Condition": {operator: {key: value}},
        }
        sources = read_service_principal_sources(
            statement, set(self.ORG_ACCOUNT_IDS), self.ORG_ID, "Queue 'example-queue'"
        )
        assert len(sources) == 1
        return sources[0]

    def test_source_account_is_a_guard_under_a_plain_operator(self) -> None:
        """A pinned aws:SourceAccount names one account, which an allowlist carries."""
        source = self._read_one("StringEquals", "aws:SourceAccount", "111111111111")

        assert source.source_account_ids == ["111111111111"]
        assert source.has_wildcard_source is False

    def test_source_account_is_still_a_guard_under_if_exists(self) -> None:
        """
        aws:SourceAccount is the one key IfExists is safe on.

        The deployed statement carries `Null aws:SourceAccount = "false"`, so
        it applies only to a service call that populates this key. A call that
        omits it - the case IfExists additionally permits - falls outside the
        deny, so the resource policy and the RCP agree.
        """
        source = self._read_one(
            "StringEqualsIfExists", "aws:SourceAccount", "111111111111"
        )

        assert source.source_account_ids == ["111111111111"]
        assert source.has_wildcard_source is False

    def test_source_arn_is_a_guard_under_a_plain_operator(self) -> None:
        """A pinned aws:SourceArn yields the account in its account field."""
        source = self._read_one(
            "ArnEquals", "aws:SourceArn", "arn:aws:sns:us-east-1:111111111111:topic-one"
        )

        assert source.source_account_ids == ["111111111111"]
        assert source.has_wildcard_source is False

    def test_source_arn_under_if_exists_is_a_wildcard(self) -> None:
        """
        An IfExists guard on aws:SourceArn permits a call the RCP denies.

        The statement conditions on aws:SourceOrgID and aws:SourceAccount and
        does not mention aws:SourceArn, so a service call carrying
        aws:SourceAccount and no aws:SourceArn satisfies this resource policy
        and is denied by the deployed RCP. No allowlist can express that, so
        the statement is withheld from the account.
        """
        source = self._read_one(
            "ArnEqualsIfExists",
            "aws:SourceArn",
            "arn:aws:sns:us-east-1:111111111111:topic-one",
        )

        assert source.source_account_ids == ["111111111111"]
        assert source.has_wildcard_source is True

    def test_source_org_id_naming_this_organization_is_a_guard(self) -> None:
        """A scope naming this organization needs no allowlist entry at all."""
        source = self._read_one("StringEquals", "aws:SourceOrgID", self.ORG_ID)

        assert source.source_account_ids == []
        assert source.has_wildcard_source is False

    def test_source_org_id_under_if_exists_is_a_wildcard(self) -> None:
        """Even this organization's own ID stops being a guard under IfExists."""
        source = self._read_one("StringEqualsIfExists", "aws:SourceOrgID", self.ORG_ID)

        assert source.has_wildcard_source is True

    def test_source_org_paths_naming_this_organization_is_a_guard(self) -> None:
        """An aws:SourceOrgPaths value carries the organization ID first."""
        source = self._read_one(
            "StringEquals", "aws:SourceOrgPaths", f"{self.ORG_ID}/r-1111/ou-1111-11111111/"
        )

        assert source.source_account_ids == []
        assert source.has_wildcard_source is False

    def test_source_org_paths_under_if_exists_is_a_wildcard(self) -> None:
        """aws:SourceOrgPaths takes the same rule as aws:SourceOrgID."""
        source = self._read_one(
            "StringEqualsIfExists",
            "aws:SourceOrgPaths",
            f"{self.ORG_ID}/r-1111/ou-1111-11111111/",
        )

        assert source.has_wildcard_source is True

    def test_source_guard_if_exists_operators_is_exactly_the_suffix_subset(self) -> None:
        """
        SOURCE_GUARD_IF_EXISTS_OPERATORS must track SOURCE_GUARD_OPERATORS.

        The brief chose to name the four forms explicitly rather than compute
        them from a suffix, so that adding an operator to SOURCE_GUARD_OPERATORS
        is a deliberate edit rather than an automatic one. Nothing else ties the
        two frozensets together, so an operator added to SOURCE_GUARD_OPERATORS
        and forgotten here would silently restore the bug this class exists to
        close - the newly added operator would guard a key even when its
        request omits that key entirely. This test derives the expected set by
        suffix, the opposite of how the production code lists it by name, so
        the two can actually disagree with each other.
        """
        derived_from_suffix = {
            operator for operator in SOURCE_GUARD_OPERATORS if operator.endswith("IfExists")
        }

        assert SOURCE_GUARD_IF_EXISTS_OPERATORS == derived_from_suffix


ACTION_ELEMENT_KEYS = frozenset({"Action", "NotAction"})


def _is_element_read(node: ast.AST, element_keys: frozenset[str]) -> bool:
    """
    Report whether one AST node reads one of these elements off a statement.

    Two forms reach a raw element: `statement["Action"]` and
    `statement.get("Action", ...)`. Each element's predicate below names
    its own keys and states its own reason; the walk that recognizes the
    two forms is this one, so a further element's guard adds a key set and
    not a copy.

    Args:
        node: One node from a function's AST
        element_keys: The statement keys that name the element

    Returns:
        True if the node is either form on one of the keys
    """
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value in element_keys

    if not isinstance(node, ast.Call):
        return False

    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return False

    return bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value in element_keys


def _is_action_element_read(node: ast.AST) -> bool:
    """
    Report whether one AST node reads an Action element off a statement.

    Both forms hand back whatever the document held - a string, a list, or
    something IAM would have rejected - so whoever performs one owes the
    result to normalize_actions.

    Args:
        node: One node from a function's AST

    Returns:
        True if the node is either form
    """
    return _is_element_read(node, ACTION_ELEMENT_KEYS)


def _functions_matching(predicate: Callable[[ast.FunctionDef], bool]) -> set[str]:
    """
    Report every function in the package whose definition satisfies predicate.

    The package walk this performs - parse every file under the package
    root, visit its function definitions, name each match
    "<module>.<function>" - used to be copied once per guard below. Three
    copies of it had drifted into this file alone, in a class whose own
    docstring is about copies of a walk drifting apart.

    Args:
        predicate: Tested against each function definition in the package

    Returns:
        "<module>.<function>" for each match, module-relative to the package
    """
    package_root = Path(headroom.__file__).parent

    found = set()
    for path in sorted(package_root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not predicate(node):
                continue
            module = path.relative_to(package_root).as_posix()
            found.add(f"{module}.{node.name}")

    return found


def _takes_parameter_named(node: ast.FunctionDef, parameter_names: frozenset[str]) -> bool:
    """
    Report whether a function definition takes one of these parameters.

    Args:
        node: One function definition from the package
        parameter_names: The parameter names that mark a reader

    Returns:
        True if the function takes one of these parameters
    """
    arguments = node.args.args + node.args.kwonlyargs
    return bool(parameter_names.intersection(a.arg for a in arguments))


def _has_unnormalized_action_read(node: ast.FunctionDef) -> bool:
    """
    Report whether a function reads an Action element it never normalizes.

    Per-function was the hole a mixed body could walk through: a function
    that called normalize_actions on one read was treated as safe for every
    read anywhere else in its body, so `good = normalize_actions(s["Action"])`
    alongside a bare `bad = s["NotAction"]` in the same function passed
    clean. A read is safe only when it appears inside the arguments of a
    normalize_actions call in this same function - a call elsewhere in the
    body, on a different read, does not cover it.

    Args:
        node: One function definition from the package

    Returns:
        True if the function contains a read not covered that way
    """
    reads = {id(inner) for inner in ast.walk(node) if _is_action_element_read(inner)}
    if not reads:
        return False

    normalized: set[int] = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        if call.func.id != "normalize_actions":
            continue
        for argument in list(call.args) + [keyword.value for keyword in call.keywords]:
            normalized.update(id(inner) for inner in ast.walk(argument) if _is_action_element_read(inner))

    return bool(reads - normalized)


PRINCIPAL_ELEMENT_KEYS = frozenset({"Principal", "NotPrincipal"})

# _read_principal is the sink all six external analyzers reach.
# _service_principals is policy_documents.py's own second canonical reader -
# test_only_policy_documents_reads_a_statement_principal already names it
# alongside _read_principal. _read_service_principal_sources binds one read to
# a local and hands it to both: _service_principals for the confused-deputy
# check's Service principals, _read_principal for the wildcard fact.
PRINCIPAL_ELEMENT_READERS = frozenset({"_read_principal", "_service_principals"})


def _is_principal_element_read(node: ast.AST) -> bool:
    """
    Report whether one AST node reads a Principal element off a statement.

    The two forms that reach the raw element are `statement["Principal"]`
    and `statement.get("Principal", ...)`, matching the pair
    _is_action_element_read recognizes. `"NotPrincipal" in statement` is a
    membership test rather than a read and is not one of them.

    Args:
        node: One node from a function's AST

    Returns:
        True if the node is either form
    """
    return _is_element_read(node, PRINCIPAL_ELEMENT_KEYS)


def _has_unread_principal_element(node: ast.FunctionDef) -> bool:
    """
    Report whether a function reads a Principal element no canonical reader sees.

    Per read rather than per function, for the reason the Action guard
    states: a function that hands one read to a canonical reader is not
    thereby excused for another it reads raw in the same body.

    Coverage has two shapes here where the Action guard has one. A read
    reaches a name in PRINCIPAL_ELEMENT_READERS inline, or it is bound to a
    local on one line and that local is passed on another - which is the
    shape read_statement_principals and _read_service_principal_sources
    write. Recognizing only the inline form would report both of them.

    There is no third. The guard once forgave one raw read per statement
    handed to read_statement_principals, because all six analyzers read the
    element themselves to skip a statement carrying none. That skip is the
    statement reader's now, which raises on such a statement, and the
    excusal - the one hole a divergent walk was shown to hide in - went
    with it.

    Args:
        node: One function definition from the package

    Returns:
        True if the function contains a read not covered either way
    """
    reads = {id(inner) for inner in ast.walk(node) if _is_principal_element_read(inner)}
    if not reads:
        return False

    bound: Dict[str, int] = {}
    for assignment in ast.walk(node):
        if not isinstance(assignment, ast.Assign) or not _is_principal_element_read(assignment.value):
            continue
        for target in assignment.targets:
            if isinstance(target, ast.Name):
                bound[target.id] = id(assignment.value)

    covered: set[int] = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        if call.func.id not in PRINCIPAL_ELEMENT_READERS:
            continue
        for argument in list(call.args) + [keyword.value for keyword in call.keywords]:
            for inner in ast.walk(argument):
                if _is_principal_element_read(inner):
                    covered.add(id(inner))
                if isinstance(inner, ast.Name) and inner.id in bound:
                    covered.add(bound[inner.id])

    return bool(reads - covered)


CONDITION_ELEMENT_KEYS = frozenset({"Condition"})


def _is_condition_element_read(node: ast.AST) -> bool:
    """
    Report whether one AST node reads the Condition block off a statement.

    The block is handed to a reader whole; there is no element-level
    reader to credit a read to, so the rule for this element is where the
    read may happen rather than what it must reach.

    Args:
        node: One node from a function's AST

    Returns:
        True if the node is either form
    """
    return _is_element_read(node, CONDITION_ELEMENT_KEYS)


def _reads_a_condition_element(node: ast.FunctionDef) -> bool:
    """
    Report whether a function reads the Condition block off a statement.

    Args:
        node: One function definition from the package

    Returns:
        True if any node in its body is such a read
    """
    return any(_is_condition_element_read(inner) for inner in ast.walk(node))


class TestOneReaderPerStatementElement:
    """
    The readers of a statement element live in policy_documents.py alone.

    Six copies of the Principal walk once disagreed four ways, and five copies
    of the Action reader disagreed four ways after that. Both were collapsed
    into one function, but nothing stopped a seventh copy appearing next to a
    new feature - which is how every previous copy arrived. These pin the
    collapse statically, because a divergent copy fails no other test: each
    analyzer's own suite passes against its own reader, which is exactly how
    the drift survived.

    A statement element is polymorphic - a string, a list, or an object - so a
    function taking one is a reader. The exceptions below all take a plain
    `str` and are named here rather than excluded by a rule, so that adding one
    is a deliberate edit.
    """

    def test_only_policy_documents_reads_a_statement_principal(self) -> None:
        """A Principal element is read in one place, or it drifts."""
        is_principal_reader = partial(_takes_parameter_named, parameter_names=frozenset({"principal"}))
        assert _functions_matching(is_principal_reader) == {
            "aws/policy_documents.py._account_ids_in_string",
            "aws/policy_documents.py._read_principal",
            "aws/policy_documents.py._service_principals",
            # The one rule for a service-linked role, read by _read_principal
            # for a Principal element and by kms.py for a grantee.
            "aws/policy_documents.py.is_service_linked_role_arn",
            # A grant's principal is a plain ARN string from ListGrants, not a
            # statement's Principal element, and no allowlist reads it.
            "aws/kms.py._grant_principal_account_id",
            "aws/kms.py._external_grant_account",
            # Classifies a grant's GranteePrincipal, not a statement's
            # Principal element. A Principal element can hold a bare unique
            # ID too, and _read_principal is the one rule for that surface;
            # kms.py reads the grantee through this module rather than
            # keeping a second copy of the shape.
            "aws/iam_unique_ids.py.iam_unique_id_kind",
        }

    def test_only_policy_documents_normalizes_a_statement_action(self) -> None:
        """An Action element is read in one place, or it drifts."""
        is_action_reader = partial(_takes_parameter_named, parameter_names=frozenset({"action", "actions"}))
        assert _functions_matching(is_action_reader) == {
            "aws/policy_documents.py.normalize_actions",
            # Matches one already-normalized action against one pattern; it
            # never sees the Action element.
            "aws/iam/roles.py._action_pattern_matches",
        }

    def test_only_policy_documents_reads_a_statement_condition(self) -> None:
        """
        A Condition block is read in one place, or it drifts.

        Action and Principal got their guards after copies of each walk had
        drifted apart. Condition never left this module, and this pins that
        before the drift rather than after it. Three readers ask the block
        different questions; all three walk it through `_condition_clauses`,
        which splits the operator, folds the key, and drops a non-ASCII key
        once, so the fourth name here is the one the other three share.
        """
        is_condition_reader = partial(_takes_parameter_named, parameter_names=frozenset({"condition"}))
        assert _functions_matching(is_condition_reader) == {
            "aws/policy_documents.py._condition_clauses",
            "aws/policy_documents.py._keys_asserted_present",
            "aws/policy_documents.py._read_principal_confinement",
            "aws/policy_documents.py._read_source_guards",
        }

    def test_every_condition_element_read_is_in_policy_documents(self) -> None:
        """
        `statement["Condition"]` is written by the two statement readers alone.

        The parameter guard cannot see an inline read, for the reason the
        Principal guard states. An adapter that reached the block itself
        would be a reader of it that no test of this module runs.
        """
        assert _functions_matching(_reads_a_condition_element) == {
            "aws/policy_documents.py._read_service_principal_sources",
            "aws/policy_documents.py.read_statement_principals",
        }

    def test_every_principal_element_read_reaches_read_principal(self) -> None:
        """
        Reading Principal or NotPrincipal off a statement obliges you to
        hand it to _read_principal.

        The parameter-name guard above cannot see an inline read: a seventh
        copy of the walk taking a parameter called `statement` rather than
        `principal` passes it while returning a different answer for bare
        twelve-digit IDs, GovCloud, China, and STS ARNs. The Action element
        got this counterpart after five copies disagreed four ways; the
        Principal element, after six copies disagreed four ways, did not.
        """
        assert _functions_matching(_has_unread_principal_element) == set()

    def test_the_principal_guard_reports_a_read_that_never_reaches_the_reader(self) -> None:
        """
        The guard above must report a bare read, or it proves nothing.

        Both shapes _is_principal_element_read recognizes are built, on both
        keys it recognizes: the subscript and the `.get`, on `Principal` and
        on `NotPrincipal`, because a branch with no assertion behind it is a
        branch that can be neutered silently.
        """
        for source in (
            'element = s["Principal"]',
            'element = s.get("Principal")',
            'element = s["NotPrincipal"]',
            'element = s.get("NotPrincipal")',
        ):
            function = ast.parse(f"def f(s):\n    {source}\n    return element").body[0]
            assert isinstance(function, ast.FunctionDef)

            assert _has_unread_principal_element(function) is True

    def test_the_principal_guard_accepts_a_read_bound_to_a_local(self) -> None:
        """
        The shape policy_documents.py's own readers write must not be reported.

        `principal = statement["Principal"]` followed by
        `_read_principal(principal, ...)` is what read_statement_principals
        and _read_service_principal_sources do, and an inline-only rule
        reports both of them as violations.
        """
        function = ast.parse(
            "def f(statement):\n"
            "    principal = statement.get('Principal')\n"
            "    return _read_principal(principal, TYPES, 'where')\n"
        ).body[0]
        assert isinstance(function, ast.FunctionDef)

        assert _has_unread_principal_element(function) is False

    def test_the_principal_guard_reports_the_skip_gate_the_analyzers_once_wrote(self) -> None:
        """
        A read off a statement handed to read_statement_principals is not excused.

        All six analyzers once read `Principal` themselves to skip a
        statement carrying none, and the guard kept a rule forgiving one such
        read per statement name. That rule was the one hole a divergent walk
        could hide in, and it was shown to hide one: an inline wildcard test
        injected into `sqs.py` beside the sanctioned call passed the whole
        class. The skip now lives in read_statement_principals, which raises
        on a statement carrying neither `Principal` nor `NotPrincipal`, so
        nothing outside policy_documents.py has a reason to touch the
        element and the guard forgives no read at all.
        """
        function = ast.parse(
            "def f(statement):\n"
            "    principal = statement.get('Principal')\n"
            "    if not principal:\n"
            "        return None\n"
            "    return read_statement_principals(statement, TYPES, SERVICE, 'o-11111111111', 'where')\n"
        ).body[0]
        assert isinstance(function, ast.FunctionDef)

        assert _has_unread_principal_element(function) is True

    def test_the_principal_guard_accepts_an_inline_read(self) -> None:
        """
        A read passed straight into the reader's call is the other shape.

        Nothing in the package writes it today, so this is the only thing
        that keeps the guard honest about it: a future inline
        `_read_principal(statement.get("Principal"), ...)` must not be
        reported.
        """
        function = ast.parse(
            "def f(statement):\n"
            "    return _read_principal(statement.get('Principal'), TYPES, 'where')\n"
        ).body[0]
        assert isinstance(function, ast.FunctionDef)

        assert _has_unread_principal_element(function) is False

    def test_every_action_element_read_is_normalized(self) -> None:
        """
        Reading Action or NotAction off a statement obliges you to normalize it.

        The parameter-name guard above cannot see an inline read: both sites
        in iam/roles.py once reached the element off a local named
        `statement`, so neither function took a parameter called `action`.
        This checks per read rather than per function, because a function
        that normalizes one read is not thereby excused for another it reads
        raw in the same body - see
        test_a_normalize_actions_call_on_one_read_does_not_excuse_another.

        It still cannot see everything: an async function's body, a read at
        module level rather than inside any function, and a read through a
        non-literal key (`k = "Action"; s[k]`) all pass silently. A green
        result here is not a proof of the property, only the absence of the
        shapes this specific check looks for.
        """
        assert _functions_matching(_has_unnormalized_action_read) == set()

    @pytest.mark.parametrize("raw_read", ["s['NotAction']", "s.get('NotAction', [])"])
    def test_a_normalize_actions_call_on_one_read_does_not_excuse_another(self, raw_read: str) -> None:
        """
        Reproduce the false negative a per-function guard had.

        The predicate this guard replaced asked only whether
        normalize_actions was called anywhere in a function's body, so a
        function normalizing one read and reading another raw passed as
        clean. This builds exactly that function and checks that the
        per-read replacement catches it.

        Both shapes _is_action_element_read recognizes are built, because the
        subscript alone left its `.get` branch with no assertion behind it:
        neutering that branch failed nothing here and was caught only by the
        coverage gate, which is a different property being measured by
        accident.
        """
        tree = ast.parse(
            "def mixed(s):\n"
            "    good = normalize_actions(s['Action'])\n"
            f"    bad = {raw_read}\n"
            "    return good, bad\n"
        )
        function = tree.body[0]
        assert isinstance(function, ast.FunctionDef)

        assert _has_unnormalized_action_read(function) is True

    def test_only_policy_documents_calls_the_element_reader_directly(self) -> None:
        """
        An adapter reaches a Principal element through the statement reader.

        `_read_principal` sees the Principal element and nothing else, so a
        caller that reaches it directly reads a wildcard confined by
        `aws:PrincipalAccount` as an unconfined wildcard and blocks its
        account for a grant that reaches nobody outside the allowlist. The
        guards above cannot see that: a direct call is the canonical reader
        rather than a divergent copy of the walk, so every one of them
        passes it. All six adapters call `read_statement_principals`, which
        composes the two, and `HOW_TO_ADD_A_CHECK.md` templates that call
        for the seventh.
        """
        package_root = Path(headroom.__file__).parent

        callers = set()
        for path in sorted(package_root.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Name) or node.func.id != "_read_principal":
                    continue
                callers.add(path.relative_to(package_root).as_posix())

        assert callers == {"aws/policy_documents.py"}
