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
    MalformedPolicyError,
    PrincipalElement,
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
    read_principal,
    read_service_principal_sources,
    unreadable_service_principal_source,
)
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
        """`Principal: "*"` is not a dict and names no service."""
        assert read_service_principal_sources(
            self._statement("*"), self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        ) == []

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
        reading = read_principal(
            {"AWS": "111111111111"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    def test_an_arn_yields_the_account_it_names(self) -> None:
        """The account segment of an ARN is the fifth colon-delimited field."""
        reading = read_principal(
            {"AWS": "arn:aws:iam::222222222222:role/example"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"222222222222"}

    def test_a_bare_wildcard_is_a_wildcard_naming_no_account(self) -> None:
        """`Principal: "*"` reaches everyone, so it names nobody in particular."""
        reading = read_principal(
            "*", RESOURCE_POLICY_PRINCIPAL_TYPES, "Queue 'example'"
        )

        assert reading.has_wildcard is True
        assert reading.account_ids == set()

    def test_a_service_principal_names_no_account(self) -> None:
        """A service principal is not an account and is not a blocker."""
        reading = read_principal(
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
        reading = read_principal(
            {"Federated": "arn:aws:iam::333333333333:saml-provider/Example"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.has_non_account_principals is True
        assert reading.account_ids == set()

    def test_a_canonical_user_names_no_account(self) -> None:
        """A canonical user ID is opaque; no allowlist can carry it."""
        reading = read_principal(
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
            read_principal(
                {"CanonicalUser": "d" * 64},
                TRUST_POLICY_PRINCIPAL_TYPES,
                "Role 'example'",
            )

        assert "Role 'example'" in str(exc_info.value)

    def test_a_key_aws_does_not_document_raises(self) -> None:
        """A key outside the documented four is a document Headroom cannot read."""
        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            read_principal(
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
            read_principal(
                {"AWS": "111111111111", "Kerberos": "example"},
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'example'",
            )

    def test_a_list_of_accounts_yields_every_account(self) -> None:
        """An array of principals grants to each of them."""
        reading = read_principal(
            {"AWS": ["111111111111", "arn:aws:iam::222222222222:root"]},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111", "222222222222"}

    def test_a_wildcard_inside_a_list_is_a_wildcard(self) -> None:
        """One wildcard entry opens the grant however many accounts follow it."""
        reading = read_principal(
            {"AWS": ["111111111111", "*"]},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.account_ids == {"111111111111"}

    def test_an_account_and_a_federated_principal_report_both(self) -> None:
        """One statement can name a readable account and an unreadable one."""
        reading = read_principal(
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
        reading = read_principal(
            {"AWS": "arn:aws:sts::444444444444:assumed-role/Example/session"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"444444444444"}

    def test_an_unrecognizable_string_yields_no_account(self) -> None:
        """A principal that is neither an ARN nor an account ID names none."""
        reading = read_principal(
            {"AWS": "not-an-arn"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is False

    def test_a_bare_string_principal_names_no_non_account_type(self) -> None:
        """
        A bare-string Principal carries no principal-type key, so it names none.

        `has_non_account_principals` is what blocks an account from a check:
        it means the policy grants to something an aws:PrincipalAccount
        allowlist cannot carry. A bare string is an ARN or an account ID, and
        an allowlist carries it fine. Flipping this branch to True passes the
        whole suite, so nothing but this assertion stands between a one-word
        edit and every such resource blocking its account.
        """
        reading = read_principal(
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
            read_principal(
                cast(PrincipalElement, principal),
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'orders'",
            )

        message = str(exc_info.value)
        assert "Queue 'orders'" in message
        assert type(principal).__name__ in message


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
        reading = read_principal(
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, "Role 'example'"
        )

        assert reading.account_ids == {self.PARTNER}

    def test_non_account_principal_yields_nothing(self) -> None:
        """A service principal carries no account ID."""
        reading = read_principal(
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


def _is_action_element_read(node: ast.AST) -> bool:
    """
    Report whether one AST node reads an Action element off a statement.

    Two forms reach the raw element: `statement["Action"]` and
    `statement.get("Action", ...)`. Both hand back whatever the document
    held - a string, a list, or something IAM would have rejected - so
    whoever performs one owes the result to normalize_actions.

    Args:
        node: One node from a function's AST

    Returns:
        True if the node is either form
    """
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value in ACTION_ELEMENT_KEYS

    if not isinstance(node, ast.Call):
        return False

    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return False

    return bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value in ACTION_ELEMENT_KEYS


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

# read_principal is the sink all six external analyzers reach.
# _service_principals is policy_documents.py's own second canonical reader -
# test_only_policy_documents_reads_a_statement_principal already names it
# alongside read_principal - and _read_service_principal_sources reaches it
# with an inline `statement.get("Principal")` for the confused-deputy check's
# Service principals, never touching read_principal at all.
PRINCIPAL_ELEMENT_READERS = frozenset({"read_principal", "_service_principals"})


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
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value in PRINCIPAL_ELEMENT_KEYS

    if not isinstance(node, ast.Call):
        return False

    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return False

    return bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value in PRINCIPAL_ELEMENT_KEYS


def _has_unread_principal_element(node: ast.FunctionDef) -> bool:
    """
    Report whether a function reads a Principal element no canonical reader sees.

    Per read rather than per function, for the reason the Action guard
    states: a function that hands one read to a canonical reader is not
    thereby excused for another it reads raw in the same body.

    Coverage has two shapes here where the Action guard has one. A read
    reaches a name in PRINCIPAL_ELEMENT_READERS inline, or it is bound to a
    local on one line and that local is passed on another - which is the
    shape all six external analyzers write. Recognizing only the inline form
    would report every one of them.

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
            "aws/policy_documents.py.read_principal",
            "aws/policy_documents.py._service_principals",
            # A grant's principal is a plain ARN string from ListGrants, not a
            # statement's Principal element, and no allowlist reads it.
            "aws/kms.py._grant_principal_account_id",
            "aws/kms.py._external_grant_account",
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

    def test_every_principal_element_read_reaches_read_principal(self) -> None:
        """
        Reading Principal or NotPrincipal off a statement obliges you to
        hand it to read_principal.

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

        Both shapes _is_principal_element_read recognizes are built: the
        subscript and the `.get`, because a branch with no assertion behind
        it is a branch that can be neutered silently.
        """
        for source in ('element = s["Principal"]', 'element = s.get("Principal")'):
            function = ast.parse(f"def f(s):\n    {source}\n    return element").body[0]
            assert isinstance(function, ast.FunctionDef)

            assert _has_unread_principal_element(function) is True

    def test_the_principal_guard_accepts_a_read_bound_to_a_local(self) -> None:
        """
        The shape all six analyzers write must not be reported.

        `principal = statement.get("Principal")` followed by
        `read_principal(principal, ...)` is the codebase's actual form, and
        an inline-only rule reports every analyzer as a violation.
        """
        function = ast.parse(
            "def f(statement):\n"
            "    principal = statement.get('Principal')\n"
            "    return read_principal(principal, TYPES, 'where')\n"
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
