"""
Tests for headroom.aws.policy_documents module.
"""

import pytest

from headroom.aws.policy_documents import (
    MalformedPolicyError,
    has_not_principal,
    normalize_statements,
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
