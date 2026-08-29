"""
Tests for headroom.aws.policy_documents module.
"""

import pytest

from headroom.aws.policy_documents import (
    MalformedPolicyError,
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
