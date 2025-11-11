"""
Tests for headroom.aws.s3 module.
"""

import json
import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.s3 import (
    S3BucketPolicyAnalysis,
    analyze_s3_bucket_policies,
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
    _normalize_actions,
    UnknownPrincipalTypeError,
)


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn(self) -> None:
        """Test extracting account ID from ARN format."""
        principal = "arn:aws:iam::111111111111:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extracting plain 12-digit account ID."""
        principal = "222222222222"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"222222222222"}

    def test_extract_from_list(self) -> None:
        """Test extracting from list of principals."""
        principal = [
            "arn:aws:iam::111111111111:root",
            "222222222222",
        ]
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_aws_key(self) -> None:
        """Test extracting from dict with AWS key."""
        principal = {
            "AWS": [
                "arn:aws:iam::333333333333:root",
                "444444444444"
            ]
        }
        result = _extract_account_ids_from_principal(principal)
        assert result == {"333333333333", "444444444444"}

    def test_wildcard_returns_empty_set(self) -> None:
        """Test that wildcard principal returns empty set."""
        principal = "*"
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_unknown_principal_type_raises_error(self) -> None:
        """Test that unknown principal type raises error."""
        principal = {"UnknownType": "value"}
        with pytest.raises(UnknownPrincipalTypeError):
            _extract_account_ids_from_principal(principal)


class TestHasWildcardPrincipal:
    """Test _has_wildcard_principal function."""

    def test_string_wildcard(self) -> None:
        """Test detecting wildcard in string."""
        assert _has_wildcard_principal("*") is True

    def test_string_not_wildcard(self) -> None:
        """Test non-wildcard string."""
        assert _has_wildcard_principal("arn:aws:iam::111111111111:root") is False

    def test_list_with_wildcard(self) -> None:
        """Test detecting wildcard in list."""
        assert _has_wildcard_principal(["*", "arn:aws:iam::111111111111:root"]) is True

    def test_list_without_wildcard(self) -> None:
        """Test list without wildcard."""
        assert _has_wildcard_principal(["arn:aws:iam::111111111111:root"]) is False

    def test_dict_with_wildcard(self) -> None:
        """Test detecting wildcard in dict."""
        assert _has_wildcard_principal({"AWS": "*"}) is True

    def test_dict_without_wildcard(self) -> None:
        """Test dict without wildcard."""
        assert _has_wildcard_principal({"AWS": "arn:aws:iam::111111111111:root"}) is False


class TestNormalizeActions:
    """Test _normalize_actions function."""

    def test_string_action(self) -> None:
        """Test normalizing single string action."""
        result = _normalize_actions("s3:GetObject")
        assert result == {"s3:GetObject"}

    def test_list_actions(self) -> None:
        """Test normalizing list of actions."""
        result = _normalize_actions(["s3:GetObject", "s3:PutObject"])
        assert result == {"s3:GetObject", "s3:PutObject"}

    def test_empty_or_invalid(self) -> None:
        """Test normalizing empty or invalid actions."""
        assert _normalize_actions(None) == set()
        assert _normalize_actions({}) == set()


class TestAnalyzeS3BucketPolicies:
    """Test analyze_s3_bucket_policies function."""

    def test_analyze_buckets_with_third_party_access(self) -> None:
        """Test analyzing buckets with third-party account access."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "test-bucket-1"},
                {"Name": "test-bucket-2"},
            ]
        }

        def mock_get_bucket_policy(Bucket: str) -> dict:
            if Bucket == "test-bucket-1":
                return {
                    "Policy": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                                "Action": ["s3:GetObject", "s3:PutObject"],
                                "Resource": f"arn:aws:s3:::{Bucket}/*"
                            }
                        ]
                    })
                }
            elif Bucket == "test-bucket-2":
                return {
                    "Policy": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                                "Action": "s3:GetObject",
                                "Resource": f"arn:aws:s3:::{Bucket}/*"
                            }
                        ]
                    })
                }
            return {}

        mock_s3_client.get_bucket_policy.side_effect = mock_get_bucket_policy

        org_account_ids = {"333333333333", "444444444444"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 2
        assert results[0].bucket_name == "test-bucket-1"
        assert results[0].third_party_account_ids == {"111111111111"}
        assert results[0].actions_by_account["111111111111"] == {"s3:GetObject", "s3:PutObject"}
        assert results[1].bucket_name == "test-bucket-2"
        assert results[1].third_party_account_ids == {"222222222222"}

    def test_analyze_bucket_with_wildcard(self) -> None:
        """Test analyzing bucket with wildcard principal."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "wildcard-bucket"}]
        }

        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::wildcard-bucket/*"
                    }
                ]
            })
        }

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].bucket_name == "wildcard-bucket"

    def test_analyze_bucket_without_policy(self) -> None:
        """Test analyzing bucket without bucket policy."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "no-policy-bucket"}]
        }

        error_response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, "GetBucketPolicy")

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_bucket_with_org_account(self) -> None:
        """Test analyzing bucket with org account (should be filtered out)."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "org-bucket"}]
        }

        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::333333333333:root"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::org-bucket/*"
                    }
                ]
            })
        }

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_empty_bucket_list(self) -> None:
        """Test analyzing with no buckets."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {"Buckets": []}

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_list_buckets_error(self) -> None:
        """Test handling of list_buckets API error."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        error_response = {"Error": {"Code": "AccessDenied"}}
        mock_s3_client.list_buckets.side_effect = ClientError(error_response, "ListBuckets")

        org_account_ids = {"333333333333"}
        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, org_account_ids)
