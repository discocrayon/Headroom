"""
Tests for headroom.aws.secretsmanager module.
"""

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from headroom.aws.secretsmanager import (
    UnsupportedPrincipalTypeError,
    UnknownPrincipalTypeError,
    _analyze_secret_policy,
    _extract_account_ids_from_principal,
    _has_non_account_principals,
    _has_wildcard_principal,
    analyze_secrets_manager_policies,
)


class TestExtractAccountIdsFromPrincipal:
    """Test account ID extraction from principals."""

    def test_extract_from_arn_format(self) -> None:
        """Test extraction from ARN format principal."""
        principal = "arn:aws:iam::123456789012:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extraction from plain account ID."""
        principal = "123456789012"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_list(self) -> None:
        """Test extraction from list of principals."""
        principal = [
            "arn:aws:iam::111111111111:root",
            "222222222222"
        ]
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_aws_key(self) -> None:
        """Test extraction from dict with AWS key."""
        principal = {
            "AWS": "arn:aws:iam::333333333333:root"
        }
        result = _extract_account_ids_from_principal(principal)  # type: ignore[arg-type]
        assert result == {"333333333333"}

    def test_extract_from_dict_aws_list(self) -> None:
        """Test extraction from dict with AWS key as list."""
        principal = {
            "AWS": [
                "arn:aws:iam::444444444444:root",
                "555555555555"
            ]
        }
        result = _extract_account_ids_from_principal(principal)  # type: ignore[arg-type]
        assert result == {"444444444444", "555555555555"}

    def test_wildcard_returns_empty(self) -> None:
        """Test that wildcard principal returns empty set."""
        principal = "*"
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_unknown_principal_type_raises(self) -> None:
        """Test that unknown principal type raises exception."""
        principal = {"UnknownType": "value"}
        with pytest.raises(UnknownPrincipalTypeError):
            _extract_account_ids_from_principal(principal)  # type: ignore[arg-type]


class TestHasWildcardPrincipal:
    """Test wildcard principal detection."""

    def test_string_wildcard(self) -> None:
        """Test detection of string wildcard."""
        assert _has_wildcard_principal("*") is True

    def test_string_non_wildcard(self) -> None:
        """Test non-wildcard string."""
        assert _has_wildcard_principal("arn:aws:iam::123456789012:root") is False

    def test_list_with_wildcard(self) -> None:
        """Test list containing wildcard."""
        assert _has_wildcard_principal(["arn:aws:iam::123456789012:root", "*"]) is True

    def test_list_without_wildcard(self) -> None:
        """Test list without wildcard."""
        assert _has_wildcard_principal(["arn:aws:iam::123456789012:root"]) is False

    def test_dict_aws_wildcard(self) -> None:
        """Test dict with AWS wildcard."""
        assert _has_wildcard_principal({"AWS": "*"}) is True

    def test_dict_aws_list_wildcard(self) -> None:
        """Test dict with AWS list containing wildcard."""
        assert _has_wildcard_principal({"AWS": ["arn:aws:iam::123456789012:root", "*"]}) is True


class TestHasNonAccountPrincipals:
    """Test non-account principal detection."""

    def test_federated_principal(self) -> None:
        """Test detection of Federated principal."""
        principal = {"Federated": "arn:aws:iam::123456789012:saml-provider/ExampleProvider"}
        assert _has_non_account_principals(principal) is True  # type: ignore[arg-type]

    def test_canonical_user_principal(self) -> None:
        """Test detection of CanonicalUser principal."""
        principal = {"CanonicalUser": "example-canonical-user-id"}
        assert _has_non_account_principals(principal) is True  # type: ignore[arg-type]

    def test_aws_principal_only(self) -> None:
        """Test AWS principal without non-account types."""
        principal = {"AWS": "arn:aws:iam::123456789012:root"}
        assert _has_non_account_principals(principal) is False  # type: ignore[arg-type]

    def test_non_dict_principal(self) -> None:
        """Test non-dict principal."""
        assert _has_non_account_principals("*") is False


class TestAnalyzeSecretPolicy:
    """Test individual secret policy analysis."""

    def test_third_party_access(self) -> None:
        """Test secret with third-party access."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111", "222222222222"}

        result = _analyze_secret_policy(
            "test-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:test-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is not None
        assert result.third_party_account_ids == {"999999999999"}
        assert result.has_wildcard_principal is False
        assert "999999999999" in result.actions_by_account
        assert "secretsmanager:GetSecretValue" in result.actions_by_account["999999999999"]

    def test_wildcard_principal(self) -> None:
        """Test secret with wildcard principal."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "public-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:public-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is not None
        assert result.has_wildcard_principal is True

    def test_federated_principal_raises(self) -> None:
        """Test that Federated principal raises exception."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/Provider"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        with pytest.raises(UnsupportedPrincipalTypeError):
            _analyze_secret_policy(
                "federated-secret",
                "arn:aws:secretsmanager:us-east-1:111111111111:secret:federated-secret",
                policy,  # type: ignore[arg-type]
                org_account_ids
            )

    def test_org_account_only_returns_none(self) -> None:
        """Test secret with only org accounts returns None."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "org-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:org-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is None

    def test_deny_statement_skipped(self) -> None:
        """Test that Deny statements are skipped."""
        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "secretsmanager:DeleteSecret"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "deny-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:deny-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is None

    def test_action_as_list(self) -> None:
        """Test secret with action as list."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "multi-action-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:multi-action-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is not None
        assert "999999999999" in result.actions_by_account
        assert "secretsmanager:GetSecretValue" in result.actions_by_account["999999999999"]
        assert "secretsmanager:DescribeSecret" in result.actions_by_account["999999999999"]

    def test_statement_without_principal(self) -> None:
        """Test statement without Principal is skipped."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "no-principal-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:no-principal-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is None

    def test_action_as_dict_normalized_to_empty(self) -> None:
        """Test that action as dict gets normalized to empty set."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": {"NotAction": "secretsmanager:*"}
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "dict-action-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:dict-action-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is not None
        assert result.third_party_account_ids == {"999999999999"}
        assert result.actions_by_account["999999999999"] == set()

    def test_statement_not_a_list(self) -> None:
        """Test that policy with Statement as non-list is handled."""
        policy = {
            "Statement": "invalid"
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "invalid-statement-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:invalid-statement-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids
        )

        assert result is None


class TestAnalyzeSecretsManagerPolicies:
    """Test full Secrets Manager policy analysis."""

    def test_successful_analysis(self) -> None:
        """Test successful analysis with secrets."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sm_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "secretsmanager": mock_sm_client
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecretList": [
                    {
                        "Name": "test-secret",
                        "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:test-secret"
                    }
                ]
            }
        ]
        mock_sm_client.get_paginator.return_value = paginator

        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        mock_sm_client.get_resource_policy.return_value = {
            "ResourcePolicy": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}
        results = analyze_secrets_manager_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].secret_name == "test-secret"
        assert results[0].third_party_account_ids == {"999999999999"}

    def test_secret_without_policy(self) -> None:
        """Test secret without resource policy is skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sm_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "secretsmanager": mock_sm_client
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecretList": [
                    {
                        "Name": "no-policy-secret",
                        "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:no-policy-secret"
                    }
                ]
            }
        ]
        mock_sm_client.get_paginator.return_value = paginator
        mock_sm_client.get_resource_policy.return_value = {"ResourcePolicy": None}

        org_account_ids = {"111111111111"}
        results = analyze_secrets_manager_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_resource_not_found_error(self) -> None:
        """Test handling of ResourceNotFoundException."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sm_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "secretsmanager": mock_sm_client
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecretList": [
                    {
                        "Name": "test-secret",
                        "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:test-secret"
                    }
                ]
            }
        ]
        mock_sm_client.get_paginator.return_value = paginator

        error_response = {"Error": {"Code": "ResourceNotFoundException"}}
        mock_sm_client.get_resource_policy.side_effect = ClientError(error_response, "GetResourcePolicy")  # type: ignore[arg-type]

        org_account_ids = {"111111111111"}
        results = analyze_secrets_manager_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_other_client_error_raises(self) -> None:
        """Test that other ClientErrors are raised."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sm_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "secretsmanager": mock_sm_client
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecretList": [
                    {
                        "Name": "test-secret",
                        "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:test-secret"
                    }
                ]
            }
        ]
        mock_sm_client.get_paginator.return_value = paginator

        error_response = {"Error": {"Code": "AccessDenied"}}
        mock_sm_client.get_resource_policy.side_effect = ClientError(error_response, "GetResourcePolicy")  # type: ignore[arg-type]

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_secrets_manager_policies(mock_session, org_account_ids)
