"""Tests for headroom.aws.kms module."""

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.kms import (
    analyze_kms_key_policies,
    UnsupportedPrincipalTypeError,
    UnknownPrincipalTypeError,
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
)


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn_string(self) -> None:
        """Test extraction from ARN format string."""
        principal = "arn:aws:iam::123456789012:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extraction from plain 12-digit account ID."""
        principal = "123456789012"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_wildcard(self) -> None:
        """Test that wildcard returns empty set."""
        principal = "*"
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_extract_from_list(self) -> None:
        """Test extraction from list of principals."""
        principal = [
            "arn:aws:iam::111111111111:root",
            "arn:aws:iam::222222222222:root"
        ]
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_aws(self) -> None:
        """Test extraction from dict with AWS key."""
        principal = {
            "AWS": "arn:aws:iam::111111111111:root"
        }
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111"}

    def test_extract_from_dict_aws_list(self) -> None:
        """Test extraction from dict with AWS key containing list."""
        principal = {
            "AWS": [
                "arn:aws:iam::111111111111:root",
                "222222222222"
            ]
        }
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_service(self) -> None:
        """Test that Service principals return empty set."""
        principal = {
            "Service": "lambda.amazonaws.com"
        }
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_unsupported_federated_principal(self) -> None:
        """Test that Federated principals raise UnsupportedPrincipalTypeError."""
        principal = {
            "Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"
        }
        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            _extract_account_ids_from_principal(principal)
        assert "Federated" in str(exc_info.value)
        assert "would break if the RCP is deployed" in str(exc_info.value)


class TestHasWildcardPrincipal:
    """Test _has_wildcard_principal function."""

    def test_wildcard_string(self) -> None:
        """Test detection of wildcard string."""
        assert _has_wildcard_principal("*") is True

    def test_non_wildcard_string(self) -> None:
        """Test non-wildcard string."""
        assert _has_wildcard_principal("arn:aws:iam::123456789012:root") is False

    def test_wildcard_in_list(self) -> None:
        """Test detection of wildcard in list."""
        principal = ["arn:aws:iam::123456789012:root", "*"]
        assert _has_wildcard_principal(principal) is True

    def test_no_wildcard_in_list(self) -> None:
        """Test list without wildcard."""
        principal = ["arn:aws:iam::123456789012:root", "arn:aws:iam::111111111111:root"]
        assert _has_wildcard_principal(principal) is False

    def test_wildcard_in_dict_aws_string(self) -> None:
        """Test detection of wildcard in dict AWS string."""
        principal = {"AWS": "*"}
        assert _has_wildcard_principal(principal) is True

    def test_wildcard_in_dict_aws_list(self) -> None:
        """Test detection of wildcard in dict AWS list."""
        principal = {
            "AWS": ["arn:aws:iam::123456789012:root", "*"]
        }
        assert _has_wildcard_principal(principal) is True

    def test_no_wildcard_in_dict(self) -> None:
        """Test dict without wildcard."""
        principal = {
            "AWS": "arn:aws:iam::123456789012:root",
            "Service": "lambda.amazonaws.com"
        }
        assert _has_wildcard_principal(principal) is False


class TestAnalyzeKmsKeyPolicies:
    """Test analyze_kms_key_policies function."""

    def test_analyze_keys_with_third_party_access(self) -> None:
        """Test successful analysis with keys having third-party access."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-123",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-123"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":["kms:Decrypt","kms:DescribeKey"],"Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].key_id == "key-123"
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == ["kms:Decrypt", "kms:DescribeKey"]
        assert results[0].has_wildcard_principal is False

    def test_analyze_keys_with_wildcard(self) -> None:
        """Test analysis with key having wildcard principal."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-wildcard",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-wildcard"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_analyze_keys_without_policy(self) -> None:
        """Test analysis when key has no policy."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-no-policy",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-no-policy"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        error_response = {"Error": {"Code": "NotFoundException"}}
        mock_kms_client.get_key_policy.side_effect = ClientError(error_response, "GetKeyPolicy")  # type: ignore[arg-type]

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_keys_org_only(self) -> None:
        """Test analysis when keys only have org access (no findings)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-org-only",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-org-only"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_keys_multiple_actions(self) -> None:
        """Test tracking multiple actions per account."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-multiple",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-multiple"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey"],"Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert len(results[0].actions_by_account["999999999999"]) == 3
        assert "kms:Decrypt" in results[0].actions_by_account["999999999999"]
        assert "kms:Encrypt" in results[0].actions_by_account["999999999999"]
        assert "kms:GenerateDataKey" in results[0].actions_by_account["999999999999"]

    def test_analyze_keys_multiple_third_party_accounts(self) -> None:
        """Test key with multiple third-party accounts."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-multi-account",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-multi-account"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::999999999999:root","arn:aws:iam::888888888888:root"]},"Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999", "888888888888"}
        assert "999999999999" in results[0].actions_by_account
        assert "888888888888" in results[0].actions_by_account

    def test_federated_principal_fails_fast(self) -> None:
        """Test that Federated principals raise UnsupportedPrincipalTypeError."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-federated",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-federated"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/MyProvider"},"Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            analyze_kms_key_policies(mock_session, org_account_ids)
        assert "Federated" in str(exc_info.value)

    def test_analyze_kms_policies_unknown_principal_type(self) -> None:
        """Test analyze_kms_key_policies with unknown principal type."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-unknown",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-unknown"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"UnknownType":"value"},"Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            analyze_kms_key_policies(mock_session, org_account_ids)
        assert "UnknownType" in str(exc_info.value)

    def test_analyze_kms_policies_deny_statement(self) -> None:
        """Test analyze_kms_key_policies with Deny statement (should be skipped)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-deny",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-deny"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        results = analyze_kms_key_policies(mock_session, org_account_ids)

        # Keys with only Deny statements don't have third-party access or wildcards, so no result
        assert len(results) == 0

    def test_analyze_kms_policies_no_principal(self) -> None:
        """Test analyze_kms_key_policies with statement missing Principal field."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-no-principal",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-no-principal"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        results = analyze_kms_key_policies(mock_session, org_account_ids)

        # Keys without Principal don't have third-party access or wildcards, so no result
        assert len(results) == 0

    def test_analyze_kms_policies_client_error(self) -> None:
        """Test analyze_kms_key_policies with ClientError during analysis."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListKeys"
        )

        mock_kms_client.get_paginator.return_value = keys_paginator

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_kms_key_policies(mock_session, org_account_ids)

    def test_analyze_kms_policies_get_policy_error(self) -> None:
        """Test analyze_kms_key_policies with ClientError when getting key policy."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-error",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-error"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator
        mock_kms_client.get_key_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetKeyPolicy"
        )

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError) as exc_info:
            analyze_kms_key_policies(mock_session, org_account_ids)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"
