"""
Tests for headroom.aws.iam module.

Tests for IAM role trust policy analysis functions.
"""

import json
import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from unittest.mock import MagicMock
from urllib.parse import quote
from headroom.aws.iam import (
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
    analyze_iam_roles_trust_policies,
    UnknownPrincipalTypeError,
    InvalidFederatedPrincipalError
)


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn_string(self) -> None:
        """Test extracting account ID from ARN string."""
        principal = "arn:aws:iam::123456789012:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_account_id_string(self) -> None:
        """Test extracting from plain account ID string."""
        principal = "123456789012"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_wildcard(self) -> None:
        """Test wildcard returns empty set."""
        principal = "*"
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_extract_from_list(self) -> None:
        """Test extracting from list of principals."""
        principal = [
            "arn:aws:iam::111111111111:root",
            "arn:aws:iam::222222222222:root"
        ]
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_aws_key(self) -> None:
        """Test extracting from dict with AWS key."""
        principal = {"AWS": "arn:aws:iam::123456789012:root"}
        result = _extract_account_ids_from_principal(principal)
        assert result == {"123456789012"}

    def test_extract_from_dict_aws_list(self) -> None:
        """Test extracting from dict with AWS key containing list."""
        principal = {
            "AWS": [
                "arn:aws:iam::111111111111:root",
                "arn:aws:iam::222222222222:root"
            ]
        }
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_ignore_service_principal(self) -> None:
        """Test that service principals are ignored."""
        principal = {"Service": "ec2.amazonaws.com"}
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_mixed_principals(self) -> None:
        """Test mixed principal types."""
        principal = {
            "AWS": ["arn:aws:iam::111111111111:root"],
            "Service": "lambda.amazonaws.com"
        }
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111"}


class TestHasWildcardPrincipal:
    """Test _has_wildcard_principal function."""

    def test_wildcard_string(self) -> None:
        """Test wildcard in string."""
        assert _has_wildcard_principal("*") is True

    def test_no_wildcard_string(self) -> None:
        """Test no wildcard in string."""
        assert _has_wildcard_principal("arn:aws:iam::123456789012:root") is False

    def test_wildcard_in_list(self) -> None:
        """Test wildcard in list."""
        assert _has_wildcard_principal(["arn:aws:iam::123456789012:root", "*"]) is True

    def test_no_wildcard_in_list(self) -> None:
        """Test no wildcard in list."""
        assert _has_wildcard_principal(["arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"]) is False

    def test_wildcard_in_dict_aws(self) -> None:
        """Test wildcard in dict AWS key."""
        assert _has_wildcard_principal({"AWS": "*"}) is True

    def test_wildcard_in_dict_aws_list(self) -> None:
        """Test wildcard in dict AWS key list."""
        assert _has_wildcard_principal({"AWS": ["arn:aws:iam::123456789012:root", "*"]}) is True

    def test_no_wildcard_in_dict(self) -> None:
        """Test no wildcard in dict."""
        assert _has_wildcard_principal({"AWS": "arn:aws:iam::123456789012:root"}) is False


class TestAnalyzeIamRolesTrustPolicies:
    """Test analyze_iam_roles_trust_policies function."""

    def test_role_with_third_party_account(self) -> None:
        """Test role with third-party account in trust policy."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "ThirdPartyRole",
                        "Arn": "arn:aws:iam::111111111111:role/ThirdPartyRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].role_name == "ThirdPartyRole"
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].has_wildcard_principal is False

    def test_role_with_wildcard(self) -> None:
        """Test role with wildcard in trust policy."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "PublicRole",
                        "Arn": "arn:aws:iam::111111111111:role/PublicRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].role_name == "PublicRole"
        assert results[0].has_wildcard_principal is True

    def test_role_with_org_accounts_only(self) -> None:
        """Test role with only organization accounts (should not be included)."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "InternalRole",
                        "Arn": "arn:aws:iam::111111111111:role/InternalRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_role_with_service_principal(self) -> None:
        """Test role with service principal (should not be included)."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "EC2Role",
                        "Arn": "arn:aws:iam::111111111111:role/EC2Role",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_multiple_roles_mixed(self) -> None:
        """Test multiple roles with mixed trust policies."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy_third_party = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::999999999999:root", "arn:aws:iam::888888888888:root"]},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        trust_policy_internal = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "ThirdPartyRole",
                        "Arn": "arn:aws:iam::111111111111:role/ThirdPartyRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy_third_party))
                    },
                    {
                        "RoleName": "InternalRole",
                        "Arn": "arn:aws:iam::111111111111:role/InternalRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy_internal))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].role_name == "ThirdPartyRole"
        assert results[0].third_party_account_ids == {"999999999999", "888888888888"}

    def test_role_deny_statement_ignored(self) -> None:
        """Test that Deny statements are ignored."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "DenyRole",
                        "Arn": "arn:aws:iam::111111111111:role/DenyRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_unknown_principal_type_raises_error(self) -> None:
        """Test that unknown principal types raise UnknownPrincipalTypeError."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"UnknownType": "something"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "BadRole",
                        "Arn": "arn:aws:iam::111111111111:role/BadRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}

        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert "UnknownType" in str(exc_info.value)

    def test_federated_with_assume_role_raises_error(self) -> None:
        """Test that Federated principal with sts:AssumeRole raises InvalidFederatedPrincipalError."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::111111111111:saml-provider/ExampleProvider"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "BadFederatedRole",
                        "Arn": "arn:aws:iam::111111111111:role/BadFederatedRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}

        with pytest.raises(InvalidFederatedPrincipalError) as exc_info:
            analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert "BadFederatedRole" in str(exc_info.value)
        assert "AssumeRoleWithSAML" in str(exc_info.value) or "AssumeRoleWithWebIdentity" in str(exc_info.value)

    def test_federated_with_assume_role_with_saml_allowed(self) -> None:
        """Test that Federated principal with sts:AssumeRoleWithSAML is allowed."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::111111111111:saml-provider/ExampleProvider"},
                    "Action": "sts:AssumeRoleWithSAML"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "GoodFederatedRole",
                        "Arn": "arn:aws:iam::111111111111:role/GoodFederatedRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}

        # Should not raise any exception
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        # No third-party accounts, no wildcards, so results should be empty
        assert len(results) == 0

    def test_role_without_principal_skipped(self) -> None:
        """Test that statements without Principal are skipped."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "NoPrincipalRole",
                        "Arn": "arn:aws:iam::111111111111:role/NoPrincipalRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        # Statement without principal should be skipped
        assert len(results) == 0

    def test_role_with_invalid_json_raises(self) -> None:
        """Test that roles with invalid trust policies raise JSONDecodeError."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        valid_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "BadJsonRole",
                        "Arn": "arn:aws:iam::111111111111:role/BadJsonRole",
                        "AssumeRolePolicyDocument": "invalid{json"
                    },
                    {
                        "RoleName": "GoodRole",
                        "Arn": "arn:aws:iam::111111111111:role/GoodRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(valid_trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}
        with pytest.raises(json.JSONDecodeError):
            analyze_iam_roles_trust_policies(mock_session, org_account_ids)

    def test_role_listing_client_error_raises(self) -> None:
        """Test that AWS API errors during role listing are raised."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        mock_iam_client.get_paginator.return_value.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListRoles"
        )

        org_account_ids = {"111111111111"}
        with pytest.raises(ClientError):
            analyze_iam_roles_trust_policies(mock_session, org_account_ids)
