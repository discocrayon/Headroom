"""
Tests for headroom.aws.iam module.

Tests cover IAM role trust policy analysis and SAML provider enumeration helpers.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Set
from unittest.mock import MagicMock
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from headroom.aws.iam import (
    InvalidFederatedPrincipalError,
    MalformedStatementError,
    SamlProviderAnalysis,
    UnknownPrincipalTypeError,
    analyze_iam_roles_trust_policies,
    get_saml_providers_analysis,
)
from headroom.aws.iam.roles import (
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
)
from headroom.aws.policy_documents import MalformedPolicyError


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn_string(self) -> None:
        """Test extracting account ID from ARN string."""
        principal = "arn:aws:iam::333333333333:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"333333333333"}

    def test_extract_from_account_id_string(self) -> None:
        """Test extracting from plain account ID string."""
        principal = "333333333333"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"333333333333"}

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
        principal = {"AWS": "arn:aws:iam::333333333333:root"}
        result = _extract_account_ids_from_principal(principal)
        assert result == {"333333333333"}

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
        assert _has_wildcard_principal("arn:aws:iam::333333333333:root") is False

    def test_wildcard_in_list(self) -> None:
        """Test wildcard in list."""
        assert _has_wildcard_principal(["arn:aws:iam::333333333333:root", "*"]) is True

    def test_no_wildcard_in_list(self) -> None:
        """Test no wildcard in list."""
        assert _has_wildcard_principal(["arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"]) is False

    def test_wildcard_in_dict_aws(self) -> None:
        """Test wildcard in dict AWS key."""
        assert _has_wildcard_principal({"AWS": "*"}) is True

    def test_wildcard_in_dict_aws_list(self) -> None:
        """Test wildcard in dict AWS key list."""
        assert _has_wildcard_principal({"AWS": ["arn:aws:iam::333333333333:root", "*"]}) is True

    def test_no_wildcard_in_dict(self) -> None:
        """Test no wildcard in dict."""
        assert _has_wildcard_principal({"AWS": "arn:aws:iam::333333333333:root"}) is False


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

    def test_role_with_dict_trust_policy(self) -> None:
        """Test handling of role with trust policy already as dict (not URL-encoded)."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "MyRole",
                        "Arn": "arn:aws:iam::111111111111:role/MyRole",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": "arn:aws:iam::999999999999:root"
                                    },
                                    "Action": "sts:AssumeRole"
                                }
                            ]
                        }
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].role_name == "MyRole"
        assert results[0].third_party_account_ids == {"999999999999"}


class TestGetIamUsersAnalysis:
    """Test get_iam_users_analysis function."""

    def test_get_iam_users(self) -> None:
        """Test getting all IAM users."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Users": [
                    {
                        "UserName": "admin",
                        "Arn": "arn:aws:iam::333333333333:user/admin",
                        "Path": "/"
                    },
                    {
                        "UserName": "developer",
                        "Arn": "arn:aws:iam::333333333333:user/developer",
                        "Path": "/devs/"
                    }
                ]
            }
        ]

        from headroom.aws.iam.users import get_iam_users_analysis
        results = get_iam_users_analysis(mock_session)

        assert len(results) == 2
        assert results[0].user_name == "admin"
        assert results[0].user_arn == "arn:aws:iam::333333333333:user/admin"
        assert results[0].path == "/"
        assert results[1].user_name == "developer"
        assert results[1].user_arn == "arn:aws:iam::333333333333:user/developer"
        assert results[1].path == "/devs/"

    def test_get_iam_users_no_users(self) -> None:
        """Test getting IAM users when there are none."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {"Users": []}
        ]

        from headroom.aws.iam.users import get_iam_users_analysis
        results = get_iam_users_analysis(mock_session)

        assert len(results) == 0

    def test_get_iam_users_client_error_raises(self) -> None:
        """Test that AWS API errors during user listing are raised."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        mock_iam_client.get_paginator.return_value.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListUsers"
        )

        from headroom.aws.iam.users import get_iam_users_analysis
        with pytest.raises(ClientError):
            get_iam_users_analysis(mock_session)


class TestGetSamlProvidersAnalysis:
    """Test get_saml_providers_analysis function."""

    def test_get_saml_providers_analysis_returns_entries(self) -> None:
        """Test successful enumeration of SAML providers."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        create_date = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        valid_until = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        mock_iam_client.list_saml_providers.return_value = {
            "SAMLProviderList": [
                {
                    "Arn": "arn:aws:iam::111111111111:saml-provider/AWSSSO_A1B2C3D4_us-east-1",
                    "CreateDate": create_date,
                    "ValidUntil": valid_until,
                }
            ]
        }

        results = get_saml_providers_analysis(mock_session)

        assert len(results) == 1
        provider = results[0]
        assert isinstance(provider, SamlProviderAnalysis)
        assert provider.arn == "arn:aws:iam::111111111111:saml-provider/AWSSSO_A1B2C3D4_us-east-1"
        assert provider.name == "AWSSSO_A1B2C3D4_us-east-1"
        assert provider.create_date == create_date
        assert provider.valid_until == valid_until

    def test_get_saml_providers_analysis_handles_missing_fields(self) -> None:
        """Test handling of providers missing optional timestamps."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        mock_iam_client.list_saml_providers.return_value = {
            "SAMLProviderList": [
                {
                    "Arn": "arn:aws:iam::111111111111:saml-provider/CustomProvider",
                }
            ]
        }

        results = get_saml_providers_analysis(mock_session)

        assert len(results) == 1
        provider = results[0]
        assert provider.name == "CustomProvider"
        assert provider.create_date is None
        assert provider.valid_until is None

    def test_get_saml_providers_analysis_raises_client_error(self) -> None:
        """Test that ClientError from AWS API is re-raised."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        error = ClientError(
            error_response={
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "User is not authorized to perform iam:ListSAMLProviders",
                }
            },
            operation_name="ListSamlProviders",
        )
        mock_iam_client.list_saml_providers.side_effect = error

        with pytest.raises(ClientError):
            get_saml_providers_analysis(mock_session)


class TestTrustPolicyActionMatching:
    """
    Tests that every IAM action form granting sts:AssumeRole is recognized.

    The gate used to be exact string membership - `"sts:AssumeRole" in action` -
    while IAM matches action names case-insensitively and expands `*` and `?`
    inside the name. A trust policy written `sts:*` therefore granted a third
    party AssumeRole while the analyzer recorded nothing: no violation, no
    error, and the account simply missing from the RCP allowlist meant to keep
    it working. `NotAction` was dropped the same way, since only `Action` was
    ever read.
    """

    PARTNER = "999999999999"
    ORG = {"111111111111"}

    def third_parties(self, statement: Dict[str, Any]) -> Set[str]:
        """Run the analyzer over one trust policy statement."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client
        trust_policy = {"Version": "2012-10-17", "Statement": [statement]}
        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "PartnerRole",
                        "Arn": "arn:aws:iam::111111111111:role/PartnerRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]
        found: Set[str] = set()
        for result in analyze_iam_roles_trust_policies(mock_session, self.ORG):
            found.update(result.third_party_account_ids)
        return found

    def allow(self, **fields: Any) -> Dict[str, Any]:
        """Build an Allow statement naming the partner account."""
        statement: Dict[str, Any] = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{self.PARTNER}:root"},
        }
        statement.update(fields)
        return statement

    @pytest.mark.parametrize("action", [
        "sts:AssumeRole",
        "STS:AssumeRole",
        "sts:assumerole",
        "sts:*",
        "sts:Assume*",
        "sts:*Role",
        "sts:AssumeRol?",
        "*",
    ])
    def test_action_form_grants_assume_role(self, action: str) -> None:
        """Every form IAM would match against sts:AssumeRole is recognized."""
        assert self.third_parties(self.allow(Action=action)) == {self.PARTNER}

    @pytest.mark.parametrize("action", [
        "sts:TagSession",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWith*",
        "sts:AssumeRoleX",
        "iam:*",
        "s3:GetObject",
    ])
    def test_action_form_does_not_grant_assume_role(self, action: str) -> None:
        """Forms IAM would not match must stay unrecognized."""
        assert self.third_parties(self.allow(Action=action)) == set()

    def test_action_list_grants_if_any_entry_matches(self) -> None:
        """One matching pattern in a list is enough."""
        statement = self.allow(Action=["sts:TagSession", "sts:Assume*"])
        assert self.third_parties(statement) == {self.PARTNER}

    def test_empty_action_list_grants_nothing(self) -> None:
        """An empty Action list matches no action."""
        assert self.third_parties(self.allow(Action=[])) == set()

    def test_not_action_excluding_assume_role_is_not_a_grant(self) -> None:
        """Allow + NotAction sts:AssumeRole permits everything but AssumeRole."""
        assert self.third_parties(self.allow(NotAction="sts:AssumeRole")) == set()

    def test_not_action_wildcard_excluding_assume_role_is_not_a_grant(self) -> None:
        """A NotAction wildcard covering AssumeRole excludes it too."""
        assert self.third_parties(self.allow(NotAction="sts:*")) == set()

    def test_not_action_leaving_assume_role_is_a_grant(self) -> None:
        """Allow + NotAction that misses AssumeRole still grants it."""
        statement = self.allow(NotAction=["sts:AssumeRoleWithSAML"])
        assert self.third_parties(statement) == {self.PARTNER}

    def test_statement_with_action_and_not_action_raises(self) -> None:
        """IAM permits exactly one of Action and NotAction."""
        statement = self.allow(Action="sts:AssumeRole", NotAction="s3:*")
        with pytest.raises(MalformedStatementError, match="both Action and NotAction"):
            self.third_parties(statement)

    def test_statement_with_neither_action_nor_not_action_raises(self) -> None:
        """A statement naming no actions cannot be classified."""
        with pytest.raises(MalformedStatementError, match="neither Action nor NotAction"):
            self.third_parties(self.allow())

    def test_deny_statement_is_ignored_before_action_is_read(self) -> None:
        """Effect is checked first, so a Deny is never classified."""
        statement = {
            "Effect": "Deny",
            "Principal": {"AWS": f"arn:aws:iam::{self.PARTNER}:root"},
        }
        assert self.third_parties(statement) == set()

    def test_wildcard_action_reaches_principal_validation(self) -> None:
        """
        A statement recognized only by the widened gate is fully validated.

        Under exact matching this statement was skipped, so its unknown
        principal type went unreported.
        """
        statement = {
            "Effect": "Allow",
            "Action": "sts:*",
            "Principal": {"NotARealPrincipalType": "whatever"},
        }
        with pytest.raises(UnknownPrincipalTypeError):
            self.third_parties(statement)


class TestPrincipalArnCoverage:
    """
    Tests that principal ARNs outside arn:aws:iam:: yield their account ID.

    The trust policy analyzer matched only `^arn:aws:iam::(\\d{12}):`, so STS
    session principals - which AWS documents as valid in a resource-based
    policy, and a role trust policy is one - and every non-commercial
    partition produced no account ID at all.
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
        assert _extract_account_ids_from_principal(principal) == {self.PARTNER}

    def test_non_account_principal_yields_nothing(self) -> None:
        """A service principal carries no account ID."""
        assert _extract_account_ids_from_principal("ec2.amazonaws.com") == set()


class TestTrustPolicyStatementShapes:
    """A trust policy's Statement may be a lone object, not only a list."""

    @staticmethod
    def _analyze(trust_policy: Any) -> Any:
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

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

        return analyze_iam_roles_trust_policies(mock_session, {"111111111111"})

    def test_lone_statement_object_is_analyzed(self) -> None:
        """The third party in a lone statement object is found, not missed."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole"
            }
        })

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """A Statement of any other type aborts rather than reporting nothing."""
        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            self._analyze({"Version": "2012-10-17", "Statement": "Allow"})
