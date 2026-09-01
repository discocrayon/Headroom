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
    analyze_iam_roles_trust_policies,
    get_saml_providers_analysis,
)
from headroom.aws.iam.users import get_iam_users_analysis
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)
from tests.constants import ORG_ID


class TestAnalyzeIamRolesTrustPolicies:
    """Test analyze_iam_roles_trust_policies function."""

    def test_a_page_without_the_roles_key_raises(self) -> None:
        """
        A `ListRoles` page with no `Roles` key aborts rather than reading empty.

        Botocore marks `Roles` required on `ListRolesResponse`. Defaulting a
        page without it would report the account as trusting nobody and clear
        it for the STS RCP, which is what INV-01 forbids.
        """
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client
        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {"IsTruncated": False}
        ]

        with pytest.raises(KeyError):
            analyze_iam_roles_trust_policies(mock_session, set(), ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

        # No third-party accounts, no wildcards, so results should be empty
        assert len(results) == 0

    def test_federated_with_wildcard_action_does_not_raise(self) -> None:
        """
        A Federated principal paired with a wildcard action is not flagged.

        This is the exact case the comment above the Federated gate in
        analyze_iam_roles_trust_policies defends: sts:* covers sts:AssumeRole
        under the wildcard-aware gate above it (so this statement is a grant
        the analyzer does examine), but the Federated gate itself is a
        literal-membership test and does not fire on it. AWS will not let a
        federated identity call plain AssumeRole regardless of what the
        policy grants, so the broad grant is sloppy rather than the
        unambiguous confusion the gate aborts the run over.
        """
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::111111111111:saml-provider/ExampleProvider"},
                    "Action": "sts:*"
                }
            ]
        }

        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "WildcardFederatedRole",
                        "Arn": "arn:aws:iam::111111111111:role/WildcardFederatedRole",
                        "AssumeRolePolicyDocument": quote(json.dumps(trust_policy))
                    }
                ]
            }
        ]

        org_account_ids = {"111111111111"}

        # Should not raise; the literal-match gate does not fire on sts:*
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_iam_roles_trust_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].role_name == "MyRole"
        assert results[0].third_party_account_ids == {"999999999999"}


class TestGetIamUsersAnalysis:
    """Test get_iam_users_analysis function."""

    def test_a_page_without_the_users_key_raises(self) -> None:
        """
        A `ListUsers` page with no `Users` key aborts rather than reading empty.

        Botocore marks `Users` required on `ListUsersResponse`, so a page
        without it is a response the service model says cannot happen -
        not an account with no users, which comes back as an empty list.
        Defaulting it would report the account as carrying no IAM users and
        clear it for the deny_iam_user_creation SCP (INV-01).
        """
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_session.client.return_value = mock_iam_client
        mock_iam_client.get_paginator.return_value.paginate.return_value = [
            {"IsTruncated": False}
        ]

        with pytest.raises(KeyError):
            get_iam_users_analysis(mock_session)

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
        for result in analyze_iam_roles_trust_policies(mock_session, self.ORG, ORG_ID):
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

    def test_a_malformed_action_aborts_rather_than_reading_as_no_grant(self) -> None:
        """
        An Action element AWS could not have stored aborts, as it does elsewhere.

        Five resource-policy adapters route the element through
        normalize_actions and abort on anything that is neither a string nor a
        list. This one read it inline and reported the statement as not granting
        sts:AssumeRole, which records a clean verdict on a grant nobody measured
        (INV-01). aws-execution.md already specified the abort.

        Run through the public analyzer, like every other test in this class,
        rather than calling the private _grants_assume_role directly - which
        also pins that the TypeError is not swallowed by the surrounding
        `except ClientError` in analyze_iam_roles_trust_policies and reaches
        the caller instead.
        """
        with pytest.raises(TypeError, match="Unexpected action type: dict"):
            self.third_parties(self.allow(Action={"unexpected": "dict"}))

    def test_a_malformed_not_action_aborts_too(self) -> None:
        """
        NotAction takes the same rule as Action.

        An Allow with NotAction grants every action its patterns do not cover, so
        an unreadable NotAction leaves the grant just as unmeasured - and it is
        the branch that decides the verdict by negation, where a wrong answer is
        the permissive one.
        """
        with pytest.raises(TypeError, match="Unexpected action type: dict"):
            self.third_parties(self.allow(NotAction={"unexpected": "dict"}))


class TestTrustPolicyGrammar:
    """Trust policy elements the analyzer must read the way IAM does."""

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

        return analyze_iam_roles_trust_policies(mock_session, {"111111111111"}, ORG_ID)

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

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal lets everyone it does not name assume the role.

        Skipping the statement for want of a Principal reported the role
        clean, so the account kept its RCP and every third party outside the
        exclusion list lost the ability to assume it on apply.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a trust policy's Deny cannot let
        anyone assume the role, so it must not block the RCP.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole"
            }
        })

        assert results == []

    def test_not_principal_without_assume_role_is_not_a_wildcard(self) -> None:
        """
        The action gate runs first, as it does for an ordinary Principal.

        A trust policy statement granting something other than AssumeRole
        says nothing about who can assume the role, whichever principal
        element it carries.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:TagSession"
            }
        })

        assert results == []

    def test_guarded_service_principal_is_recorded(self) -> None:
        """
        A trust policy pinning a third-party source records it on the role.

        The account reaches the allowlist through the confused deputy
        check, not through this analysis's third_party_account_ids.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "999999999999"}
                },
            }],
        })

        assert len(results[0].service_principal_sources) == 1
        source = results[0].service_principal_sources[0]
        assert source.service_principal == "sns.amazonaws.com"
        assert source.source_account_ids == ["999999999999"]

        # The source is inert here: it belongs to deny_service_confused_deputy,
        # and folding it into these fields would widen this check's allowlist
        # with an account that drives a service call rather than making one.
        assert results[0].third_party_account_ids == set()
        assert results[0].has_wildcard_principal is False

    def test_a_policy_with_no_service_principal_records_nothing(self) -> None:
        """The field stays empty when no statement names a service."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
            }],
        })

        assert results[0].service_principal_sources == []
