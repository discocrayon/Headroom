"""Tests for headroom.aws.kms module."""

import json
from typing import Any

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.kms import (
    analyze_kms_key_policies,
    UnsupportedPrincipalTypeError,
    UnknownGranteePrincipalError,
    UnknownPrincipalTypeError,
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
)
from headroom.aws.policy_documents import MalformedPolicyError
from tests.constants import ORG_ID


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn_string(self) -> None:
        """Test extraction from ARN format string."""
        principal = "arn:aws:iam::333333333333:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"333333333333"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extraction from plain 12-digit account ID."""
        principal = "333333333333"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"333333333333"}

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
            "Federated": "arn:aws:iam::333333333333:saml-provider/MyProvider"
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
        assert _has_wildcard_principal("arn:aws:iam::333333333333:root") is False

    def test_wildcard_in_list(self) -> None:
        """Test detection of wildcard in list."""
        principal = ["arn:aws:iam::333333333333:root", "*"]
        assert _has_wildcard_principal(principal) is True

    def test_no_wildcard_in_list(self) -> None:
        """Test list without wildcard."""
        principal = ["arn:aws:iam::333333333333:root", "arn:aws:iam::111111111111:root"]
        assert _has_wildcard_principal(principal) is False

    def test_wildcard_in_dict_aws_string(self) -> None:
        """Test detection of wildcard in dict AWS string."""
        principal = {"AWS": "*"}
        assert _has_wildcard_principal(principal) is True

    def test_wildcard_in_dict_aws_list(self) -> None:
        """Test detection of wildcard in dict AWS list."""
        principal = {
            "AWS": ["arn:aws:iam::333333333333:root", "*"]
        }
        assert _has_wildcard_principal(principal) is True

    def test_no_wildcard_in_dict(self) -> None:
        """Test dict without wildcard."""
        principal = {
            "AWS": "arn:aws:iam::333333333333:root",
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
        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::333333333333:saml-provider/MyProvider"},"Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)
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
            analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)
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

        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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

        results = analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_kms_key_policies(mock_session, org_account_ids, ORG_ID)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


class TestPolicyGrammar:
    """Policy elements the key analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
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
        mock_kms_client.get_key_policy.return_value = {"Policy": json.dumps(policy)}

        return analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_lone_statement_object_is_analyzed(self) -> None:
        """The third party in a lone statement object is found, not missed."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*"
            }
        })

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == ["kms:Decrypt"]

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """A Statement of any other type aborts rather than reporting nothing."""
        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            self._analyze({"Version": "2012-10-17", "Statement": "Allow"})

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal grants to everyone it does not name.

        Skipping the statement for want of a Principal reported the resource
        clean, so the account kept its RCP and the grant's real audience -
        every account outside the exclusion list - lost access on apply.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a resource policy's Deny cannot
        hand access to anyone, so it must not block the RCP.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*"
            }
        })

        assert results == []

    def test_guarded_service_principal_is_recorded(self) -> None:
        """
        A key policy pinning a third-party source records it on the key.

        The account reaches the allowlist through the confused deputy
        check, not through this analysis's third_party_account_ids.
        """
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "999999999999"}
                },
            }],
        }

        results = self._analyze(policy=policy)

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
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }],
        }

        results = self._analyze(policy=policy)

        assert results[0].service_principal_sources == []


class TestKeyGrants:
    """
    Test that grants are read alongside the key policy.

    A grant is a second authorization surface. GetKeyPolicy cannot see it,
    so a key whose policy names nobody outside the organization can still
    hand Decrypt to a vendor.
    """
    ORG_ACCOUNT = "111111111111"
    THIRD_PARTY = "999999999999"

    ORG_ONLY_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ORG_ACCOUNT}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }

    @staticmethod
    def _analyze(
        grants: Any,
        policy: Any = None,
        policy_error: Any = None,
        grants_error: Any = None,
    ) -> Any:
        """
        Run the analyzer over one key with the given grants and policy.

        The key policy defaults to one naming only an organization account,
        so anything the analyzer reports came from a grant.
        """
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
                        "KeyArn": (
                            "arn:aws:kms:us-east-1:"
                            f"{TestKeyGrants.ORG_ACCOUNT}:key/key-123"
                        ),
                    }
                ]
            }
        ]

        grants_paginator = MagicMock()
        if grants_error is not None:
            grants_paginator.paginate.side_effect = grants_error
        else:
            grants_paginator.paginate.return_value = [{"Grants": grants}]

        mock_kms_client.get_paginator.side_effect = lambda name: {
            "list_keys": keys_paginator,
            "list_grants": grants_paginator,
        }[name]

        if policy_error is not None:
            mock_kms_client.get_key_policy.side_effect = policy_error
        else:
            mock_kms_client.get_key_policy.return_value = {
                "Policy": json.dumps(
                    TestKeyGrants.ORG_ONLY_POLICY if policy is None else policy
                )
            }

        return analyze_kms_key_policies(
            mock_session, {TestKeyGrants.ORG_ACCOUNT}, ORG_ID
        )

    def test_cross_account_grantee_reaches_the_allowlist(self) -> None:
        """
        A grant to an external role puts its account in the allowlist.

        The key policy names nobody outside the organization, so without
        reading grants the RCP would deploy and deny this vendor.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["Decrypt", "GenerateDataKey"],
            }
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert len(results[0].grants) == 1
        grant = results[0].grants[0]
        assert grant.grant_id == "grant-abc"
        assert grant.grantee_account_id == self.THIRD_PARTY
        assert grant.retiring_principal_account_id is None
        assert grant.operations == ["kms:Decrypt", "kms:GenerateDataKey"]
        assert grant.has_constraints is False

    def test_grant_operations_are_kms_prefixed(self) -> None:
        """
        Grant operations are recorded the way policy actions are.

        ListGrants returns bare operation names; a key policy spells the
        same permissions with a kms: prefix. One list cannot hold both
        spellings and stay readable.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["Decrypt"],
            }
        ])

        assert results[0].actions_by_account[self.THIRD_PARTY] == ["kms:Decrypt"]

    def test_service_principal_grantee_reports_nothing(self) -> None:
        """
        A grant held by an AWS service is exempt from the RCP.

        The generated RCP carries BoolIfExists aws:PrincipalIsAWSService
        false, so a service principal is never denied and never needs an
        allowlist entry.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "ec2.us-west-2.amazonaws.com",
                "Operations": ["Decrypt", "CreateGrant"],
            }
        ])

        assert results == []

    def test_in_org_grantee_reports_nothing(self) -> None:
        """A grant to a role inside the organization is not a third party."""
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.ORG_ACCOUNT}:role/aws-service-role/"
                    "autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
                ),
                "Operations": ["Decrypt"],
            }
        ])

        assert results == []

    def test_cross_account_retiring_principal_reports_retire_grant(self) -> None:
        """
        An external retiring principal is recorded, with only RetireGrant.

        Retiring is the only thing that principal can do, so attributing the
        grant's operations to it would overstate its access.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": f"arn:aws:iam::{self.ORG_ACCOUNT}:role/App",
                "RetiringPrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert results[0].actions_by_account[self.THIRD_PARTY] == [
            "kms:RetireGrant"
        ]
        grant = results[0].grants[0]
        assert grant.grantee_account_id is None
        assert grant.retiring_principal_account_id == self.THIRD_PARTY

    def test_encryption_context_constraints_are_recorded(self) -> None:
        """
        A constrained grant is flagged, though the constraint is not parsed.

        Condition-aware analysis is a separate concern; recording that a
        constraint exists keeps the result honest about what was not read.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["Decrypt"],
                "Constraints": {
                    "EncryptionContextSubset": {"Department": "Finance"}
                },
            }
        ])

        assert results[0].grants[0].has_constraints is True

    def test_a_grant_is_never_a_violation(self) -> None:
        """
        Grants can widen the allowlist but never withhold the RCP.

        CreateGrant requires a concrete principal, so no grant can be a
        wildcard, and the wildcard flag is what blocks deployment.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["Decrypt"],
            }
        ])

        assert results[0].has_wildcard_principal is False

    def test_grants_are_read_when_the_key_has_no_policy(self) -> None:
        """
        A key with no policy is not a key with nothing to find.

        Returning early on a missing policy would skip the grant read on
        exactly the keys whose access lives entirely in grants.
        """
        error_response: Any = {"Error": {"Code": "NotFoundException"}}
        results = self._analyze(
            [
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": (
                        f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                    ),
                    "Operations": ["Decrypt"],
                }
            ],
            policy_error=ClientError(error_response, "GetKeyPolicy"),
        )

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}

    def test_unrecognized_grantee_principal_raises(self) -> None:
        """
        A grantee the analyzer cannot classify aborts rather than vanishing.

        Silently dropping it would leave the account out of the allowlist,
        which is the failure this whole check exists to prevent.
        """
        with pytest.raises(UnknownGranteePrincipalError, match="not-a-principal"):
            self._analyze([
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": "not-a-principal",
                    "Operations": ["Decrypt"],
                }
            ])

    def test_list_grants_error_propagates(self) -> None:
        """An unreadable grant list must not be reported as no grants."""
        error_response: Any = {"Error": {"Code": "AccessDeniedException"}}
        with pytest.raises(ClientError):
            self._analyze([], grants_error=ClientError(
                error_response, "ListGrants"
            ))

    def test_policy_and_grant_third_parties_merge(self) -> None:
        """
        Both surfaces contribute to one key's row.

        A grant attaches to the same key in the same region, so it belongs
        in that key's result rather than a row of its own.
        """
        policy_third_party = "888888888888"
        results = self._analyze(
            [
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": (
                        f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                    ),
                    "Operations": ["Decrypt"],
                }
            ],
            policy={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": f"arn:aws:iam::{policy_third_party}:root"
                        },
                        "Action": "kms:DescribeKey",
                        "Resource": "*",
                    }
                ],
            },
        )

        assert len(results) == 1
        assert results[0].third_party_account_ids == {
            policy_third_party,
            self.THIRD_PARTY,
        }
        assert [g.grantee_account_id for g in results[0].grants] == [
            self.THIRD_PARTY
        ]
