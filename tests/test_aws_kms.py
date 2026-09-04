"""Tests for headroom.aws.kms module."""

import json
import logging
from typing import Any, Optional, Set

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.kms import (
    KMSGrantFinding,
    UnknownGrantPrincipalError,
    UnresolvedKMSGrantFinding,
    analyze_kms_key_policies,
)
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)
from tests.constants import ORG_ID


class TestAnalyzeKmsKeyPolicies:
    """Test analyze_kms_key_policies function."""

    def test_an_unparseable_policy_aborts_the_run(self) -> None:
        """
        A document AWS could not have stored means Headroom misread it.

        Recording the key as clean would let the RCP deploy over whatever
        the policy actually grants, which is INV-01's case. The analyzer
        catches nothing here, so the JSONDecodeError reaches the top and
        ends the run.
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
            {"Keys": [{
                "KeyId": "key-123",
                "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-123",
            }]}
        ]
        mock_kms_client.get_paginator.return_value = keys_paginator
        mock_kms_client.get_key_policy.return_value = {"Policy": "{not json"}

        with pytest.raises(json.JSONDecodeError):
            analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)

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

    def test_a_federated_principal_blocks_the_key_rather_than_the_run(self) -> None:
        """
        A Federated principal carries no account ID the allowlist can hold.

        A SAML provider ARN carries twelve digits, but they name the account
        hosting the provider rather than the caller, so no allowlist keyed on
        aws:PrincipalAccount can preserve the grant. The key blocks the
        account for this check; the other accounts' scans still finish.
        """
        mock_session, mock_kms_client = self._single_region_session()

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

        mock_kms_client.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::333333333333:saml-provider/Example"
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }],
            })
        }

        results = analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    def test_a_canonical_user_blocks_the_key_rather_than_the_run(self) -> None:
        """A canonical user ID maps to no account the allowlist can carry."""
        mock_session, mock_kms_client = self._single_region_session()

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-canonical",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-canonical"
                    }
                ]
            }
        ]
        mock_kms_client.get_paginator.return_value = keys_paginator

        mock_kms_client.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"CanonicalUser": "d" * 64},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }],
            })
        }

        results = analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    @staticmethod
    def _single_region_session() -> tuple[MagicMock, MagicMock]:
        """Build a session mock wired to one region and return (session, kms_client)."""
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
        return mock_session, mock_kms_client

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

    # Unique IDs in the current format. The account each one carries is
    # THIRD_PARTY, behind either prefix, so a test that names one of these
    # as a grantee and then asserts THIRD_PARTY is reading the account back
    # out of the identifier and out of nothing else on the grant.
    THIRD_PARTY_ROLE_UNIQUE_ID = "AROA6RVFFB77QAAAAAAAA"
    THIRD_PARTY_USER_UNIQUE_ID = "AIDA6RVFFB77QAAAAAAAA"

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
        org_account_ids: Optional[Set[str]] = None,
    ) -> Any:
        """
        Run the analyzer over one key with the given grants and policy.

        The key policy defaults to one naming only an organization account,
        so anything the analyzer reports came from a grant, and the
        organization defaults to the one account that policy names.
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
            mock_session,
            {TestKeyGrants.ORG_ACCOUNT} if org_account_ids is None else org_account_ids,
            ORG_ID,
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

    def test_an_arn_grantee_records_the_arn_and_says_the_arn_named_the_account(self) -> None:
        """
        An account AWS spelled out is recorded as having come from the ARN.

        The other way an account reaches a finding is arithmetic on a unique
        ID, which is reverse-engineered rather than an AWS contract. A reader
        who cannot tell the two apart has to treat every entry in the
        allowlist as if it might have been computed. The principal is kept
        whole beside the source, so the ARN the account was read out of is
        there to check it against.
        """
        grantee_arn = f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": grantee_arn,
                "Operations": ["Decrypt"],
            }
        ])

        assert results[0].grants == [
            KMSGrantFinding(
                grant_id="grant-abc",
                grantee_account_id=self.THIRD_PARTY,
                grantee_principal=grantee_arn,
                grantee_account_id_source="arn",
                retiring_principal_account_id=None,
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ]

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
                "GranteePrincipal": f"arn:aws:iam::{self.ORG_ACCOUNT}:role/App",
                "Operations": ["Decrypt"],
            }
        ])

        assert results == []

    def test_a_key_policy_naming_a_service_linked_role_is_not_recorded(self) -> None:
        """
        The service-linked-role exemption does not depend on the surface.

        RCPs do not impact any service-linked role, whether a key policy or a
        grant names it, so a policy statement granting a foreign one puts
        nothing in the results and nothing in the allowlist.
        """
        results = self._analyze([], policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            f"arn:aws:iam::{self.THIRD_PARTY}:role/aws-service-role/"
                            "example.amazonaws.com/AWSServiceRoleForExample"
                        )
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        })

        assert results == []

    def test_a_key_policy_statement_granting_only_retire_grant_is_not_recorded(self) -> None:
        """
        kms:RetireGrant is not effective in a key policy, so a statement
        granting only it authorizes nothing.

        AWS documents that the grant itself decides who may retire it and
        that the permission has no effect in a key policy or an RCP. Reading
        the statement anyway allowlisted an account the RCP could not have
        denied anything to.
        """
        results = self._analyze([], policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                    },
                    "Action": "kms:RetireGrant",
                    "Resource": "*",
                }
            ],
        })

        assert results == []

    def test_a_wildcard_statement_granting_only_retire_grant_is_not_a_violation(self) -> None:
        """
        An ineffective statement cannot be a blocker either.

        `Principal: "*"` with only kms:RetireGrant hands nobody anything the
        RCP could deny, so it must not withhold the RCP from the account.
        """
        results = self._analyze([], policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["kms:RetireGrant"],
                    "Resource": "*",
                }
            ],
        })

        assert results == []

    def test_an_opaque_retiring_principal_does_not_abort_the_scan(self) -> None:
        """
        A service-created grant naming "AWS Internal" as its retiring
        principal is not a finding and not an abort.

        A retiring principal can only call RetireGrant, and AWS documents
        that RCPs do not impact kms:RetireGrant, so nothing in that field
        bears on what the RCP will deny. Reading it through the grantee's
        classifier aborted the whole organization scan over a display value.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.ORG_ACCOUNT}:role/aws-service-role/"
                    "example.amazonaws.com/AWSServiceRoleForExample"
                ),
                "RetiringPrincipal": "AWS Internal",
                "Operations": ["Decrypt", "GenerateDataKey", "RetireGrant"],
            }
        ])

        assert results == []

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

    def test_a_grant_does_not_set_the_wildcard_flag(self) -> None:
        """
        CreateGrant requires a concrete principal, so no grant is a wildcard.

        The flag is all this pins. A grant can withhold the RCP now, by
        naming a grantee whose account the encoding cannot read, and that
        route leaves this flag false - so the flag being false is no longer
        the same statement as the key being compliant.
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

        The message names the key and the grant carrying the principal.
        An abort saying only what the principal was leaves the operator to
        find it among every grant on every key in the organization.
        """
        with pytest.raises(UnknownGrantPrincipalError) as raised:
            self._analyze([
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": "not-a-principal",
                    "Operations": ["Decrypt"],
                }
            ])

        message = str(raised.value)
        assert "not-a-principal" in message
        assert "GranteePrincipal" in message
        assert "grant-abc" in message
        assert "arn:aws:kms:us-east-1:111111111111:key/key-123" in message

    def test_an_external_service_linked_role_grantee_is_exempt(self) -> None:
        """
        A service-linked role in another account is not a third party.

        RCPs do not impact the effective permissions of any service-linked
        role, so the RCP cannot deny it and its account has no business in
        the allowlist. IAM reserves the `aws-service-role/` role path to
        AWS services, so the path is what identifies the role; a role named
        to look like one, outside that path, is an ordinary role.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/aws-service-role/"
                    "example.amazonaws.com/AWSServiceRoleForExample"
                ),
                "Operations": ["Decrypt"],
            }
        ])

        assert results == []

    def test_a_grantee_service_principal_is_exempt_without_reading_the_display_principal(self) -> None:
        """
        A typed GranteeServicePrincipal settles the grantee's identity.

        AWS documents that a grant created with GranteeServicePrincipal is
        listed with that field, and that the RCP exempts AWS services with
        aws:PrincipalIsAWSService. Whatever display value sits beside it in
        GranteePrincipal is not read, so it cannot abort the scan.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteeServicePrincipal": "example.amazonaws.com",
                "GranteePrincipal": "AWS Internal",
                "Operations": ["Encrypt", "Decrypt", "GenerateDataKey"],
            }
        ])

        assert results == []

    def test_a_retire_grant_only_grant_is_not_a_third_party(self) -> None:
        """
        An external grantee holding only RetireGrant is not a third party.

        RCPs do not impact kms:RetireGrant, so the RCP cannot deny the one
        thing this grant lets its grantee do. An allowlist entry for it
        would open kms:* to an account the RCP was never going to block.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["RetireGrant"],
            }
        ])

        assert results == []

    def test_a_retire_grant_only_grant_with_no_grantee_is_skipped(self) -> None:
        """
        The RetireGrant skip is read before the grantee, so neither is missing.

        A grant carrying neither GranteeServicePrincipal nor GranteePrincipal
        aborts the run, because dropping it would read a missing grantee as
        no grantee. This one does not reach that read: what the permission
        does not authorize cannot depend on who holds it, so the operations
        are settled first and the grant is gone before the grantee matters.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "Operations": ["RetireGrant"],
            }
        ])

        assert results == []

    def test_a_mixed_operation_grant_is_analyzed_normally(self) -> None:
        """
        RetireGrant beside other operations does not exempt the grant.

        The grantee's Decrypt is what the RCP would deny, so the account
        enters the allowlist, and the operations are recorded as listed,
        RetireGrant included.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "Operations": ["RetireGrant", "Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert results[0].actions_by_account[self.THIRD_PARTY] == [
            "kms:Decrypt", "kms:RetireGrant"
        ]
        assert results[0].grants[0].operations == [
            "kms:Decrypt", "kms:RetireGrant"
        ]

    def test_a_grant_with_no_operations_is_still_recorded(self) -> None:
        """
        Missing Operations is not the same as RetireGrant only.

        Nothing in such a grant says what it authorizes, and INV-01 forbids
        reading that silence as safe, so the grantee is recorded with an
        empty operations list rather than dropped.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
            }
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert results[0].grants[0].operations == []

    def test_a_service_role_name_outside_the_reserved_path_is_ordinary(self) -> None:
        """
        A role is service-linked by its path, not by its name.

        Anyone can name a role AWSServiceRoleForExample; only AWS can put
        one under the `aws-service-role/` path. A look-alike outside that
        path is an ordinary role the RCP would deny, so its account enters
        the allowlist.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/"
                    "AWSServiceRoleForExample"
                ),
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}

    def test_an_opaque_grantee_principal_still_raises(self) -> None:
        """
        "AWS Internal" as the grantee, with no typed field beside it, aborts.

        The grantee holds Decrypt, which the RCP would deny, and nothing
        says which account it belongs to. Only a typed GranteeServicePrincipal
        proves the grantee exempt; the retiring fields say nothing about it.
        """
        with pytest.raises(UnknownGrantPrincipalError) as raised:
            self._analyze([
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": "AWS Internal",
                    "RetiringPrincipal": "AWS Internal",
                    "Operations": ["Decrypt"],
                }
            ])

        message = str(raised.value)
        assert "GranteePrincipal" in message
        assert "grant-abc" in message
        assert f"arn:aws:kms:us-east-1:{self.ORG_ACCOUNT}:key/key-123" in message

    def test_an_external_grantee_beside_an_opaque_retiring_principal_is_recorded(self) -> None:
        """
        Ignoring the retiring field does not depend on who the grantee is.

        The external grantee holds Decrypt, so it is recorded like any other,
        and the opaque retiring value beside it neither aborts the scan nor
        fills the compatibility field.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                ),
                "RetiringPrincipal": "AWS Internal",
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        grant = results[0].grants[0]
        assert grant.grantee_account_id == self.THIRD_PARTY
        assert grant.retiring_principal_account_id is None

    def test_an_external_retiring_principal_is_not_a_third_party(self) -> None:
        """
        An external retiring principal enters neither the results nor the
        allowlist.

        It can call RetireGrant and nothing else, and RCPs do not impact
        kms:RetireGrant, so the RCP cannot deny it. Allowlisting its account
        would open kms:* to a vendor the RCP was never going to block.
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

        assert results == []

    def test_a_grant_with_no_id_raises(self) -> None:
        """
        A grant carrying no ID is not a grant whose ID is the empty string.

        ListGrants always returns the ID RetireGrant takes. Recording ""
        would write a finding naming a grant nobody can retire, and leave
        every message about the grant naming no grant at all.
        """
        with pytest.raises(KeyError, match="GrantId"):
            self._analyze([
                {
                    "GranteePrincipal": (
                        f"arn:aws:iam::{self.THIRD_PARTY}:role/VendorRole"
                    ),
                    "Operations": ["Decrypt"],
                }
            ])

    def test_a_grant_with_no_grantee_raises(self) -> None:
        """
        A grant naming no grantee at all is a response Headroom has misread.

        ListGrants returns GranteeServicePrincipal or GranteePrincipal on
        every grant. Dropping one carrying neither would read a missing
        grantee as no grantee, which INV-01 forbids, so it aborts like a
        grant with no ID.
        """
        with pytest.raises(KeyError, match="GranteePrincipal"):
            self._analyze([
                {
                    "GrantId": "grant-abc",
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

    def test_a_bare_role_unique_id_grantee_is_recorded_rather_than_aborting(self) -> None:
        """
        A grantee named by unique ID blocks the key's account without a guess.

        The grantee holds Decrypt, which the RCP would deny, and nothing in
        the grant says which account it belongs to. Aborting cost the whole
        organization its results over one grant, and guessing an account
        would be worse: IssuingAccount names who created the grant, not who
        holds it, so nothing about the grant may reach the allowlist.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                # An all-A body is the shape of a legacy identifier: it
                # sits below the offset the account encoding starts at, so
                # no account can be read out of it. Every unresolved-grant
                # fixture below is built that way on purpose. Modernizing
                # one to a body that does encode an account would send its
                # grant to the allowlist and invert what the test asserts
                # while its name still says the grant was recorded.
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                "Operations": ["Decrypt"],
                "IssuingAccount": f"arn:aws:iam::{self.THIRD_PARTY}:root",
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == [
            UnresolvedKMSGrantFinding(
                grant_id="grant-abc",
                grantee_principal="AROAAAAAAAAAAAAAAAAAA",
                principal_kind="iam_role_unique_id",
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ]
        assert results[0].third_party_account_ids == set()
        assert results[0].actions_by_account == {}
        assert results[0].grants == []

    def test_a_bare_user_unique_id_grantee_is_recorded_as_a_user(self) -> None:
        """
        The two unique-ID prefixes are recorded apart, not collapsed.

        AROA names a role and AIDA a user, and an operator chasing the
        recorded grant looks the two up through different IAM calls. A
        finding that called every unique ID a role would send them to the
        wrong one.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AIDAAAAAAAAAAAAAAAAAA",
                "Operations": ["Decrypt"],
                "IssuingAccount": f"arn:aws:iam::{self.THIRD_PARTY}:root",
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == [
            UnresolvedKMSGrantFinding(
                grant_id="grant-abc",
                grantee_principal="AIDAAAAAAAAAAAAAAAAAA",
                principal_kind="iam_user_unique_id",
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ]
        assert results[0].third_party_account_ids == set()
        assert results[0].actions_by_account == {}
        assert results[0].grants == []

    def test_an_unresolved_grant_with_no_operations_is_still_recorded(self) -> None:
        """
        Missing Operations does not make an unattributable grantee harmless.

        Nothing in such a grant says what it authorizes, and INV-01 forbids
        reading that silence as safe. The grantee is recorded with an empty
        operations list, exactly as an external grantee with no operations
        is, rather than dropped for saying nothing.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants[0].operations == []

    def test_a_decoded_grant_with_no_operations_is_still_recorded(self) -> None:
        """
        Missing Operations is not the same as RetireGrant only.

        Nothing in such a grant says what it authorizes, and INV-01 forbids
        reading that silence as safe. Being able to name the grantee's
        account changes none of that, so the decoded account enters the
        allowlist with an empty operations list, exactly as an external ARN
        grantee with no operations does.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == []
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert results[0].grants[0].grantee_account_id == self.THIRD_PARTY
        assert results[0].grants[0].operations == []

    def test_an_unresolved_grantee_holding_only_retire_grant_reports_nothing(self) -> None:
        """
        An unattributable grantee holding only RetireGrant is not a blocker.

        RCPs do not impact kms:RetireGrant, so the grant authorizes nothing
        the RCP could deny and there is nothing to block the account over -
        the same exemption an external grantee holding only RetireGrant
        gets. Whether the grantee can be attributed does not change what
        the permission does, so the exemption is read before the grantee is.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                "Operations": ["RetireGrant"],
            }
        ])

        assert results == []

    def test_a_mixed_operation_unresolved_grant_records_every_operation(self) -> None:
        """
        RetireGrant beside another operation does not exempt the grant.

        The grantee's Decrypt is what the RCP would deny, so the grant is
        recorded, and its operations are recorded as listed rather than
        filtered down to the ones the RCP acts on - the operator retiring
        the grant needs to see everything it hands out.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                "Operations": ["RetireGrant", "Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants[0].operations == [
            "kms:Decrypt", "kms:RetireGrant"
        ]

    def test_a_mixed_operation_decoded_grant_records_every_operation(self) -> None:
        """
        RetireGrant beside another operation does not exempt the grant.

        The grantee's Decrypt is what the RCP would deny, so the decoded
        account enters the allowlist, and the operations are recorded as
        listed rather than filtered down to the ones the RCP acts on - the
        operator retiring the grant needs to see everything it hands out.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                "Operations": ["RetireGrant", "Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == []
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert results[0].grants[0].operations == [
            "kms:Decrypt", "kms:RetireGrant"
        ]
        assert results[0].actions_by_account[self.THIRD_PARTY] == [
            "kms:Decrypt", "kms:RetireGrant"
        ]

    def test_an_unresolved_grant_records_that_it_is_constrained(self) -> None:
        """
        A constrained unresolved grant is flagged, though the constraint is
        not parsed.

        The operator reading the finding has to decide what the grant really
        hands out before retiring it, and an encryption context subset can
        make the access far narrower than the operations suggest. Recording
        that one exists keeps the finding honest about what was not read.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                "Operations": ["Decrypt"],
                "Constraints": {
                    "EncryptionContextSubset": {"purpose": "example"}
                },
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants[0].has_constraints is True

    def test_a_grantee_service_principal_beside_a_unique_id_reports_nothing(self) -> None:
        """
        A typed GranteeServicePrincipal still settles the grantee's identity.

        AWS documents that a grant created for a service is listed with that
        field, and the RCP exempts services with aws:PrincipalIsAWSService.
        The unique ID sitting beside it is a display value for an exempt
        grantee, so recording it would block the key's account over a grant
        the RCP was never going to deny - and, unlike the "AWS Internal"
        display value the sibling test uses, it would do so silently,
        because a unique ID is a shape the analyzer records rather than
        aborts on.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteeServicePrincipal": "example.amazonaws.com",
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                "Operations": ["Decrypt"],
            }
        ])

        assert results == []

    def test_a_grantee_service_principal_beside_a_decodable_unique_id_reports_nothing(self) -> None:
        """
        The typed field settles the grantee even when the display value
        names an account.

        AWS documents that a grant created for a service is listed with
        GranteeServicePrincipal, and the RCP exempts services with
        aws:PrincipalIsAWSService. Reading the unique ID beside it would
        write whatever account that display value happens to spell into the
        allowlist - opening kms:* to an account nothing on this key names,
        which is worse than the blocked account the same mistake costs when
        no account can be read out of the identifier.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteeServicePrincipal": "example.amazonaws.com",
                "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                "Operations": ["Decrypt"],
            }
        ])

        assert results == []

    def test_an_opaque_grantee_holding_only_retire_grant_does_not_abort(self) -> None:
        """
        An unclassifiable grantee holding only RetireGrant aborts nothing.

        RCPs do not impact kms:RetireGrant, so the analyzer never has to
        decide whose account this grantee belongs to: whatever the answer,
        the RCP denies it nothing. Resolving the grantee first aborted the
        whole organization scan over a display value on a grant that could
        not have mattered.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AWS Internal",
                "Operations": ["RetireGrant"],
            }
        ])

        assert results == []

    @pytest.mark.parametrize("principal", [
        pytest.param("aroaaaaaaaaaaaaaaaaaa", id="lowercase-copy"),
        pytest.param("AROAAAAAAAAAAAAAAAAA", id="sixteen-character-body"),
        pytest.param("AROAAAAAAAAAAAAAAAAAAA", id="eighteen-character-body"),
        pytest.param("AROAAAAAAAAAAAAAAAAAA:session-name", id="role-session-suffix"),
        pytest.param("AROA11111111111111111", id="digit-outside-the-alphabet"),
    ])
    def test_a_near_miss_unique_id_aborts_rather_than_being_recorded(self, principal: str) -> None:
        """
        A value that only resembles a unique ID is not read as one.

        Recording it would claim the analyzer knows what the string is,
        when a lowercase copy, a short body, a long body, a session
        suffix, or a body holding one of the four digits AWS Base32 omits
        could equally be some identifier Headroom has never seen. Each
        case is a valid identifier altered in exactly one way, so each one
        pins one rule on its own: the four whose bodies are in the
        alphabet would all survive a loosened alphabet, and the last one,
        being the right length behind the right prefix, would survive a
        loosened case, length, or end anchor. The abort says which grant
        on which key carries it, and names the one shape the analyzer does
        accept, so the operator can tell a near miss from something new.
        """
        with pytest.raises(UnknownGrantPrincipalError) as raised:
            self._analyze([
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": principal,
                    "Operations": ["Decrypt"],
                }
            ])

        message = str(raised.value)
        assert principal in message
        assert "grant-abc" in message
        assert f"arn:aws:kms:us-east-1:{self.ORG_ACCOUNT}:key/key-123" in message
        assert "IAM unique ID" in message

    def test_an_arn_grantee_is_never_read_as_a_unique_id(self) -> None:
        """
        A resolvable grantee is allowlisted, not recorded as unresolved.

        An ARN and a unique ID both name a principal, and the classifier
        is asked first, so a classifier that matched an ARN would move
        this vendor out of the allowlist and into unresolved_grants -
        blocking the key's own account for KMS over a grantee whose
        account the ARN states outright. That is the inversion the
        allowlist exists to prevent, and it is the one shape whose
        misclassification loses access rather than merely aborting. The
        near-miss cases above pin what the classifier declines; this pins
        the shape it must never claim.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": f"arn:aws:iam::{self.THIRD_PARTY}:role/vendor",
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == []
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert [g.grant_id for g in results[0].grants] == ["grant-abc"]

    def test_a_key_carrying_both_kinds_of_grant_records_each_in_its_own_list(self) -> None:
        """
        One unattributable grant does not cost the key its resolved ones.

        The external grantee still belongs in the allowlist, or the RCP
        deploys and denies it; the unattributable one still blocks the
        account. Folding either into the other list would lose one of the
        two, and stopping at the first unresolved grant would lose the rest
        of the key's grants along with it.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                "Operations": ["Decrypt"],
                "IssuingAccount": f"arn:aws:iam::{self.THIRD_PARTY}:root",
            },
            {
                "GrantId": "grant-ext",
                "GranteePrincipal": (
                    f"arn:aws:iam::{self.THIRD_PARTY}:role/vendor"
                ),
                "Operations": ["Decrypt"],
            },
        ])

        assert len(results) == 1
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert len(results[0].grants) == 1
        assert results[0].grants[0].grant_id == "grant-ext"
        assert len(results[0].unresolved_grants) == 1
        assert results[0].unresolved_grants[0].grant_id == "grant-abc"

    def test_an_unresolved_grant_is_logged_where_the_operator_will_see_it(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        The grant is named in the run's log, not only in the results file.

        The account is blocked for KMS and the operator has to go find the
        grant to clear it. ListGrants is per key per region, so a warning
        that omitted the key ARN or the grant ID would leave them searching
        every key in the organization - which is what the abort this
        replaces at least told them.
        """
        with caplog.at_level(logging.WARNING):
            self._analyze([
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": "AROAAAAAAAAAAAAAAAAAA",
                    "Operations": ["Decrypt"],
                }
            ])

        warnings = [
            record for record in caplog.records
            if record.levelno == logging.WARNING
        ]
        assert len(warnings) == 1
        assert "AROAAAAAAAAAAAAAAAAAA" in warnings[0].message
        assert "grant-abc" in warnings[0].message
        assert (
            f"arn:aws:kms:us-east-1:{self.ORG_ACCOUNT}:key/key-123"
            in warnings[0].message
        )

    def test_a_decoded_grant_is_not_logged_as_unattributable(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        The warning belongs to the grants nobody can attribute.

        It tells the operator to go find a grant and clear a blocked
        account, and a decoded grantee gives them neither errand. Logging
        one per decodable grant would bury the grants that do need finding
        under a line for every unique ID in the organization.
        """
        with caplog.at_level(logging.WARNING):
            self._analyze([
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                    "Operations": ["Decrypt"],
                }
            ])

        assert [
            record for record in caplog.records
            if record.levelno == logging.WARNING
        ] == []

    def test_a_decodable_role_unique_id_grantee_reaches_the_allowlist(self) -> None:
        """
        A unique ID in the current format names its own account, so its
        grantee is attributed rather than blocked.

        The account the identifier carries is outside the organization, so
        the grant belongs in the allowlist like any external ARN. Recording
        it as unresolved would block the key's own account for KMS over a
        grantee the grant already identifies.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == []
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert [g.grantee_account_id for g in results[0].grants] == [self.THIRD_PARTY]
        assert results[0].grants[0].grant_id == "grant-abc"
        assert results[0].actions_by_account[self.THIRD_PARTY] == ["kms:Decrypt"]

    def test_a_decoded_grantee_records_the_identifier_and_says_it_was_decoded(self) -> None:
        """
        An account nothing spelled out is recorded as having been computed.

        This account was not read off the grant; it was decoded from the
        identifier by an encoding AWS does not document and could change
        without notice. A finding that recorded it the way it records an
        account out of an ARN would hide the one entry in the allowlist an
        operator should check by hand. The identifier is kept whole, because
        it is what they would search IAM for.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                "Operations": ["Decrypt"],
            }
        ])

        assert results[0].grants == [
            KMSGrantFinding(
                grant_id="grant-abc",
                grantee_account_id=self.THIRD_PARTY,
                grantee_principal=self.THIRD_PARTY_ROLE_UNIQUE_ID,
                grantee_account_id_source="iam_unique_id",
                retiring_principal_account_id=None,
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ]

    def test_a_decodable_user_unique_id_grantee_reaches_the_allowlist(self) -> None:
        """
        An IAM user's unique ID names its account the way a role's does.

        The account sits in the same characters behind either prefix, so an
        AIDA grantee whose account can be read is allowlisted rather than
        blocked. Reading only AROA would leave every grant to a user
        blocking its key's account for KMS.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": self.THIRD_PARTY_USER_UNIQUE_ID,
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == []
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert [g.grantee_account_id for g in results[0].grants] == [self.THIRD_PARTY]

    def test_a_decodable_unique_id_grantee_inside_the_organization_reports_nothing(self) -> None:
        """
        An account read out of an identifier is not a third party when the
        organization holds it.

        The grantee resolves to an account the RCP already exempts, so the
        grant belongs in neither list. Allowlisting it would name an
        organization account, and recording it as unresolved would block
        the key's account over access that never leaves the organization -
        exactly what an in-organization ARN grantee reports, which is
        nothing.
        """
        results = self._analyze(
            [
                {
                    "GrantId": "grant-abc",
                    "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                    "Operations": ["Decrypt"],
                }
            ],
            org_account_ids={self.ORG_ACCOUNT, self.THIRD_PARTY},
        )

        assert results == []

    def test_a_grantee_the_organization_holds_says_so_at_debug(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        This exit records neither a finding nor an unresolved entry.

        It is the only one that does not, so without a line here an
        operator asking why a grant they can read in the console is absent
        from the results has no artifact to answer from. DEBUG rather than
        WARNING because the drop is correct: a warning would fire for
        every internal unique ID in the organization and bury the grants
        that do need finding.
        """
        with caplog.at_level(logging.DEBUG):
            self._analyze(
                [
                    {
                        "GrantId": "grant-abc",
                        "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                        "Operations": ["Decrypt"],
                    }
                ],
                org_account_ids={self.ORG_ACCOUNT, self.THIRD_PARTY},
            )

        dropped = [
            record for record in caplog.records
            if self.THIRD_PARTY_ROLE_UNIQUE_ID in record.message
        ]

        assert len(dropped) == 1
        assert dropped[0].levelno == logging.DEBUG
        assert self.THIRD_PARTY in dropped[0].message
        assert "grant-abc" in dropped[0].message

    def test_a_decoded_grantee_is_attributed_over_a_disagreeing_issuing_account(self) -> None:
        """
        IssuingAccount names who created the grant, not who holds it.

        The identifier is the only thing on the grant that says whose the
        grantee is, so a disagreeing IssuingAccount must not displace it.
        Allowlisting the issuer would open kms:* to an account that merely
        created the grant while the account really holding Decrypt stayed
        denied.
        """
        issuing_account = "222222222222"
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": self.THIRD_PARTY_ROLE_UNIQUE_ID,
                "Operations": ["Decrypt"],
                "IssuingAccount": f"arn:aws:iam::{issuing_account}:root",
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == []
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}
        assert [g.grantee_account_id for g in results[0].grants] == [self.THIRD_PARTY]
        assert issuing_account not in results[0].actions_by_account

    def test_a_unique_id_decoding_out_of_range_is_recorded_rather_than_allowlisted(self) -> None:
        """
        A decoding landing outside the accounts AWS can issue is not an
        account.

        Allowlisting the number would name an account that cannot exist
        while the real grantee stayed denied, so the grant is recorded as
        unresolved, exactly as an identifier the encoding does not support
        for any other reason is.
        """
        results = self._analyze([
            {
                "GrantId": "grant-abc",
                "GranteePrincipal": "AROA77777777AAAAAAAAA",
                "Operations": ["Decrypt"],
            }
        ])

        assert len(results) == 1
        assert results[0].unresolved_grants == [
            UnresolvedKMSGrantFinding(
                grant_id="grant-abc",
                grantee_principal="AROA77777777AAAAAAAAA",
                principal_kind="iam_role_unique_id",
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ]
        assert results[0].grants == []
        assert results[0].third_party_account_ids == set()
        assert results[0].actions_by_account == {}


class TestAWSManagedKeys:
    """
    AWS-managed keys are skipped on `KeyManager`, before any policy is read.

    RCPs do not apply to AWS-managed keys, so no statement this scan generates
    can reach one. Their default policy grants `Principal: {"AWS": "*"}` under
    `kms:CallerAccount`, which `read_principal` reads as a wildcard, so before
    the skip every account holding one was blocked for the KMS RCP by a
    policy its operator cannot change.
    """

    KEY_ID = "11111111-1111-1111-1111-111111111111"
    KEY_ARN = f"arn:aws:kms:us-east-1:111111111111:key/{KEY_ID}"

    # The documented default policy of an AWS-managed key, with the key's own
    # account in kms:CallerAccount and the owning service in kms:ViaService.
    AWS_MANAGED_DEFAULT_POLICY = {
        "Version": "2012-10-17",
        "Id": "auto-s3-2",
        "Statement": [
            {
                "Sid": "Allow access through S3 for all principals in the account that are authorized to use S3",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:CallerAccount": "111111111111",
                        "kms:ViaService": "s3.us-east-1.amazonaws.com",
                    }
                },
            },
            {
                "Sid": "Allow direct access to key metadata to the account",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:RevokeGrant"],
                "Resource": "*",
            },
        ],
    }

    @staticmethod
    def _one_key_client(describe_key_response: Any) -> tuple[MagicMock, MagicMock]:
        """
        Build a session wired to one region holding one key.

        Returns the session and the KMS client, so a test can assert which
        reads the analyzer made against the key.
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
            {"Keys": [{"KeyId": TestAWSManagedKeys.KEY_ID, "KeyArn": TestAWSManagedKeys.KEY_ARN}]}
        ]
        grants_paginator = MagicMock()
        grants_paginator.paginate.return_value = [{"Grants": []}]

        mock_kms_client.get_paginator.side_effect = lambda name: {
            "list_keys": keys_paginator,
            "list_grants": grants_paginator,
        }[name]

        if isinstance(describe_key_response, Exception):
            mock_kms_client.describe_key.side_effect = describe_key_response
        else:
            mock_kms_client.describe_key.return_value = describe_key_response

        mock_kms_client.get_key_policy.return_value = {
            "Policy": json.dumps(TestAWSManagedKeys.AWS_MANAGED_DEFAULT_POLICY)
        }
        return mock_session, mock_kms_client

    def test_an_aws_managed_key_is_skipped_before_its_policy_is_read(self) -> None:
        """
        A key AWS manages is neither recorded nor read past DescribeKey.

        Its policy would be read as a wildcard, and RCPs do not apply to the
        key, so reading it could only produce a false blocker. Skipping
        before GetKeyPolicy and ListGrants also saves those two calls.
        """
        mock_session, mock_kms_client = self._one_key_client(
            {"KeyMetadata": {"KeyId": self.KEY_ID, "KeyManager": "AWS"}}
        )

        results = analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)

        assert results == []
        mock_kms_client.describe_key.assert_called_once_with(KeyId=self.KEY_ID)
        mock_kms_client.get_key_policy.assert_not_called()
        assert all(
            call.args[0] != "list_grants"
            for call in mock_kms_client.get_paginator.call_args_list
        )

    def test_a_customer_managed_key_with_the_same_policy_is_a_violation(self) -> None:
        """
        The skip reads the key type, not the policy's Condition block.

        A customer-managed key written with the AWS-managed idiom is still
        read as a wildcard: RCPs do apply to it, and `kms:CallerAccount` is
        deliberately not evaluated.
        """
        mock_session, mock_kms_client = self._one_key_client(
            {"KeyMetadata": {"KeyId": self.KEY_ID, "KeyManager": "CUSTOMER"}}
        )

        results = analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].key_id == self.KEY_ID
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_a_describe_key_failure_aborts_the_run(self) -> None:
        """
        A key whose type cannot be read is not read as customer-managed.

        Guessing either way is wrong: reading the policy would block the
        account over a key that may be AWS-managed, and skipping would drop
        a key that may grant a third party. The ClientError propagates.
        """
        mock_session, _ = self._one_key_client(
            ClientError({"Error": {"Code": "AccessDeniedException"}}, "DescribeKey")
        )

        with pytest.raises(ClientError):
            analyze_kms_key_policies(mock_session, {"111111111111"}, ORG_ID)
