"""
Tests for headroom.aws.secretsmanager module.
"""

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)
from headroom.aws.secretsmanager import (
    _analyze_secret_policy,
    analyze_secrets_manager_policies,
)
from headroom.types import JsonDict
from tests.constants import ORG_ID


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
            org_account_ids,
            ORG_ID
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
            org_account_ids,
            ORG_ID
        )

        assert result is not None
        assert result.has_wildcard_principal is True

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal grants to everyone it does not name.

        Skipping the statement for want of a Principal reported the secret
        clean, so the account kept its RCP and the grant's real audience -
        every account outside the exclusion list - lost access on apply.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }

        result = _analyze_secret_policy(
            "shared-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:shared-secret",
            policy,  # type: ignore[arg-type]
            {"111111111111"},
            ORG_ID
        )

        assert result is not None
        assert result.has_wildcard_principal is True
        assert result.third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a resource policy's Deny cannot
        hand access to anyone, so it must not block the RCP.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }

        result = _analyze_secret_policy(
            "shared-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:shared-secret",
            policy,  # type: ignore[arg-type]
            {"111111111111"},
            ORG_ID
        )

        assert result is None

    def test_a_federated_principal_blocks_the_secret_rather_than_the_run(self) -> None:
        """
        A Federated principal blocks the account rather than aborting the run.

        No allowlist entry can stand for a federated identity, so the secret
        cannot be cleared. Aborting instead would have cost every other
        account in the organization its results over this one secret.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::666666666666:saml-provider/Provider"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        analysis = _analyze_secret_policy(
            "federated-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:federated-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids,
            ORG_ID,
        )

        assert analysis is not None
        assert analysis.has_non_account_principals is True

    def test_a_canonical_user_blocks_the_secret_rather_than_the_run(self) -> None:
        """
        A canonical user ID maps to no account the allowlist can carry.

        Blocks the account for the same reason a Federated principal does,
        and for the same reason does not abort.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"CanonicalUser": "d" * 64},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        analysis = _analyze_secret_policy(
            "canonical-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:canonical-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids,
            ORG_ID,
        )

        assert analysis is not None
        assert analysis.has_non_account_principals is True

    def test_a_principal_key_aws_does_not_document_aborts(self) -> None:
        """
        An undocumented principal key still stops the run.

        AWS validates the Principal element when PutResourcePolicy stores the
        document, so a key outside the documented four means the policy was
        misread or names a principal type nobody has modelled here.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Kerberos": "example"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }

        with pytest.raises(UnknownPrincipalTypeError):
            _analyze_secret_policy(
                "odd-secret",
                "arn:aws:secretsmanager:us-east-1:111111111111:secret:odd-secret",
                policy,  # type: ignore[arg-type]
                {"111111111111"},
                ORG_ID,
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
            org_account_ids,
            ORG_ID
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
            org_account_ids,
            ORG_ID
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
            org_account_ids,
            ORG_ID
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
            org_account_ids,
            ORG_ID
        )

        assert result is None

    def test_action_as_dict_raises_type_error(self) -> None:
        """Test that action as dict raises TypeError (fail fast)."""
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

        with pytest.raises(TypeError, match="Unexpected action type: dict"):
            _analyze_secret_policy(
                "dict-action-secret",
                "arn:aws:secretsmanager:us-east-1:111111111111:secret:dict-action-secret",
                policy,  # type: ignore[arg-type]
                org_account_ids,
                ORG_ID,
            )

    def test_lone_statement_object_is_analyzed(self) -> None:
        """
        Test that a policy whose Statement is one object, not a list, is read.

        IAM accepts a lone statement object in place of a one-element list,
        and Secrets Manager hands the policy back the way it was stored. A
        secret shared this way must not be reported as having no third-party
        access.
        """
        policy: JsonDict = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "ShareWithVendor",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            },
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "vendor-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:vendor-secret",
            policy,
            org_account_ids,
            ORG_ID
        )

        assert result is not None
        assert result.third_party_account_ids == {"999999999999"}
        assert result.actions_by_account == {
            "999999999999": {"secretsmanager:GetSecretValue"}
        }

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """
        Test that a Statement that is neither an object nor a list aborts.

        Skipping it would report the secret as having no third-party access,
        which is the one answer that must never be guessed.
        """
        policy = {
            "Statement": "invalid"
        }
        org_account_ids = {"111111111111"}

        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            _analyze_secret_policy(
                "invalid-statement-secret",
                "arn:aws:secretsmanager:us-east-1:111111111111:secret:invalid-statement-secret",
                policy,  # type: ignore[arg-type]
                org_account_ids,
                ORG_ID,
            )

    def test_guarded_service_principal_is_recorded(self) -> None:
        """
        A secret policy pinning a third-party source records it.

        The account reaches the allowlist through the confused deputy
        check, not through this analysis's third_party_account_ids.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "secretsmanager:GetSecretValue",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": "999999999999"}
                    },
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "guarded-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:guarded-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids,
            ORG_ID
        )

        assert result is not None
        assert len(result.service_principal_sources) == 1
        source = result.service_principal_sources[0]
        assert source.service_principal == "sns.amazonaws.com"
        assert source.source_account_ids == ["999999999999"]

        # The source is inert here: it belongs to deny_service_confused_deputy,
        # and folding it into these fields would widen this check's allowlist
        # with an account that drives a service call rather than making one.
        assert result.third_party_account_ids == set()
        assert result.has_wildcard_principal is False

    def test_wildcard_service_principal_source_is_recorded(self) -> None:
        """
        A secret policy whose only source guard is a wildcard is still surfaced.

        aws:SourceAccount: "*" pins no single account, so no allowlist can
        express it. That is the case has_actionable_service_principal_source's
        wildcard arm exists to catch, distinct from the concrete-account arm
        the guarded test above already covers.
        """
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "secretsmanager:GetSecretValue",
                    "Condition": {
                        "StringLike": {"aws:SourceAccount": "*"}
                    },
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "wildcard-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:wildcard-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids,
            ORG_ID
        )

        assert result is not None
        assert len(result.service_principal_sources) == 1
        source = result.service_principal_sources[0]
        assert source.has_wildcard_source is True
        assert source.source_account_ids == []

    def test_a_policy_with_no_service_principal_records_nothing(self) -> None:
        """The field stays empty when no statement names a service."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        org_account_ids = {"111111111111"}

        result = _analyze_secret_policy(
            "unguarded-secret",
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:unguarded-secret",
            policy,  # type: ignore[arg-type]
            org_account_ids,
            ORG_ID
        )

        assert result is not None
        assert result.service_principal_sources == []


class TestAnalyzeSecretsManagerPolicies:
    """Test full Secrets Manager policy analysis."""

    def test_an_unparseable_policy_aborts_the_run(self) -> None:
        """
        A document AWS could not have stored means Headroom misread it.

        Recording the secret as clean would let the RCP deploy over whatever
        the policy actually grants, which is INV-01's case. The surrounding
        except catches ClientError only, so the JSONDecodeError passes it.
        """
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
            {"SecretList": [{
                "Name": "test-secret",
                "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:test-secret",
            }]}
        ]
        mock_sm_client.get_paginator.return_value = paginator
        mock_sm_client.get_resource_policy.return_value = {"ResourcePolicy": "{not json"}

        with pytest.raises(json.JSONDecodeError):
            analyze_secrets_manager_policies(mock_session, {"111111111111"}, ORG_ID)

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
        results = analyze_secrets_manager_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_secrets_manager_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_secrets_manager_policies(mock_session, org_account_ids, ORG_ID)

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
            analyze_secrets_manager_policies(mock_session, org_account_ids, ORG_ID)
