"""
Tests for headroom.aws.ecr module.
"""

import json

import pytest
from typing import Any, List, Optional
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.ecr import (
    ECRPolicyAnalysis,
    analyze_ecr_policies,
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
    _normalize_actions,
    UnknownPrincipalTypeError,
    UnsupportedPrincipalTypeError,
)
from headroom.aws.policy_documents import MalformedPolicyError

ORG_ID = "o-example12345"


def _no_registry_policy(mock_ecr_client: MagicMock) -> None:
    """
    Configure a mock ECR client to report that its region has no registry policy.

    Every test not about registry policies needs this. An unconfigured
    MagicMock returns a Mock from get_registry_policy(), which the analyzer
    would hand to json.loads().
    """
    error_response: Any = {"Error": {"Code": "RegistryPolicyNotFoundException"}}
    mock_ecr_client.get_registry_policy.side_effect = ClientError(
        error_response, "GetRegistryPolicy"
    )


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn_string(self) -> None:
        """Test extracting account ID from ARN string."""
        principal = "arn:aws:iam::111111111111:root"
        account_ids = _extract_account_ids_from_principal(principal)
        assert account_ids == {"111111111111"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extracting from plain 12-digit account ID."""
        principal = "222222222222"
        account_ids = _extract_account_ids_from_principal(principal)
        assert account_ids == {"222222222222"}

    def test_extract_from_wildcard(self) -> None:
        """Test wildcard returns empty set."""
        principal = "*"
        account_ids = _extract_account_ids_from_principal(principal)
        assert account_ids == set()

    def test_extract_from_list(self) -> None:
        """Test extracting from list of principals."""
        principal = [
            "arn:aws:iam::111111111111:root",
            "222222222222",
            "arn:aws:iam::333333333333:user/test"
        ]
        account_ids = _extract_account_ids_from_principal(principal)
        assert account_ids == {"111111111111", "222222222222", "333333333333"}

    def test_extract_from_aws_dict(self) -> None:
        """Test extracting from AWS principal dict."""
        principal = {
            "AWS": [
                "arn:aws:iam::111111111111:root",
                "222222222222"
            ]
        }
        account_ids = _extract_account_ids_from_principal(principal)
        assert account_ids == {"111111111111", "222222222222"}

    def test_extract_from_service_principal(self) -> None:
        """Test service principal returns empty set."""
        principal = {"Service": "lambda.amazonaws.com"}
        account_ids = _extract_account_ids_from_principal(principal)
        assert account_ids == set()

    def test_unknown_principal_type_raises(self) -> None:
        """Test unknown principal type raises error."""
        principal = {"UnknownType": "something"}
        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            _extract_account_ids_from_principal(principal)
        assert "UnknownType" in str(exc_info.value)

    def test_federated_principal_raises(self) -> None:
        """Test federated principal raises UnsupportedPrincipalTypeError."""
        principal = {
            "Federated": "arn:aws:iam::111111111111:saml-provider/TestProvider"
        }
        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            _extract_account_ids_from_principal(principal)
        assert "Federated" in str(exc_info.value)
        assert "would break if the RCP is deployed" in str(exc_info.value)


class TestHasWildcardPrincipal:
    """Test _has_wildcard_principal function."""

    def test_wildcard_string(self) -> None:
        """Test wildcard string detection."""
        assert _has_wildcard_principal("*") is True

    def test_non_wildcard_string(self) -> None:
        """Test non-wildcard string."""
        assert _has_wildcard_principal("arn:aws:iam::111111111111:root") is False

    def test_wildcard_in_list(self) -> None:
        """Test wildcard in list."""
        principal = ["arn:aws:iam::111111111111:root", "*"]
        assert _has_wildcard_principal(principal) is True

    def test_wildcard_in_aws_dict(self) -> None:
        """Test wildcard in AWS principal dict."""
        principal = {"AWS": "*"}
        assert _has_wildcard_principal(principal) is True

    def test_wildcard_in_aws_list(self) -> None:
        """Test wildcard in AWS principal list."""
        principal = {"AWS": ["arn:aws:iam::111111111111:root", "*"]}
        assert _has_wildcard_principal(principal) is True

    def test_no_wildcard(self) -> None:
        """Test no wildcard present."""
        principal = {"AWS": "arn:aws:iam::111111111111:root"}
        assert _has_wildcard_principal(principal) is False


class TestNormalizeActions:
    """Test _normalize_actions function."""

    def test_string_action(self) -> None:
        """Test normalizing string action."""
        assert _normalize_actions("ecr:GetDownloadUrlForLayer") == ["ecr:GetDownloadUrlForLayer"]

    def test_list_actions(self) -> None:
        """Test normalizing list of actions."""
        actions = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        assert _normalize_actions(actions) == actions

    def test_none_action(self) -> None:
        """Test normalizing None."""
        assert _normalize_actions(None) == []

    def test_empty_list(self) -> None:
        """Test normalizing empty list."""
        assert _normalize_actions([]) == []


class TestAnalyzeECRRepositoryPolicies:
    """Test analyze_ecr_policies function."""

    def test_successful_analysis(self) -> None:
        """Test successful ECR repository policy analysis."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999999999999:root"
                    },
                    "Action": [
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage"
                    ]
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].repository_name == "test-repo"
        assert results[0].third_party_account_ids == {"999999999999"}
        assert "999999999999" in results[0].actions_by_account
        assert "ecr:GetDownloadUrlForLayer" in results[0].actions_by_account["999999999999"]
        assert "ecr:BatchGetImage" in results[0].actions_by_account["999999999999"]

    def test_repository_without_policy(self) -> None:
        """Test repository without policy is skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        from botocore.exceptions import ClientError
        error_response: Any = {"Error": {"Code": "RepositoryPolicyNotFoundException"}}
        mock_ecr_client.get_repository_policy.side_effect = ClientError(
            error_response, "GetRepositoryPolicy"
        )

        org_account_ids = {"111111111111"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_wildcard_principal_detection(self) -> None:
        """Test detection of wildcard principals."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "public-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/public-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_org_account_filtered_out(self) -> None:
        """Test organization accounts are filtered out."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "internal-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/internal-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::222222222222:root"
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_actions_deduplicated_per_account(self) -> None:
        """Ensure duplicate actions are not repeated for an account."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "dedup-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/dedup-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999999999999:root"
                    },
                    "Action": [
                        "ecr:BatchGetImage",
                        "ecr:BatchGetImage"
                    ]
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        actions = results[0].actions_by_account["999999999999"]
        assert actions == ["ecr:BatchGetImage"]

    def test_multiple_repositories_multiple_regions(self) -> None:
        """Test analysis across multiple repositories and regions."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        ecr_clients = {}
        for region in ["us-east-1", "us-west-2"]:
            mock_ecr_client = MagicMock()
            _no_registry_policy(mock_ecr_client)
            repository_paginator = MagicMock()
            repository_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": f"repo-{region}",
                            "repositoryArn": f"arn:aws:ecr:{region}:111111111111:repository/repo-{region}"
                        }
                    ]
                }
            ]
            mock_ecr_client.get_paginator.return_value = repository_paginator

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::999999999999:root"
                        },
                        "Action": "ecr:BatchGetImage"
                    }
                ]
            }

            mock_ecr_client.get_repository_policy.return_value = {
                "policyText": json.dumps(policy)
            }
            ecr_clients[region] = mock_ecr_client

        def client_side_effect(service: str, **kwargs: Any) -> object:
            if service == "ec2":
                return mock_ec2_client
            region = kwargs.get("region_name", "us-east-1")
            return ecr_clients.get(region)

        mock_session.client.side_effect = client_side_effect

        org_account_ids = {"111111111111"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 2
        regions_found = {r.region for r in results}
        assert regions_found == {"us-east-1", "us-west-2"}

    def test_mixed_third_party_and_org_accounts(self) -> None:
        """Test policy with both third-party and org accounts."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "mixed-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/mixed-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::222222222222:root",
                            "arn:aws:iam::999999999999:root"
                        ]
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}

    def test_deny_statement_ignored(self) -> None:
        """Test that Deny statements are ignored."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": "arn:aws:iam::999999999999:root"
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_policy_with_no_principal(self) -> None:
        """Test that statements without principals are skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_get_repository_policy_error(self) -> None:
        """Test that non-RepositoryPolicyNotFoundException errors are raised."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        error_response: Any = {"Error": {"Code": "AccessDeniedException"}}
        mock_ecr_client.get_repository_policy.side_effect = ClientError(
            error_response, "GetRepositoryPolicy"
        )

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

    def test_ecr_client_error(self) -> None:
        """Test that ECR client errors during describe_repositories are raised."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        error_response: Any = {"Error": {"Code": "AccessDeniedException"}}
        repository_paginator = MagicMock()
        repository_paginator.paginate.side_effect = ClientError(
            error_response, "DescribeRepositories"
        )

        mock_ecr_client.get_paginator.return_value = repository_paginator

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

    def test_federated_principal_fails_fast(self) -> None:
        """Test that Federated principal causes immediate failure."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "federated-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/federated-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::111111111111:saml-provider/TestProvider"
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert "Federated" in str(exc_info.value)
        assert "would break if the RCP is deployed" in str(exc_info.value)


class TestPolicyGrammar:
    """Policy elements the repository analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        return analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_lone_statement_object_is_analyzed(self) -> None:
        """The third party in a lone statement object is found, not missed."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "ecr:BatchGetImage"
            }
        })

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == ["ecr:BatchGetImage"]

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
                "Action": "ecr:BatchGetImage"
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
                "Action": "ecr:BatchGetImage"
            }
        })

        assert results == []

    def test_guarded_service_principal_is_recorded(self) -> None:
        """
        A repository policy pinning a third-party source records it.

        The account reaches the allowlist through the confused deputy
        check, not through this analysis's third_party_account_ids.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "ecr:BatchGetImage",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "999999999999"}
                },
            }],
        })

        assert len(results[0].service_principal_sources) == 1
        source = results[0].service_principal_sources[0]
        assert source.service_principal == "sns.amazonaws.com"
        assert source.source_account_ids == ["999999999999"]

    def test_a_policy_with_no_service_principal_records_nothing(self) -> None:
        """The field stays empty when no statement names a service."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "ecr:BatchGetImage",
            }],
        })

        assert results[0].service_principal_sources == []


class TestRegistryPolicy:
    """
    The registry policy, which AWS enforces on every ECR request in the region.

    A repository policy governs one repository. A registry policy governs the
    whole registry, so a third party named in one reaches every repository the
    region holds - and reaches them without any repository policy saying so.
    """

    ORG_ACCOUNT = "111111111111"
    THIRD_PARTY = "999999999999"

    @staticmethod
    def _policy(principal: Any, action: Any = "ecr:BatchGetImage") -> Any:
        """
        Build a one-statement Allow policy.

        Args:
            principal: Principal field for the statement
            action: Action field for the statement

        Returns:
            A policy document
        """
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": principal, "Action": action}
            ],
        }

    @staticmethod
    def _analyze(
        registry_policy: Any = None,
        repositories: Optional[List[Any]] = None,
        repository_policy: Any = None,
        registry_error: Optional[str] = None,
    ) -> List[ECRPolicyAnalysis]:
        """
        Run the analyzer over a single region.

        Args:
            registry_policy: Registry policy document, or None for a registry
                that carries no policy
            repositories: Repositories the region holds - empty by default, so
                that any result can only have come from the registry policy
            repository_policy: Policy returned for those repositories, or None
                for repositories that carry no policy
            registry_error: AWS error code get_registry_policy should raise
                instead of returning, which takes precedence over
                registry_policy

        Returns:
            The analyzer's results for the region
        """
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [{"repositories": repositories or []}]
        mock_ecr_client.get_paginator.return_value = paginator

        if repository_policy is None:
            missing_repository_policy: Any = {
                "Error": {"Code": "RepositoryPolicyNotFoundException"}
            }
            mock_ecr_client.get_repository_policy.side_effect = ClientError(
                missing_repository_policy, "GetRepositoryPolicy"
            )
        else:
            mock_ecr_client.get_repository_policy.return_value = {
                "policyText": json.dumps(repository_policy)
            }

        if registry_error is not None:
            failure: Any = {"Error": {"Code": registry_error}}
            mock_ecr_client.get_registry_policy.side_effect = ClientError(
                failure, "GetRegistryPolicy"
            )
        elif registry_policy is None:
            _no_registry_policy(mock_ecr_client)
        else:
            mock_ecr_client.get_registry_policy.return_value = {
                "policyText": json.dumps(registry_policy)
            }

        return analyze_ecr_policies(
            mock_session, {TestRegistryPolicy.ORG_ACCOUNT}, ORG_ID
        )

    def test_third_party_in_registry_policy_is_found(self) -> None:
        """A third party named only here still reaches the allowlist."""
        results = self._analyze(
            registry_policy=self._policy(
                {"AWS": f"arn:aws:iam::{self.THIRD_PARTY}:root"}
            )
        )

        assert len(results) == 1
        assert results[0].scope == "registry"
        assert results[0].third_party_account_ids == {self.THIRD_PARTY}

    def test_registry_policy_names_no_repository(self) -> None:
        """A registry policy is not a repository, so it reports none."""
        results = self._analyze(
            registry_policy=self._policy(
                {"AWS": f"arn:aws:iam::{self.THIRD_PARTY}:root"}
            )
        )

        assert results[0].repository_name is None
        assert results[0].repository_arn is None
        assert results[0].region == "us-east-1"

    def test_replication_actions_are_recorded_like_any_other(self) -> None:
        """
        Replication grants are reported, not special-cased.

        Deciding a grant is replication-only means inferring that the caller
        will be the ECR service-linked role, which the analyzer never observes.
        """
        results = self._analyze(
            registry_policy=self._policy(
                {"AWS": f"arn:aws:iam::{self.THIRD_PARTY}:root"},
                ["ecr:ReplicateImage", "ecr:CreateRepository"],
            )
        )

        assert results[0].actions_by_account[self.THIRD_PARTY] == [
            "ecr:CreateRepository",
            "ecr:ReplicateImage",
        ]

    def test_absent_registry_policy_reports_nothing(self) -> None:
        """A registry that carries no policy contributes no result."""
        assert self._analyze(registry_policy=None) == []

    def test_registry_policy_naming_only_org_accounts_reports_nothing(self) -> None:
        """An in-org grant is not third-party access."""
        results = self._analyze(
            registry_policy=self._policy(
                {"AWS": f"arn:aws:iam::{self.ORG_ACCOUNT}:root"}
            )
        )

        assert results == []

    def test_wildcard_registry_policy_is_flagged(self) -> None:
        """A wildcard here reaches everyone, across every repository at once."""
        results = self._analyze(registry_policy=self._policy({"AWS": "*"}))

        assert len(results) == 1
        assert results[0].scope == "registry"
        assert results[0].has_wildcard_principal is True

    def test_registry_policy_error_propagates(self) -> None:
        """An error other than a missing policy aborts rather than reporting nothing."""
        with pytest.raises(ClientError):
            self._analyze(registry_error="AccessDeniedException")

    def test_repository_and_registry_are_reported_separately(self) -> None:
        """The two surfaces are separate resources, so each gets its own row."""
        results = self._analyze(
            registry_policy=self._policy(
                {"AWS": f"arn:aws:iam::{self.THIRD_PARTY}:root"}
            ),
            repositories=[
                {
                    "repositoryName": "test-repo",
                    "repositoryArn": (
                        f"arn:aws:ecr:us-east-1:{self.ORG_ACCOUNT}"
                        ":repository/test-repo"
                    ),
                }
            ],
            repository_policy=self._policy({"AWS": "arn:aws:iam::888888888888:root"}),
        )

        by_scope = {result.scope: result for result in results}

        assert set(by_scope) == {"registry", "repository"}
        assert by_scope["registry"].third_party_account_ids == {self.THIRD_PARTY}
        assert by_scope["repository"].third_party_account_ids == {"888888888888"}
        assert by_scope["repository"].repository_name == "test-repo"
