"""
Tests for headroom.aws.ecr module.
"""

import pytest
from typing import Any
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.ecr import (
    analyze_ecr_repository_policies,
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
    _normalize_actions,
    UnknownPrincipalTypeError,
    UnsupportedPrincipalTypeError,
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
    """Test analyze_ecr_repository_policies function."""

    def test_successful_analysis(self) -> None:
        """Test successful ECR repository policy analysis."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

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

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_wildcard_principal_detection(self) -> None:
        """Test detection of wildcard principals."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_org_account_filtered_out(self) -> None:
        """Test organization accounts are filtered out."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

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

            import json
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

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 2
        regions_found = {r.region for r in results}
        assert regions_found == {"us-east-1", "us-west-2"}

    def test_mixed_third_party_and_org_accounts(self) -> None:
        """Test policy with both third-party and org accounts."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}

    def test_deny_statement_ignored(self) -> None:
        """Test that Deny statements are ignored."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_policy_with_no_principal(self) -> None:
        """Test that statements without principals are skipped."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_get_repository_policy_error(self) -> None:
        """Test that non-RepositoryPolicyNotFoundException errors are raised."""
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
            analyze_ecr_repository_policies(mock_session, org_account_ids)

    def test_ecr_client_error(self) -> None:
        """Test that ECR client errors during describe_repositories are raised."""
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

        error_response: Any = {"Error": {"Code": "AccessDeniedException"}}
        repository_paginator = MagicMock()
        repository_paginator.paginate.side_effect = ClientError(
            error_response, "DescribeRepositories"
        )

        mock_ecr_client.get_paginator.return_value = repository_paginator

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_ecr_repository_policies(mock_session, org_account_ids)

    def test_federated_principal_fails_fast(self) -> None:
        """Test that Federated principal causes immediate failure."""
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

        import json
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert "Federated" in str(exc_info.value)
        assert "would break if the RCP is deployed" in str(exc_info.value)
