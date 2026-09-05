"""
Tests for headroom.aws.ecr module.
"""

import json

import pytest
from typing import Any, Dict, List, Optional, Sequence
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.ecr import (
    ECRPolicyAnalysis,
    _analyze_policy_statements,
    analyze_ecr_policies,
)
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)
from headroom.types import JsonDict
from tests.constants import ORG_ID

# What analyze_ecr_policies passes _analyze_policy_statements for the
# repository these tests build. It reaches an error message and nothing else,
# so it matters only that a test reading the policy directly names the same
# repository the mocked adapter was given.
REPOSITORY_CONTEXT = "Repository 'test-repo' in us-east-1"


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


class TestAnalyzeECRRepositoryPolicies:
    """Test analyze_ecr_policies function."""

    def test_an_unparseable_policy_aborts_the_run(self) -> None:
        """
        A document AWS could not have stored means Headroom misread it.

        Recording the repository as clean would let the RCP deploy over
        whatever the policy actually grants, which is INV-01's case. The
        analyzer catches nothing here, so the JSONDecodeError ends the run.
        """
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
            {"repositories": [{
                "repositoryName": "test-repo",
                "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo",
            }]}
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator
        mock_ecr_client.get_repository_policy.return_value = {"policyText": "{not json"}

        with pytest.raises(json.JSONDecodeError):
            analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_a_response_without_policy_text_aborts_the_run(self) -> None:
        """
        A 200 response always carries policyText, because a missing policy is
        an exception, not an empty response.

        A response missing it means Headroom misread the API, not that the
        repository carries no policy - AWS signals that case with
        RepositoryPolicyNotFoundException, not an empty response. Defaulting to
        "{}" here would report the repository as clean on a policy nobody read,
        which is INV-01's case, so a missing key raises KeyError instead.
        """
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
            {"repositories": [{
                "repositoryName": "test-repo",
                "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo",
            }]}
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator
        mock_ecr_client.get_repository_policy.return_value = {}

        with pytest.raises(KeyError, match="policyText"):
            analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

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

        policy: JsonDict = {
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
        findings = _analyze_policy_statements(
            policy, "Repository 'internal-repo' in us-east-1", org_account_ids, ORG_ID
        )

        # Reporting nothing is also what a policy nobody read looks like, so
        # the fetch is asserted and the reading is taken directly: the
        # account was read and then filtered as in-organization, not missed.
        assert len(results) == 0
        mock_ecr_client.get_repository_policy.assert_called_once()
        assert findings.third_party_account_ids == set()
        assert findings.has_wildcard_principal is False

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

        policy: JsonDict = {
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
        findings = _analyze_policy_statements(
            policy, REPOSITORY_CONTEXT, org_account_ids, ORG_ID
        )

        # Reporting nothing is also what a policy nobody read looks like, so
        # the fetch is asserted and the reading is taken directly: the Deny
        # was read and passed over, not skipped for want of a policy.
        assert len(results) == 0
        mock_ecr_client.get_repository_policy.assert_called_once()
        assert findings.third_party_account_ids == set()
        assert findings.has_wildcard_principal is False

    def test_a_statement_with_no_principal_aborts_the_run(self) -> None:
        """
        An Allow carrying neither Principal nor NotPrincipal is a document AWS never stored.

        The analyzer once skipped it with a read of its own; the shared
        statement reader raises instead. Both entry points are driven, so
        the raise is shown to come from the statement walk rather than
        from the fetch around it.
        """
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

        policy: JsonDict = {
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

        with pytest.raises(MalformedPolicyError, match="has an Allow statement carrying neither"):
            analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)
        mock_ecr_client.get_repository_policy.assert_called_once()

        with pytest.raises(MalformedPolicyError, match="has an Allow statement carrying neither"):
            _analyze_policy_statements(policy, REPOSITORY_CONTEXT, org_account_ids, ORG_ID)

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

    def test_a_federated_principal_blocks_the_repository_rather_than_the_run(self) -> None:
        """
        A Federated principal carries no account ID the allowlist can hold.

        The RCP restricts on aws:PrincipalAccount, which cannot express a
        Federated principal, so the repository blocks the account for this
        check and the other accounts' scans still finish.
        """
        mock_session, mock_ecr_client = self._single_region_session()

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

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::111111111111:saml-provider/Example"
                        },
                        "Action": "ecr:*"
                    }
                ]
            })
        }

        results = analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    def test_a_canonical_user_blocks_the_repository_rather_than_the_run(self) -> None:
        """A canonical user ID maps to no account the allowlist can carry."""
        mock_session, mock_ecr_client = self._single_region_session()

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "canonical-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/canonical-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"CanonicalUser": "d" * 64},
                        "Action": "ecr:*"
                    }
                ]
            })
        }

        results = analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    def test_a_principal_key_aws_does_not_document_aborts(self) -> None:
        """
        An undocumented principal key still stops the run.

        AWS validates the Principal element when it stores a repository
        policy, so a key outside the documented four means the document was
        misread or names a principal type nobody has modelled here.
        """
        mock_session, mock_ecr_client = self._single_region_session()

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "odd-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/odd-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Kerberos": "example"},
                        "Action": "ecr:*"
                    }
                ]
            })
        }

        with pytest.raises(UnknownPrincipalTypeError):
            analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

    @staticmethod
    def _single_region_session() -> tuple[MagicMock, MagicMock]:
        """Build a session mock wired to one region and return (session, ecr_client)."""
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
        _no_registry_policy(mock_ecr_client)
        return mock_session, mock_ecr_client

    def test_a_second_caller_is_served_from_the_memo(self) -> None:
        """
        `deny_service_confused_deputy` re-reads what the ECR check just read.

        Both checks run against one account's session, back to back, and this
        analyzer sweeps every enabled region. Reading the repositories twice
        costs the account a second full sweep for policies that cannot have
        changed between two checks of the same run.

        The counts come from the client, not from the memo: a decorator that
        stopped being applied would leave every other ECR test green and show
        up only here.
        """
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()
        _no_registry_policy(mock_ecr_client)

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo",
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": ["ecr:BatchGetImage"],
                    }
                ],
            })
        }

        org_account_ids = {"111111111111"}

        first = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)
        second = analyze_ecr_policies(mock_session, org_account_ids, ORG_ID)

        assert first == second
        assert mock_ec2_client.describe_regions.call_count == 1
        assert mock_ecr_client.get_repository_policy.call_count == 2


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

        results = analyze_ecr_policies(mock_session, {"111111111111"}, ORG_ID)

        # Every test in this class may assert that nothing was reported, and
        # a policy nobody read reports nothing too. The fetch is asserted
        # here so that no test in the class can pass without one.
        mock_ecr_client.get_repository_policy.assert_called_once()

        return results

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

        Dropping out is also what a policy nobody read looks like, so the
        same document goes through _analyze_policy_statements directly,
        ahead of the reporting gate, and the reading itself is asserted.
        """
        policy: JsonDict = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "ecr:BatchGetImage"
            }
        }

        results = self._analyze(policy)
        findings = _analyze_policy_statements(
            policy, REPOSITORY_CONTEXT, {"111111111111"}, ORG_ID
        )

        assert results == []
        assert findings.has_wildcard_principal is False
        assert findings.third_party_account_ids == set()

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
                "Action": "ecr:BatchGetImage",
            }],
        })

        assert results[0].service_principal_sources == []

    def test_a_wildcard_confined_to_a_third_party_account_is_allowlisted(self) -> None:
        """
        The account the condition names reaches the allowlist, not the wildcard flag.

        Dropping the wildcard without recording the account would generate
        an RCP that denies the very access this statement grants.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ecr:BatchGetImage",
                "Condition": {
                    "StringEquals": {"aws:PrincipalAccount": ["333333333333"]}
                },
            }],
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is False
        assert results[0].third_party_account_ids == {"333333333333"}
        assert results[0].actions_by_account["333333333333"] == ["ecr:BatchGetImage"]
        assert results[0].confined_by == {"aws:principalaccount"}

    def test_a_wildcard_confined_to_this_organization_names_nobody(self) -> None:
        """
        aws:PrincipalOrgID admits only callers the RCP already spares.

        The bound is real, so the wildcard falls, and every caller it admits
        is inside the organization, so there is no account to allowlist. The
        repository is left with nothing an RCP could break and drops out of
        the results, where before it blocked the account's whole ECR RCP.

        Dropping out is also what a policy nobody read looks like, so the
        same document goes through _analyze_policy_statements directly, ahead
        of the reporting gate, and the reading itself is asserted.
        """
        policy: JsonDict = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ecr:BatchGetImage",
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": ORG_ID}
                },
            }],
        }

        results = self._analyze(policy)
        findings = _analyze_policy_statements(
            policy, REPOSITORY_CONTEXT, {"111111111111"}, ORG_ID
        )

        assert results == []
        assert findings.has_wildcard_principal is False
        assert findings.confined_by == {"aws:principalorgid"}

    def test_a_wildcard_under_kms_caller_account_is_still_a_wildcard(self) -> None:
        """
        kms:CallerAccount bounds a KMS key policy and nothing else.

        No Amazon ECR request carries the key, so the clause admits nobody
        and the statement grants nobody anything. Reading it as a bound
        would clear the repository and put an account no policy granted
        into the allowlist, so this pins the PolicyService this analyzer
        declares: passing PolicyService.KMS from here reads the clause as a
        bound.

        The value is a well-formed twelve-digit account ID on purpose: a
        value the reader would reject anyway proves only that some rule
        refused the shape, not that the service is what refused it.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "ecr:GetDownloadUrlForLayer",
                "Condition": {
                    "StringEquals": {"kms:CallerAccount": "333333333333"}
                },
            }],
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()
        assert results[0].confined_by == set()


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
        registry_response: Optional[Dict[str, str]] = None,
    ) -> Sequence[ECRPolicyAnalysis]:
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
            registry_response: Raw get_registry_policy() response to return
                verbatim, taking precedence over both registry_error and
                registry_policy - for a response shaped unlike any real one,
                such as one missing policyText entirely

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

        if registry_response is not None:
            mock_ecr_client.get_registry_policy.return_value = registry_response
        elif registry_error is not None:
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

    def test_a_registry_response_without_policy_text_aborts_the_run(self) -> None:
        """
        A 200 response always carries policyText, because a missing policy is
        an exception, not an empty response.

        A response missing it means Headroom misread the API, not that the
        registry carries no policy - AWS signals that case with
        RegistryPolicyNotFoundException, not an empty response. Defaulting to
        "{}" here would report the registry as clean on a policy nobody read,
        which is INV-01's case, so a missing key raises KeyError instead.
        """
        with pytest.raises(KeyError, match="policyText"):
            self._analyze(registry_response={})

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
