"""
Tests for headroom.aws.aoss module.
"""

import json
from typing import Dict, List, Set
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from headroom.aws.aoss import (
    AossResourcePolicyAnalysis,
    _analyze_access_policy,
    _extract_account_ids_from_principals,
    analyze_aoss_resource_policies,
)


class TestExtractAccountIdsFromPrincipals:
    """Test _extract_account_ids_from_principals function."""

    def test_extract_from_arn_format(self) -> None:
        """Test extracting account ID from ARN format."""
        principals = ["arn:aws:iam::999888777666:root"]
        result = _extract_account_ids_from_principals(principals)
        assert result == {"999888777666"}

    def test_extract_from_arn_with_user(self) -> None:
        """Test extracting account ID from ARN with user path."""
        principals = ["arn:aws:iam::111222333444:user/service-account"]
        result = _extract_account_ids_from_principals(principals)
        assert result == {"111222333444"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extracting plain 12-digit account ID."""
        principals = ["555666777888"]
        result = _extract_account_ids_from_principals(principals)
        assert result == {"555666777888"}

    def test_extract_multiple_principals(self) -> None:
        """Test extracting from multiple principals."""
        principals = [
            "arn:aws:iam::999888777666:root",
            "arn:aws:iam::111222333444:user/test",
            "555666777888",
        ]
        result = _extract_account_ids_from_principals(principals)
        assert result == {"999888777666", "111222333444", "555666777888"}

    def test_extract_duplicate_accounts(self) -> None:
        """Test that duplicate accounts are deduplicated."""
        principals = [
            "arn:aws:iam::999888777666:root",
            "arn:aws:iam::999888777666:user/test",
            "999888777666",
        ]
        result = _extract_account_ids_from_principals(principals)
        assert result == {"999888777666"}

    def test_extract_empty_list(self) -> None:
        """Test extracting from empty list."""
        principals: List[str] = []
        result = _extract_account_ids_from_principals(principals)
        assert result == set()

    def test_extract_invalid_principal(self) -> None:
        """Test extracting from invalid principal format."""
        principals = ["not-an-arn", "12345", "invalid"]
        result = _extract_account_ids_from_principals(principals)
        assert result == set()


class TestAnalyzeAccessPolicy:
    """Test _analyze_access_policy function."""

    def test_analyze_simple_policy_with_third_party(self) -> None:
        """Test analyzing policy with single third-party account."""
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "Permission": ["aoss:ReadDocument", "aoss:WriteDocument"],
                "ResourceType": "collection",
            }],
            "Principal": ["arn:aws:iam::999888777666:root"],
        }])

        org_account_ids = {"111111111111", "222222222222"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 1
        assert results[0].resource_name == "test-collection"
        assert results[0].resource_type == "collection"
        assert results[0].third_party_account_ids == {"999888777666"}
        assert results[0].allowed_actions == ["aoss:ReadDocument", "aoss:WriteDocument"]
        assert "arn:aws:aoss:us-east-1:111111111111:collection/test-collection" in results[0].resource_arn

    def test_analyze_policy_with_multiple_third_parties(self) -> None:
        """Test analyzing policy with multiple third-party accounts."""
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "Permission": ["aoss:ReadDocument"],
                "ResourceType": "collection",
            }],
            "Principal": [
                "arn:aws:iam::999888777666:root",
                "arn:aws:iam::111222333444:root",
            ],
        }])

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-west-2",
            account_id="111111111111",
        )

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999888777666", "111222333444"}

    def test_analyze_policy_with_index_resources(self) -> None:
        """Test analyzing policy with index resources."""
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": ["index/test-collection/*"],
                "Permission": ["aoss:CreateIndex", "aoss:UpdateIndex"],
                "ResourceType": "index",
            }],
            "Principal": ["arn:aws:iam::999888777666:root"],
        }])

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 1
        assert results[0].resource_name == "test-collection"
        assert results[0].resource_type == "index"

    def test_analyze_policy_with_org_accounts_only(self) -> None:
        """Test analyzing policy with only org accounts (no third-party)."""
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "Permission": ["aoss:ReadDocument"],
                "ResourceType": "collection",
            }],
            "Principal": [
                "arn:aws:iam::111111111111:root",
                "arn:aws:iam::222222222222:root",
            ],
        }])

        org_account_ids = {"111111111111", "222222222222"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 0

    def test_analyze_policy_with_multiple_rules(self) -> None:
        """Test analyzing policy with multiple rules."""
        policy_doc = json.dumps([{
            "Rules": [
                {
                    "Resource": ["collection/collection-1"],
                    "Permission": ["aoss:ReadDocument"],
                    "ResourceType": "collection",
                },
                {
                    "Resource": ["index/collection-1/*"],
                    "Permission": ["aoss:WriteDocument"],
                    "ResourceType": "index",
                },
            ],
            "Principal": ["arn:aws:iam::999888777666:root"],
        }])

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 2
        assert results[0].resource_type == "collection"
        assert results[1].resource_type == "index"

    def test_analyze_policy_with_multiple_resources(self) -> None:
        """Test analyzing policy with multiple resources in one rule."""
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": [
                    "collection/collection-1",
                    "collection/collection-2",
                ],
                "Permission": ["aoss:ReadDocument"],
                "ResourceType": "collection",
            }],
            "Principal": ["arn:aws:iam::999888777666:root"],
        }])

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 2
        resource_names = {r.resource_name for r in results}
        assert resource_names == {"collection-1", "collection-2"}

    def test_analyze_policy_invalid_json(self) -> None:
        """Test analyzing policy with invalid JSON."""
        policy_doc = "not valid json"

        org_account_ids = {"111111111111"}
        with pytest.raises(json.JSONDecodeError):
            _analyze_access_policy(
                policy_name="test-policy",
                policy_document=policy_doc,
                org_account_ids=org_account_ids,
                region="us-east-1",
                account_id="111111111111",
            )

    def test_analyze_policy_not_a_list(self) -> None:
        """Test analyzing policy that is not a list."""
        policy_doc = json.dumps({"key": "value"})

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 0

    def test_analyze_policy_empty_principals(self) -> None:
        """Test analyzing policy with empty principals."""
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "Permission": ["aoss:ReadDocument"],
                "ResourceType": "collection",
            }],
            "Principal": [],
        }])

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 0


class TestAnalyzeAossResourcePolicies:
    """Test analyze_aoss_resource_policies function."""

    def test_analyze_successful_with_policies(self) -> None:
        """Test successful analysis with AOSS policies."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_aoss_client = MagicMock()
        mock_sts_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "opensearchserverless": mock_aoss_client,
            "sts": mock_sts_client,
        }[service]

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}],
        }

        # Mock STS get_caller_identity
        mock_sts_client.get_caller_identity.return_value = {
            "Account": "111111111111",
        }

        # Mock access policies list
        policy_paginator = MagicMock()
        policy_paginator.paginate.return_value = [{
            "accessPolicySummaries": [
                {"name": "test-policy"},
            ],
        }]
        mock_aoss_client.get_paginator.return_value = policy_paginator

        # Mock get_access_policy
        policy_doc = json.dumps([{
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "Permission": ["aoss:ReadDocument"],
                "ResourceType": "collection",
            }],
            "Principal": ["arn:aws:iam::999888777666:root"],
        }])

        mock_aoss_client.get_access_policy.return_value = {
            "accessPolicyDetail": {
                "policy": policy_doc,
            },
        }

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].resource_name == "test-collection"
        assert results[0].third_party_account_ids == {"999888777666"}

    def test_analyze_empty_policies(self) -> None:
        """Test analysis with no access policies."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_aoss_client = MagicMock()
        mock_sts_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "opensearchserverless": mock_aoss_client,
            "sts": mock_sts_client,
        }[service]

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}],
        }

        # Mock STS
        mock_sts_client.get_caller_identity.return_value = {
            "Account": "111111111111",
        }

        # Mock empty access policies
        policy_paginator = MagicMock()
        policy_paginator.paginate.return_value = [{
            "accessPolicySummaries": [],
        }]
        mock_aoss_client.get_paginator.return_value = policy_paginator

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_multiple_regions(self) -> None:
        """Test analysis across multiple regions."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sts_client = MagicMock()

        # Track AOSS client calls per region
        aoss_clients: Dict[str, MagicMock] = {}

        def get_client(service: str, region_name: str = None, **kwargs: object) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            if service == "sts":
                return mock_sts_client
            if service == "opensearchserverless":
                if region_name not in aoss_clients:
                    aoss_clients[region_name] = MagicMock()
                return aoss_clients[region_name]
            raise ValueError(f"Unexpected service: {service}")

        mock_session.client.side_effect = get_client

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"},
            ],
        }

        # Mock STS
        mock_sts_client.get_caller_identity.return_value = {
            "Account": "111111111111",
        }

        # Setup each region's AOSS client
        for region in ["us-east-1", "us-west-2"]:
            policy_paginator = MagicMock()
            policy_paginator.paginate.return_value = [{
                "accessPolicySummaries": [],
            }]
            aoss_clients[region].get_paginator.return_value = policy_paginator

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Verify both regions were called
        assert len(aoss_clients) == 2
        assert "us-east-1" in aoss_clients
        assert "us-west-2" in aoss_clients
        assert len(results) == 0

    def test_analyze_region_not_supported(self) -> None:
        """Test handling of region where AOSS is not available."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_aoss_client = MagicMock()
        mock_sts_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "opensearchserverless": mock_aoss_client,
            "sts": mock_sts_client,
        }[service]

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "ap-southeast-3"}],
        }

        # Mock STS
        mock_sts_client.get_caller_identity.return_value = {
            "Account": "111111111111",
        }

        # Mock AOSS not available error
        policy_paginator = MagicMock()
        error_response = {
            "Error": {"Code": "UnrecognizedClientException"},
        }
        policy_paginator.paginate.side_effect = ClientError(
            error_response,
            "list_access_policies",
        )
        mock_aoss_client.get_paginator.return_value = policy_paginator

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Should handle gracefully and return empty results
        assert len(results) == 0

    def test_analyze_policy_not_found(self) -> None:
        """Test handling of policy not found error."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_aoss_client = MagicMock()
        mock_sts_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "opensearchserverless": mock_aoss_client,
            "sts": mock_sts_client,
        }[service]

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}],
        }

        # Mock STS
        mock_sts_client.get_caller_identity.return_value = {
            "Account": "111111111111",
        }

        # Mock access policies list
        policy_paginator = MagicMock()
        policy_paginator.paginate.return_value = [{
            "accessPolicySummaries": [
                {"name": "test-policy"},
            ],
        }]
        mock_aoss_client.get_paginator.return_value = policy_paginator

        # Mock get_access_policy with ResourceNotFoundException
        error_response = {
            "Error": {"Code": "ResourceNotFoundException"},
        }
        mock_aoss_client.get_access_policy.side_effect = ClientError(
            error_response,
            "get_access_policy",
        )

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Should handle gracefully and return empty results
        assert len(results) == 0
