"""
Tests for headroom.aws.aoss module.
"""

import json
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from headroom.aws.aoss import (
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

    def test_analyze_policy_with_non_dict_statement(self) -> None:
        """Test analyzing policy with non-dict statement (should skip)."""
        policy_doc = json.dumps(["not-a-dict", {"Principal": ["arn:aws:iam::999888777666:root"], "Rules": []}])

        org_account_ids = {"111111111111"}
        results = _analyze_access_policy(
            policy_name="test-policy",
            policy_document=policy_doc,
            org_account_ids=org_account_ids,
            region="us-east-1",
            account_id="111111111111",
        )

        assert len(results) == 0

    def test_analyze_policy_with_non_list_principals(self) -> None:
        """Test analyzing policy with non-list principals."""
        policy_doc = json.dumps([{
            "Principal": "arn:aws:iam::999888777666:root",
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "ResourceType": "collection",
                "Permission": ["aoss:ReadDocument"],
            }],
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

    def test_analyze_policy_with_non_list_rules(self) -> None:
        """Test analyzing policy with non-list rules."""
        policy_doc = json.dumps([{
            "Principal": ["arn:aws:iam::999888777666:root"],
            "Rules": {
                "Resource": ["collection/test-collection"],
                "ResourceType": "collection",
                "Permission": ["aoss:ReadDocument"],
            },
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

    def test_analyze_policy_with_non_dict_rule(self) -> None:
        """Test analyzing policy with non-dict rule (should skip)."""
        policy_doc = json.dumps([{
            "Principal": ["arn:aws:iam::999888777666:root"],
            "Rules": ["not-a-dict", {
                "Resource": ["collection/test-collection"],
                "ResourceType": "collection",
                "Permission": ["aoss:ReadDocument"],
            }],
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

    def test_analyze_policy_with_non_list_permissions(self) -> None:
        """Test analyzing policy with non-list permissions."""
        policy_doc = json.dumps([{
            "Principal": ["arn:aws:iam::999888777666:root"],
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "ResourceType": "collection",
                "Permission": "aoss:ReadDocument",
            }],
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

    def test_analyze_policy_with_non_list_resources(self) -> None:
        """Test analyzing policy with non-list resources."""
        policy_doc = json.dumps([{
            "Principal": ["arn:aws:iam::999888777666:root"],
            "Rules": [{
                "Resource": "collection/test-collection",
                "ResourceType": "collection",
                "Permission": ["aoss:ReadDocument"],
            }],
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

    def test_analyze_policy_missing_resource_type(self) -> None:
        """Test analyzing policy with missing ResourceType field."""
        policy_doc = json.dumps([{
            "Principal": ["arn:aws:iam::999888777666:root"],
            "Rules": [{
                "Resource": ["collection/test-collection"],
                "Permission": ["aoss:ReadDocument"],
            }],
        }])

        org_account_ids = {"111111111111"}
        with pytest.raises(ValueError, match="missing required 'ResourceType' field"):
            _analyze_access_policy(
                policy_name="test-policy",
                policy_document=policy_doc,
                org_account_ids=org_account_ids,
                region="us-east-1",
                account_id="111111111111",
            )

    def test_analyze_policy_with_non_string_resource(self) -> None:
        """Test analyzing policy with non-string resource (should skip)."""
        policy_doc = json.dumps([{
            "Principal": ["arn:aws:iam::999888777666:root"],
            "Rules": [{
                "Resource": [123, "collection/test-collection"],
                "ResourceType": "collection",
                "Permission": ["aoss:ReadDocument"],
            }],
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

        # Mock access policies list (manual pagination, no nextToken)
        mock_aoss_client.list_access_policies.return_value = {
            "accessPolicySummaries": [
                {"name": "test-policy"},
            ],
            # No "nextToken" key - this terminates the pagination loop
        }

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

    def test_analyze_with_pagination(self) -> None:
        """Test successful analysis with paginated AOSS policies."""
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

        # Mock paginated access policies list (2 pages)
        page1 = {
            "accessPolicySummaries": [{"name": "policy-1"}],
            "nextToken": "token123",
        }
        page2 = {
            "accessPolicySummaries": [{"name": "policy-2"}],
        }
        mock_aoss_client.list_access_policies.side_effect = [page1, page2]

        # Mock get_access_policy for both policies
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

        # Should have 2 results (one per policy)
        assert len(results) == 2
        # Verify list_access_policies was called twice (pagination)
        assert mock_aoss_client.list_access_policies.call_count == 2

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

        # Mock empty access policies list
        mock_aoss_client.list_access_policies.return_value = {
            "accessPolicySummaries": [],
        }

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

        def get_client(service: str, region_name: Optional[str] = None, **kwargs: object) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            if service == "sts":
                return mock_sts_client
            if service == "opensearchserverless":
                if region_name is None:
                    region_name = "default"
                if region_name not in aoss_clients:
                    aoss_clients[region_name] = MagicMock()
                    # Mock list_access_policies with empty results (no nextToken)
                    aoss_clients[region_name].list_access_policies.return_value = {
                        "accessPolicySummaries": [],
                    }
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

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Verify both regions were called
        assert len(aoss_clients) == 2
        assert "us-east-1" in aoss_clients
        assert "us-west-2" in aoss_clients
        assert len(results) == 0

        # Test defensive code paths in get_client
        # Test None region_name
        get_client("opensearchserverless", region_name=None)
        assert "default" in aoss_clients
        # Test unexpected service
        import pytest as pytest_import
        with pytest_import.raises(ValueError, match="Unexpected service"):
            get_client("unexpected_service")

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
        error_response = {
            "Error": {"Code": "UnrecognizedClientException"},
        }
        from typing import cast as type_cast, Any
        mock_aoss_client.list_access_policies.side_effect = ClientError(
            type_cast(Any, error_response),
            "list_access_policies",
        )

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
        mock_aoss_client.list_access_policies.return_value = {
            "accessPolicySummaries": [
                {"name": "test-policy"},
            ],
        }

        # Mock get_access_policy with ResourceNotFoundException
        error_response = {
            "Error": {"Code": "ResourceNotFoundException"},
        }
        from typing import cast as type_cast, Any
        mock_aoss_client.get_access_policy.side_effect = ClientError(
            type_cast(Any, error_response),
            "get_access_policy",
        )

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Should handle gracefully and return empty results
        assert len(results) == 0

    def test_analyze_policy_summary_without_name(self) -> None:
        """Test handling of policy summary without name field."""
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

        # Mock policy without name
        mock_aoss_client.list_access_policies.return_value = {
            "accessPolicySummaries": [
                {},
                {"name": "valid-policy"},
            ],
        }
        mock_aoss_client.get_access_policy.return_value = {
            "accessPolicyDetail": {},
        }

        org_account_ids = {"111111111111"}
        results = analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Should skip the policy without name
        assert len(results) == 0

    def test_analyze_get_access_policy_other_error(self) -> None:
        """Test handling of non-ResourceNotFoundException errors in get_access_policy."""
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

        # Mock policy list
        mock_aoss_client.list_access_policies.return_value = {
            "accessPolicySummaries": [
                {"name": "test-policy"},
            ],
        }

        # Mock get_access_policy with other error
        error_response = {
            "Error": {"Code": "AccessDeniedException"},
        }
        from typing import cast as type_cast, Any
        mock_aoss_client.get_access_policy.side_effect = ClientError(
            type_cast(Any, error_response),
            "get_access_policy",
        )

        org_account_ids = {"111111111111"}
        with pytest.raises(ClientError):
            analyze_aoss_resource_policies(mock_session, org_account_ids)

    def test_analyze_list_access_policies_other_error(self) -> None:
        """Test handling of non-UnrecognizedClientException errors in list_access_policies."""
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

        # Mock list_access_policies with other error
        error_response = {
            "Error": {"Code": "AccessDeniedException"},
        }
        from typing import cast as type_cast, Any
        mock_aoss_client.list_access_policies.side_effect = ClientError(
            type_cast(Any, error_response),
            "list_access_policies",
        )

        org_account_ids = {"111111111111"}
        with pytest.raises(ClientError):
            analyze_aoss_resource_policies(mock_session, org_account_ids)

    def test_get_client_with_none_region(self) -> None:
        """Test get_client helper with None region_name."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sts_client = MagicMock()

        aoss_clients: Dict[str, MagicMock] = {}

        def get_client(service: str, region_name: Optional[str] = None, **kwargs: object) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            if service == "sts":
                return mock_sts_client
            if service == "opensearchserverless":
                if region_name is None:
                    region_name = "default"
                if region_name not in aoss_clients:
                    aoss_clients[region_name] = MagicMock()
                    # Mock list_access_policies with empty results (no nextToken)
                    aoss_clients[region_name].list_access_policies.return_value = {
                        "accessPolicySummaries": [],
                    }
                return aoss_clients[region_name]
            raise ValueError(f"Unexpected service: {service}")

        mock_session.client.side_effect = get_client

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}],
        }

        # Mock STS
        mock_sts_client.get_caller_identity.return_value = {
            "Account": "111111111111",
        }

        org_account_ids = {"111111111111"}
        # This should trigger the None region_name path
        analyze_aoss_resource_policies(mock_session, org_account_ids)

        # Should have created a client for "us-east-1"
        assert "us-east-1" in aoss_clients

        # Test None region_name explicitly
        get_client("opensearchserverless", region_name=None)
        assert "default" in aoss_clients

        # Test unexpected service
        with pytest.raises(ValueError, match="Unexpected service"):
            get_client("unexpected_service")
