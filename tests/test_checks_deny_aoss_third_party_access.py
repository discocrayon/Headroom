"""
Tests for headroom.checks.rcps.deny_aoss_third_party_access module.
"""

import shutil
import tempfile
from typing import Generator, List, Set
from unittest.mock import MagicMock, patch

import pytest

from headroom.aws.aoss import AossResourcePolicyAnalysis
from headroom.checks.rcps.deny_aoss_third_party_access import DenyAossThirdPartyAccessCheck
from headroom.constants import DENY_AOSS_THIRD_PARTY_ACCESS


class TestDenyAossThirdPartyAccessCheck:
    """Test deny_aoss_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> Set[str]:
        """Organization account IDs for testing."""
        return {"111111111111", "222222222222", "333333333333"}

    @pytest.fixture
    def sample_aoss_results_mixed(self) -> List[AossResourcePolicyAnalysis]:
        """Create sample AOSS results with mixed third-party access."""
        return [
            AossResourcePolicyAnalysis(
                resource_name="collection-1",
                resource_type="collection",
                resource_arn="arn:aws:aoss:us-east-1:111111111111:collection/collection-1",
                policy_name="policy-1",
                third_party_account_ids={"999888777666"},
                allowed_actions=["aoss:ReadDocument", "aoss:WriteDocument"],
            ),
            AossResourcePolicyAnalysis(
                resource_name="collection-2",
                resource_type="collection",
                resource_arn="arn:aws:aoss:us-west-2:111111111111:collection/collection-2",
                policy_name="policy-2",
                third_party_account_ids={"111222333444", "555666777888"},
                allowed_actions=["aoss:ReadDocument"],
            ),
        ]

    @pytest.fixture
    def sample_aoss_results_single(self) -> List[AossResourcePolicyAnalysis]:
        """Create sample AOSS results with single third-party access."""
        return [
            AossResourcePolicyAnalysis(
                resource_name="test-collection",
                resource_type="collection",
                resource_arn="arn:aws:aoss:us-east-1:111111111111:collection/test-collection",
                policy_name="test-policy",
                third_party_account_ids={"999888777666"},
                allowed_actions=[
                    "aoss:CreateIndex",
                    "aoss:DescribeCollection",
                    "aoss:ReadDocument",
                    "aoss:UpdateIndex",
                    "aoss:WriteDocument",
                ],
            ),
        ]

    def test_check_with_mixed_results(
        self,
        sample_aoss_results_mixed: List[AossResourcePolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with multiple AOSS resources and third-party accounts."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_aoss_third_party_access.analyze_aoss_resource_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            mock_analysis.return_value = sample_aoss_results_mixed

            check = DenyAossThirdPartyAccessCheck(
                check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            # Verify write_check_results was called
            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args.kwargs["results_data"]

            # Verify categorization
            assert len(results_data["resources_with_third_party_access"]) == 2

            # Verify summary fields
            summary = results_data["summary"]
            assert summary["total_resources_with_third_party_access"] == 2
            assert summary["third_party_account_count"] == 3
            assert set(summary["unique_third_party_accounts"]) == {
                "999888777666",
                "111222333444",
                "555666777888",
            }

            # Verify actions_by_third_party_account
            actions_by_account = summary["actions_by_third_party_account"]
            assert "999888777666" in actions_by_account
            assert "aoss:ReadDocument" in actions_by_account["999888777666"]
            assert "aoss:WriteDocument" in actions_by_account["999888777666"]

            assert "111222333444" in actions_by_account
            assert "aoss:ReadDocument" in actions_by_account["111222333444"]

            assert "555666777888" in actions_by_account
            assert "aoss:ReadDocument" in actions_by_account["555666777888"]

    def test_check_with_single_resource(
        self,
        sample_aoss_results_single: List[AossResourcePolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with single AOSS resource."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_aoss_third_party_access.analyze_aoss_resource_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            mock_analysis.return_value = sample_aoss_results_single

            check = DenyAossThirdPartyAccessCheck(
                check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args.kwargs["results_data"]
            summary = results_data["summary"]

            assert summary["total_resources_with_third_party_access"] == 1
            assert summary["third_party_account_count"] == 1
            assert summary["unique_third_party_accounts"] == ["999888777666"]

            # Verify all actions are tracked
            actions_by_account = summary["actions_by_third_party_account"]
            assert "999888777666" in actions_by_account
            expected_actions = [
                "aoss:CreateIndex",
                "aoss:DescribeCollection",
                "aoss:ReadDocument",
                "aoss:UpdateIndex",
                "aoss:WriteDocument",
            ]
            assert set(actions_by_account["999888777666"]) == set(expected_actions)

    def test_check_with_empty_results(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with no AOSS resources."""
        mock_session = MagicMock()
        empty_results: List[AossResourcePolicyAnalysis] = []

        with (
            patch("headroom.checks.rcps.deny_aoss_third_party_access.analyze_aoss_resource_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            mock_analysis.return_value = empty_results

            check = DenyAossThirdPartyAccessCheck(
                check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args.kwargs["results_data"]
            summary = results_data["summary"]

            assert summary["total_resources_with_third_party_access"] == 0
            assert summary["third_party_account_count"] == 0
            assert summary["unique_third_party_accounts"] == []
            assert summary["actions_by_third_party_account"] == {}

    def test_categorize_result_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test categorization of AOSS resource with third-party access."""
        check = DenyAossThirdPartyAccessCheck(
            check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = AossResourcePolicyAnalysis(
            resource_name="test-collection",
            resource_type="collection",
            resource_arn="arn:aws:aoss:us-east-1:111111111111:collection/test-collection",
            policy_name="test-policy",
            third_party_account_ids={"999888777666"},
            allowed_actions=["aoss:ReadDocument"],
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["resource_name"] == "test-collection"
        assert result_dict["resource_type"] == "collection"
        assert result_dict["policy_name"] == "test-policy"
        assert result_dict["third_party_account_ids"] == ["999888777666"]
        assert result_dict["allowed_actions"] == ["aoss:ReadDocument"]

    def test_categorize_multiple_results_tracks_union(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test that multiple results track union of third-party accounts."""
        check = DenyAossThirdPartyAccessCheck(
            check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result1 = AossResourcePolicyAnalysis(
            resource_name="collection-1",
            resource_type="collection",
            resource_arn="arn:aws:aoss:us-east-1:111111111111:collection/collection-1",
            policy_name="policy-1",
            third_party_account_ids={"999888777666"},
            allowed_actions=["aoss:ReadDocument"],
        )

        result2 = AossResourcePolicyAnalysis(
            resource_name="collection-2",
            resource_type="collection",
            resource_arn="arn:aws:aoss:us-west-2:111111111111:collection/collection-2",
            policy_name="policy-2",
            third_party_account_ids={"111222333444"},
            allowed_actions=["aoss:WriteDocument"],
        )

        check.categorize_result(result1)
        check.categorize_result(result2)

        # Verify union of accounts
        assert check.all_third_party_accounts == {"999888777666", "111222333444"}

        # Verify actions are tracked separately
        assert "aoss:ReadDocument" in check.actions_by_account["999888777666"]
        assert "aoss:WriteDocument" in check.actions_by_account["111222333444"]

    def test_categorize_same_account_multiple_resources(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test same account with different actions on multiple resources."""
        check = DenyAossThirdPartyAccessCheck(
            check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result1 = AossResourcePolicyAnalysis(
            resource_name="collection-1",
            resource_type="collection",
            resource_arn="arn:aws:aoss:us-east-1:111111111111:collection/collection-1",
            policy_name="policy-1",
            third_party_account_ids={"999888777666"},
            allowed_actions=["aoss:ReadDocument"],
        )

        result2 = AossResourcePolicyAnalysis(
            resource_name="collection-2",
            resource_type="collection",
            resource_arn="arn:aws:aoss:us-west-2:111111111111:collection/collection-2",
            policy_name="policy-2",
            third_party_account_ids={"999888777666"},
            allowed_actions=["aoss:WriteDocument", "aoss:UpdateIndex"],
        )

        check.categorize_result(result1)
        check.categorize_result(result2)

        # Verify same account tracked once
        assert check.all_third_party_accounts == {"999888777666"}

        # Verify actions are unioned
        actions = check.actions_by_account["999888777666"]
        assert "aoss:ReadDocument" in actions
        assert "aoss:WriteDocument" in actions
        assert "aoss:UpdateIndex" in actions

    def test_build_summary_fields(
        self,
        sample_aoss_results_mixed: List[AossResourcePolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test build_summary_fields method."""
        check = DenyAossThirdPartyAccessCheck(
            check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        # Categorize results to populate tracking
        for result in sample_aoss_results_mixed:
            check.categorize_result(result)

        # Create mock CategorizedCheckResult
        mock_check_result = MagicMock()
        mock_check_result.compliant = [{}] * len(sample_aoss_results_mixed)
        mock_check_result.violations = []
        mock_check_result.exemptions = []

        summary_fields = check.build_summary_fields(mock_check_result)

        assert summary_fields["total_resources_with_third_party_access"] == 2
        assert summary_fields["third_party_account_count"] == 3
        from typing import cast as type_cast
        assert set(type_cast(list, summary_fields["unique_third_party_accounts"])) == {
            "999888777666",
            "111222333444",
            "555666777888",
        }

        # Verify actions_by_third_party_account is serializable
        actions_by_account = summary_fields["actions_by_third_party_account"]
        assert isinstance(actions_by_account, dict)
        for account, actions in actions_by_account.items():
            assert isinstance(account, str)
            assert isinstance(actions, list)
            assert all(isinstance(action, str) for action in actions)

    def test_build_results_data_format(
        self,
        sample_aoss_results_single: List[AossResourcePolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test _build_results_data returns correct format."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_aoss_third_party_access.analyze_aoss_resource_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            mock_analysis.return_value = sample_aoss_results_single

            check = DenyAossThirdPartyAccessCheck(
                check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args.kwargs["results_data"]

            # Verify structure
            assert "summary" in results_data
            assert "resources_with_third_party_access" in results_data

            # Verify no violations or exemptions keys
            assert "violations" not in results_data
            assert "exemptions" not in results_data

            # Verify resources_with_third_party_access structure
            resources = results_data["resources_with_third_party_access"]
            assert len(resources) == 1
            assert resources[0]["resource_name"] == "test-collection"
            assert resources[0]["resource_type"] == "collection"

    def test_check_with_index_resources(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with index resources."""
        mock_session = MagicMock()
        index_results = [
            AossResourcePolicyAnalysis(
                resource_name="test-collection",
                resource_type="index",
                resource_arn="arn:aws:aoss:us-east-1:111111111111:index/test-collection",
                policy_name="index-policy",
                third_party_account_ids={"999888777666"},
                allowed_actions=["aoss:CreateIndex", "aoss:UpdateIndex"],
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_aoss_third_party_access.analyze_aoss_resource_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            mock_analysis.return_value = index_results

            check = DenyAossThirdPartyAccessCheck(
                check_name=DENY_AOSS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args.kwargs["results_data"]
            resources = results_data["resources_with_third_party_access"]

            assert len(resources) == 1
            assert resources[0]["resource_type"] == "index"
            assert resources[0]["resource_name"] == "test-collection"
