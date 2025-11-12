"""
Tests for headroom.checks.scps.deny_eks_create_cluster_without_tag module.

Tests for DenyEksCreateClusterWithoutTagCheck and its integration with EKS analysis.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.scps.deny_eks_create_cluster_without_tag import (
    DenyEksCreateClusterWithoutTagCheck,
)
from headroom.constants import DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG
from headroom.aws.eks import DenyEksCreateClusterWithoutTag


class TestCheckDenyEksCreateClusterWithoutTag:
    """Test deny_eks_create_cluster_without_tag check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_eks_results_mixed(self) -> List[DenyEksCreateClusterWithoutTag]:
        """Create sample EKS results with mixed compliance status."""
        return [
            DenyEksCreateClusterWithoutTag(
                cluster_name="approved-cluster-1",
                cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/approved-cluster-1",
                region="us-east-1",
                tags={"PavedRoad": "true", "Environment": "prod"},
                has_paved_road_tag=True
            ),
            DenyEksCreateClusterWithoutTag(
                cluster_name="legacy-cluster",
                cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/legacy-cluster",
                region="us-east-1",
                tags={"Environment": "dev"},
                has_paved_road_tag=False
            ),
            DenyEksCreateClusterWithoutTag(
                cluster_name="approved-cluster-2",
                cluster_arn="arn:aws:eks:us-west-2:111111111111:cluster/approved-cluster-2",
                region="us-west-2",
                tags={"PavedRoad": "true", "Team": "platform"},
                has_paved_road_tag=True
            )
        ]

    @pytest.fixture
    def sample_eks_results_compliant(self) -> List[DenyEksCreateClusterWithoutTag]:
        """Create sample EKS results with all compliant clusters."""
        return [
            DenyEksCreateClusterWithoutTag(
                cluster_name="compliant-1",
                cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/compliant-1",
                region="us-east-1",
                tags={"PavedRoad": "true"},
                has_paved_road_tag=True
            ),
            DenyEksCreateClusterWithoutTag(
                cluster_name="compliant-2",
                cluster_arn="arn:aws:eks:us-west-2:111111111111:cluster/compliant-2",
                region="us-west-2",
                tags={"PavedRoad": "true"},
                has_paved_road_tag=True
            )
        ]

    @pytest.fixture
    def sample_eks_results_violations(self) -> List[DenyEksCreateClusterWithoutTag]:
        """Create sample EKS results with all violations."""
        return [
            DenyEksCreateClusterWithoutTag(
                cluster_name="violation-1",
                cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/violation-1",
                region="us-east-1",
                tags={},
                has_paved_road_tag=False
            ),
            DenyEksCreateClusterWithoutTag(
                cluster_name="violation-2",
                cluster_arn="arn:aws:eks:us-west-2:111111111111:cluster/violation-2",
                region="us-west-2",
                tags={"Environment": "test"},
                has_paved_road_tag=False
            )
        ]

    def test_check_deny_eks_create_cluster_mixed_results(
        self,
        sample_eks_results_mixed: List[DenyEksCreateClusterWithoutTag],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.scps.deny_eks_create_cluster_without_tag.get_eks_cluster_tag_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_eks_results_mixed

            check = DenyEksCreateClusterWithoutTagCheck(
                check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify analysis was called
            mock_analysis.assert_called_once_with(mock_session)

            # Verify write_check_results was called
            mock_write.assert_called_once()

            # Verify write_check_results arguments
            write_call_args = mock_write.call_args
            assert write_call_args[1]["check_name"] == "deny_eks_create_cluster_without_tag"
            assert write_call_args[1]["account_name"] == account_name
            assert write_call_args[1]["account_id"] == account_id
            assert write_call_args[1]["results_base_dir"] == temp_results_dir

            # Verify JSON structure
            results_data = write_call_args[1]["results_data"]

            # Check summary
            summary = results_data["summary"]
            assert summary["account_name"] == "test-account"
            assert summary["account_id"] == "111111111111"
            assert summary["check"] == "deny_eks_create_cluster_without_tag"
            assert summary["total_clusters"] == 3
            assert summary["violations"] == 1
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == pytest.approx(66.67, rel=0.01)

            # Check violations
            violations = results_data["violations"]
            assert len(violations) == 1
            assert violations[0]["cluster_name"] == "legacy-cluster"
            assert violations[0]["has_paved_road_tag"] is False

            # Check compliant instances
            compliant = results_data["compliant_instances"]
            assert len(compliant) == 2
            compliant_names = [c["cluster_name"] for c in compliant]
            assert "approved-cluster-1" in compliant_names
            assert "approved-cluster-2" in compliant_names

            # Verify compliant details
            for cluster in compliant:
                assert cluster["has_paved_road_tag"] is True
                assert "PavedRoad" in cluster["tags"]
                assert cluster["tags"]["PavedRoad"] == "true"

    def test_check_deny_eks_create_cluster_all_compliant(
        self,
        sample_eks_results_compliant: List[DenyEksCreateClusterWithoutTag],
        temp_results_dir: str,
    ) -> None:
        """Test check function with all compliant clusters."""
        mock_session = MagicMock()
        account_name = "compliant-account"
        account_id = "222222222222"

        with (
            patch("headroom.checks.scps.deny_eks_create_cluster_without_tag.get_eks_cluster_tag_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_eks_results_compliant

            check = DenyEksCreateClusterWithoutTagCheck(
                check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results
            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_clusters"] == 2
            assert summary["violations"] == 0
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == 100.0

            # No violations
            assert len(results_data["violations"]) == 0

            # All compliant
            assert len(results_data["compliant_instances"]) == 2

    def test_check_deny_eks_create_cluster_all_violations(
        self,
        sample_eks_results_violations: List[DenyEksCreateClusterWithoutTag],
        temp_results_dir: str,
    ) -> None:
        """Test check function with all violations."""
        mock_session = MagicMock()
        account_name = "violations-account"
        account_id = "333333333333"

        with (
            patch("headroom.checks.scps.deny_eks_create_cluster_without_tag.get_eks_cluster_tag_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_eks_results_violations

            check = DenyEksCreateClusterWithoutTagCheck(
                check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results
            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_clusters"] == 2
            assert summary["violations"] == 2
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 0.0

            # All violations
            assert len(results_data["violations"]) == 2

            # No compliant
            assert len(results_data["compliant_instances"]) == 0

    def test_check_deny_eks_create_cluster_empty_results(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test check function with no clusters."""
        mock_session = MagicMock()
        account_name = "empty-account"
        account_id = "444444444444"

        with (
            patch("headroom.checks.scps.deny_eks_create_cluster_without_tag.get_eks_cluster_tag_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyEksCreateClusterWithoutTagCheck(
                check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results
            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_clusters"] == 0
            assert summary["violations"] == 0
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 100.0  # Empty is 100% compliant

            # No results
            assert len(results_data["violations"]) == 0
            assert len(results_data["compliant_instances"]) == 0

    def test_categorize_result_compliant(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test categorization of compliant cluster."""
        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyEksCreateClusterWithoutTag(
            cluster_name="compliant-cluster",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/compliant-cluster",
            region="us-east-1",
            tags={"PavedRoad": "true", "Environment": "prod"},
            has_paved_road_tag=True
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["cluster_name"] == "compliant-cluster"
        assert result_dict["has_paved_road_tag"] is True
        assert result_dict["tags"]["PavedRoad"] == "true"

    def test_categorize_result_violation(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test categorization of violation cluster."""
        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyEksCreateClusterWithoutTag(
            cluster_name="violation-cluster",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/violation-cluster",
            region="us-east-1",
            tags={"Environment": "dev"},
            has_paved_road_tag=False
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["cluster_name"] == "violation-cluster"
        assert result_dict["has_paved_road_tag"] is False
        assert "PavedRoad" not in result_dict["tags"]

    def test_categorize_result_case_sensitivity(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test that case sensitivity causes violations."""
        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        # Lowercase key
        result1 = DenyEksCreateClusterWithoutTag(
            cluster_name="lowercase-key",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/lowercase-key",
            region="us-east-1",
            tags={"pavedroad": "true"},  # Wrong case
            has_paved_road_tag=False
        )

        category1, _ = check.categorize_result(result1)
        assert category1 == "violation"

        # Uppercase value
        result2 = DenyEksCreateClusterWithoutTag(
            cluster_name="uppercase-value",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/uppercase-value",
            region="us-east-1",
            tags={"PavedRoad": "True"},  # Wrong case
            has_paved_road_tag=False
        )

        category2, _ = check.categorize_result(result2)
        assert category2 == "violation"

    def test_build_summary_fields(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test summary field building."""
        from headroom.checks.base import CategorizedCheckResult

        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        # Create mock categorized result
        categorized_result = CategorizedCheckResult(
            violations=[
                {"cluster_name": "v1"},
                {"cluster_name": "v2"}
            ],
            exemptions=[],
            compliant=[
                {"cluster_name": "c1"},
                {"cluster_name": "c2"},
                {"cluster_name": "c3"}
            ],
            summary={}
        )

        summary = check.build_summary_fields(categorized_result)

        assert summary["total_clusters"] == 5
        assert summary["violations"] == 2
        assert summary["compliant"] == 3
        assert summary["compliance_percentage"] == 60.0

    def test_build_summary_fields_empty(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test summary field building with empty results."""
        from headroom.checks.base import CategorizedCheckResult

        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        # Create mock empty categorized result
        categorized_result = CategorizedCheckResult(
            violations=[],
            exemptions=[],
            compliant=[],
            summary={}
        )

        summary = check.build_summary_fields(categorized_result)

        assert summary["total_clusters"] == 0
        assert summary["violations"] == 0
        assert summary["compliant"] == 0
        assert summary["compliance_percentage"] == 100.0  # Empty is 100%

    def test_check_edge_case_paved_road_false(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test edge case: PavedRoad tag set to 'false'."""
        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyEksCreateClusterWithoutTag(
            cluster_name="false-value",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/false-value",
            region="us-east-1",
            tags={"PavedRoad": "false"},  # Explicit false
            has_paved_road_tag=False
        )

        category, _ = check.categorize_result(result)
        assert category == "violation"

    def test_check_edge_case_empty_tags(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test edge case: Cluster with empty tags dict."""
        check = DenyEksCreateClusterWithoutTagCheck(
            check_name=DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyEksCreateClusterWithoutTag(
            cluster_name="no-tags",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/no-tags",
            region="us-east-1",
            tags={},  # Empty tags
            has_paved_road_tag=False
        )

        category, result_dict = check.categorize_result(result)
        assert category == "violation"
        assert result_dict["tags"] == {}
