"""
Tests for headroom.checks.rcps.deny_ecr_third_party_access module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import Generator, List

from headroom.checks.rcps.deny_ecr_third_party_access import DenyECRThirdPartyAccessCheck
from headroom.constants import DENY_ECR_THIRD_PARTY_ACCESS
from headroom.aws.ecr import ECRRepositoryPolicyAnalysis


class TestCheckDenyECRThirdPartyAccess:
    """Test deny_ecr_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> set[str]:
        """Set of organization account IDs."""
        return {"111111111111", "222222222222"}

    @pytest.fixture
    def sample_ecr_results_mixed(self) -> List[ECRRepositoryPolicyAnalysis]:
        """Create sample ECR results with mixed compliance status."""
        return [
            ECRRepositoryPolicyAnalysis(
                repository_name="compliant-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/compliant-repo",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
                },
                has_wildcard_principal=False
            ),
            ECRRepositoryPolicyAnalysis(
                repository_name="wildcard-repo",
                repository_arn="arn:aws:ecr:us-west-2:111111111111:repository/wildcard-repo",
                region="us-west-2",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
        ]

    def test_check_deny_ecr_third_party_access_mixed_results(
        self,
        sample_ecr_results_mixed: List[ECRRepositoryPolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_ecr_results_mixed

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[0][0]

            assert len(results_data["repositories_with_wildcards"]) == 1
            assert len(results_data["repositories_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_repositories_analyzed"] == 2
            assert summary["repositories_with_wildcards"] == 1
            assert summary["repositories_third_parties_can_access"] == 2
            assert summary["violations"] == 1
            assert summary["third_party_account_count"] == 1
            assert "999999999999" in summary["unique_third_party_accounts"]

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all repositories compliant."""
        mock_session = MagicMock()

        all_compliant = [
            ECRRepositoryPolicyAnalysis(
                repository_name="vendor-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/vendor-repo",
                region="us-east-1",
                third_party_account_ids={"888888888888"},
                actions_by_account={
                    "888888888888": ["ecr:BatchGetImage"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["repositories_with_wildcards"] == 0
            assert summary["repositories_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all repositories having wildcards."""
        mock_session = MagicMock()

        all_violations = [
            ECRRepositoryPolicyAnalysis(
                repository_name="public-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/public-repo",
                region="us-east-1",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["repositories_with_wildcards"] == 1

    def test_check_empty_results(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with no repositories found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["total_repositories_analyzed"] == 0
            assert summary["violations"] == 0
            assert summary["third_party_account_count"] == 0

    def test_categorize_result_violation(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of violation (wildcard)."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = ECRRepositoryPolicyAnalysis(
            repository_name="wildcard-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/wildcard-repo",
            region="us-east-1",
            third_party_account_ids=set(),
            actions_by_account={},
            has_wildcard_principal=True
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of compliant (third-party but no wildcard)."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = ECRRepositoryPolicyAnalysis(
            repository_name="vendor-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/vendor-repo",
            region="us-east-1",
            third_party_account_ids={"999999999999"},
            actions_by_account={
                "999999999999": ["ecr:GetDownloadUrlForLayer"]
            },
            has_wildcard_principal=False
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["has_wildcard_principal"] is False
        assert "999999999999" in result_dict["third_party_account_ids"]

    def test_actions_by_account_union(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test that actions are unioned across multiple repositories."""
        mock_session = MagicMock()

        results = [
            ECRRepositoryPolicyAnalysis(
                repository_name="repo1",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer"]
                },
                has_wildcard_principal=False
            ),
            ECRRepositoryPolicyAnalysis(
                repository_name="repo2",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo2",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:BatchGetImage", "ecr:DescribeImages"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            actions = summary["actions_by_account"]["999999999999"]
            assert len(actions) == 3
            assert "ecr:GetDownloadUrlForLayer" in actions
            assert "ecr:BatchGetImage" in actions
            assert "ecr:DescribeImages" in actions

    def test_multiple_third_party_accounts(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test multiple third-party accounts across repositories."""
        mock_session = MagicMock()

        results = [
            ECRRepositoryPolicyAnalysis(
                repository_name="repo1",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer"]
                },
                has_wildcard_principal=False
            ),
            ECRRepositoryPolicyAnalysis(
                repository_name="repo2",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo2",
                region="us-east-1",
                third_party_account_ids={"888888888888"},
                actions_by_account={
                    "888888888888": ["ecr:BatchGetImage"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["third_party_account_count"] == 2
            assert "999999999999" in summary["unique_third_party_accounts"]
            assert "888888888888" in summary["unique_third_party_accounts"]
            assert "999999999999" in summary["actions_by_account"]
            assert "888888888888" in summary["actions_by_account"]

    def test_wildcard_with_third_party_accounts(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test repository with both wildcard and third-party accounts."""
        mock_session = MagicMock()

        results = [
            ECRRepositoryPolicyAnalysis(
                repository_name="mixed-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/mixed-repo",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer"]
                },
                has_wildcard_principal=True
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_repository_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["repositories_with_wildcards"] == 1
            assert summary["repositories_third_parties_can_access"] == 1
            assert summary["third_party_account_count"] == 1

    def test_result_dict_format(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test that result dict has correct format."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = ECRRepositoryPolicyAnalysis(
            repository_name="test-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/test-repo",
            region="us-east-1",
            third_party_account_ids={"999999999999", "888888888888"},
            actions_by_account={
                "999999999999": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "888888888888": ["ecr:DescribeImages"]
            },
            has_wildcard_principal=False
        )

        category, result_dict = check.categorize_result(result)

        assert "repository_name" in result_dict
        assert "repository_arn" in result_dict
        assert "region" in result_dict
        assert "third_party_account_ids" in result_dict
        assert "actions_by_account" in result_dict
        assert "has_wildcard_principal" in result_dict

        assert isinstance(result_dict["third_party_account_ids"], list)
        assert result_dict["third_party_account_ids"] == sorted(["999999999999", "888888888888"])

        assert isinstance(result_dict["actions_by_account"], dict)
        for account_id, actions in result_dict["actions_by_account"].items():
            assert isinstance(actions, list)
            assert actions == sorted(actions)
