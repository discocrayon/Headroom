"""
Tests for headroom.checks.rcps.deny_s3_third_party_access module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import Generator, List

from headroom.checks.rcps.deny_s3_third_party_access import DenyS3ThirdPartyAccessCheck
from headroom.constants import DENY_S3_THIRD_PARTY_ACCESS
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.s3 import S3BucketPolicyAnalysis


class TestDenyS3ThirdPartyAccessCheck:
    """Test deny_s3_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> set[str]:
        """Organization account IDs for testing."""
        return {"999999999999", "888888888888"}

    @pytest.fixture
    def sample_s3_results_mixed(self) -> List[S3BucketPolicyAnalysis]:
        """Create sample S3 results with mixed compliance status."""
        return [
            S3BucketPolicyAnalysis(
                bucket_name="compliant-bucket",
                bucket_arn="arn:aws:s3:::compliant-bucket",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                actions_by_account={"111111111111": {"s3:GetObject", "s3:PutObject"}}
            ),
            S3BucketPolicyAnalysis(
                bucket_name="wildcard-bucket",
                bucket_arn="arn:aws:s3:::wildcard-bucket",
                third_party_account_ids={"222222222222"},
                has_wildcard_principal=True,
                actions_by_account={"222222222222": {"s3:GetObject"}}
            ),
        ]

    def test_check_deny_s3_third_party_access_mixed_results(
        self,
        sample_s3_results_mixed: List[S3BucketPolicyAnalysis],
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_s3_results_mixed

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[0][0]

            assert len(results_data["buckets_with_wildcards"]) == 1
            assert len(results_data["buckets_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_buckets_analyzed"] == 2
            assert summary["buckets_with_wildcards"] == 1
            assert summary["buckets_third_parties_can_access"] == 2
            assert summary["violations"] == 1
            assert set(summary["unique_third_party_accounts"]) == {"111111111111", "222222222222"}
            assert summary["third_party_account_count"] == 2

    def test_check_all_compliant(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with all buckets compliant."""
        mock_session = MagicMock()

        all_compliant = [
            S3BucketPolicyAnalysis(
                bucket_name="compliant-bucket-1",
                bucket_arn="arn:aws:s3:::compliant-bucket-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                actions_by_account={"111111111111": {"s3:GetObject"}}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["buckets_with_wildcards"] == 0
            assert summary["buckets_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with all buckets having violations."""
        mock_session = MagicMock()

        all_violations = [
            S3BucketPolicyAnalysis(
                bucket_name="wildcard-bucket-1",
                bucket_arn="arn:aws:s3:::wildcard-bucket-1",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
                actions_by_account={}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["buckets_with_wildcards"] == 1

    def test_check_empty_results(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with no buckets found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["total_buckets_analyzed"] == 0
            assert summary["violations"] == 0

    def test_categorize_result_violation(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of violation."""
        check = DenyS3ThirdPartyAccessCheck(
            check_name=DENY_S3_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
        )

        result = S3BucketPolicyAnalysis(
            bucket_name="wildcard-bucket",
            bucket_arn="arn:aws:s3:::wildcard-bucket",
            third_party_account_ids={"222222222222"},
            has_wildcard_principal=True,
            actions_by_account={"222222222222": {"s3:*"}}
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of compliant."""
        check = DenyS3ThirdPartyAccessCheck(
            check_name=DENY_S3_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
        )

        result = S3BucketPolicyAnalysis(
            bucket_name="compliant-bucket",
            bucket_arn="arn:aws:s3:::compliant-bucket",
            third_party_account_ids={"333333333333"},
            has_wildcard_principal=False,
            actions_by_account={"333333333333": {"s3:GetObject"}}
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["has_wildcard_principal"] is False

    def test_actions_by_account_tracking(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that actions by account are correctly tracked and aggregated."""
        mock_session = MagicMock()

        results = [
            S3BucketPolicyAnalysis(
                bucket_name="bucket-1",
                bucket_arn="arn:aws:s3:::bucket-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                actions_by_account={"111111111111": {"s3:GetObject", "s3:PutObject"}}
            ),
            S3BucketPolicyAnalysis(
                bucket_name="bucket-2",
                bucket_arn="arn:aws:s3:::bucket-2",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                actions_by_account={"111111111111": {"s3:DeleteObject"}}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert "111111111111" in summary["actions_by_third_party_account"]
            actions = set(summary["actions_by_third_party_account"]["111111111111"])
            assert actions == {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}

    def test_buckets_by_account_tracking(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that buckets by account are correctly tracked."""
        mock_session = MagicMock()

        results = [
            S3BucketPolicyAnalysis(
                bucket_name="bucket-1",
                bucket_arn="arn:aws:s3:::bucket-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                actions_by_account={"111111111111": {"s3:GetObject"}}
            ),
            S3BucketPolicyAnalysis(
                bucket_name="bucket-2",
                bucket_arn="arn:aws:s3:::bucket-2",
                third_party_account_ids={"111111111111", "222222222222"},
                has_wildcard_principal=False,
                actions_by_account={
                    "111111111111": {"s3:PutObject"},
                    "222222222222": {"s3:GetObject"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert "111111111111" in summary["buckets_by_third_party_account"]
            buckets = set(summary["buckets_by_third_party_account"]["111111111111"])
            assert buckets == {"arn:aws:s3:::bucket-1", "arn:aws:s3:::bucket-2"}

            assert "222222222222" in summary["buckets_by_third_party_account"]
            buckets = set(summary["buckets_by_third_party_account"]["222222222222"])
            assert buckets == {"arn:aws:s3:::bucket-2"}
