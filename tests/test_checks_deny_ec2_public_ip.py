"""
Tests for headroom.checks.scps.deny_ec2_public_ip module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.scps.deny_ec2_public_ip import DenyEc2PublicIpCheck
from headroom.constants import DENY_EC2_PUBLIC_IP
from headroom.aws.ec2 import DenyEc2PublicIp


class TestCheckDenyEc2PublicIp:
    """Test deny_ec2_public_ip check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_ec2_results_mixed(self) -> List[DenyEc2PublicIp]:
        """Create sample EC2 results with mixed compliance status."""
        return [
            DenyEc2PublicIp(
                instance_id="i-1111111111111111",
                region="us-east-1",
                public_ip_address="54.123.45.67",
                has_public_ip=True,
                instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1111111111111111"
            ),
            DenyEc2PublicIp(
                instance_id="i-2222222222222222",
                region="us-west-2",
                public_ip_address=None,
                has_public_ip=False,
                instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-2222222222222222"
            ),
            DenyEc2PublicIp(
                instance_id="i-3333333333333333",
                region="eu-west-1",
                public_ip_address="52.98.76.54",
                has_public_ip=True,
                instance_arn="arn:aws:ec2:eu-west-1:111111111111:instance/i-3333333333333333"
            ),
        ]

    def test_check_deny_ec2_public_ip_mixed_results(
        self,
        sample_ec2_results_mixed: List[DenyEc2PublicIp],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.scps.deny_ec2_public_ip.get_ec2_public_ip_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_ec2_results_mixed

            check = DenyEc2PublicIpCheck(
                check_name=DENY_EC2_PUBLIC_IP,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[0][0]

            assert len(results_data["violations"]) == 2
            assert len(results_data["compliant_instances"]) == 1

            summary = results_data["summary"]
            assert summary["total_instances"] == 3
            assert summary["violations"] == 2
            assert summary["compliant"] == 1
            assert summary["compliance_percentage"] == pytest.approx(33.33, rel=0.01)

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test check with all instances compliant."""
        mock_session = MagicMock()

        all_compliant = [
            DenyEc2PublicIp(
                instance_id="i-1111111111111111",
                region="us-east-1",
                public_ip_address=None,
                has_public_ip=False,
                instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1111111111111111"
            ),
            DenyEc2PublicIp(
                instance_id="i-2222222222222222",
                region="us-west-2",
                public_ip_address=None,
                has_public_ip=False,
                instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-2222222222222222"
            ),
        ]

        with (
            patch("headroom.checks.scps.deny_ec2_public_ip.get_ec2_public_ip_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyEc2PublicIpCheck(
                check_name=DENY_EC2_PUBLIC_IP,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["compliance_percentage"] == 100.0
            assert summary["violations"] == 0
            assert summary["compliant"] == 2

    def test_check_all_violations(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test check with all instances having violations."""
        mock_session = MagicMock()

        all_violations = [
            DenyEc2PublicIp(
                instance_id="i-1111111111111111",
                region="us-east-1",
                public_ip_address="54.123.45.67",
                has_public_ip=True,
                instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1111111111111111"
            ),
            DenyEc2PublicIp(
                instance_id="i-2222222222222222",
                region="us-west-2",
                public_ip_address="52.98.76.54",
                has_public_ip=True,
                instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-2222222222222222"
            ),
        ]

        with (
            patch("headroom.checks.scps.deny_ec2_public_ip.get_ec2_public_ip_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyEc2PublicIpCheck(
                check_name=DENY_EC2_PUBLIC_IP,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["compliance_percentage"] == 0.0
            assert summary["violations"] == 2
            assert summary["compliant"] == 0

    def test_check_empty_results(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test check with no EC2 instances found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.scps.deny_ec2_public_ip.get_ec2_public_ip_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyEc2PublicIpCheck(
                check_name=DENY_EC2_PUBLIC_IP,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["compliance_percentage"] == 100.0
            assert summary["total_instances"] == 0
            assert summary["violations"] == 0
            assert summary["compliant"] == 0

    def test_categorize_result_violation(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test categorization of violation."""
        check = DenyEc2PublicIpCheck(
            check_name=DENY_EC2_PUBLIC_IP,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyEc2PublicIp(
            instance_id="i-1111111111111111",
            region="us-east-1",
            public_ip_address="54.123.45.67",
            has_public_ip=True,
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1111111111111111"
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_public_ip"] is True
        assert result_dict["public_ip_address"] == "54.123.45.67"

    def test_categorize_result_compliant(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test categorization of compliant."""
        check = DenyEc2PublicIpCheck(
            check_name=DENY_EC2_PUBLIC_IP,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyEc2PublicIp(
            instance_id="i-2222222222222222",
            region="us-west-2",
            public_ip_address=None,
            has_public_ip=False,
            instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-2222222222222222"
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["has_public_ip"] is False
        assert result_dict["public_ip_address"] is None

    def test_build_summary_fields(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test summary field building."""
        check = DenyEc2PublicIpCheck(
            check_name=DENY_EC2_PUBLIC_IP,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        from headroom.checks.base import CategorizedCheckResult

        check_result = CategorizedCheckResult(
            violations=[{"instance_id": "i-111"}, {"instance_id": "i-222"}],
            exemptions=[],
            compliant=[{"instance_id": "i-333"}]
        )

        summary_fields = check.build_summary_fields(check_result)

        assert summary_fields["total_instances"] == 3
        assert summary_fields["violations"] == 2
        assert summary_fields["compliant"] == 1
        assert summary_fields["compliance_percentage"] == pytest.approx(33.33, rel=0.01)
