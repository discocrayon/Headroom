"""
Tests for headroom.checks.scps.deny_ec2_ami_owner module.

Tests for DenyEc2AmiOwnerCheck and its integration with AWS EC2 AMI owner analysis.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator
from headroom.checks.scps.deny_ec2_ami_owner import DenyEc2AmiOwnerCheck
from headroom.constants import DENY_EC2_AMI_OWNER
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.ec2 import DenyEc2AmiOwner


class TestCheckDenyEc2AmiOwner:
    """Test DenyEc2AmiOwnerCheck with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_ami_owner_results_mixed(self) -> List[DenyEc2AmiOwner]:
        """Create sample AMI owner results with mixed owners."""
        return [
            DenyEc2AmiOwner(
                instance_id="i-amazon-ami",
                region="us-east-1",
                ami_id="ami-12345678",
                ami_owner="amazon",
                ami_name="Amazon Linux 2",
                instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-amazon-ami"
            ),
            DenyEc2AmiOwner(
                instance_id="i-marketplace-ami",
                region="us-east-1",
                ami_id="ami-87654321",
                ami_owner="aws-marketplace",
                ami_name="Marketplace AMI",
                instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-marketplace-ami"
            ),
            DenyEc2AmiOwner(
                instance_id="i-custom-ami",
                region="us-west-2",
                ami_id="ami-abcdef12",
                ami_owner="222222222222",
                ami_name="Custom AMI",
                instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-custom-ami"
            ),
            DenyEc2AmiOwner(
                instance_id="i-unknown-ami",
                region="us-west-2",
                ami_id="ami-unknown",
                ami_owner="unknown",
                ami_name=None,
                instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-unknown-ami"
            ),
        ]

    @pytest.fixture
    def sample_ami_owner_results_all_compliant(self) -> List[DenyEc2AmiOwner]:
        """Create sample AMI owner results with all from trusted owners."""
        return [
            DenyEc2AmiOwner(
                instance_id="i-amazon-1",
                region="us-east-1",
                ami_id="ami-12345678",
                ami_owner="amazon",
                ami_name="Amazon Linux 2",
                instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-amazon-1"
            ),
            DenyEc2AmiOwner(
                instance_id="i-amazon-2",
                region="us-west-2",
                ami_id="ami-87654321",
                ami_owner="amazon",
                ami_name="Amazon Linux 2023",
                instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-amazon-2"
            ),
        ]

    def test_check_deny_ec2_ami_owner_mixed_results(
        self,
        sample_ami_owner_results_mixed: List[DenyEc2AmiOwner],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed AMI owners."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.scps.deny_ec2_ami_owner.get_ec2_ami_owner_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_ami_owner_results_mixed

            check = DenyEc2AmiOwnerCheck(
                check_name=DENY_EC2_AMI_OWNER,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[0][0]

            assert len(results_data["violations"]) == 0
            assert len(results_data["compliant_instances"]) == 4

            summary = results_data["summary"]
            assert summary["total_instances"] == 4
            assert summary["violations"] == 0
            assert summary["compliant"] == 4
            assert summary["compliance_percentage"] == pytest.approx(100.0, rel=0.01)
            assert set(summary["unique_ami_owners"]) == {"222222222222", "amazon", "aws-marketplace", "unknown"}

    def test_check_all_compliant(
        self,
        sample_ami_owner_results_all_compliant: List[DenyEc2AmiOwner],
        temp_results_dir: str,
    ) -> None:
        """Test check with all instances from trusted AMI owners."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.scps.deny_ec2_ami_owner.get_ec2_ami_owner_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_ami_owner_results_all_compliant

            check = DenyEc2AmiOwnerCheck(
                check_name=DENY_EC2_AMI_OWNER,
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
            assert summary["unique_ami_owners"] == ["amazon"]

    def test_check_empty_results(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test check with no EC2 instances found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.scps.deny_ec2_ami_owner.get_ec2_ami_owner_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyEc2AmiOwnerCheck(
                check_name=DENY_EC2_AMI_OWNER,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["total_instances"] == 0
            assert summary["violations"] == 0
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 100.0
            assert summary["unique_ami_owners"] == []

    def test_categorize_result_compliant(self) -> None:
        """Test categorization of instance from any AMI owner."""
        check = DenyEc2AmiOwnerCheck(
            check_name=DENY_EC2_AMI_OWNER,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
        )

        result = DenyEc2AmiOwner(
            instance_id="i-test",
            region="us-east-1",
            ami_id="ami-12345678",
            ami_owner="amazon",
            ami_name="Amazon Linux 2",
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-test"
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["instance_id"] == "i-test"
        assert result_dict["ami_owner"] == "amazon"

    def test_categorize_result_with_none_ami_name(self) -> None:
        """Test categorization when AMI name is None."""
        check = DenyEc2AmiOwnerCheck(
            check_name=DENY_EC2_AMI_OWNER,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
        )

        result = DenyEc2AmiOwner(
            instance_id="i-test",
            region="us-east-1",
            ami_id="ami-unknown",
            ami_owner="unknown",
            ami_name=None,
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-test"
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["ami_name"] is None

    def test_build_summary_fields(self, temp_results_dir: str) -> None:
        """Test summary fields calculation."""
        from headroom.checks.base import CategorizedCheckResult

        violations = []
        compliant = [
            {
                "instance_id": "i-1",
                "ami_owner": "amazon",
                "region": "us-east-1",
                "ami_id": "ami-1",
                "ami_name": "AL2",
                "instance_arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-1"
            },
            {
                "instance_id": "i-2",
                "ami_owner": "aws-marketplace",
                "region": "us-west-2",
                "ami_id": "ami-2",
                "ami_name": "Marketplace",
                "instance_arn": "arn:aws:ec2:us-west-2:111111111111:instance/i-2"
            },
            {
                "instance_id": "i-3",
                "ami_owner": "amazon",
                "region": "eu-west-1",
                "ami_id": "ami-3",
                "ami_name": "AL2023",
                "instance_arn": "arn:aws:ec2:eu-west-1:111111111111:instance/i-3"
            },
        ]

        check_result = CategorizedCheckResult(
            violations=violations,
            exemptions=[],
            compliant=compliant
        )

        check = DenyEc2AmiOwnerCheck(
            check_name=DENY_EC2_AMI_OWNER,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        summary = check.build_summary_fields(check_result)

        assert summary["total_instances"] == 3
        assert summary["violations"] == 0
        assert summary["compliant"] == 3
        assert summary["compliance_percentage"] == 100.0
        assert set(summary["unique_ami_owners"]) == {"amazon", "aws-marketplace"}

    def test_analyze_method_calls_analysis_function(self) -> None:
        """Test that analyze method properly calls the analysis function."""
        mock_session = MagicMock()

        with patch("headroom.checks.scps.deny_ec2_ami_owner.get_ec2_ami_owner_analysis") as mock_analysis:
            mock_analysis.return_value = []

            check = DenyEc2AmiOwnerCheck(
                check_name=DENY_EC2_AMI_OWNER,
                account_name="test",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
            )

            result = check.analyze(mock_session)

            mock_analysis.assert_called_once_with(mock_session)
            assert result == []
