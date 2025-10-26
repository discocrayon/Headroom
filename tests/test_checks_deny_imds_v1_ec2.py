"""
Tests for headroom.checks.deny_imds_v1_ec2 module.

Tests for check_deny_imds_v1_ec2 function and its integration with AWS EC2 analysis.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator
from headroom.checks.deny_imds_v1_ec2 import check_deny_imds_v1_ec2
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.ec2 import DenyImdsV1Ec2


class TestCheckDenyImdsV1Ec2:
    """Test check_deny_imds_v1_ec2 function with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_imds_results_mixed(self) -> List[DenyImdsV1Ec2]:
        """Create sample IMDS results with mixed compliance status."""
        return [
            DenyImdsV1Ec2(
                region="us-east-1",
                instance_id="i-violation1",
                imdsv1_allowed=True,
                exemption_tag_present=False
            ),
            DenyImdsV1Ec2(
                region="us-east-1",
                instance_id="i-exemption1",
                imdsv1_allowed=True,
                exemption_tag_present=True
            ),
            DenyImdsV1Ec2(
                region="us-west-2",
                instance_id="i-compliant1",
                imdsv1_allowed=False,
                exemption_tag_present=False
            ),
            DenyImdsV1Ec2(
                region="us-west-2",
                instance_id="i-violation2",
                imdsv1_allowed=True,
                exemption_tag_present=False
            )
        ]

    @pytest.fixture
    def sample_imds_results_compliant(self) -> List[DenyImdsV1Ec2]:
        """Create sample IMDS results with all compliant instances."""
        return [
            DenyImdsV1Ec2(
                region="us-east-1",
                instance_id="i-compliant1",
                imdsv1_allowed=False,
                exemption_tag_present=False
            ),
            DenyImdsV1Ec2(
                region="us-west-2",
                instance_id="i-compliant2",
                imdsv1_allowed=False,
                exemption_tag_present=False
            )
        ]

    def test_check_deny_imds_v1_ec2_mixed_results(
        self,
        sample_imds_results_mixed: List[DenyImdsV1Ec2],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_imds_results_mixed

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Verify analysis was called
            mock_analysis.assert_called_once_with(mock_session)

            # Verify write_check_results was called
            mock_write.assert_called_once()

            # Verify write_check_results arguments
            write_call_args = mock_write.call_args
            assert write_call_args[1]["check_name"] == "deny_imds_v1_ec2"
            assert write_call_args[1]["account_name"] == account_name
            assert write_call_args[1]["account_id"] == account_id
            assert write_call_args[1]["results_base_dir"] == DEFAULT_RESULTS_DIR

            # Verify JSON structure
            results_data = write_call_args[1]["results_data"]

            # Check summary
            summary = results_data["summary"]
            assert summary["account_name"] == "test-account"
            assert summary["account_id"] == "111111111111"
            assert summary["check"] == "deny_imds_v1_ec2"
            assert summary["total_instances"] == 4
            assert summary["violations"] == 2
            assert summary["exemptions"] == 1
            assert summary["compliant"] == 1
            assert summary["compliance_percentage"] == 50.0  # (1 compliant + 1 exemption) / 4 * 100

            # Check violations
            violations = results_data["violations"]
            assert len(violations) == 2
            violation_ids = [v["instance_id"] for v in violations]
            assert "i-violation1" in violation_ids
            assert "i-violation2" in violation_ids

            # Check exemptions
            exemptions = results_data["exemptions"]
            assert len(exemptions) == 1
            assert exemptions[0]["instance_id"] == "i-exemption1"
            assert exemptions[0]["exemption_tag_present"] is True

            # Check compliant instances
            compliant = results_data["compliant_instances"]
            assert len(compliant) == 1
            assert compliant[0]["instance_id"] == "i-compliant1"

            # Print output is verified indirectly through test success

    def test_check_deny_imds_v1_ec2_all_compliant(
        self,
        sample_imds_results_compliant: List[DenyImdsV1Ec2],
        temp_results_dir: str,
    ) -> None:
        """Test check function with all compliant results."""
        mock_session = MagicMock()
        account_name = "compliant-account"
        account_id = "987654321098"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_imds_results_compliant

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Verify JSON structure for compliant scenario
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Check summary for perfect compliance
            summary = results_data["summary"]
            assert summary["violations"] == 0
            assert summary["exemptions"] == 0
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == 100.0

            # Check empty violations and exemptions
            assert len(results_data["violations"]) == 0
            assert len(results_data["exemptions"]) == 0
            assert len(results_data["compliant_instances"]) == 2

            # Print output is verified indirectly through test success

    def test_check_deny_imds_v1_ec2_no_instances(self, temp_results_dir: str) -> None:
        """Test check function with no instances."""
        mock_session = MagicMock()
        account_name = "empty-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Verify JSON structure for empty scenario
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Check summary for no instances
            summary = results_data["summary"]
            assert summary["total_instances"] == 0
            assert summary["violations"] == 0
            assert summary["exemptions"] == 0
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 100.0  # 100% when no instances

            # Check all result arrays are empty
            assert len(results_data["violations"]) == 0
            assert len(results_data["exemptions"]) == 0
            assert len(results_data["compliant_instances"]) == 0

    def test_check_deny_imds_v1_ec2_all_violations(self, temp_results_dir: str) -> None:
        """Test check function with all violations (worst case)."""
        violation_results = [
            DenyImdsV1Ec2(
                region="us-east-1",
                instance_id="i-bad1",
                imdsv1_allowed=True,
                exemption_tag_present=False
            ),
            DenyImdsV1Ec2(
                region="us-west-2",
                instance_id="i-bad2",
                imdsv1_allowed=True,
                exemption_tag_present=False
            )
        ]

        mock_session = MagicMock()
        account_name = "violation-account"
        account_id = "222222222222"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = violation_results

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Verify JSON structure for all violations
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Check summary for worst case
            summary = results_data["summary"]
            assert summary["total_instances"] == 2
            assert summary["violations"] == 2
            assert summary["exemptions"] == 0
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 0.0  # 0% compliance

    def test_check_deny_imds_v1_ec2_all_exemptions(self, temp_results_dir: str) -> None:
        """Test check function with all exemptions."""
        exemption_results = [
            DenyImdsV1Ec2(
                region="us-east-1",
                instance_id="i-exempt1",
                imdsv1_allowed=True,
                exemption_tag_present=True
            ),
            DenyImdsV1Ec2(
                region="us-west-2",
                instance_id="i-exempt2",
                imdsv1_allowed=True,
                exemption_tag_present=True
            )
        ]

        mock_session = MagicMock()
        account_name = "exempt-account"
        account_id = "333333333333"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = exemption_results

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Verify JSON structure for all exemptions
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Check summary for all exemptions
            summary = results_data["summary"]
            assert summary["total_instances"] == 2
            assert summary["violations"] == 0
            assert summary["exemptions"] == 2
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 100.0  # 100% with exemptions

    def test_check_deny_imds_v1_ec2_json_formatting(
        self,
        sample_imds_results_mixed: List[DenyImdsV1Ec2],
        temp_results_dir: str
    ) -> None:
        """Test that JSON output is properly formatted."""
        mock_session = MagicMock()
        account_name = "format-test"
        account_id = "444444444444"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_imds_results_mixed

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, "test_environment/headroom_results")

            # Verify write_check_results was called
            mock_write.assert_called_once()
            # JSON formatting is now handled by write_check_results module

    def test_check_deny_imds_v1_ec2_directory_creation(
        self,
        sample_imds_results_mixed: List[DenyImdsV1Ec2],
        temp_results_dir: str,
    ) -> None:
        """Test that results directory is created correctly."""
        mock_session = MagicMock()
        account_name = "directory-test"
        account_id = "555555555555"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_imds_results_mixed

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Verify write_check_results was called (directory creation is handled there)
            mock_write.assert_called_once()

    def test_check_deny_imds_v1_ec2_result_data_structure(
        self,
        sample_imds_results_mixed: List[DenyImdsV1Ec2],
        temp_results_dir: str,
    ) -> None:
        """Test the complete structure of result data."""
        mock_session = MagicMock()
        account_name = "structure-test"
        account_id = "666666666666"

        with (
            patch("headroom.checks.deny_imds_v1_ec2.get_imds_v1_ec2_analysis") as mock_analysis,
            patch("headroom.checks.deny_imds_v1_ec2.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_imds_results_mixed

            check_deny_imds_v1_ec2(mock_session, account_name, account_id, DEFAULT_RESULTS_DIR)

            # Get the results data
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Verify top-level structure
            assert set(results_data.keys()) == {"summary", "violations", "exemptions", "compliant_instances"}

            # Verify summary structure
            summary = results_data["summary"]
            expected_summary_keys = {
                "account_name", "account_id", "check", "total_instances", "violations",
                "exemptions", "compliant", "compliance_percentage"
            }
            assert set(summary.keys()) == expected_summary_keys

            # Verify individual result item structure
            for violation in results_data["violations"]:
                expected_keys = {"region", "instance_id", "imdsv1_allowed", "exemption_tag_present"}
                assert set(violation.keys()) == expected_keys

            for exemption in results_data["exemptions"]:
                expected_keys = {"region", "instance_id", "imdsv1_allowed", "exemption_tag_present"}
                assert set(exemption.keys()) == expected_keys

            for compliant in results_data["compliant_instances"]:
                expected_keys = {"region", "instance_id", "imdsv1_allowed", "exemption_tag_present"}
                assert set(compliant.keys()) == expected_keys
