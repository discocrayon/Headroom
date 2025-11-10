"""
Tests for headroom.checks.scps.deny_rds_unencrypted module.

Tests for DenyRdsUnencryptedCheck and its integration with RDS analysis.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.scps.deny_rds_unencrypted import DenyRdsUnencryptedCheck
from headroom.constants import DENY_RDS_UNENCRYPTED
from headroom.aws.rds import DenyRdsUnencrypted


class TestCheckDenyRdsUnencrypted:
    """Test deny_rds_unencrypted check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_rds_results_mixed(self) -> List[DenyRdsUnencrypted]:
        """Create sample RDS results with mixed compliance status."""
        return [
            DenyRdsUnencrypted(
                db_identifier="encrypted-instance",
                db_type="instance",
                region="us-east-1",
                engine="postgres",
                encrypted=True,
                db_arn="arn:aws:rds:us-east-1:111111111111:db:encrypted-instance"
            ),
            DenyRdsUnencrypted(
                db_identifier="unencrypted-instance",
                db_type="instance",
                region="us-east-1",
                engine="mysql",
                encrypted=False,
                db_arn="arn:aws:rds:us-east-1:111111111111:db:unencrypted-instance"
            ),
            DenyRdsUnencrypted(
                db_identifier="encrypted-cluster",
                db_type="cluster",
                region="us-west-2",
                engine="aurora-mysql",
                encrypted=True,
                db_arn="arn:aws:rds:us-west-2:111111111111:cluster:encrypted-cluster"
            ),
            DenyRdsUnencrypted(
                db_identifier="unencrypted-cluster",
                db_type="cluster",
                region="us-west-2",
                engine="aurora-postgresql",
                encrypted=False,
                db_arn="arn:aws:rds:us-west-2:111111111111:cluster:unencrypted-cluster"
            )
        ]

    @pytest.fixture
    def sample_rds_results_compliant(self) -> List[DenyRdsUnencrypted]:
        """Create sample RDS results with all encrypted databases."""
        return [
            DenyRdsUnencrypted(
                db_identifier="encrypted-db-1",
                db_type="instance",
                region="us-east-1",
                engine="postgres",
                encrypted=True,
                db_arn="arn:aws:rds:us-east-1:111111111111:db:encrypted-db-1"
            ),
            DenyRdsUnencrypted(
                db_identifier="encrypted-db-2",
                db_type="cluster",
                region="us-west-2",
                engine="aurora-mysql",
                encrypted=True,
                db_arn="arn:aws:rds:us-west-2:111111111111:cluster:encrypted-db-2"
            )
        ]

    def test_check_deny_rds_unencrypted_mixed_results(
        self,
        sample_rds_results_mixed: List[DenyRdsUnencrypted],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.scps.deny_rds_unencrypted.get_rds_unencrypted_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_rds_results_mixed

            check = DenyRdsUnencryptedCheck(
                check_name=DENY_RDS_UNENCRYPTED,
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
            assert write_call_args[1]["check_name"] == "deny_rds_unencrypted"
            assert write_call_args[1]["account_name"] == account_name
            assert write_call_args[1]["account_id"] == account_id
            assert write_call_args[1]["results_base_dir"] == temp_results_dir

            # Verify JSON structure
            results_data = write_call_args[1]["results_data"]

            # Check summary
            summary = results_data["summary"]
            assert summary["account_name"] == "test-account"
            assert summary["account_id"] == "111111111111"
            assert summary["check"] == "deny_rds_unencrypted"
            assert summary["total_databases"] == 4
            assert summary["violations"] == 2
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == 50.0

            # Check violations
            violations = results_data["violations"]
            assert len(violations) == 2
            violation_ids = [v["db_identifier"] for v in violations]
            assert "unencrypted-instance" in violation_ids
            assert "unencrypted-cluster" in violation_ids

            # Verify violation details
            for violation in violations:
                assert violation["encrypted"] is False
                assert "db_type" in violation
                assert "region" in violation
                assert "engine" in violation
                assert "db_arn" in violation

            # Check compliant databases
            compliant = results_data["compliant_instances"]
            assert len(compliant) == 2
            compliant_ids = [c["db_identifier"] for c in compliant]
            assert "encrypted-instance" in compliant_ids
            assert "encrypted-cluster" in compliant_ids

            # Verify compliant details
            for comp in compliant:
                assert comp["encrypted"] is True

    def test_check_deny_rds_unencrypted_all_compliant(
        self,
        sample_rds_results_compliant: List[DenyRdsUnencrypted],
        temp_results_dir: str,
    ) -> None:
        """Test check function with all encrypted databases."""
        mock_session = MagicMock()
        account_name = "compliant-account"
        account_id = "222222222222"

        with (
            patch("headroom.checks.scps.deny_rds_unencrypted.get_rds_unencrypted_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_rds_results_compliant

            check = DenyRdsUnencryptedCheck(
                check_name=DENY_RDS_UNENCRYPTED,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify JSON structure for compliant scenario
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Check summary for perfect compliance
            summary = results_data["summary"]
            assert summary["violations"] == 0
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == 100.0

            # Check empty violations
            assert len(results_data["violations"]) == 0
            assert len(results_data["compliant_instances"]) == 2

    def test_check_deny_rds_unencrypted_no_databases(self, temp_results_dir: str) -> None:
        """Test check function with no databases."""
        mock_session = MagicMock()
        account_name = "empty-account"
        account_id = "333333333333"

        with (
            patch("headroom.checks.scps.deny_rds_unencrypted.get_rds_unencrypted_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyRdsUnencryptedCheck(
                check_name=DENY_RDS_UNENCRYPTED,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results for empty account
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            summary = results_data["summary"]
            assert summary["total_databases"] == 0
            assert summary["violations"] == 0
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 100.0  # No databases = 100% compliant

            assert len(results_data["violations"]) == 0
            assert len(results_data["compliant_instances"]) == 0

    def test_check_deny_rds_unencrypted_all_violations(self, temp_results_dir: str) -> None:
        """Test check function with all unencrypted databases."""
        mock_session = MagicMock()
        account_name = "violation-account"
        account_id = "444444444444"

        all_unencrypted = [
            DenyRdsUnencrypted(
                db_identifier="unencrypted-1",
                db_type="instance",
                region="us-east-1",
                engine="mysql",
                encrypted=False,
                db_arn="arn:aws:rds:us-east-1:444444444444:db:unencrypted-1"
            ),
            DenyRdsUnencrypted(
                db_identifier="unencrypted-2",
                db_type="cluster",
                region="us-west-2",
                engine="aurora-postgresql",
                encrypted=False,
                db_arn="arn:aws:rds:us-west-2:444444444444:cluster:unencrypted-2"
            )
        ]

        with (
            patch("headroom.checks.scps.deny_rds_unencrypted.get_rds_unencrypted_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_unencrypted

            check = DenyRdsUnencryptedCheck(
                check_name=DENY_RDS_UNENCRYPTED,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results for all violations
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            summary = results_data["summary"]
            assert summary["total_databases"] == 2
            assert summary["violations"] == 2
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 0.0

            assert len(results_data["violations"]) == 2
            assert len(results_data["compliant_instances"]) == 0

    def test_check_deny_rds_unencrypted_categorize_result(self) -> None:
        """Test categorize_result method for correct categorization."""
        check = DenyRdsUnencryptedCheck(
            check_name=DENY_RDS_UNENCRYPTED,
            account_name="test",
            account_id="111111111111",
            results_dir="/tmp/test-results",
        )

        # Test unencrypted database (violation)
        unencrypted = DenyRdsUnencrypted(
            db_identifier="unencrypted-db",
            db_type="instance",
            region="us-east-1",
            engine="postgres",
            encrypted=False,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:unencrypted-db"
        )

        category, result_dict = check.categorize_result(unencrypted)
        assert category == "violation"
        assert result_dict["db_identifier"] == "unencrypted-db"
        assert result_dict["encrypted"] is False

        # Test encrypted database (compliant)
        encrypted = DenyRdsUnencrypted(
            db_identifier="encrypted-db",
            db_type="cluster",
            region="us-west-2",
            engine="aurora-mysql",
            encrypted=True,
            db_arn="arn:aws:rds:us-west-2:111111111111:cluster:encrypted-db"
        )

        category, result_dict = check.categorize_result(encrypted)
        assert category == "compliant"
        assert result_dict["db_identifier"] == "encrypted-db"
        assert result_dict["encrypted"] is True

    def test_check_deny_rds_unencrypted_build_summary_fields(self) -> None:
        """Test build_summary_fields method for correct calculations."""
        from headroom.checks.base import CategorizedCheckResult

        check = DenyRdsUnencryptedCheck(
            check_name=DENY_RDS_UNENCRYPTED,
            account_name="test",
            account_id="111111111111",
            results_dir="/tmp/test-results",
        )

        # Test with mixed results
        violations = [
            {"db_identifier": "unencrypted-1", "encrypted": False},
            {"db_identifier": "unencrypted-2", "encrypted": False}
        ]

        compliant = [
            {"db_identifier": "encrypted-1", "encrypted": True},
            {"db_identifier": "encrypted-2", "encrypted": True},
            {"db_identifier": "encrypted-3", "encrypted": True}
        ]

        check_result = CategorizedCheckResult(
            violations=violations,
            compliant=compliant,
            exemptions=[],
            summary={}
        )

        summary_fields = check.build_summary_fields(check_result)

        assert summary_fields["total_databases"] == 5
        assert summary_fields["violations"] == 2
        assert summary_fields["compliant"] == 3
        assert summary_fields["compliance_percentage"] == pytest.approx(60.0, rel=0.01)

        # Test with all compliant
        check_result_all_compliant = CategorizedCheckResult(
            violations=[],
            compliant=compliant,
            exemptions=[],
            summary={}
        )

        summary_fields_compliant = check.build_summary_fields(check_result_all_compliant)
        assert summary_fields_compliant["compliance_percentage"] == pytest.approx(100.0, rel=0.01)

        # Test with no databases
        check_result_empty = CategorizedCheckResult(
            violations=[],
            compliant=[],
            exemptions=[],
            summary={}
        )

        summary_fields_empty = check.build_summary_fields(check_result_empty)
        assert summary_fields_empty["total_databases"] == 0
        assert summary_fields_empty["compliance_percentage"] == 100.0
