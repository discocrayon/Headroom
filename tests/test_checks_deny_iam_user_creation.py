"""Tests for headroom.checks.scps.deny_iam_user_creation module."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from boto3.session import Session

from headroom.aws.iam import IamUserAnalysis
from headroom.checks.scps.deny_iam_user_creation import DenyIamUserCreationCheck


class TestCheckDenyIamUserCreation:
    """Test deny_iam_user_creation check."""

    def test_check_with_users(self, tmp_path: Path) -> None:
        """Test check when there are users in the account."""
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="123456789012",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=Session)

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = [
                IamUserAnalysis(
                    user_name="admin",
                    user_arn="arn:aws:iam::123456789012:user/admin",
                    path="/",
                ),
                IamUserAnalysis(
                    user_name="developer",
                    user_arn="arn:aws:iam::123456789012:user/developer",
                    path="/",
                ),
            ]

            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_user_creation" / "test-account_123456789012.json"
        assert results_file.exists()

        with open(results_file) as f:
            results = json.load(f)

        assert results["summary"]["total_users"] == 2
        assert len(results["summary"]["users"]) == 2
        assert "arn:aws:iam::123456789012:user/admin" in results["summary"]["users"]
        assert "arn:aws:iam::123456789012:user/developer" in results["summary"]["users"]
        assert len(results["compliant_instances"]) == 2
        assert len(results["violations"]) == 0

    def test_check_no_users(self, tmp_path: Path) -> None:
        """Test check when there are no users."""
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="123456789012",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=Session)

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = []

            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_user_creation" / "test-account_123456789012.json"
        assert results_file.exists()

        with open(results_file) as f:
            results = json.load(f)

        assert results["summary"]["total_users"] == 0
        assert results["summary"]["users"] == []

    def test_check_result_data_structure(self, tmp_path: Path) -> None:
        """Test that result data has correct structure."""
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="123456789012",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=Session)

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = [
                IamUserAnalysis(
                    user_name="admin",
                    user_arn="arn:aws:iam::123456789012:user/admin",
                    path="/",
                ),
                IamUserAnalysis(
                    user_name="developer",
                    user_arn="arn:aws:iam::123456789012:user/developer",
                    path="/dev/",
                ),
            ]

            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_user_creation" / "test-account_123456789012.json"

        with open(results_file) as f:
            results = json.load(f)

        assert "summary" in results
        assert "violations" in results
        assert "compliant_instances" in results

        assert len(results["violations"]) == 0
        assert len(results["compliant_instances"]) == 2

        compliant = results["compliant_instances"][0]
        assert "user_name" in compliant
        assert "user_arn" in compliant
        assert "path" in compliant
        assert compliant["user_name"] == "admin"
        assert compliant["path"] == "/"
