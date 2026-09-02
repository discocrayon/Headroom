"""Tests for headroom.checks.scps.deny_iam_user_creation module."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from boto3.session import Session

from headroom.aws.iam import IamUserAnalysis
from headroom.checks.scps.deny_iam_user_creation import DenyIamUserCreationCheck
from headroom.parse_results import parse_scp_result_files
from headroom.types import AccountOrgPlacement, OrganizationHierarchy


def make_single_account_hierarchy() -> OrganizationHierarchy:
    """Build a one-account hierarchy naming 111111111111 as test-account."""
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="test-account",
                parent_ou_id=None,
                ou_path=["Root"],
            )
        },
    )


class TestCheckDenyIamUserCreation:
    """Test deny_iam_user_creation check."""

    def test_check_with_users(self, tmp_path: Path) -> None:
        """Test check when there are users in the account."""
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=Session)

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = [
                IamUserAnalysis(
                    user_name="admin",
                    user_arn="arn:aws:iam::111111111111:user/admin",
                    path="/",
                ),
                IamUserAnalysis(
                    user_name="developer",
                    user_arn="arn:aws:iam::111111111111:user/developer",
                    path="/",
                ),
            ]

            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_user_creation" / "test-account_111111111111.json"
        assert results_file.exists()

        with open(results_file) as f:
            results = json.load(f)

        assert results["summary"]["total_users"] == 2
        assert len(results["summary"]["users"]) == 2
        assert "arn:aws:iam::111111111111:user/admin" in results["summary"]["users"]
        assert "arn:aws:iam::111111111111:user/developer" in results["summary"]["users"]
        assert len(results["compliant_instances"]) == 2
        assert len(results["violations"]) == 0

    def test_check_no_users(self, tmp_path: Path) -> None:
        """Test check when there are no users."""
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=Session)

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = []

            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_user_creation" / "test-account_111111111111.json"
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
            account_id="111111111111",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=Session)

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = [
                IamUserAnalysis(
                    user_name="admin",
                    user_arn="arn:aws:iam::111111111111:user/admin",
                    path="/",
                ),
                IamUserAnalysis(
                    user_name="developer",
                    user_arn="arn:aws:iam::111111111111:user/developer",
                    path="/dev/",
                ),
            ]

            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_user_creation" / "test-account_111111111111.json"

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


class TestWhatThisCheckWritesCanBeParsedBack:
    """
    The check's own output has to survive the reader that consumes it.

    Nothing drove this round trip, so the check could write a summary the
    parser rejects and the suite stay green. That is how it went unnoticed that
    every entry being compliant left the summary with no violations count at
    all - fine while the reader defaulted a missing key, fatal once it stopped.
    """

    def test_a_written_result_parses(self, tmp_path: Path) -> None:
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
        )
        user = IamUserAnalysis(
            user_name="breakglass",
            user_arn="arn:aws:iam::111111111111:user/breakglass",
            path="/",
        )

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = [user]
            check.execute(MagicMock(spec=Session))

        hierarchy = make_single_account_hierarchy()
        parsed = parse_scp_result_files(str(tmp_path), hierarchy)

        assert [result.violations for result in parsed] == [0]
        assert [result.allowlist_values for result in parsed] == [
            ["arn:aws:iam::111111111111:user/breakglass"]
        ]

    def test_a_redacted_result_parses_back_to_the_real_arn(self, tmp_path: Path) -> None:
        """
        The writer's redaction and the reader's restoration are one round trip.

        `write_check_results` scrubs the account ID from every ARN when
        `exclude_account_ids` is set; `_read_declared_allowlist` has to
        restore exactly that account ID, or the allowlist names a
        placeholder rather than the account that actually observed the user.
        """
        check = DenyIamUserCreationCheck(
            check_name="deny_iam_user_creation",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
            exclude_account_ids=True,
        )
        user = IamUserAnalysis(
            user_name="breakglass",
            user_arn="arn:aws:iam::111111111111:user/breakglass",
            path="/",
        )

        with patch(
            "headroom.checks.scps.deny_iam_user_creation.get_iam_users_analysis"
        ) as mock_get_users:
            mock_get_users.return_value = [user]
            check.execute(MagicMock(spec=Session))

        written_files = list((tmp_path / "scps" / "deny_iam_user_creation").glob("*.json"))
        assert len(written_files) == 1
        written = written_files[0].read_text()
        assert "arn:aws:iam::REDACTED:user/breakglass" in written
        assert "111111111111" not in written

        hierarchy = make_single_account_hierarchy()
        parsed = parse_scp_result_files(str(tmp_path), hierarchy)

        assert [result.allowlist_values for result in parsed] == [
            ["arn:aws:iam::111111111111:user/breakglass"]
        ]
