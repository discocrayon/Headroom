"""
Extended tests for analysis.py covering new SCP analysis functionality.

Tests for get_relevant_subaccounts, get_headroom_session, and run_checks functions.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator
from botocore.exceptions import ClientError  # type: ignore
from headroom.analysis import (
    get_relevant_subaccounts,
    get_headroom_session,
    run_checks,
    get_all_organization_account_ids,
    AccountInfo
)
from headroom.config import HeadroomConfig, AccountTagLayout


class TestGetRelevantSubaccounts:
    """Test get_relevant_subaccounts function with various filtering scenarios."""

    def test_get_relevant_subaccounts_returns_all_accounts(self) -> None:
        """Test that get_relevant_subaccounts returns all provided accounts."""
        account_infos = [
            AccountInfo(account_id="111111111111", environment="prod", name="prod-account", owner="team-a"),
            AccountInfo(account_id="222222222222", environment="dev", name="dev-account", owner="team-b"),
            AccountInfo(account_id="333333333333", environment="staging", name="staging-account", owner="team-c")
        ]

        result = get_relevant_subaccounts(account_infos)

        assert result == account_infos
        assert len(result) == 3

    def test_get_relevant_subaccounts_empty_input(self) -> None:
        """Test get_relevant_subaccounts with empty input list."""
        account_infos: List[AccountInfo] = []

        result = get_relevant_subaccounts(account_infos)

        assert result == []
        assert len(result) == 0

    def test_get_relevant_subaccounts_single_account(self) -> None:
        """Test get_relevant_subaccounts with single account."""
        account_infos = [
            AccountInfo(account_id="111111111111", environment="prod", name="single-account", owner="team-x")
        ]

        result = get_relevant_subaccounts(account_infos)

        assert result == account_infos
        assert len(result) == 1
        assert result[0].account_id == "111111111111"

    def test_get_relevant_subaccounts_preserves_order(self) -> None:
        """Test that get_relevant_subaccounts preserves input order."""
        account_infos = [
            AccountInfo(account_id="333333333333", environment="staging", name="staging-account", owner="team-c"),
            AccountInfo(account_id="111111111111", environment="prod", name="prod-account", owner="team-a"),
            AccountInfo(account_id="222222222222", environment="dev", name="dev-account", owner="team-b")
        ]

        result = get_relevant_subaccounts(account_infos)

        assert result == account_infos
        assert result[0].account_id == "333333333333"
        assert result[1].account_id == "111111111111"
        assert result[2].account_id == "222222222222"

    def test_get_relevant_subaccounts_handles_unknown_values(self) -> None:
        """Test get_relevant_subaccounts handles accounts with unknown values."""
        account_infos = [
            AccountInfo(account_id="111111111111", environment="unknown", name="111111111111", owner="unknown"),
            AccountInfo(account_id="222222222222", environment="dev", name="dev-account", owner="unknown")
        ]

        result = get_relevant_subaccounts(account_infos)

        assert result == account_infos
        assert len(result) == 2
        assert result[0].environment == "unknown"
        assert result[1].environment == "dev"


class TestGetHeadroomSession:
    """Test get_headroom_session function with various scenarios."""

    @pytest.fixture
    def mock_config(self) -> HeadroomConfig:
        """Create mock HeadroomConfig for testing."""
        return HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )

    def test_get_headroom_session_success(self, mock_config: HeadroomConfig) -> None:
        """Test successful Headroom session creation."""
        # Mock security session
        mock_security_session = MagicMock()
        mock_sts = MagicMock()
        mock_security_session.client.return_value = mock_sts

        # Mock STS response
        creds = {
            "AccessKeyId": "FAKE_ACCESS_KEY_ID",
            "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
            "SessionToken": "FAKE_SESSION_TOKEN"
        }
        mock_sts.assume_role.return_value = {"Credentials": creds}

        # Mock boto3.Session
        with patch("headroom.analysis.boto3.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session

            result = get_headroom_session(mock_config, mock_security_session, "111111111111")

            # Verify STS assume_role call
            mock_sts.assume_role.assert_called_once_with(
                RoleArn="arn:aws:iam::111111111111:role/Headroom",
                RoleSessionName="HeadroomAnalysisSession"
            )

            # Verify session creation
            mock_session_class.assert_called_once_with(
                aws_access_key_id="FAKE_ACCESS_KEY_ID",
                aws_secret_access_key="FAKE_SECRET_ACCESS_KEY",
                aws_session_token="FAKE_SESSION_TOKEN"
            )

            assert result == mock_session

    def test_get_headroom_session_assume_role_failure(self, mock_config: HeadroomConfig) -> None:
        """Test get_headroom_session when assume_role fails."""

        # Mock security session
        mock_security_session = MagicMock()
        mock_sts = MagicMock()
        mock_security_session.client.return_value = mock_sts

        # Mock STS failure
        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "AssumeRole"
        )

        with pytest.raises(RuntimeError, match="Failed to assume Headroom role in account 111111111111"):
            get_headroom_session(mock_config, mock_security_session, "111111111111")

    def test_get_headroom_session_different_account_ids(self, mock_config: HeadroomConfig) -> None:
        """Test get_headroom_session with different account IDs."""
        # Mock security session
        mock_security_session = MagicMock()
        mock_sts = MagicMock()
        mock_security_session.client.return_value = mock_sts

        creds = {
            "AccessKeyId": "FAKE_ACCESS_KEY_ID",
            "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
            "SessionToken": "FAKE_SESSION_TOKEN"
        }
        mock_sts.assume_role.return_value = {"Credentials": creds}

        with patch("headroom.analysis.boto3.Session"):
            # Test different account ID formats
            get_headroom_session(mock_config, mock_security_session, "111111111111")
            mock_sts.assume_role.assert_called_with(
                RoleArn="arn:aws:iam::111111111111:role/Headroom",
                RoleSessionName="HeadroomAnalysisSession"
            )

            get_headroom_session(mock_config, mock_security_session, "999999999999")
            mock_sts.assume_role.assert_called_with(
                RoleArn="arn:aws:iam::999999999999:role/Headroom",
                RoleSessionName="HeadroomAnalysisSession"
            )


class TestRunChecks:
    """Test run_checks function with various scenarios."""

    @pytest.fixture
    def mock_config(self) -> HeadroomConfig:
        """Create mock HeadroomConfig for testing."""
        return HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )

    @pytest.fixture
    def sample_account_infos(self) -> List[AccountInfo]:
        """Create sample AccountInfo list for testing."""
        return [
            AccountInfo(account_id="111111111111", environment="prod", name="prod-account", owner="team-a"),
            AccountInfo(account_id="222222222222", environment="dev", name="dev-account", owner="team-b")
        ]

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_run_checks_success(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo],
        temp_results_dir: str
    ) -> None:
        """Test successful run_checks execution."""
        mock_security_session = MagicMock()

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.analysis.check_deny_imds_v1_ec2") as mock_check,
            patch("headroom.analysis.check_third_party_role_access"),
            patch("headroom.analysis.logger") as mock_logger,
            patch("headroom.analysis.results_exist", return_value=False)
        ):
            mock_headroom_session1 = MagicMock()
            mock_headroom_session2 = MagicMock()
            mock_get_session.side_effect = [mock_headroom_session1, mock_headroom_session2]

            org_account_ids = {"111111111111", "222222222222", "333333333333"}
            run_checks(mock_security_session, sample_account_infos, mock_config, org_account_ids)

            # Directory creation is handled by individual check functions, not run_checks
            # run_checks itself no longer creates directories

            # Verify get_headroom_session calls
            assert mock_get_session.call_count == 2
            mock_get_session.assert_any_call(mock_config, mock_security_session, "111111111111")
            mock_get_session.assert_any_call(mock_config, mock_security_session, "222222222222")

            # Verify check function calls (includes results_dir and exclude_account_ids)
            assert mock_check.call_count == 2
            mock_check.assert_any_call(
                mock_headroom_session1,
                "prod-account",
                "111111111111",
                mock_config.results_dir,
                mock_config.exclude_account_ids,
            )
            mock_check.assert_any_call(
                mock_headroom_session2,
                "dev-account",
                "222222222222",
                mock_config.results_dir,
                mock_config.exclude_account_ids,
            )

            # Verify logging
            assert mock_logger.info.call_count == 4
            mock_logger.info.assert_any_call("Running checks for account: prod-account_111111111111")
            mock_logger.info.assert_any_call("Checks completed for account: prod-account_111111111111")

    def test_run_checks_with_fallback_account_name(
        self,
        mock_config: HeadroomConfig,
        temp_results_dir: str
    ) -> None:
        """Test run_checks with account using account ID as name fallback."""
        account_infos = [
            AccountInfo(account_id="111111111111", environment="prod", name="111111111111", owner="team-a")
        ]
        mock_security_session = MagicMock()

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.analysis.check_deny_imds_v1_ec2") as mock_check,
            patch("headroom.analysis.check_third_party_role_access"),
            patch("headroom.analysis.results_exist", return_value=False),
            patch("os.makedirs"),
            patch("os.getcwd") as mock_getcwd
        ):
            mock_getcwd.return_value = temp_results_dir
            mock_headroom_session = MagicMock()
            mock_get_session.return_value = mock_headroom_session

            org_account_ids = {"111111111111", "222222222222"}
            run_checks(mock_security_session, account_infos, mock_config, org_account_ids)

            # Verify check called with account ID as fallback name (includes results_dir and exclude_account_ids)
            mock_check.assert_called_once_with(
                mock_headroom_session,
                "111111111111",
                "111111111111",
                mock_config.results_dir,
                mock_config.exclude_account_ids,
            )

    def test_run_checks_session_failure(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo],
        temp_results_dir: str
    ) -> None:
        """Test run_checks when get_headroom_session fails."""
        mock_security_session = MagicMock()

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.analysis.check_deny_imds_v1_ec2"),
            patch("headroom.analysis.check_third_party_role_access"),
            patch("headroom.analysis.results_exist", return_value=False),
            patch("os.makedirs"),
            patch("os.getcwd") as mock_getcwd,
            pytest.raises(RuntimeError, match="Failed to run checks for account prod-account_111111111111: Failed to assume Headroom role")
        ):
            mock_getcwd.return_value = temp_results_dir
            mock_get_session.side_effect = RuntimeError("Failed to assume Headroom role")

            org_account_ids = {"111111111111", "222222222222"}
            run_checks(mock_security_session, sample_account_infos, mock_config, org_account_ids)

    def test_run_checks_skip_existing_results(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo],
        temp_results_dir: str
    ) -> None:
        """Test run_checks skips accounts when results already exist."""
        mock_security_session = MagicMock()

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.analysis.check_deny_imds_v1_ec2") as mock_check,
            patch("headroom.analysis.check_third_party_role_access"),
            patch("headroom.analysis.logger") as mock_logger,
            patch("headroom.analysis.results_exist") as mock_check_results
        ):
            # Mock that results exist for first account but not second (IMDS and RCP checks)
            mock_check_results.side_effect = [True, True, False, False]

            mock_headroom_session = MagicMock()
            mock_get_session.return_value = mock_headroom_session

            org_account_ids = {"111111111111", "222222222222"}
            run_checks(mock_security_session, sample_account_infos, mock_config, org_account_ids)

            # Verify get_headroom_session was only called for the second account
            assert mock_get_session.call_count == 1
            mock_get_session.assert_called_with(mock_config, mock_security_session, "222222222222")

            # Verify check was only called for the second account (includes results_dir and exclude_account_ids)
            assert mock_check.call_count == 1
            mock_check.assert_called_with(
                mock_headroom_session,
                "dev-account",
                "222222222222",
                mock_config.results_dir,
                mock_config.exclude_account_ids,
            )

            # Verify skip logging for first account
            mock_logger.info.assert_any_call("Results already exist for account prod-account_111111111111, skipping checks")

            # Verify normal execution logging for second account
            mock_logger.info.assert_any_call("Running checks for account: dev-account_222222222222")
            mock_logger.info.assert_any_call("Checks completed for account: dev-account_222222222222")

    def test_run_checks_empty_account_list(
        self,
        mock_config: HeadroomConfig,
        temp_results_dir: str
    ) -> None:
        """Test run_checks with empty account list."""
        mock_security_session = MagicMock()
        account_infos: List[AccountInfo] = []

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.analysis.check_deny_imds_v1_ec2") as mock_check,
            patch("headroom.analysis.check_third_party_role_access") as mock_rcp_check
        ):
            org_account_ids: set[str] = set()
            run_checks(mock_security_session, account_infos, mock_config, org_account_ids)

            # Verify no sessions or checks attempted
            mock_get_session.assert_not_called()
            mock_check.assert_not_called()
            mock_rcp_check.assert_not_called()


class TestGetAllOrganizationAccountIds:
    """Test get_all_organization_account_ids function."""

    def test_get_all_organization_account_ids_success(self) -> None:
        """Test successful retrieval of all organization account IDs."""
        mock_config = MagicMock()
        mock_config.management_account_id = "999999999999"

        mock_session = MagicMock()
        mock_sts = MagicMock()

        def mock_client_factory(service_name: str) -> MagicMock:
            if service_name == "sts":
                return mock_sts
            return MagicMock()  # pragma: no cover

        mock_session.client.side_effect = mock_client_factory

        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "FAKE_ACCESS_KEY_ID",
                "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
                "SessionToken": "FAKE_SESSION_TOKEN"
            }
        }

        mock_mgmt_session = MagicMock()
        mock_org_client = MagicMock()
        mock_mgmt_session.client.return_value = mock_org_client

        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator

        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "Name": "Account1"},
                    {"Id": "222222222222", "Name": "Account2"}
                ]
            },
            {
                "Accounts": [
                    {"Id": "333333333333", "Name": "Account3"}
                ]
            }
        ]

        with patch("headroom.analysis.boto3.Session", return_value=mock_mgmt_session):
            result = get_all_organization_account_ids(mock_config, mock_session)

        assert result == {"111111111111", "222222222222", "333333333333"}
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::999999999999:role/OrgAndAccountInfoReader",
            RoleSessionName="HeadroomOrgAccountListSession"
        )

    def test_get_all_organization_account_ids_missing_management_account_id(self) -> None:
        """Test that missing management_account_id raises ValueError."""
        mock_session = MagicMock()
        mock_config = MagicMock()
        mock_config.management_account_id = None

        with pytest.raises(ValueError, match="management_account_id must be set in config"):
            get_all_organization_account_ids(mock_config, mock_session)

    def test_get_all_organization_account_ids_assume_role_failure(self) -> None:
        """Test that assume role failure raises RuntimeError."""
        mock_config = MagicMock()
        mock_config.management_account_id = "999999999999"

        mock_session = MagicMock()
        mock_sts = MagicMock()

        def mock_client_factory(service_name: str) -> MagicMock:
            if service_name == "sts":
                return mock_sts
            return MagicMock()  # pragma: no cover

        mock_session.client.side_effect = mock_client_factory

        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "AssumeRole"
        )

        with pytest.raises(RuntimeError, match="Failed to assume OrgAndAccountInfoReader role"):
            get_all_organization_account_ids(mock_config, mock_session)
