"""
Extended tests for analysis.py covering new SCP analysis functionality.

Tests for get_relevant_subaccounts, get_headroom_session, and run_checks functions.
"""

import pytest
import tempfile
import shutil
import threading
from boto3.session import Session
from unittest.mock import MagicMock, patch
from typing import List, Generator

from botocore.exceptions import ClientError
from headroom.analysis import (
    get_relevant_subaccounts,
    get_headroom_session,
    run_checks,
    run_checks_for_type,
    get_all_organization_account_ids,
    AccountInfo
)
from headroom.checks.base import BaseCheck
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
        with patch("headroom.analysis.assume_role") as mock_assume_role:
            mock_session = MagicMock()
            mock_assume_role.return_value = mock_session

            result = get_headroom_session(mock_config, mock_security_session, "111111111111")

            mock_assume_role.assert_called_once_with(
                "arn:aws:iam::111111111111:role/Headroom",
                "HeadroomAnalysisSession",
                mock_security_session
            )

            assert result is mock_session

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

        with pytest.raises(ClientError) as exc_info:
            get_headroom_session(mock_config, mock_security_session, "111111111111")

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

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

        with patch("headroom.analysis.new_session"):
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
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def mock_config(self, temp_results_dir: str) -> HeadroomConfig:
        """Create mock HeadroomConfig for testing."""
        return HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner"),
            results_dir=temp_results_dir
        )

    @pytest.fixture
    def sample_account_infos(self) -> List[AccountInfo]:
        """Create sample AccountInfo list for testing."""
        return [
            AccountInfo(account_id="111111111111", environment="prod", name="prod-account", owner="team-a"),
            AccountInfo(account_id="222222222222", environment="dev", name="dev-account", owner="team-b")
        ]

    def test_run_checks_success(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo],
        temp_results_dir: str
    ) -> None:
        """
        Test successful run_checks execution.

        Pinned to one worker, and not out of timidity: every assertion below
        counts calls on MagicMocks that all workers share, and
        `MagicMock.__call__` does `self.call_count += 1` in Python. That
        read-modify-write loses increments when two workers land in it at
        once, so under contention the counts come back low even though the
        run was correct -- measured at 5 failures in 200 runs at
        `sys.setswitchinterval(1e-6)`. No assertion rewrite fixes that,
        because no assertion is wrong; the measuring apparatus is what is not
        thread-safe.

        Nothing here is about concurrency. It asserts per-account behaviour:
        both accounts analyzed, each with its own session. One worker runs
        the identical code path, and concurrency is pinned deterministically
        by TestRunChecksPool.test_accounts_are_analyzed_concurrently in
        tests/test_analysis.py.
        """
        mock_security_session = MagicMock()
        mock_config.max_account_workers = 1

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.checks.scps.deny_ec2_imds_v1.DenyEc2ImdsV1Check.execute") as mock_scp_execute,
            patch("headroom.checks.scps.deny_iam_user_creation.DenyIamUserCreationCheck.execute"),
            patch("headroom.checks.scps.deny_rds_unencrypted.DenyRdsUnencryptedCheck.execute"),
            patch("headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.DenySamlProviderNotAwsSsoCheck.execute"),
            patch("headroom.checks.rcps.deny_sts_third_party_assumerole.ThirdPartyAssumeRoleCheck.execute"),
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

            # Verify check execute method was called (once per account for SCP checks)
            assert mock_scp_execute.call_count == 2
            # Check classes are instantiated with check parameters, then execute() is called with session
            mock_scp_execute.assert_any_call(mock_headroom_session1)
            mock_scp_execute.assert_any_call(mock_headroom_session2)

            # Verify logging: the pool size line, then two lines per account
            assert mock_logger.info.call_count == 5
            mock_logger.info.assert_any_call("Analyzing 2 account(s) with 1 worker(s)")
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
            patch("headroom.checks.scps.deny_ec2_imds_v1.DenyEc2ImdsV1Check.execute") as mock_check,
            patch("headroom.checks.scps.deny_iam_user_creation.DenyIamUserCreationCheck.execute"),
            patch("headroom.checks.scps.deny_rds_unencrypted.DenyRdsUnencryptedCheck.execute"),
            patch("headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.DenySamlProviderNotAwsSsoCheck.execute"),
            patch("headroom.checks.rcps.deny_sts_third_party_assumerole.ThirdPartyAssumeRoleCheck.execute"),
            patch("headroom.analysis.results_exist", return_value=False)
        ):
            mock_headroom_session = MagicMock()
            mock_get_session.return_value = mock_headroom_session

            org_account_ids = {"111111111111", "222222222222"}
            run_checks(mock_security_session, account_infos, mock_config, org_account_ids)

            # Verify check execute method was called with session
            # (check parameters are passed to constructor, not execute)
            mock_check.assert_called_once_with(mock_headroom_session)

    def test_run_checks_fails_fast_on_session_failure(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo],
        temp_results_dir: str
    ) -> None:
        """
        A session failure propagates out of run_checks instead of being skipped.

        This is intentional, not a missing feature - do not "fix" it by logging
        and continuing. See
        test_run_checks_does_not_swallow_client_errors_or_continue for the full
        rationale and for the stronger guarantee that no later account is
        attempted; this test covers only the generic case.
        """
        mock_security_session = MagicMock()

        with (
            patch("headroom.analysis.get_headroom_session") as mock_get_session,
            patch("headroom.checks.scps.deny_ec2_imds_v1.DenyEc2ImdsV1Check.execute"),
            patch("headroom.checks.scps.deny_iam_user_creation.DenyIamUserCreationCheck.execute"),
            patch("headroom.checks.scps.deny_rds_unencrypted.DenyRdsUnencryptedCheck.execute"),
            patch("headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.DenySamlProviderNotAwsSsoCheck.execute"),
            patch("headroom.checks.rcps.deny_sts_third_party_assumerole.ThirdPartyAssumeRoleCheck.execute"),
            patch("headroom.analysis.results_exist", return_value=False),
            pytest.raises(RuntimeError, match="Failed to assume Headroom role")
        ):
            mock_get_session.side_effect = RuntimeError("Failed to assume Headroom role")

            org_account_ids = {"111111111111", "222222222222"}
            run_checks(mock_security_session, sample_account_infos, mock_config, org_account_ids)

    def test_run_checks_does_not_swallow_client_errors_or_continue(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo],
        temp_results_dir: str
    ) -> None:
        """
        A ClientError from role assumption aborts the whole run, by design.

        Do not add error handling here that logs the failure and continues to the
        next account. A partial run is more dangerous than no run: Headroom's
        output drives SCP and RCP deployment, and an account skipped because of a
        transient credentials error is indistinguishable in the results from an
        account with zero violations. Swallowing the error could green-light a
        policy that breaks the account that was never actually examined.

        This pins what test_run_checks_fails_fast_on_session_failure cannot: the
        concrete error type `assume_role` raises propagates uncaught, carrying
        its error code, rather than being wrapped or replaced.

        It deliberately does not assert how many accounts were attempted.
        Accounts run in a worker pool, so every account the pool has already
        started is in flight when the first one fails, and how many that is
        depends on thread scheduling. What stops the rest is pinned
        deterministically by three tests in TestRunChecksPool, in
        tests/test_analysis.py, which together carry the whole chain: the
        failure sets the abort Event
        (test_the_first_failure_sets_the_abort_event), a queued worker returns
        without assuming a role once it is set
        (test_a_worker_returns_immediately_when_abort_is_set), and an
        in-flight worker stops at its next check boundary
        (test_abort_stops_run_checks_for_type_between_checks).
        """
        mock_security_session = MagicMock()
        access_denied = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized to assume role"}},
            "AssumeRole"
        )

        with (
            patch("headroom.analysis.assume_role", side_effect=access_denied) as mock_assume_role,
            patch("headroom.analysis.results_exist", return_value=False),
            pytest.raises(ClientError) as exc_info,
        ):
            run_checks(mock_security_session, sample_account_infos, mock_config, {"111111111111"})

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

        # The error came from assuming the Headroom role, not from somewhere else.
        assert mock_assume_role.call_args.args[0].endswith(":role/Headroom")

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
            patch("headroom.checks.scps.deny_ec2_ami_owner.DenyEc2AmiOwnerCheck.execute") as mock_check_ami,
            patch("headroom.checks.scps.deny_ec2_imds_v1.DenyEc2ImdsV1Check.execute") as mock_check,
            patch("headroom.checks.scps.deny_ec2_public_ip.DenyEc2PublicIpCheck.execute") as mock_check_public_ip,
            patch("headroom.checks.scps.deny_eks_create_cluster_without_tag.DenyEksCreateClusterWithoutTagCheck.execute") as mock_check_eks,
            patch("headroom.checks.scps.deny_iam_user_creation.DenyIamUserCreationCheck.execute") as mock_check2,
            patch("headroom.checks.scps.deny_ec2_imds_hop_limit.DenyEc2ImdsHopLimitCheck.execute") as mock_check_hop,
            patch("headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.DenySamlProviderNotAwsSsoCheck.execute") as mock_check_saml,
            patch("headroom.checks.scps.deny_lambda_auth_type_none.DenyLambdaAuthTypeNoneCheck.execute") as mock_check_lambda,
            patch("headroom.checks.scps.deny_rds_unencrypted.DenyRdsUnencryptedCheck.execute") as mock_check3,
            patch("headroom.checks.rcps.deny_sts_third_party_assumerole.ThirdPartyAssumeRoleCheck.execute"),
            patch("headroom.checks.rcps.deny_ecr_third_party_access.DenyECRThirdPartyAccessCheck.execute"),
            patch("headroom.checks.rcps.deny_kms_third_party_access.DenyKMSThirdPartyAccessCheck.execute"),
            patch("headroom.checks.rcps.deny_s3_third_party_access.DenyS3ThirdPartyAccessCheck.execute"),
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.DenySecretsManagerThirdPartyAccessCheck.execute"),
            patch("headroom.checks.rcps.deny_sqs_third_party_access.DenySQSThirdPartyAccessCheck.execute"),
            patch("headroom.analysis.logger") as mock_logger,
            patch("headroom.analysis.results_exist") as mock_check_results
        ):
            # Results exist for the first account and for no other. Keyed on the
            # account rather than on call order: accounts are analyzed
            # concurrently, so the order `results_exist` is reached in is not
            # defined, and the up-front completeness filter regroups the calls
            # even at one worker.
            def results_exist_for_first_account(**kwargs: object) -> bool:
                return kwargs["account_name"] == "prod-account"

            mock_check_results.side_effect = results_exist_for_first_account

            mock_headroom_session = MagicMock()
            mock_get_session.return_value = mock_headroom_session

            org_account_ids = {"111111111111", "222222222222"}
            run_checks(mock_security_session, sample_account_infos, mock_config, org_account_ids)

            # Verify get_headroom_session was only called for the second account
            assert mock_get_session.call_count == 1
            mock_get_session.assert_called_with(mock_config, mock_security_session, "222222222222")

            # Verify check execute methods were only called for the second account
            # (check parameters are passed to constructor, not execute)
            # Order: ami(0), imds_v1(1), public_ip(2), eks(3), iam_saml(4), iam_user(5), rds(6)
            assert mock_check_ami.call_count == 1
            mock_check_ami.assert_called_with(mock_headroom_session)
            assert mock_check.call_count == 1
            mock_check.assert_called_with(mock_headroom_session)
            assert mock_check_public_ip.call_count == 1
            mock_check_public_ip.assert_called_with(mock_headroom_session)
            assert mock_check_eks.call_count == 1
            mock_check_eks.assert_called_with(mock_headroom_session)
            assert mock_check_saml.call_count == 1
            mock_check_saml.assert_called_with(mock_headroom_session)
            assert mock_check2.call_count == 1
            mock_check2.assert_called_with(mock_headroom_session)
            assert mock_check_lambda.call_count == 1
            mock_check_lambda.assert_called_with(mock_headroom_session)
            assert mock_check_hop.call_count == 1
            mock_check_hop.assert_called_with(mock_headroom_session)
            assert mock_check3.call_count == 1
            mock_check3.assert_called_with(mock_headroom_session)

            # Verify skip logging for first account
            mock_logger.info.assert_any_call("All results already exist for account prod-account_111111111111, skipping checks")

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
            patch("headroom.checks.scps.deny_ec2_imds_v1.DenyEc2ImdsV1Check.execute") as mock_check,
            patch("headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.DenySamlProviderNotAwsSsoCheck.execute") as mock_saml_check,
            patch("headroom.checks.rcps.deny_sts_third_party_assumerole.ThirdPartyAssumeRoleCheck.execute") as mock_rcp_check
        ):
            org_account_ids: set[str] = set()
            run_checks(mock_security_session, account_infos, mock_config, org_account_ids)

            # Verify no sessions or checks attempted
            mock_get_session.assert_not_called()
            mock_check.assert_not_called()
            mock_saml_check.assert_not_called()
            mock_rcp_check.assert_not_called()

    def test_run_checks_for_type_skips_individual_check(
        self,
        mock_config: HeadroomConfig,
        sample_account_infos: List[AccountInfo]
    ) -> None:
        """Test run_checks_for_type skips individual checks when results exist."""
        mock_session = MagicMock(spec=Session)
        account_info = sample_account_infos[0]

        # Create two mock check classes
        mock_check1 = MagicMock(spec=BaseCheck)
        mock_check1.CHECK_NAME = "check_1"
        mock_check1_instance = MagicMock()
        mock_check1.return_value = mock_check1_instance

        mock_check2 = MagicMock(spec=BaseCheck)
        mock_check2.CHECK_NAME = "check_2"
        mock_check2_instance = MagicMock()
        mock_check2.return_value = mock_check2_instance

        with (
            patch("headroom.analysis.get_all_check_classes", return_value=[mock_check1, mock_check2]),
            patch("headroom.analysis.results_exist") as mock_results_exist
        ):
            # First check results exist (skip with continue), second doesn't (run it)
            mock_results_exist.side_effect = [True, False]

            org_account_ids = {"111111111111"}
            completed = run_checks_for_type(
                "scps", mock_session, account_info, mock_config, org_account_ids, threading.Event()
            )

            # Verify first check was skipped (not instantiated or executed)
            mock_check1.assert_not_called()
            mock_check1_instance.execute.assert_not_called()

            # Verify second check was instantiated and executed
            mock_check2.assert_called_once()
            mock_check2_instance.execute.assert_called_once_with(mock_session)

            # A check already on disk is not an early stop: the type ran to the end.
            assert completed is True


class TestGetAllOrganizationAccountIds:
    """Test get_all_organization_account_ids function."""

    def test_get_all_organization_account_ids_success(self) -> None:
        """Test successful retrieval of all organization account IDs."""
        mock_config = MagicMock()
        mock_config.management_account_id = "999999999999"

        mock_session = MagicMock()

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

        with patch("headroom.analysis.get_management_account_session", return_value=mock_mgmt_session) as mock_get_mgmt_session:
            result = get_all_organization_account_ids(mock_config, mock_session)

        assert result == {"111111111111", "222222222222", "333333333333"}
        mock_get_mgmt_session.assert_called_once_with(mock_config, mock_session)

    def test_get_all_organization_account_ids_includes_non_active_accounts(self) -> None:
        """
        Non-active accounts must stay in the organization membership set.

        This set is the "is this principal inside my organization?" oracle for the
        third-party RCP checks. A CLOSED or SUSPENDED account remains an
        organization member until AWS removes it, and organization-based RCP
        conditions still match it. Filtering it out here would reclassify a
        recently-closed sibling account as a third party and produce false
        positive findings, so the lifecycle-state filtering applied in
        get_subaccount_information deliberately does not apply to this function.
        """
        mock_config = MagicMock()
        mock_config.management_account_id = "999999999999"

        mock_mgmt_session = MagicMock()
        mock_org_client = MagicMock()
        mock_mgmt_session.client.return_value = mock_org_client
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "Name": "Active", "State": "ACTIVE"},
                    {"Id": "222222222222", "Name": "Closed", "State": "CLOSED"},
                    {"Id": "333333333333", "Name": "Suspended", "State": "SUSPENDED"},
                    {"Id": "444444444444", "Name": "Closing", "State": "PENDING_CLOSURE"},
                ]
            }
        ]

        with patch("headroom.analysis.get_management_account_session", return_value=mock_mgmt_session):
            result = get_all_organization_account_ids(mock_config, MagicMock())

        assert result == {
            "111111111111",
            "222222222222",
            "333333333333",
            "444444444444",
        }

    def test_get_all_organization_account_ids_includes_skipped_accounts(self) -> None:
        """
        Accounts named in skip_account_ids must stay in the membership set.

        skip_account_ids means "do not scan this account", not "pretend it left
        the organization". This set is subtracted from the principals observed
        in resource policies to find third parties, so dropping a skipped
        account would reclassify it as a third party and add it to the
        generated RCP allowlist. That widens the policy, which is the opposite
        of what skipping an account should do.
        """
        config = HeadroomConfig(
            management_account_id="999999999999",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner"),
            skip_account_ids=["222222222222"],
        )

        mock_mgmt_session = MagicMock()
        mock_org_client = MagicMock()
        mock_mgmt_session.client.return_value = mock_org_client
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "Name": "Scanned", "State": "ACTIVE"},
                    {"Id": "222222222222", "Name": "Skipped", "State": "ACTIVE"},
                ]
            }
        ]

        with patch("headroom.analysis.get_management_account_session", return_value=mock_mgmt_session):
            result = get_all_organization_account_ids(config, MagicMock())

        assert result == {"111111111111", "222222222222"}

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
        mock_session.region_name = "us-west-2"
        mock_sts = MagicMock()

        def mock_client_factory(service_name: str, region_name: str, config: object) -> MagicMock:
            if service_name == "sts":
                return mock_sts
            return MagicMock()  # pragma: no cover

        mock_session.client.side_effect = mock_client_factory

        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "AssumeRole"
        )

        with pytest.raises(ClientError) as exc_info:
            get_all_organization_account_ids(mock_config, mock_session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"
