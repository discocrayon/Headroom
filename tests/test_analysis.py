import logging
import re
import threading
from concurrent.futures import Future, ThreadPoolExecutor

import pytest
from typing import Any, Dict, Iterable, Iterator, List, Tuple, cast, get_args
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from mypy_boto3_organizations.literals import AccountStateType
from mypy_boto3_organizations.type_defs import AccountTypeDef

from headroom.analysis import (
    get_security_analysis_session,
    perform_analysis,
    get_subaccount_information,
    run_checks,
    run_checks_for_type,
    _build_account_info_from_account_dict,
    _run_checks_for_account,
    _verify_no_duplicate_account_names,
    ACTIVE_ACCOUNT_STATE,
    INACTIVE_ACCOUNT_STATES,
    AccountInfo
)
from headroom.config import HeadroomConfig, AccountTagLayout
from headroom.log_context import AccountContextFilter


class TestSecurityAnalysisSession:
    def test_get_security_analysis_session_success(self) -> None:
        config = HeadroomConfig(
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        mock_session = MagicMock()
        with patch("headroom.analysis.assume_role", return_value=mock_session) as assume_role_patch:
            session = get_security_analysis_session(config)
            assume_role_patch.assert_called_once_with(
                "arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
                "HeadroomSecurityAnalysisSession"
            )
            assert session is mock_session

    def test_get_security_analysis_session_missing_account_id(self) -> None:
        config = HeadroomConfig(
            security_analysis_account_id=None,
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        with patch("headroom.analysis.new_session") as session_patch:
            session = get_security_analysis_session(config)
            session_patch.assert_called_once_with()
            assert session is session_patch.return_value

    def test_get_security_analysis_session_missing_account_id_with_logging(self) -> None:
        config = HeadroomConfig(
            security_analysis_account_id=None,
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        with (
            patch("headroom.analysis.new_session") as session_patch,
            patch("headroom.analysis.logger") as mock_logger,
        ):
            session = get_security_analysis_session(config)
            mock_logger.debug.assert_called_once_with("No security_analysis_account_id provided, assuming already in security analysis account")
            session_patch.assert_called_once_with()
            assert session is session_patch.return_value

    def test_get_security_analysis_session_sts_failure(self) -> None:
        config = HeadroomConfig(
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        with patch("headroom.analysis.assume_role", side_effect=RuntimeError("Failed to assume role")):
            with pytest.raises(RuntimeError, match="Failed to assume role"):
                get_security_analysis_session(config)


class TestPerformAnalysis:
    def test_perform_analysis_success(self) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        mock_session = MagicMock()
        with (
            patch("headroom.analysis.get_security_analysis_session", return_value=mock_session) as mock_get_session,
            patch("headroom.analysis.get_all_organization_account_ids", return_value=set()) as mock_get_org_ids,
            patch("headroom.analysis.get_subaccount_information", return_value=[]) as mock_get_subs,
            patch("headroom.analysis.run_checks"),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            perform_analysis(config)
            mock_get_session.assert_called_once_with(config)
            mock_get_org_ids.assert_called_once_with(config, mock_session)
            mock_get_subs.assert_called_once_with(config, mock_session)
            assert mock_logger.info.call_count == 7
            mock_logger.info.assert_any_call("Starting security analysis")
            mock_logger.info.assert_any_call("Successfully obtained security analysis session")
            mock_logger.info.assert_any_call("Fetched subaccount information: []")
            mock_logger.info.assert_any_call("Filtered to 0 relevant accounts for analysis")
            mock_logger.info.assert_any_call("Security analysis completed")

    def test_perform_analysis_without_account_id(self) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id=None,
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        mock_session = MagicMock()
        with (
            patch("headroom.analysis.get_security_analysis_session", return_value=mock_session) as mock_get_session,
            patch("headroom.analysis.get_all_organization_account_ids", return_value=set()) as mock_get_org_ids,
            patch("headroom.analysis.get_subaccount_information", return_value=[]) as mock_get_subs,
            patch("headroom.analysis.run_checks"),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            perform_analysis(config)
            mock_get_session.assert_called_once_with(config)
            mock_get_org_ids.assert_called_once_with(config, mock_session)
            mock_get_subs.assert_called_once_with(config, mock_session)
            assert mock_logger.info.call_count == 7
            mock_logger.info.assert_any_call("Filtered to 0 relevant accounts for analysis")

    def test_perform_analysis_aborts_before_run_checks_on_duplicate_names(self) -> None:
        """
        The duplicate-name guard must gate run_checks, not merely exist.

        Pins the ordering rather than just the raising: if the call to
        _verify_no_duplicate_account_names were deleted, or moved to after
        run_checks, this test would fail even though the guard itself would
        still raise correctly when called directly.
        """
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner"),
            exclude_account_ids=True,
        )
        colliding_account_infos = [
            AccountInfo(account_id="333333333333", environment="prod", name="shared-name", owner="team"),
            AccountInfo(account_id="444444444444", environment="prod", name="shared-name", owner="team"),
        ]
        mock_session = MagicMock()
        with (
            patch("headroom.analysis.get_security_analysis_session", return_value=mock_session),
            patch("headroom.analysis.get_all_organization_account_ids", return_value=set()),
            patch("headroom.analysis.get_subaccount_information", return_value=colliding_account_infos),
            patch("headroom.analysis.run_checks") as mock_run_checks,
        ):
            with pytest.raises(RuntimeError, match="shared-name"):
                perform_analysis(config)

            mock_run_checks.assert_not_called()


class TestGetSubaccountInformation:
    @patch("headroom.analysis.get_management_account_session")
    @patch("headroom.analysis.logger")
    def test_get_subaccount_information_name_from_tags(self, mock_logger: MagicMock, mock_get_mgmt_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [
                {"Id": "222222222222", "Name": "MgmtAccount", "State": "ACTIVE"},  # Should be skipped
                {"Id": "333333333333", "Name": "SubAccount1", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "SubAccount2", "State": "ACTIVE"},
                {"Id": "555555555555", "Name": "SubAccount3", "State": "ACTIVE"},  # No tags
            ]}
        ]
        tag_map = {
            "333333333333": {"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "NameTag", "Value": "TagName1"}, {"Key": "OwnerTag", "Value": "Alice"}]},
            "444444444444": {"Tags": [{"Key": "Env", "Value": "dev"}, {"Key": "NameTag", "Value": "TagName2"}, {"Key": "OwnerTag", "Value": "Bob"}]},
            # "555555555555" intentionally missing to test default
        }
        mock_org_client.list_tags_for_resource.side_effect = lambda ResourceId: tag_map.get(ResourceId, {"Tags": []})
        mgmt_session = MagicMock()
        mgmt_session.client.return_value = mock_org_client
        mock_get_mgmt_session.return_value = mgmt_session
        result = get_subaccount_information(config, MagicMock())
        assert result == [
            AccountInfo(account_id="333333333333", environment="prod", name="TagName1", owner="Alice"),
            AccountInfo(account_id="444444444444", environment="dev", name="TagName2", owner="Bob"),
            AccountInfo(account_id="555555555555", environment="unknown", name="555555555555", owner="unknown"),
        ]

    @patch("headroom.analysis.get_management_account_session")
    @patch("headroom.analysis.logger")
    def test_get_subaccount_information_name_from_api(self, mock_logger: MagicMock, mock_get_mgmt_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [
                {"Id": "222222222222", "Name": "MgmtAccount", "State": "ACTIVE"},
                {"Id": "333333333333", "Name": "SubAccount1", "State": "ACTIVE"}
            ]}
        ]
        mock_org_client.list_tags_for_resource.return_value = {"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "OwnerTag", "Value": "Alice"}]}
        mgmt_session = MagicMock()
        mgmt_session.client.return_value = mock_org_client
        mock_get_mgmt_session.return_value = mgmt_session
        result = get_subaccount_information(config, MagicMock())
        assert result == [
            AccountInfo(account_id="333333333333", environment="prod", name="SubAccount1", owner="Alice")
        ]

    def test_get_subaccount_information_missing_management_account_id(self) -> None:
        config = HeadroomConfig(
            management_account_id=None,
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        session = MagicMock()
        with pytest.raises(ValueError, match="management_account_id must be set in config"):
            get_subaccount_information(config, session)

    @patch("headroom.analysis.get_management_account_session")
    @patch("headroom.analysis.logger")
    def test_get_subaccount_information_tag_fetch_error(self, mock_logger: MagicMock, mock_get_mgmt_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [
                {"Id": "333333333333", "Name": "SubAccount1", "State": "ACTIVE"}
            ]}
        ]
        mock_org_client.list_tags_for_resource.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListTagsForResource")
        mgmt_session = MagicMock()
        mgmt_session.client.return_value = mock_org_client
        mock_get_mgmt_session.return_value = mgmt_session
        result = get_subaccount_information(config, MagicMock())
        assert result == [
            AccountInfo(account_id="333333333333", environment="unknown", name="333333333333", owner="unknown")
        ]
        mock_logger.warning.assert_called()

    def test_get_subaccount_information_assume_role_failure(self) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        # Patch session.client("sts").assume_role to raise ClientError
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "AssumeRole")
        session = MagicMock()
        session.client.return_value = mock_sts
        with pytest.raises(ClientError) as exc_info:
            get_subaccount_information(config, session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


class TestAccountStateFiltering:
    """
    Test that only ACTIVE accounts are analyzed.

    AWS Organizations reports an account's lifecycle position through two
    fields: `State` (PENDING_ACTIVATION, ACTIVE, SUSPENDED, PENDING_CLOSURE,
    CLOSED) and the older `Status` (ACTIVE, SUSPENDED, PENDING_CLOSURE), which
    AWS retires on 2026-09-09. Only an ACTIVE account can have the Headroom
    role assumed in it, so every other state is skipped.
    """

    @staticmethod
    def _config() -> HeadroomConfig:
        """Build a config whose management account is 222222222222."""
        return HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )

    def _run(
        self,
        accounts: List[Dict[str, Any]]
    ) -> Tuple[List[AccountInfo], MagicMock, MagicMock]:
        """Run get_subaccount_information over raw Organizations account dicts."""
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [{"Accounts": accounts}]
        mock_org_client.list_tags_for_resource.return_value = {"Tags": []}
        mgmt_session = MagicMock()
        mgmt_session.client.return_value = mock_org_client

        with (
            patch("headroom.analysis.get_management_account_session", return_value=mgmt_session),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            result = get_subaccount_information(self._config(), MagicMock())

        return result, mock_org_client, mock_logger

    def _analyzed_ids(self, accounts: List[Dict[str, Any]]) -> List[str]:
        """Return the account IDs that survived state filtering."""
        result, _, _ = self._run(accounts)
        return [account.account_id for account in result]

    def test_closed_account_is_skipped(self) -> None:
        """A CLOSED account is excluded; role assumption there is impossible."""
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Closed", "State": "CLOSED", "Status": "SUSPENDED"},
            {"Id": "444444444444", "Name": "Live", "State": "ACTIVE", "Status": "ACTIVE"},
        ])

        assert analyzed == ["444444444444"]

    def test_suspended_account_is_skipped(self) -> None:
        """A SUSPENDED account is excluded; AWS has restricted its access."""
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Suspended", "State": "SUSPENDED"},
            {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
        ])

        assert analyzed == ["444444444444"]

    def test_pending_closure_account_is_skipped(self) -> None:
        """
        A PENDING_CLOSURE account is excluded.

        Unlike the other skipped states this account is still functional, so the
        exclusion is deliberate policy: an account on its way out of the
        organization should not hold back an organization-wide recommendation.
        """
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Closing", "State": "PENDING_CLOSURE"},
            {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
        ])

        assert analyzed == ["444444444444"]

    def test_pending_activation_account_is_skipped(self) -> None:
        """A PENDING_ACTIVATION account is excluded; sign-up never completed."""
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Unactivated", "State": "PENDING_ACTIVATION"},
            {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
        ])

        assert analyzed == ["444444444444"]

    def test_active_account_is_analyzed(self) -> None:
        """An ACTIVE account is analyzed."""
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Live", "State": "ACTIVE", "Status": "ACTIVE"},
        ])

        assert analyzed == ["333333333333"]

    def test_state_takes_precedence_over_status(self) -> None:
        """
        `State` wins when the two fields disagree.

        AWS retires `Status` on 2026-09-09, so `State` is the authoritative field.
        """
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Live", "State": "ACTIVE", "Status": "SUSPENDED"},
        ])

        assert analyzed == ["333333333333"]

    def test_falls_back_to_status_when_state_absent(self) -> None:
        """
        `Status` is used when `State` is missing.

        An SDK released before 2025-09-09 does not model `State`, so botocore
        drops it from the response and only `Status` is available.
        """
        analyzed = self._analyzed_ids([
            {"Id": "333333333333", "Name": "Suspended", "Status": "SUSPENDED"},
            {"Id": "444444444444", "Name": "Live", "Status": "ACTIVE"},
        ])

        assert analyzed == ["444444444444"]

    def test_account_with_no_state_or_status_aborts_the_run(self) -> None:
        """
        An account reporting neither field aborts the run, with a remediation hint.

        The cause is environment-wide rather than per-account: an SDK too old to
        model `State` at a point when `Status` has been retired makes every
        account report nothing. Analyzing anyway would attempt every closed
        account and then die inside assume_role with an AccessDenied that names
        none of the real cause, so this fails at the point the information is
        actually missing.
        """
        with pytest.raises(RuntimeError, match="neither State nor Status") as exc_info:
            self._run([{"Id": "333333333333", "Name": "Unknown"}])

        # The error must be actionable, not merely loud.
        assert "boto3" in str(exc_info.value)

    def test_account_with_unrecognized_state_aborts_the_run(self) -> None:
        """
        A state this code does not classify aborts the run rather than guessing.

        Neither guess is safe. Analyzing an account that turns out to be unusable
        burns the run on a downstream error that explains nothing, and skipping
        one that is actually usable drops it from the compliance picture that
        gates SCP deployment. Refusing to guess keeps a human in the loop, so the
        message has to name both the offending value and the fix.
        """
        with pytest.raises(RuntimeError, match="does not recognize") as exc_info:
            self._run([{"Id": "333333333333", "Name": "Future", "State": "SOME_FUTURE_STATE"}])

        message = str(exc_info.value)
        assert "SOME_FUTURE_STATE" in message
        assert "INACTIVE_ACCOUNT_STATES" in message

    def test_every_state_aws_defines_is_classified(self) -> None:
        """
        The recognized states must exhaustively cover the AWS enum.

        Because an unrecognized state now aborts the run, a state AWS adds would
        break Headroom in production. This test moves that discovery to the point
        where boto3-stubs is upgraded: AccountStateType is the SDK's own
        enumeration, so if AWS adds a sixth state this fails in CI and names it,
        instead of a run failing at a customer.
        """
        assert set(get_args(AccountStateType)) == {ACTIVE_ACCOUNT_STATE} | INACTIVE_ACCOUNT_STATES

    def test_skipped_account_does_not_incur_a_tag_api_call(self) -> None:
        """Filtering happens before tag fetching, so skipped accounts cost no API calls."""
        _, mock_org_client, _ = self._run([
            {"Id": "333333333333", "Name": "Closed", "State": "CLOSED"},
            {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
        ])

        tagged_ids = [
            call.kwargs["ResourceId"]
            for call in mock_org_client.list_tags_for_resource.call_args_list
        ]
        assert tagged_ids == ["444444444444"]

    def test_management_account_is_still_excluded(self) -> None:
        """State filtering does not disturb the existing management account exclusion."""
        analyzed = self._analyzed_ids([
            {"Id": "222222222222", "Name": "Mgmt", "State": "ACTIVE"},
            {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
        ])

        assert analyzed == ["444444444444"]

    def test_skipped_accounts_are_summarized(self) -> None:
        """A summary line reports how many accounts were skipped in each state."""
        _, _, mock_logger = self._run([
            {"Id": "333333333333", "Name": "A", "State": "CLOSED"},
            {"Id": "444444444444", "Name": "B", "State": "CLOSED"},
            {"Id": "555555555555", "Name": "C", "State": "SUSPENDED"},
            {"Id": "666666666666", "Name": "D", "State": "ACTIVE"},
        ])

        logged = " ".join(str(call) for call in mock_logger.info.call_args_list)
        assert "2 CLOSED" in logged
        assert "1 SUSPENDED" in logged


class TestBuildAccountInfoFromAccountDict:
    """Test _build_account_info_from_account_dict helper function."""

    def test_build_account_info_with_tags_and_use_name_from_tags(self) -> None:
        """Test building AccountInfo when using name from tags."""
        config = HeadroomConfig(
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "production"},
                {"Key": "NameTag", "Value": "TagAccountName"},
                {"Key": "OwnerTag", "Value": "TeamA"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "TagAccountName"
        assert result.environment == "production"
        assert result.owner == "TeamA"

    def test_build_account_info_without_tags_use_api_name(self) -> None:
        """Test building AccountInfo when not using name from tags."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "staging"},
                {"Key": "NameTag", "Value": "TagAccountName"},
                {"Key": "OwnerTag", "Value": "TeamB"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "ApiAccountName"
        assert result.environment == "staging"
        assert result.owner == "TeamB"

    def test_build_account_info_missing_tags_defaults_to_unknown(self) -> None:
        """Test building AccountInfo with missing tags defaults to 'unknown'."""
        config = HeadroomConfig(
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {"Tags": []}

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "777777777777"
        assert result.environment == "unknown"
        assert result.owner == "unknown"

    def test_build_account_info_partial_tags(self) -> None:
        """Test building AccountInfo with only some tags present."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "dev"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "ApiAccountName"
        assert result.environment == "dev"
        assert result.owner == "unknown"

    @patch("headroom.analysis.logger")
    def test_build_account_info_tag_fetch_failure(self, mock_logger: MagicMock) -> None:
        """Test building AccountInfo when tag fetching fails."""
        config = HeadroomConfig(
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "ListTagsForResource"
        )

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "777777777777"
        assert result.environment == "unknown"
        assert result.owner == "unknown"
        mock_logger.warning.assert_called_once()

    @patch("headroom.analysis.logger")
    def test_build_account_info_with_other_client_error(self, mock_logger: MagicMock) -> None:
        """Test building AccountInfo when tags fetch fails with non-AccessDenied error."""
        config = HeadroomConfig(
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "Service Error"}},
            "ListTagsForResource"
        )

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "777777777777"
        assert result.environment == "unknown"
        assert result.owner == "unknown"
        mock_logger.error.assert_called_once()

    def test_build_account_info_missing_account_name_in_api(self) -> None:
        """Test building AccountInfo when account Name field is missing."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "777777777777"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "production"},
                {"Key": "OwnerTag", "Value": "TeamC"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "777777777777"
        assert result.name == "777777777777"
        assert result.environment == "production"
        assert result.owner == "TeamC"


class TestSkipAccountIds:
    """
    Test that accounts named in skip_account_ids are excluded from analysis.

    A skipped account is never scanned, so it writes no result files. Placement
    only ever sees accounts that have results, so a skipped account cannot hold
    back an org-wide policy and does not appear in its affected accounts. The
    generated policy may therefore deny actions the skipped account relies on,
    which is the accepted cost of skipping it.
    """

    @staticmethod
    def _config(skip_account_ids: List[str]) -> HeadroomConfig:
        """Build a config whose management account is 222222222222."""
        return HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag"),
            skip_account_ids=skip_account_ids,
        )

    def _run(
        self,
        accounts: List[Dict[str, Any]],
        skip_account_ids: List[str]
    ) -> Tuple[List[AccountInfo], MagicMock, MagicMock]:
        """Run get_subaccount_information over raw Organizations account dicts."""
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [{"Accounts": accounts}]
        mock_org_client.list_tags_for_resource.return_value = {"Tags": []}
        mgmt_session = MagicMock()
        mgmt_session.client.return_value = mock_org_client

        with (
            patch("headroom.analysis.get_management_account_session", return_value=mgmt_session),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            result = get_subaccount_information(self._config(skip_account_ids), MagicMock())

        return result, mock_org_client, mock_logger

    def test_skipped_account_is_excluded(self) -> None:
        """An account named in skip_account_ids is not analyzed."""
        result, _, _ = self._run(
            [
                {"Id": "333333333333", "Name": "Skipped", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
            ],
            skip_account_ids=["333333333333"],
        )

        assert [account.account_id for account in result] == ["444444444444"]

    def test_empty_skip_list_analyzes_every_active_account(self) -> None:
        """The default empty skip list excludes nothing."""
        result, _, _ = self._run(
            [
                {"Id": "333333333333", "Name": "One", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "Two", "State": "ACTIVE"},
            ],
            skip_account_ids=[],
        )

        assert [account.account_id for account in result] == ["333333333333", "444444444444"]

    def test_skipped_account_is_not_tag_queried(self) -> None:
        """
        A skipped account costs no Organizations API call.

        Skipping happens before AccountInfo is built, so the per-account
        ListTagsForResource call is never made for it.
        """
        _, mock_org_client, _ = self._run(
            [
                {"Id": "333333333333", "Name": "Skipped", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
            ],
            skip_account_ids=["333333333333"],
        )

        mock_org_client.list_tags_for_resource.assert_called_once_with(ResourceId="444444444444")

    def test_skipped_accounts_are_logged(self) -> None:
        """The operator can see which accounts the config excluded."""
        _, _, mock_logger = self._run(
            [
                {"Id": "333333333333", "Name": "SkippedOne", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "SkippedTwo", "State": "ACTIVE"},
                {"Id": "555555555555", "Name": "Live", "State": "ACTIVE"},
            ],
            skip_account_ids=["444444444444", "333333333333"],
        )

        mock_logger.info.assert_any_call(
            "Skipped 2 account(s) named in skip_account_ids: 333333333333, 444444444444"
        )

    def test_skip_takes_precedence_over_unknown_lifecycle_state(self) -> None:
        """
        Skipping an account bypasses lifecycle classification for it.

        An unrecognized lifecycle state normally aborts the run. Checking the
        skip list first makes skip_account_ids an escape hatch for the account
        that triggered the abort, so one odd account cannot block the run.
        """
        result, _, _ = self._run(
            [
                {"Id": "333333333333", "Name": "Odd", "State": "SOME_NEW_STATE"},
                {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
            ],
            skip_account_ids=["333333333333"],
        )

        assert [account.account_id for account in result] == ["444444444444"]

    def test_skipping_the_management_account_is_allowed(self) -> None:
        """
        Naming the always-excluded management account is redundant, not an error.

        The management account is filtered out before the skip list is consulted,
        so it never registers as skipped, but it is still a real organization
        member and must not be reported as unmatched.
        """
        result, _, _ = self._run(
            [
                {"Id": "222222222222", "Name": "Mgmt", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "Live", "State": "ACTIVE"},
            ],
            skip_account_ids=["222222222222"],
        )

        assert [account.account_id for account in result] == ["444444444444"]

    def test_skip_id_matching_no_account_aborts(self) -> None:
        """
        An entry matching no account aborts rather than silently doing nothing.

        A typo leaves the intended account being analyzed while the operator
        believes it is excluded, so the mismatch must surface.
        """
        with pytest.raises(RuntimeError, match="999999999999"):
            self._run(
                [{"Id": "444444444444", "Name": "Live", "State": "ACTIVE"}],
                skip_account_ids=["999999999999"],
            )

    def test_abort_names_every_unmatched_skip_id(self) -> None:
        """The error lists all bad entries so they can be fixed in one pass."""
        with pytest.raises(RuntimeError) as exc_info:
            self._run(
                [{"Id": "444444444444", "Name": "Live", "State": "ACTIVE"}],
                skip_account_ids=["999999999999", "888888888888"],
            )

        assert "888888888888, 999999999999" in str(exc_info.value)


class TestDuplicateAccountNameGuard:
    """
    Test that duplicate account names abort before any result file is written.

    With exclude_account_ids set, the result filename is the account name
    alone, so two accounts sharing a name resolve to one path. Serially that
    is last-writer-wins; with a worker per account it interleaves two
    accounts' JSON into one file, which then feeds policy generation.
    """

    @staticmethod
    def _config(exclude_account_ids: bool) -> HeadroomConfig:
        """Build a config with the given redaction setting."""
        return HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Env", name="NameTag", owner="OwnerTag"
            ),
            exclude_account_ids=exclude_account_ids,
        )

    @staticmethod
    def _accounts(*names: str) -> List[AccountInfo]:
        """Build one AccountInfo per name, each with a distinct account ID."""
        return [
            AccountInfo(
                account_id=str(index + 1) * 12,
                environment="prod",
                name=name,
                owner="team",
            )
            for index, name in enumerate(names)
        ]

    def test_duplicate_names_abort_when_ids_are_excluded(self) -> None:
        """Two accounts sharing a name would write the same file, so abort."""
        with pytest.raises(RuntimeError, match="shared-name"):
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                self._accounts("shared-name", "unique", "shared-name"),
            )

    def test_the_abort_message_names_no_account_id(self) -> None:
        """
        The message names the duplicated name and the count, never the IDs.

        Printing the IDs would defeat exclude_account_ids, which is the
        setting that created the collision in the first place.
        """
        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                self._accounts("shared-name", "shared-name"),
            )

        message = str(excinfo.value)
        assert "shared-name (2 accounts)" in message
        assert not re.search(r"\d{12}", message)

    def test_duplicate_names_are_allowed_when_ids_are_included(self) -> None:
        """
        With IDs in the filename, two accounts named alike do not collide.

        format_account_identifier appends the account ID, which is unique.
        """
        _verify_no_duplicate_account_names(
            self._config(exclude_account_ids=False),
            self._accounts("shared-name", "shared-name"),
        )

    def test_unique_names_pass(self) -> None:
        """Distinct names never collide, whatever the redaction setting."""
        _verify_no_duplicate_account_names(
            self._config(exclude_account_ids=True),
            self._accounts("one", "two", "three"),
        )

    def test_case_insensitive_collision_is_caught(self) -> None:
        """
        Names collide case-insensitively.

        Development happens on macOS, where APFS is case-insensitive by
        default: accounts named `Prod` and `prod` resolve to the same file
        on the filesystem this tool actually runs on, even though the two
        strings differ. The message must show both spellings so an operator
        sees why two names they consider different are flagged.
        """
        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                self._accounts("Prod", "prod"),
            )

        message = str(excinfo.value)
        assert "Prod" in message
        assert "prod" in message


class TestRunChecksPool:
    """Test the worker pool and its cooperative abort."""

    @staticmethod
    def _accounts(count: int) -> List[AccountInfo]:
        """Build `count` accounts with distinct names and IDs."""
        return [
            AccountInfo(
                account_id=str(index + 1) * 12,
                environment="prod",
                name=f"account-{index}",
                owner="team",
            )
            for index in range(count)
        ]

    @staticmethod
    def _config(max_account_workers: int) -> HeadroomConfig:
        """Build a config with the given pool size."""
        return HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Env", name="NameTag", owner="OwnerTag"
            ),
            max_account_workers=max_account_workers,
        )

    def test_every_pending_account_is_analyzed(self) -> None:
        """All accounts without results reach the worker."""
        seen: List[str] = []
        lock = threading.Lock()

        def record(account_info: AccountInfo, *args: object) -> None:
            with lock:
                seen.append(account_info.account_id)

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=record),
        ):
            run_checks(MagicMock(), self._accounts(5), self._config(4), set())

        assert sorted(seen) == sorted(a.account_id for a in self._accounts(5))

    def test_completed_accounts_never_reach_the_pool(self) -> None:
        """
        Accounts with all results present are filtered serially, up front.

        The filter is local filesystem I/O, so doing it before the pool starts
        keeps the "N accounts to scan" log line accurate.
        """
        worker = MagicMock()

        with (
            patch("headroom.analysis._all_checks_complete", return_value=True),
            patch("headroom.analysis._run_checks_for_account", worker),
        ):
            run_checks(MagicMock(), self._accounts(3), self._config(4), set())

        worker.assert_not_called()

    def test_accounts_are_analyzed_concurrently(self) -> None:
        """
        With four workers, four accounts are in flight at once.

        The barrier is the assertion: if fewer than four run simultaneously it
        times out and the test fails, which is how this pins parallelism
        rather than assuming it.
        """
        barrier = threading.Barrier(4, timeout=5)

        def wait_for_the_others(account_info: AccountInfo, *args: object) -> None:
            barrier.wait()

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=wait_for_the_others),
        ):
            run_checks(MagicMock(), self._accounts(4), self._config(4), set())

    def test_a_worker_failure_propagates_unchanged(self) -> None:
        """
        The first failure aborts the run rather than being logged and skipped.

        A partial run is more dangerous than no run: this output drives policy
        deployment, and an account skipped for a transient error looks exactly
        like an account with zero violations.
        """
        failure = RuntimeError("role assumption failed")

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=failure),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), self._accounts(3), self._config(1), set())

    def test_a_worker_returns_immediately_when_abort_is_set(self) -> None:
        """
        An in-flight worker bails at its next checkpoint.

        Python cannot kill a running thread, so cancelling queued futures is
        not enough: without this check, shutdown would block until every
        in-flight account finished all its remaining checks.
        """
        abort = threading.Event()
        abort.set()

        with patch("headroom.analysis.get_headroom_session") as mock_session:
            _run_checks_for_account(
                self._accounts(1)[0], MagicMock(), self._config(1), set(), abort
            )

        mock_session.assert_not_called()

    def test_no_further_checks_run_once_abort_is_set(self) -> None:
        """`run_checks_for_type` stops before starting the next check."""
        abort = threading.Event()
        abort.set()

        with patch("headroom.analysis.get_all_check_classes") as mock_classes:
            mock_classes.return_value = [MagicMock()]
            run_checks_for_type(
                "scps", MagicMock(), self._accounts(1)[0], self._config(1), set(), abort
            )

        mock_classes.return_value[0].assert_not_called()

    def test_the_first_failure_sets_the_abort_event(self) -> None:
        """
        The pool half of the abort: a failure sets the Event workers poll.

        The two checkpoint tests prove a worker stops once the Event is set.
        This proves the Event gets set, which nothing else pins: deleting
        `abort.set()` leaves the rest of the suite green while turning a
        prompt abort into one that waits out every in-flight account.
        """
        events: List[threading.Event] = []
        lock = threading.Lock()

        def fail(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            abort: threading.Event,
        ) -> None:
            with lock:
                events.append(abort)
            raise RuntimeError("role assumption failed")

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=fail),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), self._accounts(3), self._config(1), set())

        assert events
        assert events[0].is_set()

    def test_abort_stops_run_checks_for_type_between_checks(self) -> None:
        """
        The checkpoint sits in the loop body, so the next check never starts.

        Setting the Event before the call would pass with the checkpoint
        hoisted above the loop; failing mid-run is what pins the placement.
        """
        abort = threading.Event()
        first = MagicMock()
        second = MagicMock()
        first.CHECK_NAME = "first_check"
        second.CHECK_NAME = "second_check"
        first.return_value.execute.side_effect = lambda session: abort.set()

        with (
            patch("headroom.analysis.get_all_check_classes", return_value=[first, second]),
            patch("headroom.analysis.results_exist", return_value=False),
        ):
            run_checks_for_type(
                "scps", MagicMock(), self._accounts(1)[0], self._config(1), set(), abort
            )

        first.assert_called_once()
        second.assert_not_called()

    def test_each_account_builds_its_session_on_its_own_worker_thread(self) -> None:
        """
        Sessions are constructed inside the worker, never hoisted.

        The per-session memoization in `aws/helpers.py` and `aws/ec2.py` reads
        and writes without a lock, which is only safe because one thread owns
        each session. Building them on the calling thread would leave every
        account with its own session and every existing test green, while
        falsifying that premise and serializing N AssumeRole round trips.

        The barrier holds all four workers in `get_headroom_session` at once,
        so "four distinct threads" is a fact about the pool rather than about
        how fast a reused worker thread recycles.
        """
        barrier = threading.Barrier(4, timeout=5)
        lock = threading.Lock()
        building_threads: List[int] = []

        def record_building_thread(
            config: HeadroomConfig, security_session: object, account_id: str
        ) -> MagicMock:
            barrier.wait()
            with lock:
                building_threads.append(threading.get_ident())
            return MagicMock()

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis.all_check_results_exist", return_value=True),
            patch("headroom.analysis.get_headroom_session", side_effect=record_building_thread),
        ):
            run_checks(MagicMock(), self._accounts(4), self._config(4), set())

        assert len(building_threads) == 4
        assert threading.get_ident() not in building_threads
        assert len(set(building_threads)) == 4

    def test_a_worker_registers_its_account_for_log_records(self) -> None:
        """
        The worker wires Task 4's log context to the pool.

        `tests/test_log_context.py` covers the filter and `set_account` on
        their own; nothing else covers the single call site that connects
        them, so dropping it would silently revert every worker's log records
        to the no-account placeholder. The check runs on a thread of its own
        because an earlier test calling `_run_checks_for_account` directly
        leaves this thread's context already set.
        """
        stamped: List[str] = []

        def stamp_a_record(config: HeadroomConfig, security_session: object, account_id: str) -> MagicMock:
            record = logging.LogRecord(
                name="headroom.aws.ec2",
                level=logging.INFO,
                pathname=__file__,
                lineno=1,
                msg="Collecting EC2 instances in eu-west-1",
                args=(),
                exc_info=None,
            )
            AccountContextFilter().filter(record)
            stamped.append(record.account)  # type: ignore[attr-defined]
            return MagicMock()

        def run_the_worker() -> None:
            with (
                patch("headroom.analysis.all_check_results_exist", return_value=True),
                patch("headroom.analysis.get_headroom_session", side_effect=stamp_a_record),
            ):
                _run_checks_for_account(
                    self._accounts(1)[0], MagicMock(), self._config(1), set(), threading.Event()
                )

        thread = threading.Thread(target=run_the_worker)
        thread.start()
        thread.join(timeout=5)

        assert stamped == ["account-0_111111111111"]

    def test_the_cancel_loop_cancels_futures_still_in_the_queue(self) -> None:
        """
        Queued accounts are cancelled, not merely left to return early.

        Call-count assertions cannot see this loop: a queued account that is
        not cancelled still starts and returns immediately at the
        `_run_checks_for_account` abort checkpoint, so "did it run" cannot
        tell cancelled apart from merely-fast. `Future.cancelled()` can.
        `outstanding.cancel()` is the only `.cancel()` call in the package, so
        a captured future reporting cancelled is unambiguous evidence that
        this loop ran and took effect.

        `futures` is local to `run_checks`, so capturing the futures means
        patching `ThreadPoolExecutor.submit` -- a public method -- rather than
        reaching into the function under test.

        The queue is deliberately far longer than one worker can drain while
        the main thread is being scheduled to cancel it. That length is the
        margin, and it was measured rather than guessed: at 20 accounts the
        worker empties the queue often enough that nothing is left to cancel
        in 5 runs out of 400 under `setswitchinterval(1e-6)`, while at 200 the
        smallest count seen over 400 runs was 42 contended and 69 uncontended.
        """
        accounts = self._accounts(200)
        failing_account_id = accounts[0].account_id
        captured: List[Future[None]] = []
        real_submit = ThreadPoolExecutor.submit

        def capturing_submit(
            executor: ThreadPoolExecutor, fn: object, *args: object, **kwargs: object
        ) -> Future[None]:
            future: Future[None] = real_submit(executor, fn, *args, **kwargs)  # type: ignore[arg-type]
            captured.append(future)
            return future

        def fail_the_first_account(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            abort: threading.Event,
        ) -> None:
            if account_info.account_id == failing_account_id:
                raise RuntimeError("role assumption failed")

        with (
            patch.object(ThreadPoolExecutor, "submit", capturing_submit),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=fail_the_first_account),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), accounts, self._config(1), set())

        assert len(captured) == len(accounts)
        assert sum(1 for future in captured if future.cancelled()) >= 1

    def test_a_keyboard_interrupt_aborts_the_run_rather_than_draining_the_queue(self) -> None:
        """
        Ctrl-C sets the abort Event and cancels the accounts still queued.

        `Executor.__exit__` calls `shutdown(wait=True)`, whose default
        `cancel_futures=False` drains nothing: the `None` sentinel goes to the
        back of the work queue, so every queued account still runs before a
        worker sees it. Without the handler an interrupt therefore waits out
        the entire remaining run -- at `max_account_workers=1`, the value
        SETUP.md recommends for debugging, hours of ignoring Ctrl-C. The
        serial loop this pool replaced raised immediately.

        A `KeyboardInterrupt` raised inside a worker is a different scenario.
        The real one is SIGINT delivered to the main thread while it blocks in
        `as_completed` waiting for the first account to finish, which is what
        patching `as_completed` reproduces.

        The first account parks until the Event is set, so the pool's one
        worker is genuinely in flight when the interrupt lands and the other
        accounts are genuinely queued behind it -- the shape that makes
        cancellation observable rather than a race against a worker that has
        already emptied the queue.
        """
        accounts = self._accounts(200)
        blocking_account_id = accounts[0].account_id
        captured: List[Future[None]] = []
        aborts: List[threading.Event] = []
        entered: List[str] = []
        lock = threading.Lock()
        real_submit = ThreadPoolExecutor.submit

        def capturing_submit(
            executor: ThreadPoolExecutor, fn: object, *args: object, **kwargs: object
        ) -> Future[None]:
            future: Future[None] = real_submit(executor, fn, *args, **kwargs)  # type: ignore[arg-type]
            captured.append(future)
            aborts.append(cast(threading.Event, args[4]))
            return future

        def park_the_first_account(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            abort: threading.Event,
        ) -> None:
            with lock:
                entered.append(account_info.account_id)
            if account_info.account_id == blocking_account_id:
                abort.wait(timeout=5)

        def interrupt_while_the_main_thread_waits(
            futures: Iterable[Future[None]]
        ) -> Iterator[Future[None]]:
            """
            Stand in for `as_completed` and raise where a SIGINT would land.

            `yield from ()` makes this a generator that yields no future, so
            the raise happens on the loop's first `next()` -- inside the `for`
            statement, exactly where the signal handler would raise it -- and
            not at the call.
            """
            yield from ()
            raise KeyboardInterrupt

        with (
            patch.object(ThreadPoolExecutor, "submit", capturing_submit),
            patch("headroom.analysis.as_completed", interrupt_while_the_main_thread_waits),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=park_the_first_account),
            pytest.raises(KeyboardInterrupt),
        ):
            run_checks(MagicMock(), accounts, self._config(1), set())

        assert len(captured) == len(accounts)
        assert aborts[0].is_set()
        assert sum(1 for future in captured if future.cancelled()) >= 1
        assert len(entered) < len(accounts)

    def test_an_aborted_account_does_not_log_that_its_checks_completed(self) -> None:
        """
        A worker cut short mid-flight says so rather than claiming success.

        The entry checkpoint only covers a worker that has not started. One
        that is already running finds `run_checks_for_type` returning early
        for both check types and then reaches the end of the function, where
        it used to log "Checks completed" -- during exactly the incident an
        operator is reading the log to diagnose.
        """
        abort = threading.Event()

        def abort_partway_through(*args: object) -> None:
            abort.set()

        with (
            patch("headroom.analysis.get_headroom_session"),
            patch("headroom.analysis.all_check_results_exist", return_value=False),
            patch("headroom.analysis.run_checks_for_type", side_effect=abort_partway_through),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            _run_checks_for_account(
                self._accounts(1)[0], MagicMock(), self._config(1), set(), abort
            )

        logged = [call.args[0] for call in mock_logger.info.call_args_list]
        assert "Checks aborted for account: account-0_111111111111" in logged
        assert "Checks completed for account: account-0_111111111111" not in logged
