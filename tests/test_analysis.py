import pytest
from typing import Any, Dict, List, Tuple, cast, get_args
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from mypy_boto3_organizations.literals import AccountStateType
from mypy_boto3_organizations.type_defs import AccountTypeDef

from headroom.analysis import (
    get_security_analysis_session,
    perform_analysis,
    get_subaccount_information,
    _build_account_info_from_account_dict,
    ACTIVE_ACCOUNT_STATE,
    INACTIVE_ACCOUNT_STATES,
    AccountInfo
)
from headroom.config import HeadroomConfig, AccountTagLayout


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
        account = cast(AccountTypeDef, {"Id": "123456789012", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "production"},
                {"Key": "NameTag", "Value": "TagAccountName"},
                {"Key": "OwnerTag", "Value": "TeamA"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
        assert result.name == "TagAccountName"
        assert result.environment == "production"
        assert result.owner == "TeamA"

    def test_build_account_info_without_tags_use_api_name(self) -> None:
        """Test building AccountInfo when not using name from tags."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "123456789012", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "staging"},
                {"Key": "NameTag", "Value": "TagAccountName"},
                {"Key": "OwnerTag", "Value": "TeamB"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
        assert result.name == "ApiAccountName"
        assert result.environment == "staging"
        assert result.owner == "TeamB"

    def test_build_account_info_missing_tags_defaults_to_unknown(self) -> None:
        """Test building AccountInfo with missing tags defaults to 'unknown'."""
        config = HeadroomConfig(
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "123456789012", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {"Tags": []}

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
        assert result.name == "123456789012"
        assert result.environment == "unknown"
        assert result.owner == "unknown"

    def test_build_account_info_partial_tags(self) -> None:
        """Test building AccountInfo with only some tags present."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "123456789012", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "dev"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
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
        account = cast(AccountTypeDef, {"Id": "123456789012", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "ListTagsForResource"
        )

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
        assert result.name == "123456789012"
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
        account = cast(AccountTypeDef, {"Id": "123456789012", "Name": "ApiAccountName"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "Service Error"}},
            "ListTagsForResource"
        )

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
        assert result.name == "123456789012"
        assert result.environment == "unknown"
        assert result.owner == "unknown"
        mock_logger.error.assert_called_once()

    def test_build_account_info_missing_account_name_in_api(self) -> None:
        """Test building AccountInfo when account Name field is missing."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        account = cast(AccountTypeDef, {"Id": "123456789012"})
        mock_org_client = MagicMock()
        mock_org_client.list_tags_for_resource.return_value = {
            "Tags": [
                {"Key": "Env", "Value": "production"},
                {"Key": "OwnerTag", "Value": "TeamC"}
            ]
        }

        result = _build_account_info_from_account_dict(account, mock_org_client, config)

        assert result.account_id == "123456789012"
        assert result.name == "123456789012"
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
