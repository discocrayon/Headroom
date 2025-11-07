import pytest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from headroom.analysis import get_security_analysis_session, perform_analysis, get_subaccount_information, AccountInfo
from headroom.config import HeadroomConfig, AccountTagLayout


class TestSecurityAnalysisSession:
    def test_get_security_analysis_session_success(self) -> None:
        config = HeadroomConfig(
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        mock_sts = MagicMock()
        mock_session = MagicMock()
        creds = {
            "AccessKeyId": "FAKE_ACCESS_KEY_ID",
            "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
            "SessionToken": "FAKE_SESSION_TOKEN"
        }
        mock_sts.assume_role.return_value = {"Credentials": creds}
        with (
            patch("boto3.client", return_value=mock_sts) as client_patch,
            patch("boto3.Session", return_value=mock_session) as session_patch,
        ):
            session = get_security_analysis_session(config)
            client_patch.assert_called_once_with("sts")
            mock_sts.assume_role.assert_called_once_with(
                RoleArn="arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
                RoleSessionName="HeadroomSecurityAnalysisSession"
            )
            session_patch.assert_called_once_with(
                aws_access_key_id="FAKE_ACCESS_KEY_ID",
                aws_secret_access_key="FAKE_SECRET_ACCESS_KEY",
                aws_session_token="FAKE_SESSION_TOKEN"
            )
            assert session is mock_session

    def test_get_security_analysis_session_missing_account_id(self) -> None:
        config = HeadroomConfig(
            security_analysis_account_id=None,
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner")
        )
        with patch("boto3.Session") as session_patch:
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
            patch("boto3.Session") as session_patch,
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
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "AssumeRole")
        with patch("boto3.client", return_value=mock_sts):
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
    @patch("headroom.analysis.boto3.Session")
    @patch("headroom.analysis.logger")
    def test_get_subaccount_information_name_from_tags(self, mock_logger: MagicMock, mock_boto_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [
                {"Id": "222222222222", "Name": "MgmtAccount"},  # Should be skipped
                {"Id": "333333333333", "Name": "SubAccount1"},
                {"Id": "444444444444", "Name": "SubAccount2"},
                {"Id": "555555555555", "Name": "SubAccount3"},  # No tags
            ]}
        ]
        tag_map = {
            "333333333333": {"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "NameTag", "Value": "TagName1"}, {"Key": "OwnerTag", "Value": "Alice"}]},
            "444444444444": {"Tags": [{"Key": "Env", "Value": "dev"}, {"Key": "NameTag", "Value": "TagName2"}, {"Key": "OwnerTag", "Value": "Bob"}]},
            # "555555555555" intentionally missing to test default
        }
        mock_org_client.list_tags_for_resource.side_effect = lambda ResourceId: tag_map.get(ResourceId, {"Tags": []})
        mgmt_session = MagicMock()
        mgmt_session.client.side_effect = lambda service: mock_org_client if service == "organizations" else mock_sts
        mock_boto_session.return_value = mgmt_session
        session = MagicMock()
        session.client.return_value = mock_sts
        result = get_subaccount_information(config, session)
        assert result == [
            AccountInfo(account_id="333333333333", environment="prod", name="TagName1", owner="Alice"),
            AccountInfo(account_id="444444444444", environment="dev", name="TagName2", owner="Bob"),
            AccountInfo(account_id="555555555555", environment="unknown", name="555555555555", owner="unknown"),
        ]

    @patch("headroom.analysis.boto3.Session")
    @patch("headroom.analysis.logger")
    def test_get_subaccount_information_name_from_api(self, mock_logger: MagicMock, mock_boto_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [
                {"Id": "222222222222", "Name": "MgmtAccount"},
                {"Id": "333333333333", "Name": "SubAccount1"}
            ]}
        ]
        mock_org_client.list_tags_for_resource.return_value = {"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "OwnerTag", "Value": "Alice"}]}
        mgmt_session = MagicMock()
        mgmt_session.client.side_effect = lambda service: mock_org_client if service == "organizations" else mock_sts
        mock_boto_session.return_value = mgmt_session
        session = MagicMock()
        session.client.return_value = mock_sts
        result = get_subaccount_information(config, session)
        assert result == [
            AccountInfo(account_id="333333333333", environment="prod", name="SubAccount1", owner="Alice")
        ]

    @patch("headroom.analysis.boto3.Session")
    def test_get_subaccount_information_missing_management_account_id(self, mock_boto_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id=None,
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        session = MagicMock()
        with pytest.raises(ValueError, match="management_account_id must be set in config"):
            get_subaccount_information(config, session)

    @patch("headroom.analysis.boto3.Session")
    @patch("headroom.analysis.logger")
    def test_get_subaccount_information_tag_fetch_error(self, mock_logger: MagicMock, mock_boto_session: MagicMock) -> None:
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=True,
            account_tag_layout=AccountTagLayout(environment="Env", name="NameTag", owner="OwnerTag")
        )
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}
        mock_org_client = MagicMock()
        mock_org_client.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [
                {"Id": "333333333333", "Name": "SubAccount1"}
            ]}
        ]
        mock_org_client.list_tags_for_resource.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListTagsForResource")
        mgmt_session = MagicMock()
        mgmt_session.client.side_effect = lambda service: mock_org_client if service == "organizations" else mock_sts
        mock_boto_session.return_value = mgmt_session
        session = MagicMock()
        session.client.return_value = mock_sts
        result = get_subaccount_information(config, session)
        assert result == [
            AccountInfo(account_id="333333333333", environment="unknown", name="333333333333", owner="unknown")
        ]
        mock_logger.warning.assert_called()

    @patch("headroom.analysis.boto3.Session")
    def test_get_subaccount_information_assume_role_failure(self, mock_boto_session: MagicMock) -> None:
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
        with pytest.raises(RuntimeError, match="Failed to assume OrgAndAccountInfoReader role"):
            get_subaccount_information(config, session)
