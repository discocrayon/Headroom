import logging
import re
import threading
from concurrent.futures import Future, ThreadPoolExecutor, wait
from contextlib import ExitStack

import pytest
from typing import Any, Dict, Iterable, Iterator, List, Set, Tuple, cast, get_args
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
    _fetch_account_tags,
    _run_checks_for_account,
    _verify_account_names_are_filename_safe,
    _verify_no_duplicate_account_names,
    ACTIVE_ACCOUNT_STATE,
    INACTIVE_ACCOUNT_STATES,
    AccountInfo
)
from headroom.checks.base import BaseCheck
from headroom.checks.registry import get_all_check_classes, get_check_names
from headroom.config import HeadroomConfig, AccountTagLayout
from headroom.log_context import NO_ACCOUNT, AccountContextFilter
from tests.constants import ORG_ID


# The AAAABBBBCCCC pattern in HOW_TO_ADD_A_CHECK.md has 1000 values.
# `_account_infos` starts at the tertiary one, 333333333333, which both reads
# clearest for the first account and puts every ID it builds out of reach of the
# 111111111111 and 222222222222 that the `_config` helpers below already use.
FIRST_ACCOUNT_TRIPLE = 333
MAX_GENERATED_ACCOUNTS = 1000 - FIRST_ACCOUNT_TRIPLE


def _account_infos(*names: str) -> List[AccountInfo]:
    """
    Build one AccountInfo per name, each with a distinct twelve-digit ID.

    One derivation serves all three callers. Three copies of it is what let
    `str(index + 1) * 12` survive here after the pool tests were fixed: that
    expression is twelve digits only through index 8.

    Args:
        *names: Account names, in the order the IDs are assigned

    Returns:
        One account per name, IDs ascending from 333333333333

    Raises:
        ValueError: If more names arrive than the pattern has values left
    """
    if len(names) > MAX_GENERATED_ACCOUNTS:
        raise ValueError(
            f"only {MAX_GENERATED_ACCOUNTS} accounts can be built: the "
            f"AAAABBBBCCCC pattern has 1000 values and this helper starts at "
            f"{FIRST_ACCOUNT_TRIPLE}, so {len(names)} of them cannot all have a "
            "twelve-digit ID"
        )
    return [
        AccountInfo(
            account_id="".join(
                digit * 4 for digit in f"{FIRST_ACCOUNT_TRIPLE + index:03d}"
            ),
            environment="prod",
            name=name,
            owner="team",
        )
        for index, name in enumerate(names)
    ]


def _org_client_for_account_listing(accounts_pages: List[Dict[str, Any]]) -> Tuple[MagicMock, MagicMock]:
    """
    Build an Organizations client whose get_paginator routes by operation name.

    get_subaccount_information calls get_paginator twice on the same client --
    once for list_accounts, then once per account for list_tags_for_resource --
    and a plain MagicMock returns the identical sub-mock for both calls
    regardless of the operation name passed, so configuring one paginator's
    `paginate` would silently answer the other's calls too. list_accounts
    always yields accounts_pages here; the tags paginator is returned
    separately so a caller configures its `paginate` however the test needs --
    a fixed return_value, a per-ResourceId side_effect, or a ClientError -- and
    can inspect the calls recorded on it afterward.

    Args:
        accounts_pages: Pages list_accounts' paginator yields

    Returns:
        The Organizations client, and the paginator list_tags_for_resource
        routes to
    """
    accounts_paginator = MagicMock()
    accounts_paginator.paginate.return_value = accounts_pages
    tags_paginator = MagicMock()

    def get_paginator(operation_name: str) -> MagicMock:
        return accounts_paginator if operation_name == "list_accounts" else tags_paginator

    org_client = MagicMock()
    org_client.get_paginator.side_effect = get_paginator
    return org_client, tags_paginator


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
            patch("headroom.analysis.get_organization_id", return_value=ORG_ID) as mock_get_org_id,
            patch("headroom.analysis.get_subaccount_information", return_value=[]) as mock_get_subs,
            patch("headroom.analysis.run_checks"),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            perform_analysis(config)
            mock_get_session.assert_called_once_with(config)
            mock_get_org_ids.assert_called_once_with(config, mock_session)
            mock_get_org_id.assert_called_once_with(config, mock_session)
            mock_get_subs.assert_called_once_with(config, mock_session)
            assert mock_logger.info.call_count == 8
            mock_logger.info.assert_any_call("Starting security analysis")
            mock_logger.info.assert_any_call("Successfully obtained security analysis session")
            mock_logger.info.assert_any_call("Fetched subaccount information: []")
            mock_logger.info.assert_any_call("Filtered to 0 relevant accounts for analysis")
            mock_logger.info.assert_any_call(f"Organization ID: {ORG_ID}")
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
            patch("headroom.analysis.get_organization_id", return_value=ORG_ID) as mock_get_org_id,
            patch("headroom.analysis.get_subaccount_information", return_value=[]) as mock_get_subs,
            patch("headroom.analysis.run_checks"),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            perform_analysis(config)
            mock_get_session.assert_called_once_with(config)
            mock_get_org_ids.assert_called_once_with(config, mock_session)
            mock_get_org_id.assert_called_once_with(config, mock_session)
            mock_get_subs.assert_called_once_with(config, mock_session)
            assert mock_logger.info.call_count == 8
            mock_logger.info.assert_any_call("Filtered to 0 relevant accounts for analysis")

    def test_perform_analysis_aborts_before_run_checks_on_an_unusable_name(self) -> None:
        """
        The filename guard must gate run_checks, not merely exist.

        Pins two things the direct-call tests cannot. That the call is there
        at all: deleting it leaves every test in
        TestAccountNamesAreFilenameSafe green. And that it is unconditional --
        exclude_account_ids is false here, because both naming modes put the
        account name into the filename, unlike the duplicate-name guard next
        to it.
        """
        config = HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner"),
            exclude_account_ids=False,
        )
        account_infos = [
            AccountInfo(account_id="333333333333", environment="prod", name="Prod/US", owner="team"),
        ]
        mock_session = MagicMock()
        with (
            patch("headroom.analysis.get_security_analysis_session", return_value=mock_session),
            patch("headroom.analysis.get_all_organization_account_ids", return_value=set()),
            patch("headroom.analysis.get_organization_id", return_value=ORG_ID),
            patch("headroom.analysis.get_subaccount_information", return_value=account_infos),
            patch("headroom.analysis.run_checks") as mock_run_checks,
        ):
            with pytest.raises(RuntimeError, match="Prod/US"):
                perform_analysis(config)

            mock_run_checks.assert_not_called()

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
            patch("headroom.analysis.get_organization_id", return_value=ORG_ID),
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
        tag_map = {
            "333333333333": {"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "NameTag", "Value": "TagName1"}, {"Key": "OwnerTag", "Value": "Alice"}]},
            "444444444444": {"Tags": [{"Key": "Env", "Value": "dev"}, {"Key": "NameTag", "Value": "TagName2"}, {"Key": "OwnerTag", "Value": "Bob"}]},
            # "555555555555" intentionally missing to test default
        }
        mock_org_client, tags_paginator = _org_client_for_account_listing([
            {"Accounts": [
                {"Id": "222222222222", "Name": "MgmtAccount", "State": "ACTIVE"},  # Should be skipped
                {"Id": "333333333333", "Name": "SubAccount1", "State": "ACTIVE"},
                {"Id": "444444444444", "Name": "SubAccount2", "State": "ACTIVE"},
                {"Id": "555555555555", "Name": "SubAccount3", "State": "ACTIVE"},  # No tags
            ]}
        ])
        tags_paginator.paginate.side_effect = lambda ResourceId: [tag_map.get(ResourceId, {"Tags": []})]
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
        mock_org_client, tags_paginator = _org_client_for_account_listing([
            {"Accounts": [
                {"Id": "222222222222", "Name": "MgmtAccount", "State": "ACTIVE"},
                {"Id": "333333333333", "Name": "SubAccount1", "State": "ACTIVE"}
            ]}
        ])
        tags_paginator.paginate.return_value = [{"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "OwnerTag", "Value": "Alice"}]}]
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
        mock_org_client, tags_paginator = _org_client_for_account_listing([
            {"Accounts": [
                {"Id": "333333333333", "Name": "SubAccount1", "State": "ACTIVE"}
            ]}
        ])
        tags_paginator.paginate.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListTagsForResource")
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
        mock_org_client, tags_paginator = _org_client_for_account_listing([{"Accounts": accounts}])
        tags_paginator.paginate.return_value = [{"Tags": []}]
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

        # list_tags_for_resource is never called directly now -- tags are read
        # through get_paginator("list_tags_for_resource").paginate(...), so the
        # calls a tag lookup makes are recorded on that paginator's `paginate`
        # instead. get_paginator's side_effect (set up by
        # _org_client_for_account_listing) returns the same tags paginator
        # every time it is asked for this operation, so asking for it again
        # here retrieves the one the real run already called.
        tags_paginator = mock_org_client.get_paginator("list_tags_for_resource")
        tagged_ids = [
            call.kwargs["ResourceId"]
            for call in tags_paginator.paginate.call_args_list
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


class TestFetchAccountTags:
    """Test _fetch_account_tags directly, below the get_subaccount_information layer."""

    def test_a_tag_on_the_second_page_is_read(self) -> None:
        """
        list_tags_for_resource paginates, and page one is not the answer.

        With use_account_name_from_tags set, a Name tag on page two left the
        account named by its ID, which then named its result files.
        """
        org_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Tags": [{"Key": "Owner", "Value": "payments-team"}]},
            {"Tags": [{"Key": "Name", "Value": "payments"}]},
        ]
        org_client.get_paginator.return_value = paginator

        tags = _fetch_account_tags(org_client, "111111111111", "payments")

        assert tags == {"Owner": "payments-team", "Name": "payments"}

    def test_a_client_error_on_the_second_page_discards_the_first(self) -> None:
        """
        A failure partway through pagination returns {}, not the pages already read.

        A half-read tag set is precisely the case where a missing Name tag
        silently renames an account, so a page-two failure must not leave
        page one's Owner tag in the result.
        """
        def _pages() -> Iterator[Dict[str, Any]]:
            yield {"Tags": [{"Key": "Owner", "Value": "payments-team"}]}
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                "ListTagsForResource"
            )

        org_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = _pages()
        org_client.get_paginator.return_value = paginator

        with patch("headroom.analysis.logger") as mock_logger:
            tags = _fetch_account_tags(org_client, "111111111111", "payments")

        assert tags == {}
        mock_logger.warning.assert_called_once()


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
        mock_org_client.get_paginator.return_value.paginate.return_value = [{
            "Tags": [
                {"Key": "Env", "Value": "production"},
                {"Key": "NameTag", "Value": "TagAccountName"},
                {"Key": "OwnerTag", "Value": "TeamA"}
            ]
        }]

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
        mock_org_client.get_paginator.return_value.paginate.return_value = [{
            "Tags": [
                {"Key": "Env", "Value": "staging"},
                {"Key": "NameTag", "Value": "TagAccountName"},
                {"Key": "OwnerTag", "Value": "TeamB"}
            ]
        }]

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
        mock_org_client.get_paginator.return_value.paginate.return_value = [{"Tags": []}]

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
        mock_org_client.get_paginator.return_value.paginate.return_value = [{
            "Tags": [
                {"Key": "Env", "Value": "dev"}
            ]
        }]

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
        mock_org_client.get_paginator.return_value.paginate.side_effect = ClientError(
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
        mock_org_client.get_paginator.return_value.paginate.side_effect = ClientError(
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
        mock_org_client.get_paginator.return_value.paginate.return_value = [{
            "Tags": [
                {"Key": "Env", "Value": "production"},
                {"Key": "OwnerTag", "Value": "TeamC"}
            ]
        }]

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
        mock_org_client, tags_paginator = _org_client_for_account_listing([{"Accounts": accounts}])
        tags_paginator.paginate.return_value = [{"Tags": []}]
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

        # As in TestAccountStateFiltering above: the direct method is never
        # called now, so the call is recorded on the tags paginator instead,
        # which get_paginator's side_effect hands back again on request.
        tags_paginator = mock_org_client.get_paginator("list_tags_for_resource")
        tags_paginator.paginate.assert_called_once_with(ResourceId="444444444444")

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

    "Sharing a name" is what the filesystem thinks, not what `==` thinks: the
    guard folds case and Unicode normal form, because APFS collapses both.
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

    def test_duplicate_names_abort_when_ids_are_excluded(self) -> None:
        """Two accounts sharing a name would write the same file, so abort."""
        with pytest.raises(RuntimeError, match="shared-name"):
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                _account_infos("shared-name", "unique", "shared-name"),
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
                _account_infos("shared-name", "shared-name"),
            )

        message = str(excinfo.value)
        assert "shared-name (2 accounts)" in message
        assert not re.search(r"\d{12}", message)

    def test_the_count_is_the_group_size_not_a_pair(self) -> None:
        """
        Three accounts on one name report three, not two.

        Every other test here collides exactly two accounts, so a message
        hardcoding "(2 accounts)" would satisfy all of them while telling an
        operator the wrong number of accounts to go and rename.
        """
        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                _account_infos("shared-name", "shared-name", "shared-name"),
            )

        assert "shared-name (3 accounts)" in str(excinfo.value)

    def test_every_colliding_group_is_reported_not_just_the_first(self) -> None:
        """
        Two independent collisions both appear in the one message.

        The guard runs once and aborts, so a message that listed only the
        first group would send the operator back for a second full run to
        discover the second -- and every other test here has just one group,
        so truncating the list passes them all.
        """
        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                _account_infos(
                    "alpha", "alpha", "unique", "beta", "beta"
                ),
            )

        message = str(excinfo.value)
        assert "alpha (2 accounts)" in message
        assert "beta (2 accounts)" in message

    def test_duplicate_names_are_allowed_when_ids_are_included(self) -> None:
        """
        With IDs in the filename, two accounts named alike do not collide.

        format_account_identifier appends the account ID, which is unique.
        """
        _verify_no_duplicate_account_names(
            self._config(exclude_account_ids=False),
            _account_infos("shared-name", "shared-name"),
        )

    def test_unique_names_pass(self) -> None:
        """Distinct names never collide, whatever the redaction setting."""
        _verify_no_duplicate_account_names(
            self._config(exclude_account_ids=True),
            _account_infos("one", "two", "three"),
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
                _account_infos("Prod", "prod"),
            )

        message = str(excinfo.value)
        assert "Prod" in message
        assert "prod" in message

    def test_a_unicode_normalization_collision_is_caught(self) -> None:
        """
        Names collide across Unicode normal forms as well as across case.

        APFS folds two axes, not one. `caf\u00e9` composed (NFC, a single
        U+00E9) and decomposed (NFD, `e` followed by the combining acute
        U+0301) are different strings that resolve to the same file, exactly
        as `Prod` and `prod` do. Folding case alone lets this pair through and
        interleaves two accounts' JSON into one file -- the outcome the guard
        exists to prevent, reached through the same filesystem property that
        justifies the case folding.
        """
        composed = "caf\u00e9"
        decomposed = "cafe\u0301"
        assert composed != decomposed

        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                _account_infos(composed, decomposed),
            )

        assert "(2 accounts)" in str(excinfo.value)

    def test_a_case_fold_that_breaks_composition_is_caught(self) -> None:
        """
        Folding the two axes in sequence is not folding them together.

        Case folding can undo the composition normalization just performed,
        so NFC-then-casefold closes each axis and leaves their composition
        open. Unicode calls the closed form canonical caseless matching
        (D145): `NFD(casefold(NFD(x)))`, where the trailing NFD re-normalizes
        whatever the fold decomposed.

        `\u017f` (long s) followed by the combining acute `\u0301` has no
        precomposed form, so NFC returns it unchanged; casefold then maps
        `\u017f` to `s`, producing `s` + `\u0301`. That is the decomposition
        of `\u015b`, not `\u015b` itself, so the two names key differently
        while APFS stores them in one inode -- verified against APFS, which
        reports the same `st_ino` for both spellings.
        """
        long_s_acute = "\u017f\u0301"
        s_acute = "\u015b"
        assert long_s_acute != s_acute

        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                _account_infos(long_s_acute, s_acute),
            )

        assert "(2 accounts)" in str(excinfo.value)


class TestAccountNamesAreFilenameSafe:
    """Test the guard on account names that do not survive becoming a path."""

    def test_a_name_holding_a_separator_aborts(self) -> None:
        """
        `Prod/US` builds a path into a subdirectory, not a filename.

        `Path(check_dir) / "Prod/US.json"` is `check_dir/Prod/US.json`. With
        no such directory the worker thread raises FileNotFoundError partway
        through the run; with one, the file is written where the reader's
        `*.json` glob cannot see it and the account drops out of the analysis
        silently.
        """
        with pytest.raises(RuntimeError, match="Prod/US"):
            _verify_account_names_are_filename_safe(_account_infos("Prod/US"))

    def test_a_name_that_climbs_out_of_the_results_directory_aborts(self) -> None:
        """
        `../Prod` writes outside the check directory, silently.

        Verified: the write succeeds, lands one level up, overwrites whatever
        was there, and the reader's glob returns nothing for that account. Of
        the three ways a separator can go wrong this is the worst, because
        nothing fails and the account is simply missing from the results the
        policies are generated from.
        """
        with pytest.raises(RuntimeError, match=r"\.\./Prod"):
            _verify_account_names_are_filename_safe(_account_infos("../Prod"))

    def test_an_empty_name_aborts(self) -> None:
        """
        An empty name cannot become a Terraform identifier.

        Not a filename failure: it yields `.json`, which `pathlib`'s glob
        matches and the readers read back fine. It fails later, in
        `make_account_base_names`, which is after the whole scan has run --
        so the guard pays that same check in seconds instead.
        """
        with pytest.raises(RuntimeError):
            _verify_account_names_are_filename_safe(_account_infos(""))

    def test_a_name_too_long_for_the_filesystem_aborts(self) -> None:
        """
        A name is capped by what the filename it lands in can hold.

        Organizations caps an account name at 50 characters, but
        `use_account_name_from_tags` takes the name from a tag value, and a
        tag value runs to 256. The resolver adds `_`, a twelve-digit account
        ID, and `.json` -- eighteen bytes -- to a component both Linux and
        macOS cap at 255, so 237 is the longest name that fits. Past it the
        worker raises OSError partway through the run.
        """
        _verify_account_names_are_filename_safe(_account_infos("a" * 237))

        with pytest.raises(RuntimeError, match="too long"):
            _verify_account_names_are_filename_safe(_account_infos("a" * 238))

    def test_a_name_holding_a_null_byte_aborts(self) -> None:
        """
        A null byte cannot reach a syscall, so the write raises ValueError.

        `Path` carries the byte without complaint and compares equal to the
        name it came from, so the separator check above passes it through.
        Only `open()` rejects it, which is a worker thread failing partway
        through the run rather than a name the operator can fix up front.
        """
        with pytest.raises(RuntimeError, match="null byte"):
            _verify_account_names_are_filename_safe(_account_infos("a\x00b"))

    def test_a_leading_dot_is_not_a_reason_to_abort(self) -> None:
        """
        `pathlib.Path.glob` matches dotfiles; `glob.glob` is the one that does not.

        Both readers glob `*.json` through `pathlib`, which returns
        `.Prod.json` alongside every other result, and neither takes account
        identity from the filename -- `parse_results` and `generate_rcps`
        both read it out of the JSON `summary`. A hidden result file is read
        back like any other, so rejecting the name would drop an account for
        no reason.
        """
        _verify_account_names_are_filename_safe(_account_infos(".Prod"))

    def test_ordinary_names_pass(self) -> None:
        """Names that are already filenames are left alone."""
        _verify_account_names_are_filename_safe(
            _account_infos("Prod US", "prod-us", "caf\u00e9", "Prod.US")
        )


class TestRunChecksPool:
    """Test the worker pool and its cooperative abort."""

    @staticmethod
    def _accounts(count: int) -> List[AccountInfo]:
        """
        Build `count` accounts named `account-0` upward.

        Args:
            count: How many accounts to build

        Returns:
            Accounts named `account-0` upward, each with a distinct account ID
        """
        return _account_infos(*(f"account-{index}" for index in range(count)))

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

    def test_the_account_helper_builds_twelve_digit_account_ids(self) -> None:
        """
        Every ID `_account_infos` builds matches the repository's pattern.

        `str(index + 1) * 12` held that shape only through index 8, and four
        of the tests below already ask for 200 accounts: 191 of those IDs came
        out 24 or 36 digits long. Nothing downstream validates an account ID,
        so the suite stayed green on them.

        The pattern here is copied from the `fake_account_ids` block in
        `HOW_TO_ADD_A_CHECK.md` rather than derived from the construction it
        checks. It is also what bounds the derivation: 1000 values exist and
        it starts at 333, so 667 accounts is the most it can build before an
        ID repeats. Clearing the two IDs `_config` uses would need an offset
        of only 223; the remaining 110 buy 333333333333 for the first account,
        which is the value the convention names as tertiary.
        """
        account_ids = [
            account.account_id for account in self._accounts(MAX_GENERATED_ACCOUNTS)
        ]
        config = self._config(1)

        assert all(
            re.fullmatch(r"(\d)\1{3}(\d)\2{3}(\d)\3{3}", account_id)
            for account_id in account_ids
        )
        assert len(set(account_ids)) == MAX_GENERATED_ACCOUNTS
        assert config.management_account_id not in account_ids
        assert config.security_analysis_account_id not in account_ids

        with pytest.raises(ValueError, match=str(MAX_GENERATED_ACCOUNTS)):
            self._accounts(MAX_GENERATED_ACCOUNTS + 1)

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
            run_checks(MagicMock(), self._accounts(5), self._config(4), set(), ORG_ID)

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
            run_checks(MagicMock(), self._accounts(3), self._config(4), set(), ORG_ID)

        worker.assert_not_called()

    def test_the_log_line_counts_what_the_pool_is_actually_given(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        An operator sizes the wait off this line, so both halves are real.

        It reported the configured cap rather than the workers that will
        exist. ThreadPoolExecutor spawns threads on demand, so a resumed run
        with all but two accounts already on disk announced the full worker
        count and then did two accounts' work on two threads.

        The account half was unpinned in the same line: swapping `len(pending)`
        back to the unfiltered list left the whole suite green, because the
        only other test reading this line runs with nothing filtered out and
        the two counts equal.
        """
        accounts = self._accounts(5)
        already_on_disk = {account.account_id for account in accounts[:3]}

        def complete(account_info: AccountInfo, config: HeadroomConfig) -> bool:
            return account_info.account_id in already_on_disk

        with (
            caplog.at_level(logging.INFO, logger="headroom.analysis"),
            patch("headroom.analysis._all_checks_complete", side_effect=complete),
            patch("headroom.analysis._run_checks_for_account"),
        ):
            run_checks(MagicMock(), accounts, self._config(16), set(), ORG_ID)

        assert "Analyzing 2 account(s) with 2 worker(s)" in caplog.text

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
            run_checks(MagicMock(), self._accounts(4), self._config(4), set(), ORG_ID)

    def test_the_pool_is_built_with_the_configured_worker_count(self) -> None:
        """
        `max_account_workers: 1` reaches the executor as 1, and stays serial.

        The test above pins the ceiling with a barrier; this pins the floor,
        and it has to assert the constructor argument to do it. Observing
        threads cannot: ThreadPoolExecutor creates one only when no idle
        thread is free, so four fast tasks stay on a single thread whatever
        the cap is, and a thread-identity assertion passes just as happily
        with a floor of two silently imposed underneath it. Measured -- that
        is exactly what `max(2, config.max_account_workers)` does to it.

        This is the setting that matters most to get right: it exists for
        accounts under an API quota tight enough that a second thread breaks
        them, and every other pool test here asks for four workers or more.
        """
        threads: List[int] = []
        lock = threading.Lock()

        def record(account_info: AccountInfo, *args: object) -> None:
            with lock:
                threads.append(threading.get_ident())

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=record),
            patch(
                "headroom.analysis.ThreadPoolExecutor", wraps=ThreadPoolExecutor
            ) as pool,
        ):
            run_checks(MagicMock(), self._accounts(4), self._config(1), set(), ORG_ID)

        assert pool.call_args.kwargs["max_workers"] == 1
        assert len(threads) == 4
        assert len(set(threads)) == 1

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
            run_checks(MagicMock(), self._accounts(3), self._config(1), set(), ORG_ID)

    def test_a_worker_returns_immediately_when_abort_is_set(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        An in-flight worker bails at its next checkpoint, and says so.

        Python cannot kill a running thread, so cancelling queued futures is
        not enough: without this check, shutdown would block until every
        in-flight account finished all its remaining checks.

        It logs the same line as a worker stopped partway through its checks,
        because the outcome is the same and the two paths are otherwise the
        only ones that end an account silently. The run-level count reports
        cancelled accounts only, so an in-flight account that returned here
        without a line would appear in no tally at all.
        """
        abort = threading.Event()
        abort.set()

        with (
            caplog.at_level(logging.INFO, logger="headroom.analysis"),
            patch("headroom.analysis.get_headroom_session") as mock_session,
        ):
            _run_checks_for_account(
                self._accounts(1)[0], MagicMock(), self._config(1), set(), ORG_ID, abort
            )

        mock_session.assert_not_called()
        assert "Checks aborted for account: account-0_333333333333" in caplog.text

    def test_no_further_checks_run_once_abort_is_set(self) -> None:
        """
        `run_checks_for_type` stops before starting the next check.

        The check is missing from disk, so the skip cannot account for its
        not running: the checkpoint is the only thing that stops it.
        """
        abort = threading.Event()
        abort.set()

        with (
            patch("headroom.analysis.get_all_check_classes") as mock_classes,
            patch("headroom.analysis.results_exist", return_value=False),
        ):
            mock_classes.return_value = [MagicMock()]
            completed = run_checks_for_type(
                "scps", MagicMock(), self._accounts(1)[0], self._config(1), set(), ORG_ID, abort
            )

        mock_classes.return_value[0].assert_not_called()
        assert completed is False

    def test_the_first_failure_sets_the_abort_event(self) -> None:
        """
        The pool half of the abort: a failure sets the Event workers poll.

        The two checkpoint tests prove a worker stops once the Event is set.
        This proves the Event gets set. Deleting `abort.set()` fails three
        tests rather than this one alone -- the interrupt and submit-failure
        tests below reach it by their own paths -- but those assert on
        cancellation counts and read the Event only as a means. This one
        holds the Event the worker was handed and asserts on it directly, so
        a regression here names what broke instead of only that something
        did.
        """
        events: List[threading.Event] = []
        lock = threading.Lock()

        def fail(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
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
            run_checks(MagicMock(), self._accounts(3), self._config(1), set(), ORG_ID)

        assert events
        assert events[0].is_set()

    def test_every_failure_is_reported_not_only_the_first(self) -> None:
        """
        Failures that lose the race to `as_completed` are still logged.

        Only one exception can propagate, and `concurrent.futures.Future` has
        no `__del__`, so the others are collected without even the "exception
        was never retrieved" warning asyncio would print. An operator missing
        the Headroom role in forty accounts otherwise fixes one, re-runs,
        and is told about the next -- forty rounds of a scan that takes hours.

        The sweep cannot run in the `except` inside the `with`: the workers
        are joined by `__exit__`, which has not run yet there, so the other
        futures hold no exception to find. It has to sit outside the block.

        The barrier holds both accounts in flight until each has failed, so
        neither can be cancelled while queued and the second failure is a
        fact about the pool rather than about scheduling.
        """
        barrier = threading.Barrier(2, timeout=5)

        def fail(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
            abort: threading.Event,
        ) -> None:
            barrier.wait()
            raise RuntimeError(f"role assumption failed in {account_info.name}")

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=fail),
            patch("headroom.analysis.logger") as mock_logger,
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), self._accounts(2), self._config(2), set(), ORG_ID)

        reported = [call.args[0] for call in mock_logger.error.call_args_list]
        assert len(reported) == 2
        assert any("account-0_333333333333" in line for line in reported)
        assert any("account-1_333333334444" in line for line in reported)

    def test_a_failure_raised_after_the_abort_is_set_is_still_reported(self) -> None:
        """
        The sweep finds a failure that happened after the run began aborting.

        The barrier in the test above holds both accounts until each has
        failed, so neither failure is ordered with respect to the abort and
        `pytest.raises(match=...)` cannot say which account propagated. This
        orders them: the second account blocks until the first failure has set
        the abort, and only then raises its own error. That is the shape a
        real run produces -- one account fails, the abort goes up, and another
        already in flight hits its own error before reaching a checkpoint.

        The barrier is still needed, for a different job than above: without
        it the first account fails so fast that its worker goes idle and
        serves the second submit too, so the second account is cancelled
        while queued and never runs at all. The barrier gets both in flight;
        the abort wait is what orders them.

        What it pins is that `_log_every_failure` reads every future rather
        than only those that completed before the abort. The two messages are
        distinct so the assertions name which account produced which.
        """
        both_in_flight = threading.Barrier(2, timeout=5)

        def fail(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
            abort: threading.Event,
        ) -> None:
            both_in_flight.wait()
            if account_info.name == "account-0":
                raise RuntimeError("role assumption failed in account-0")
            assert abort.wait(timeout=5), "the first failure never set the abort"
            raise RuntimeError("credentials expired in account-1")

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=fail),
            patch("headroom.analysis.logger") as mock_logger,
            pytest.raises(RuntimeError, match="role assumption failed in account-0"),
        ):
            run_checks(MagicMock(), self._accounts(2), self._config(2), set(), ORG_ID)

        reported = [call.args[0] for call in mock_logger.error.call_args_list]
        assert len(reported) == 2
        assert any("role assumption failed in account-0" in line for line in reported)
        assert any("credentials expired in account-1" in line for line in reported)

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
            completed = run_checks_for_type(
                "scps", MagicMock(), self._accounts(1)[0], self._config(1), set(), ORG_ID, abort
            )

        first.assert_called_once()
        second.assert_not_called()
        assert completed is False

    def test_an_abort_does_not_relabel_checks_already_on_disk(self) -> None:
        """
        The checkpoint sits below the skip, so an on-disk check still counts.

        Above the skip it reports the account aborted whenever the Event lands
        after the last check this account actually had to run, even though
        every remaining check is already on disk. The operator reads "Checks
        aborted", re-runs, and gets "All results already exist" -- the same
        misleading pair `test_an_account_that_ran_every_check_is_not_logged_as_aborted`
        closes for the last-iteration case, reached instead through the last
        *missing* check.

        The first check is missing and sets the Event as it finishes; the
        second is already on disk. Nothing is left to run, so the account ran
        everything it owned and the loop must say so.
        """
        abort = threading.Event()
        first = MagicMock()
        second = MagicMock()
        first.CHECK_NAME = "first_check"
        second.CHECK_NAME = "second_check"
        first.return_value.execute.side_effect = lambda session: abort.set()

        with (
            patch("headroom.analysis.get_all_check_classes", return_value=[first, second]),
            patch("headroom.analysis.results_exist", side_effect=[False, True]),
        ):
            completed = run_checks_for_type(
                "scps", MagicMock(), self._accounts(1)[0], self._config(1), set(), ORG_ID, abort
            )

        first.assert_called_once()
        second.assert_not_called()
        assert abort.is_set()
        assert completed is True

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
            run_checks(MagicMock(), self._accounts(4), self._config(4), set(), ORG_ID)

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
        so that the stamp it reads can only have come from this worker: a
        fresh thread's context is unset by construction, which no amount of
        whatever ran before can undo.
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
                    self._accounts(1)[0], MagicMock(), self._config(1), set(), ORG_ID, threading.Event()
                )

        thread = threading.Thread(target=run_the_worker)
        thread.start()
        thread.join(timeout=5)

        assert stamped == ["account-0_333333333333"]

    @staticmethod
    def _stamp_on_this_thread() -> str:
        """Return the account a record emitted on this thread would carry."""
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
        return str(record.account)  # type: ignore[attr-defined]

    def test_a_worker_stops_carrying_its_account_when_it_returns(self) -> None:
        """
        A pool thread outlives the account it just finished.

        `set_account` writes to thread-local storage and the pool reuses its
        threads, so a worker that returns without clearing leaves the next
        record that thread emits -- anything between the pool picking up the
        next account and that worker's own `set_account` -- named for the
        previous account, confidently and wrongly. `-` is the honest answer
        in that window.

        Runs on a thread of its own for the same reason as
        test_a_worker_registers_its_account_for_log_records: on a thread
        nothing has touched, `-` can only be what the `finally` wrote.
        """
        stamped_after: List[str] = []

        def run_the_worker() -> None:
            with (
                patch("headroom.analysis.all_check_results_exist", return_value=True),
                patch("headroom.analysis.get_headroom_session", return_value=MagicMock()),
            ):
                _run_checks_for_account(
                    self._accounts(1)[0], MagicMock(), self._config(1), set(), ORG_ID, threading.Event()
                )
            stamped_after.append(self._stamp_on_this_thread())

        thread = threading.Thread(target=run_the_worker)
        thread.start()
        thread.join(timeout=5)

        assert stamped_after == [NO_ACCOUNT]

    def test_a_worker_stops_carrying_its_account_when_it_raises(self) -> None:
        """
        The failing account is exactly when a stale name misleads most.

        A worker that raises is the one whose thread goes back to the pool
        mid-analysis, and the operator is already reading the log to find out
        which account broke. Clearing on the way out has to be in a `finally`
        rather than at the end of the body for this path to hold.
        """
        stamped_after: List[str] = []

        def run_the_worker() -> None:
            with (
                patch("headroom.analysis.all_check_results_exist", return_value=True),
                patch(
                    "headroom.analysis.get_headroom_session",
                    side_effect=RuntimeError("assume role failed"),
                ),
            ):
                with pytest.raises(RuntimeError, match="assume role failed"):
                    _run_checks_for_account(
                        self._accounts(1)[0], MagicMock(), self._config(1), set(), ORG_ID,
                        threading.Event()
                    )
            stamped_after.append(self._stamp_on_this_thread())

        thread = threading.Thread(target=run_the_worker)
        thread.start()
        thread.join(timeout=5)

        assert stamped_after == [NO_ACCOUNT]

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

        The floor is one rather than a number near 200, and two attempts to
        raise it structurally were measured and abandoned. Parking every
        non-failing account on the abort never executes: the cancel loop
        beats the worker to the queue outright, so the park is dead code that
        only breaks the coverage gate. Holding the worker until the last
        submit is worse than doing nothing -- it releases the worker exactly
        as the main thread enters `as_completed`, and the worker then drains
        all 199, measured at zero cancelled. Closing this properly needs
        `run_checks` to expose a synchronization point between `abort.set()`
        and the cancel loop, which is production code complicated for a
        test's benefit.
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
            org_id: str,
            abort: threading.Event,
        ) -> None:
            if account_info.account_id == failing_account_id:
                raise RuntimeError("role assumption failed")

        with (
            patch.object(ThreadPoolExecutor, "submit", capturing_submit),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch(
                "headroom.analysis._run_checks_for_account",
                side_effect=fail_the_first_account,
            ),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), accounts, self._config(1), set(), ORG_ID)

        assert len(captured) == len(accounts)
        assert sum(1 for future in captured if future.cancelled()) >= 1

    def test_a_submit_that_fails_after_queueing_aborts_rather_than_drains(self) -> None:
        """
        The shape the submit handler exists for, actually produced.

        CPython's `submit` puts the work item on the queue and only then calls
        `_adjust_thread_count`, so a thread that fails to start leaves an item
        queued whose future was never returned: it is not in
        `accounts_by_future` and nothing can cancel it. The handler is
        documented against that shape but nothing built it, so the two things
        it guarantees went unpinned.

        Both are asserted here. The submit failure propagates rather than
        being swallowed, and the accounts behind it in the loop are never
        submitted at all -- which is what makes this an abort rather than
        `__exit__` draining the rest of the organization.

        What is deliberately not asserted is whether the orphaned item runs.
        A worker already exists at that point, so it may pick the item up
        before or after `abort.set()`; the ordering is not determined and the
        outcome is the same either way, since an account analyzed once more
        than needed costs time rather than correctness.
        """
        submits: List[int] = []
        analyzed: List[str] = []
        lock = threading.Lock()
        real_submit = ThreadPoolExecutor.submit

        def submit_that_fails_after_queueing(
            executor: ThreadPoolExecutor, fn: object, *args: object, **kwargs: object
        ) -> Future[None]:
            future: Future[None] = real_submit(executor, fn, *args, **kwargs)  # type: ignore[arg-type]
            with lock:
                submits.append(1)
                failing = len(submits) == 3
            if failing:
                raise RuntimeError("can't start new thread")
            return future

        def record(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
            abort: threading.Event,
        ) -> None:
            with lock:
                analyzed.append(account_info.name)

        with (
            patch.object(ThreadPoolExecutor, "submit", submit_that_fails_after_queueing),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=record),
            pytest.raises(RuntimeError, match="can't start new thread"),
        ):
            run_checks(MagicMock(), self._accounts(5), self._config(1), set(), ORG_ID)

        assert len(submits) == 3
        assert "account-3" not in analyzed
        assert "account-4" not in analyzed

    def test_the_operator_is_told_how_many_accounts_never_ran(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        A cancelled account leaves no trace of its own.

        _log_every_failure skips cancelled futures, correctly -- they hold no
        failure. But nothing else mentions them either, so an aborted run
        printed `Analyzing 200 account(s)`, a handful of completions, the
        failures, and a traceback, leaving the operator to work out by
        subtraction how much of the organization went unanalyzed. That number
        is what decides whether the results on disk are worth generating
        policies from.

        The count is read off Future.cancelled() rather than parsed out of
        the line, and the assertion needs it to be both non-zero and the
        number reported. The floor is one for the reason the cancel-loop test
        above gives.
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
            org_id: str,
            abort: threading.Event,
        ) -> None:
            if account_info.account_id == failing_account_id:
                raise RuntimeError("role assumption failed")

        with (
            caplog.at_level(logging.ERROR, logger="headroom.analysis"),
            patch.object(ThreadPoolExecutor, "submit", capturing_submit),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch(
                "headroom.analysis._run_checks_for_account",
                side_effect=fail_the_first_account,
            ),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), accounts, self._config(1), set(), ORG_ID)

        cancelled = sum(1 for future in captured if future.cancelled())
        assert cancelled >= 1
        assert f"{cancelled} account(s) were never analyzed" in caplog.text

    def test_a_run_that_loses_no_account_says_nothing_about_it(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Nothing cancelled, no line. One worker and one account leaves no
        queue behind, so the count is zero and reporting it would be noise
        on top of the failure the operator already has.
        """
        def fail(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
            abort: threading.Event,
        ) -> None:
            raise RuntimeError("role assumption failed")

        with (
            caplog.at_level(logging.ERROR, logger="headroom.analysis"),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=fail),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), self._accounts(1), self._config(1), set(), ORG_ID)

        assert "never analyzed" not in caplog.text

    def test_a_keyboard_interrupt_still_reports_the_failures_already_collected(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Ctrl-C must not throw away the failure report the run had earned.

        The outer handler is the only thing that calls `_log_every_failure`,
        and it catches `BaseException` for the same reason the inner one
        does: `KeyboardInterrupt` is not an `Exception`. Narrowing it to
        `except Exception` leaves every other test in this file green, and
        turns three accounts failing on a missing role into a bare traceback
        naming none of them -- the exact report this handler exists to print.

        `as_completed` is replaced with a stand-in that waits for the pool to
        finish before raising, which is what makes the count deterministic:
        every account has failed and none is cancellable by the time the
        interrupt lands, so all three failures are there to be reported or
        lost.
        """
        accounts = self._accounts(3)

        def fail(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
            abort: threading.Event,
        ) -> None:
            raise RuntimeError("role assumption failed")

        def interrupt_once_every_worker_has_finished(
            futures: Iterable[Future[None]]
        ) -> Iterator[Future[None]]:
            """
            Stand in for `as_completed` and raise where a SIGINT would land.

            `yield from ()` makes this a generator, so the whole body runs on
            the loop's first `next()` -- inside the `for` statement, where the
            signal handler would raise -- rather than at the call.
            """
            wait(list(futures))
            yield from ()
            raise KeyboardInterrupt

        with (
            caplog.at_level(logging.ERROR, logger="headroom.analysis"),
            patch("headroom.analysis.as_completed", interrupt_once_every_worker_has_finished),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=fail),
            pytest.raises(KeyboardInterrupt),
        ):
            run_checks(MagicMock(), accounts, self._config(1), set(), ORG_ID)

        for account_info in accounts:
            identifier = f"{account_info.name}_{account_info.account_id}"
            assert f"Checks failed for account {identifier}" in caplog.text

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
            aborts.append(cast(threading.Event, args[5]))
            return future

        def park_the_first_account(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
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
            run_checks(MagicMock(), accounts, self._config(1), set(), ORG_ID)

        assert len(captured) == len(accounts)
        assert aborts[0].is_set()
        assert sum(1 for future in captured if future.cancelled()) >= 1
        assert len(entered) < len(accounts)

    def test_a_failure_to_submit_aborts_the_accounts_already_submitted(self) -> None:
        """
        `executor.submit` can raise, and the abort has to cover that window.

        `submit` reaches `_adjust_thread_count`, whose `Thread.start()` raises
        `RuntimeError("can't start new thread")` once the host is at its
        thread limit -- likeliest at `max_account_workers=32`, the ceiling an
        operator raises the setting to. Ctrl-C can land in the submit loop
        too, but this trigger does not depend on when a signal arrives, which
        is what makes it testable without a race.

        With the submit loop outside the `try`, nothing raised there reaches
        the handler: `abort` stays clear and `Executor.__exit__` runs
        `shutdown(wait=True)`, whose default `cancel_futures=False` puts its
        sentinel behind every account already submitted. The run the operator
        just lost finishes in full anyway.

        The futures are appended one at a time rather than comprehended for
        this test's second assertion: a comprehension binds its target only on
        completion, so a `submit` that raises halfway leaves the handler an
        empty list and cancels nothing.

        The first account parks until the abort is set, so one worker is
        genuinely in flight and the rest are genuinely queued when submission
        fails. The queue is deliberately far longer than one worker can drain
        while the main thread is being scheduled to cancel it, for the reason
        measured in test_the_cancel_loop_cancels_futures_still_in_the_queue.
        """
        accounts = self._accounts(200)
        blocking_account_id = accounts[0].account_id
        submitted: List[Future[None]] = []
        aborts: List[threading.Event] = []
        real_submit = ThreadPoolExecutor.submit

        def submit_until_the_host_runs_out_of_threads(
            executor: ThreadPoolExecutor, fn: object, *args: object, **kwargs: object
        ) -> Future[None]:
            if len(submitted) == 100:
                raise RuntimeError("can't start new thread")
            future: Future[None] = real_submit(executor, fn, *args, **kwargs)  # type: ignore[arg-type]
            submitted.append(future)
            aborts.append(cast(threading.Event, args[5]))
            return future

        def park_the_first_account(
            account_info: AccountInfo,
            security_session: object,
            config: HeadroomConfig,
            org_account_ids: object,
            org_id: str,
            abort: threading.Event,
        ) -> None:
            if account_info.account_id == blocking_account_id:
                abort.wait(timeout=5)

        with (
            patch.object(ThreadPoolExecutor, "submit", submit_until_the_host_runs_out_of_threads),
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=park_the_first_account),
            pytest.raises(RuntimeError, match="can.t start new thread"),
        ):
            run_checks(MagicMock(), accounts, self._config(1), set(), ORG_ID)

        assert len(submitted) == 100
        assert aborts[0].is_set()
        assert sum(1 for future in submitted if future.cancelled()) >= 1

    def test_an_account_that_ran_every_check_is_not_logged_as_aborted(self) -> None:
        """
        Another account failing during the last check does not relabel this one.

        The worker used to pick its closing line by re-reading the Event. An
        account whose final `check.execute()` overlaps another account's
        failure has run and written every check it owns, yet finds the Event
        set on the way out and reports itself aborted. The operator reads that
        line, believes the account is incomplete, and the re-run answers "All
        results already exist" -- the inverse of the bug the aborted line was
        added to fix, and just as misleading.

        The RCP results are already on disk so the SCP loop is the account's
        last work, and the single SCP check sets the Event as it finishes:
        every check ran, and the Event is set, at the same time.
        """
        abort = threading.Event()
        check_class = MagicMock()
        check_class.CHECK_NAME = "deny_iam_user_creation"
        check_class.return_value.execute.side_effect = lambda session: abort.set()

        with (
            patch("headroom.analysis.get_headroom_session"),
            patch("headroom.analysis.all_check_results_exist", side_effect=[False, True]),
            patch("headroom.analysis.get_all_check_classes", return_value=[check_class]),
            patch("headroom.analysis.results_exist", return_value=False),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            _run_checks_for_account(
                self._accounts(1)[0], MagicMock(), self._config(1), set(), ORG_ID, abort
            )

        check_class.return_value.execute.assert_called_once()
        assert abort.is_set()

        logged = [call.args[0] for call in mock_logger.info.call_args_list]
        assert "Checks completed for account: account-0_333333333333" in logged
        assert "Checks aborted for account: account-0_333333333333" not in logged

    def test_an_aborted_account_does_not_log_that_its_checks_completed(self) -> None:
        """
        A worker cut short mid-flight says so rather than claiming success.

        The entry checkpoint only covers a worker that has not started. One
        that is already running finds `run_checks_for_type` returning early
        for both check types and then reaches the end of the function, where
        it used to log "Checks completed" -- during exactly the incident an
        operator is reading the log to diagnose.

        The stand-in returns what the real function returns when a checkpoint
        stops it, since that return value is what picks the line. Its
        `abort.set()` is what makes the scenario realistic rather than what
        the assertion rests on; see
        test_an_account_that_ran_every_check_is_not_logged_as_aborted for the
        case where the two disagree.
        """
        abort = threading.Event()

        def abort_partway_through(*args: object) -> bool:
            abort.set()
            return False

        with (
            patch("headroom.analysis.get_headroom_session"),
            patch("headroom.analysis.all_check_results_exist", return_value=False),
            patch("headroom.analysis.run_checks_for_type", side_effect=abort_partway_through),
            patch("headroom.analysis.logger") as mock_logger,
        ):
            _run_checks_for_account(
                self._accounts(1)[0], MagicMock(), self._config(1), set(), ORG_ID, abort
            )

        logged = [call.args[0] for call in mock_logger.info.call_args_list]
        assert "Checks aborted for account: account-0_333333333333" in logged
        assert "Checks completed for account: account-0_333333333333" not in logged

    def test_the_real_registry_runs_every_check_per_account_across_workers(self) -> None:
        """
        The registry-driven pipeline, run by more than one worker.

        `TestRunChecks.test_run_checks_success` in
        tests/test_analysis_extended.py is the only other test that reaches
        the real check classes, and it is pinned to one worker because its
        assertions count calls on shared MagicMocks. Every multi-worker test
        in this class replaces `_run_checks_for_account` or
        `get_headroom_session` with a stand-in, so the loop in
        `run_checks_for_type` -- registry lookup, per-account construction,
        `execute` -- has never run concurrently under test at all.

        Measurement is a list under a lock rather than mock call counts,
        which is what lets the worker count rise here: `MagicMock.__call__`
        does a read-modify-write on `call_count` and loses increments under
        contention.

        The barrier holds every account inside its first check at once, so
        the isolation asserted below is a fact about four accounts genuinely
        in flight, not about a pool that happened to get through them one at
        a time. An account that reaches no check never arrives, and the
        barrier times out rather than hanging.

        What this pins is the premise the three per-session memos rest on:
        every check of one account sees one session on one thread, and no
        session reaches two accounts. That part takes its oracle from the
        other accounts rather than from the registry: "each account ran the
        same checks, each exactly once" compares the accounts against one
        another, so a registry reporting the wrong list cannot make it pass.

        The one comparison against `get_check_names()` is narrower than it
        looks, and deliberately so. Both sides read `_CHECK_REGISTRY`, so it
        cannot notice a check that never registered. What it does notice is
        a check the registry holds that neither pass runs: the executed set
        is `get_all_check_classes` filtered by the two type strings
        `_run_checks_for_account` passes, and the expected set is the whole
        registry, so a check registered under some third type -- or either
        literal misspelt -- leaves the two unequal.

        Patching over `get_all_check_classes()` is what keeps a check
        registered tomorrow covered without editing this test.
        """
        accounts = self._accounts(4)
        barrier = threading.Barrier(len(accounts), timeout=5)
        lock = threading.Lock()
        executions: List[Tuple[str, str, int, int]] = []
        accounts_past_the_barrier: Set[str] = set()
        sessions_built: List[MagicMock] = []

        def build_a_session(
            config: HeadroomConfig, security_session: object, account_id: str
        ) -> MagicMock:
            session = MagicMock()
            with lock:
                sessions_built.append(session)
            return session

        def record(check: BaseCheck, session: object) -> None:
            with lock:
                is_first_for_this_account = check.account_name not in accounts_past_the_barrier
                accounts_past_the_barrier.add(check.account_name)
            if is_first_for_this_account:
                barrier.wait()
            with lock:
                executions.append(
                    (check.account_name, check.check_name, id(session), threading.get_ident())
                )

        with ExitStack() as patches:
            patches.enter_context(patch("headroom.analysis.results_exist", return_value=False))
            patches.enter_context(
                patch("headroom.analysis.all_check_results_exist", return_value=False)
            )
            patches.enter_context(
                patch("headroom.analysis.get_headroom_session", side_effect=build_a_session)
            )
            for check_class in get_all_check_classes():
                patches.enter_context(
                    patch.object(check_class, "execute", autospec=True, side_effect=record)
                )
            run_checks(MagicMock(), accounts, self._config(len(accounts)), set(), ORG_ID)

        rows_by_account: Dict[str, List[Tuple[str, str, int, int]]] = {}
        for row in executions:
            rows_by_account.setdefault(row[0], []).append(row)

        assert sorted(rows_by_account) == sorted(account.name for account in accounts)

        checks_per_account = [sorted(row[1] for row in rows) for rows in rows_by_account.values()]
        assert checks_per_account[0] == sorted(get_check_names())
        assert all(checks == checks_per_account[0] for checks in checks_per_account)
        assert len(set(checks_per_account[0])) == len(checks_per_account[0])

        for rows in rows_by_account.values():
            assert len({row[2] for row in rows}) == 1
            assert len({row[3] for row in rows}) == 1

        assert len({rows[0][2] for rows in rows_by_account.values()}) == len(accounts)
        assert len({rows[0][3] for rows in rows_by_account.values()}) == len(accounts)
