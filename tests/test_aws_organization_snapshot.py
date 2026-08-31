"""Tests for headroom/aws/organization_snapshot.py."""

from typing import Any, Callable, Dict, Iterator, List, Optional, get_args
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from mypy_boto3_organizations.literals import AccountStateType

from headroom.aws.organization_snapshot import (
    ACTIVE_ACCOUNT_STATE,
    INACTIVE_ACCOUNT_STATES,
    _fetch_account_tags,
    discover_organization,
)
from headroom.config import AccountTagLayout, HeadroomConfig
from tests.constants import ORG_ID

MANAGEMENT = "111111111111"
PAYMENTS = "222222222222"
BILLING = "333333333333"
RETIRED = "444444444444"
SKIPPED = "555555555555"


def _config(**overrides: Any) -> HeadroomConfig:
    """A configuration whose management account is MANAGEMENT."""
    values: Dict[str, Any] = {
        "management_account_id": MANAGEMENT,
        "security_analysis_account_id": PAYMENTS,
        "use_account_name_from_tags": False,
        "account_tag_layout": AccountTagLayout(environment="Env", name="Name", owner="Owner"),
    }
    values.update(overrides)
    return HeadroomConfig(**values)


# Note: `tests/test_aws_organization.py` has a similarly-named helper whose
# per-parent values are *lists of pages*. This one takes a flat list per
# parent, because these tests are about projections rather than pagination.
def _org_client(
    accounts: List[Dict[str, str]],
    ous_by_parent: Optional[Dict[str, List[Dict[str, str]]]] = None,
    accounts_by_parent: Optional[Dict[str, List[Dict[str, str]]]] = None,
    tags_by_account: Optional[Dict[str, List[Dict[str, str]]]] = None,
    tag_calls: Optional[List[str]] = None,
) -> Mock:
    """
    Build an Organizations client backed by one consistent organization.

    `accounts` is the global list_accounts view. `accounts_by_parent` is the
    placement view; when omitted every account hangs off the root, which keeps
    the two views in agreement by construction so a test that is not about the
    cross-check does not have to restate the organization twice.
    """
    ous_by_parent = ous_by_parent or {}
    if accounts_by_parent is None:
        accounts_by_parent = {"r-1111": accounts}
    tags_by_account = tags_by_account or {}

    def get_paginator(operation_name: str) -> Mock:
        paginator = Mock()

        def paginate_op(**kwargs: str) -> List[Dict[str, object]]:
            if operation_name == "list_accounts":
                return [{"Accounts": accounts}]
            if operation_name == "list_roots":
                return [{"Roots": [{"Id": "r-1111"}]}]
            if operation_name == "list_tags_for_resource":
                account_id = kwargs["ResourceId"]
                if tag_calls is not None:
                    tag_calls.append(account_id)
                return [{"Tags": tags_by_account.get(account_id, [])}]
            if operation_name == "list_organizational_units_for_parent":
                return [{"OrganizationalUnits": ous_by_parent.get(kwargs["ParentId"], [])}]
            return [{"Accounts": accounts_by_parent.get(kwargs["ParentId"], [])}]

        paginator.paginate.side_effect = paginate_op
        return paginator

    org_client = Mock()
    org_client.get_paginator.side_effect = get_paginator
    org_client.describe_organization.return_value = {"Organization": {"Id": ORG_ID}}
    return org_client


class TestProjections:
    """Membership, analyzable accounts, and hierarchy are distinct views."""

    def test_management_closed_and_skipped_accounts_stay_out_of_analysis_only(self) -> None:
        """
        The three projections disagree on purpose.

        Membership is the RCP third-party oracle, so a closed sibling must
        stay in it or its account ID reads as a third party. The hierarchy
        resolves result files written before an account closed. Only the
        analyzable set is filtered.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
            {"Id": RETIRED, "Name": "retired", "Status": "SUSPENDED"},
            {"Id": SKIPPED, "Name": "sandbox", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        snapshot = discover_organization(
            _config(skip_account_ids=[SKIPPED]), org_client
        )

        assert snapshot.organization_id == ORG_ID
        assert snapshot.member_account_ids == frozenset(
            {MANAGEMENT, PAYMENTS, RETIRED, SKIPPED}
        )
        assert set(snapshot.hierarchy.accounts) == {
            MANAGEMENT,
            PAYMENTS,
            RETIRED,
            SKIPPED,
        }
        assert [account.account_id for account in snapshot.analyzable_accounts] == [
            PAYMENTS
        ]

    def test_no_tags_are_fetched_for_excluded_accounts(self) -> None:
        """
        A tag lookup is a call per account. The management account and a
        skipped one are never analyzed, so paying for their tags is waste,
        and reading a skipped account at all is what the setting rules out.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
            {"Id": RETIRED, "Name": "retired", "Status": "SUSPENDED"},
            {"Id": SKIPPED, "Name": "sandbox", "Status": "ACTIVE"},
        ]
        tag_calls: List[str] = []
        org_client = _org_client(accounts, tag_calls=tag_calls)

        discover_organization(_config(skip_account_ids=[SKIPPED]), org_client)

        assert tag_calls == [PAYMENTS]

    def test_the_tag_name_and_the_organizations_name_stay_distinct(self) -> None:
        """
        Two names, on purpose, and a second-page tag proves both are read.

        AccountInfo.name is the analysis name and names the result files;
        AccountOrgPlacement.account_name is what Organizations reports and is
        what lookup_account_id_by_name matches. Collapsing them would break
        the fallback that bridges "Payments Account" to "payments-account".
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "Payments Account", "Status": "ACTIVE"},
        ]
        org_client = _org_client(
            accounts,
            tags_by_account={PAYMENTS: [{"Key": "Name", "Value": "payments"}]},
        )

        snapshot = discover_organization(
            _config(use_account_name_from_tags=True), org_client
        )

        assert snapshot.analyzable_accounts[0].name == "payments"
        assert snapshot.hierarchy.accounts[PAYMENTS].account_name == "Payments Account"

    def test_an_unmatched_skip_entry_aborts_ahead_of_an_unknown_state(self) -> None:
        """
        Full membership is known before any filtering now, so a mistyped skip
        entry reports itself rather than losing the race to a lifecycle abort
        it may well have caused.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "BRAND_NEW_STATE"},
        ]
        org_client = _org_client(accounts)

        with pytest.raises(RuntimeError, match="not in the organization"):
            discover_organization(_config(skip_account_ids=[BILLING]), org_client)


class TestOrganizationIdIsRequired:
    """`_read_organization_id` aborts before any other call is made."""

    def test_a_response_with_no_organization_id_aborts_the_run(self) -> None:
        """
        Every source guard scoped to an organization is classified against
        this value, so continuing without it would put a foreign
        organization's sources in an allowlist, or leave this one's out.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)
        org_client.describe_organization.return_value = {"Organization": {}}

        with pytest.raises(RuntimeError, match="no organization ID"):
            discover_organization(_config(), org_client)


class TestEveryStateIsClassified:
    """Moved with `ACTIVE_ACCOUNT_STATE` and `INACTIVE_ACCOUNT_STATES`, below."""

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


class TestFetchAccountTagsPagination:
    """`_fetch_account_tags` paginates; moved here with the Task 5 regression test it covers."""

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

        org_client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = _pages()
        org_client.get_paginator.return_value = paginator

        with patch("headroom.aws.organization_snapshot.logger") as mock_logger:
            tags = _fetch_account_tags(org_client, "111111111111", "payments")

        assert tags == {}
        mock_logger.warning.assert_called_once()


class TestTagFetchFailureDuringDiscovery:
    """Invariant 11, driven through discover_organization rather than the account helper directly."""

    def test_tag_fetch_error_warns_and_defaults_rather_than_aborting(self) -> None:
        """
        A tag access failure must not abort the run.

        `_fetch_account_tags` already defaults to {} and warns on ClientError;
        this pins that `discover_organization` surfaces that behavior rather
        than letting the exception escape and abort every other account too.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)
        organization_view: Callable[[str], Mock] = org_client.get_paginator.side_effect

        def get_paginator(operation_name: str) -> Mock:
            if operation_name == "list_tags_for_resource":
                paginator = Mock()
                paginator.paginate.side_effect = ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                    "ListTagsForResource"
                )
                return paginator
            return organization_view(operation_name)

        org_client.get_paginator.side_effect = get_paginator

        with patch("headroom.aws.organization_snapshot.logger") as mock_logger:
            snapshot = discover_organization(_config(), org_client)

        assert [account.account_id for account in snapshot.analyzable_accounts] == [PAYMENTS]
        assert snapshot.analyzable_accounts[0].environment == "unknown"
        assert snapshot.analyzable_accounts[0].owner == "unknown"
        mock_logger.warning.assert_called()


class TestSkipPrecedesLifecycleClassification:
    """The order `_select_analyzable_accounts` documents, exercised end to end."""

    def test_skip_takes_precedence_over_unknown_lifecycle_state(self) -> None:
        """
        Skipping an account bypasses lifecycle classification for it.

        An unrecognized lifecycle state normally aborts the run. Checking the
        skip list first makes skip_account_ids an escape hatch for the account
        that triggered the abort, so one odd account cannot block the run.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": BILLING, "Name": "Odd", "Status": "SOME_NEW_STATE"},
            {"Id": PAYMENTS, "Name": "Live", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        snapshot = discover_organization(
            _config(skip_account_ids=[BILLING]), org_client
        )

        assert [account.account_id for account in snapshot.analyzable_accounts] == [PAYMENTS]
