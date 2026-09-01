"""Tests for headroom/aws/organization_snapshot.py."""

import re
from typing import Any, Callable, Dict, Iterator, List, Optional, cast, get_args
from unittest.mock import MagicMock, Mock, patch

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from mypy_boto3_organizations.literals import AccountStateType
from mypy_boto3_organizations.type_defs import AccountTypeDef

from headroom.aws.organization_snapshot import (
    ACTIVE_ACCOUNT_STATE,
    INACTIVE_ACCOUNT_STATES,
    _build_account_info_from_account_dict,
    _fetch_account_tags,
    _verify_account_names_are_filename_safe,
    _verify_no_duplicate_account_names,
    discover_organization,
)
from headroom.config import AccountTagLayout, HeadroomConfig
from tests.constants import ORG_ID
# `_account_infos` stays in tests/test_analysis.py, next to the
# `MAX_GENERATED_ACCOUNTS` bound it enforces and the test that validates the
# IDs it builds. Duplicating it here is what the helper's own docstring warns
# against: three copies of the derivation are how `str(index + 1) * 12`
# survived producing 24-digit account IDs.
from tests.test_analysis import _account_infos

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

        Retention is asserted over more than one inactive state on purpose:
        CLOSED is the state an operator most expects to disappear from an
        organization, and SUSPENDED the one AWS keeps longest. Both remain
        members and both remain placed.

        The management account's own state is deliberately unrecognizable
        (`BRAND_NEW_STATE`, not `ACTIVE`). `_select_analyzable_accounts`
        excludes the management account before it ever consults
        `_should_skip_account`, so this must not abort. If that ordering
        regressed -- lifecycle classification running first -- a management
        account in any state the lifecycle check cannot classify would abort
        the entire run, for an account excluded from analysis regardless of
        its state.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "BRAND_NEW_STATE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
            {"Id": BILLING, "Name": "billing", "Status": "CLOSED"},
            {"Id": RETIRED, "Name": "retired", "Status": "SUSPENDED"},
            {"Id": SKIPPED, "Name": "sandbox", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        snapshot = discover_organization(
            _config(skip_account_ids=[SKIPPED]), org_client
        )

        assert snapshot.organization_id == ORG_ID
        assert snapshot.member_account_ids == frozenset(
            {MANAGEMENT, PAYMENTS, BILLING, RETIRED, SKIPPED}
        )
        assert set(snapshot.hierarchy.accounts) == {
            MANAGEMENT,
            PAYMENTS,
            BILLING,
            RETIRED,
            SKIPPED,
        }
        assert [account.account_id for account in snapshot.analyzable_accounts] == [
            PAYMENTS
        ]

    def test_analyzable_accounts_keep_the_order_organizations_reported(self) -> None:
        """
        `OrganizationSnapshot.analyzable_accounts` promises Organizations'
        order, and nothing downstream re-sorts it: the worker pool consumes
        the tuple as it stands, so this order is the order accounts are
        scanned and result files appear in.

        The fixture is deliberately neither ascending nor descending by
        account ID, so a `sorted()` and a `[::-1]` both fail it -- reversing
        the list survived the entire suite. The two excluded accounts are
        interleaved rather than appended, which is what shows their removal
        does not disturb the accounts either side of them.
        """
        accounts = [
            {"Id": BILLING, "Name": "billing", "Status": "ACTIVE"},
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
            {"Id": SKIPPED, "Name": "sandbox", "Status": "ACTIVE"},
            {"Id": RETIRED, "Name": "retired", "Status": "ACTIVE"},
        ]

        snapshot = discover_organization(
            _config(skip_account_ids=[SKIPPED]), _org_client(accounts)
        )

        assert [account.account_id for account in snapshot.analyzable_accounts] == [
            BILLING,
            PAYMENTS,
            RETIRED,
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
        Two names, on purpose.

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

        Asserting the abort alone would not distinguish "reads the ID first"
        from "reads everything, then checks the ID last." `get_paginator` is
        never called at all here, which pins the former: the account listing
        -- and every other Organizations call -- is never requested.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)
        org_client.describe_organization.return_value = {"Organization": {}}

        with pytest.raises(RuntimeError, match="no organization ID"):
            discover_organization(_config(), org_client)

        org_client.get_paginator.assert_not_called()

    def test_an_empty_organization_id_aborts_the_run(self) -> None:
        """
        An empty ID is a present field, so a `None` check lets it through.

        `snapshot.organization_id` is what every `aws:SourceOrgID` condition
        is compared against. The empty string matches no organization, so
        every organization-scoped source guard in the estate would classify
        as naming a foreign org -- the allowlist inverted, reached with no
        error anywhere. That is the outcome this abort exists to prevent, and
        the missing-ID case above cannot pin it: narrowing the guard to
        `org_id is None` still passes every other test in the suite.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)
        org_client.describe_organization.return_value = {"Organization": {"Id": ""}}

        with pytest.raises(RuntimeError, match="no organization ID"):
            discover_organization(_config(), org_client)

    def test_a_response_with_no_organization_at_all_aborts_the_run(self) -> None:
        """
        DescribeOrganization is documented to carry an Organization block, so
        a response without one is a shape this code has never seen -- which
        is exactly when a bare KeyError helps least. The `{}` default keeps
        the abort here, carrying the message that says what the ID is for.
        """
        org_client = _org_client(
            [{"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"}]
        )
        org_client.describe_organization.return_value = {}

        with pytest.raises(RuntimeError, match="no organization ID"):
            discover_organization(_config(), org_client)

    def test_a_connection_failure_reading_the_organization_aborts_the_run(self) -> None:
        """
        `describe_organization` is the first Organizations call a run makes,
        and a connection-level failure leaves botocore as a BotoCoreError,
        not a ClientError. `main`'s reporter catches ValueError, RuntimeError
        and ClientError only, so unwrapped this ends the run in a traceback
        naming neither the phase nor the call.
        """
        org_client = _org_client(
            [{"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"}]
        )
        org_client.describe_organization.side_effect = EndpointConnectionError(
            endpoint_url="https://organizations.amazonaws.com/"
        )

        with pytest.raises(RuntimeError, match="Failed to describe the organization"):
            discover_organization(_config(), org_client)


class TestEveryStateIsClassified:
    """Moved with `ACTIVE_ACCOUNT_STATE` and `INACTIVE_ACCOUNT_STATES`, below."""

    def test_every_state_aws_defines_is_classified(self) -> None:
        """
        The recognized states must exhaustively cover the AWS enum.

        Because an unrecognized state now aborts the run, a state AWS adds would
        break Headroom in production. This test moves that discovery to the point
        where boto3-stubs is upgraded: AccountStateType is the SDK's own
        enumeration, so if AWS adds a sixth state this fails when a human runs
        `tox` and names it, instead of a run failing at a customer. Nothing runs
        it automatically: the repository carries no CI configuration.
        """
        assert set(get_args(AccountStateType)) == {ACTIVE_ACCOUNT_STATE} | INACTIVE_ACCOUNT_STATES


class TestLifecycleStateFiltering:
    """
    Only ACTIVE accounts are analyzed.

    AWS Organizations reports an account's lifecycle position through two
    fields: `State` (PENDING_ACTIVATION, ACTIVE, SUSPENDED, PENDING_CLOSURE,
    CLOSED) and the older `Status` (ACTIVE, SUSPENDED, PENDING_CLOSURE), which
    AWS retires on 2026-09-09. Only an ACTIVE account can have the Headroom
    role assumed in it, so every other state is skipped.

    Every account dictionary below carries `State` rather than `Status` on
    purpose: the rest of this file uses `Status` exclusively, so without these
    the precedence between the two fields would go unpinned.
    """

    @staticmethod
    def _accounts(*others: Dict[str, str]) -> List[Dict[str, str]]:
        """The management account, which is never analyzed, plus `others`."""
        return [
            {"Id": MANAGEMENT, "Name": "management", "State": "ACTIVE"},
            *others,
        ]

    def _analyzed_ids(self, *others: Dict[str, str]) -> List[str]:
        """Return the account IDs that survived lifecycle filtering."""
        snapshot = discover_organization(
            _config(), _org_client(self._accounts(*others))
        )
        return [account.account_id for account in snapshot.analyzable_accounts]

    @pytest.mark.parametrize(
        "state", ["CLOSED", "SUSPENDED", "PENDING_CLOSURE", "PENDING_ACTIVATION"]
    )
    def test_a_non_active_account_is_skipped(self, state: str) -> None:
        """
        Each inactive state is excluded, for its own reason.

        CLOSED and SUSPENDED cannot have a role assumed in them at all.
        PENDING_ACTIVATION never finished sign-up. PENDING_CLOSURE is still
        functional, and excluding it is deliberate policy rather than
        necessity: an account on its way out of the organization should not
        hold back an organization-wide recommendation.
        """
        analyzed = self._analyzed_ids(
            {"Id": BILLING, "Name": "leaving", "State": state},
            {"Id": PAYMENTS, "Name": "payments", "State": "ACTIVE"},
        )

        assert analyzed == [PAYMENTS]

    def test_state_takes_precedence_over_status(self) -> None:
        """
        `State` wins when the two fields disagree.

        AWS retires `Status` on 2026-09-09, so `State` is the authoritative
        field. Reading `Status` first would drop this account from the
        compliance picture on the strength of the field being retired.
        """
        analyzed = self._analyzed_ids(
            {"Id": PAYMENTS, "Name": "payments", "State": "ACTIVE", "Status": "SUSPENDED"},
        )

        assert analyzed == [PAYMENTS]

    def test_falls_back_to_status_when_state_absent(self) -> None:
        """
        `Status` is used when `State` is missing.

        An SDK released before 2025-09-09 does not model `State`, so botocore
        drops it from the response and only `Status` is available.
        """
        analyzed = self._analyzed_ids(
            {"Id": BILLING, "Name": "retired", "Status": "SUSPENDED"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        )

        assert analyzed == [PAYMENTS]

    def test_account_with_no_state_or_status_aborts_the_run(self) -> None:
        """
        An account reporting neither field aborts the run, with a remediation hint.

        The cause is environment-wide rather than per-account: an SDK too old
        to model `State` at a point when `Status` has been retired makes every
        account report nothing. Analyzing anyway would attempt every closed
        account and then die inside assume_role with an AccessDenied that
        names none of the real cause, so this fails at the point the
        information is actually missing.
        """
        with pytest.raises(RuntimeError, match="neither State nor Status") as exc_info:
            self._analyzed_ids({"Id": PAYMENTS, "Name": "payments"})

        # The error must be actionable, not merely loud.
        assert "boto3" in str(exc_info.value)

    def test_account_with_unrecognized_state_aborts_the_run(self) -> None:
        """
        A state this code does not classify aborts the run rather than guessing.

        Neither guess is safe. Analyzing an account that turns out to be
        unusable burns the run on a downstream error that explains nothing,
        and skipping one that is actually usable drops it from the compliance
        picture that gates SCP deployment. Refusing to guess keeps a human in
        the loop, so the message has to name both the offending value and the
        fix.
        """
        with pytest.raises(RuntimeError, match="does not recognize") as exc_info:
            self._analyzed_ids(
                {"Id": PAYMENTS, "Name": "payments", "State": "SOME_FUTURE_STATE"}
            )

        message = str(exc_info.value)
        assert "SOME_FUTURE_STATE" in message
        assert "INACTIVE_ACCOUNT_STATES" in message

    def test_skipped_accounts_are_summarized_by_state(self) -> None:
        """
        One summary line reports how many accounts were skipped in each state.

        The operator's only signal that the analyzable set is smaller than the
        organization. Reported per state, because two CLOSED accounts are
        routine and two PENDING_ACTIVATION ones are an onboarding that stalled.
        """
        accounts = self._accounts(
            {"Id": BILLING, "Name": "billing", "State": "CLOSED"},
            {"Id": RETIRED, "Name": "retired", "State": "CLOSED"},
            {"Id": SKIPPED, "Name": "sandbox", "State": "SUSPENDED"},
            {"Id": PAYMENTS, "Name": "payments", "State": "ACTIVE"},
        )

        with patch("headroom.aws.organization_snapshot.logger") as mock_logger:
            discover_organization(_config(), _org_client(accounts))

        logged = " ".join(str(call) for call in mock_logger.info.call_args_list)
        assert "Skipped 3 non-active account(s)" in logged
        assert "2 CLOSED" in logged
        assert "1 SUSPENDED" in logged


class TestSkipAccountIdsReporting:
    """
    What `skip_account_ids` tells the operator it did.

    The exclusion itself is covered by `TestProjections`; these two are the
    messages, which no other test asserts on -- and a skip that reports
    nothing is a skip the operator cannot confirm did what was intended.
    """

    def test_skipped_accounts_are_logged(self) -> None:
        """
        The operator can see which accounts the configuration excluded.

        Sorted, and named individually rather than counted: the reason to read
        this line is to confirm the entries did what was intended, and a bare
        count cannot tell a correct entry from one that matched a neighbour.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": BILLING, "Name": "billing", "Status": "ACTIVE"},
            {"Id": SKIPPED, "Name": "sandbox", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]

        with patch("headroom.aws.organization_snapshot.logger") as mock_logger:
            discover_organization(
                _config(skip_account_ids=[SKIPPED, BILLING]), _org_client(accounts)
            )

        mock_logger.info.assert_any_call(
            f"Skipped 2 account(s) named in skip_account_ids: {BILLING}, {SKIPPED}"
        )

    def test_the_abort_names_every_unmatched_skip_id(self) -> None:
        """
        All bad entries are listed, so they can be fixed in one pass.

        Reporting only the first turns a two-typo configuration into two
        aborted runs.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]

        with pytest.raises(RuntimeError) as exc_info:
            discover_organization(
                _config(skip_account_ids=[RETIRED, BILLING]), _org_client(accounts)
            )

        assert f"{BILLING}, {RETIRED}" in str(exc_info.value)


class TestFetchAccountTagsPagination:
    """
    `_fetch_account_tags` paginates, and a mid-pagination failure discards
    what it already read.
    """

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


class TestFilenameSafetyGatesAreEnforced:
    """
    `discover_organization` must call the filename-safety and duplicate-name
    checks itself, rather than depend on a caller to.

    `discover_organization` is now their sole caller: `perform_analysis`
    consumes the snapshot and calls neither. Nothing else would catch their
    removal -- `.coveragerc` sets no `branch = True`, so a deleted function
    call is invisible to line coverage, and every direct test of the two
    checks would stay green with nothing calling them. These two tests are
    what fail instead.
    """

    def test_an_unsafe_account_name_aborts_the_run(self) -> None:
        """
        Without this gate, `../Prod` reaches `ResultFilePathResolver`, which
        interpolates the account name into a path rather than treating it as
        plain text: the result file lands one level *above* its check
        directory, at `check_dir/../Prod.json`, silently overwriting
        whatever was already there instead of landing where policy
        generation reads results from.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "../Prod", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        with pytest.raises(RuntimeError, match="cannot be used as result filenames"):
            discover_organization(_config(), org_client)

    def test_duplicate_account_names_abort_the_run(self) -> None:
        """
        Without this gate, two accounts sharing a name -- legal only because
        `exclude_account_ids` drops the account ID from the filename, the
        only thing that otherwise guarantees uniqueness -- resolve to the
        same result file path. Run with a worker per account, that is two
        threads interleaving `json.dump` output into one file: either
        corrupt JSON, or a valid file silently splicing both accounts'
        results together for policy generation to read.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "shared-name", "Status": "ACTIVE"},
            {"Id": BILLING, "Name": "shared-name", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        with pytest.raises(RuntimeError, match="not unique"):
            discover_organization(_config(exclude_account_ids=True), org_client)


class TestSkippingTheManagementAccountIsAllowed:
    """
    Naming the management account in `skip_account_ids` is redundant, not an
    error -- and this is the only place that says so.
    """

    def test_naming_the_management_account_in_skip_account_ids_does_not_abort(self) -> None:
        """
        The management account is excluded before the skip list is
        consulted, so it never registers as skipped by
        `_select_analyzable_accounts` -- but `_verify_skip_account_ids_matched`
        checks every skip entry against full membership, not against the
        analyzable set, and the management account is still a real member.
        Collapsing those two projections -- checking the entry against
        analyzable accounts instead of membership -- would make this entry
        look unmatched and abort a run whose configuration is doing nothing
        wrong.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        with patch("headroom.aws.organization_snapshot.logger") as mock_logger:
            snapshot = discover_organization(
                _config(skip_account_ids=[MANAGEMENT]), org_client
            )

        assert [account.account_id for account in snapshot.analyzable_accounts] == [PAYMENTS]
        # "Excluded before the skip list is consulted" is the claim above, and
        # the analyzable set alone cannot see it: both orders exclude the
        # management account. The log line is where the two differ, and
        # consulting the skip list first would report an account as skipped by
        # a configuration entry that never did any work.
        skip_lines = [
            call.args[0] for call in mock_logger.info.call_args_list
            if "named in skip_account_ids" in call.args[0]
        ]
        assert skip_lines == []


class TestTheTwoViewsMustAgree:
    """The global listing and the OU traversal describe one organization."""

    def test_an_account_in_no_parent_aborts(self) -> None:
        """
        list_accounts_for_parent returns accounts in every lifecycle state,
        so an account that is a member but sits under nothing means the
        organization changed mid-read, not that it is closed.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]
        org_client = _org_client(
            accounts,
            accounts_by_parent={"r-1111": [accounts[0]]},
        )

        with pytest.raises(RuntimeError, match=f"under no root or OU: {PAYMENTS}"):
            discover_organization(_config(), org_client)

    def test_an_account_under_a_parent_but_not_a_member_aborts(self) -> None:
        """An account created between the two reads is in one view only."""
        accounts = [{"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"}]
        org_client = _org_client(
            accounts,
            accounts_by_parent={
                "r-1111": accounts + [{"Id": PAYMENTS, "Name": "payments"}]
            },
        )

        with pytest.raises(RuntimeError, match=f"not organization members: {PAYMENTS}"):
            discover_organization(_config(), org_client)

    def test_an_account_named_differently_by_the_two_views_aborts(self) -> None:
        """
        lookup_account_id_by_name matches the traversal's name against result
        files named from the global view, so the two disagreeing means every
        later lookup is matching against a name that no longer exists.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]
        org_client = _org_client(
            accounts,
            accounts_by_parent={
                "r-1111": [accounts[0], {"Id": PAYMENTS, "Name": "payments-renamed"}]
            },
        )

        with pytest.raises(RuntimeError, match="'payments' and 'payments-renamed'"):
            discover_organization(_config(), org_client)

    def test_agreeing_views_do_not_abort(self) -> None:
        """The ordinary case: one organization, two consistent readings."""
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]

        snapshot = discover_organization(_config(), _org_client(accounts))

        assert snapshot.member_account_ids == frozenset({MANAGEMENT, PAYMENTS})


class TestDuplicateAccountIdGuard:
    """
    list_accounts returning one account ID twice must abort on its own.

    build_organization_hierarchy already aborts when an account is placed
    under two parents; the membership view had no equivalent guard.
    """

    def test_a_duplicated_account_id_in_membership_aborts(self) -> None:
        """
        `member_account_ids` is a frozenset and `_verify_views_agree` keys
        `inventory_names` by ID, so both silently collapse a repeated
        `list_accounts` entry before anything else can see it.

        The traversal view lists PAYMENTS once, so the traversal's own
        duplicate-parent guard is not what raises here -- only the
        membership view is duplicated.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "payments", "Status": "ACTIVE"},
        ]
        org_client = _org_client(
            accounts,
            accounts_by_parent={"r-1111": accounts[:2]},
        )

        with pytest.raises(
            RuntimeError, match=f"more than once by list_accounts: {PAYMENTS}"
        ):
            discover_organization(_config(), org_client)


class TestEveryAccountMustBeNamed:
    """
    A `list_accounts` entry carrying no name aborts rather than borrowing one.

    `_verify_views_agree` compares the two views' raw Organizations names, so
    it indexes `Name` directly, and a nameless account used to reach it as a
    bare KeyError -- an exception `main`'s reporter does not catch, naming
    neither the discovery phase nor the account.
    """

    def test_an_account_with_no_name_aborts_the_run(self) -> None:
        """
        Substituting the account ID is the tempting fallback and the wrong
        one: the ID is what the two views' names would then be compared
        against, so the cross-check would report them agreeing on a name
        neither view holds.

        The gate runs over the membership listing, before the traversal, so
        the traversal's own `account["Name"]` is never reached -- the run
        stops while the listing that omitted the name is still the subject.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        with pytest.raises(
            RuntimeError, match=rf"account\(s\) with no name: {PAYMENTS}"
        ):
            discover_organization(_config(), org_client)

        org_client.get_paginator.assert_called_once_with("list_accounts")

    def test_an_empty_name_aborts_the_run_as_a_missing_one(self) -> None:
        """
        An empty name is absent for every purpose the name serves: there is
        nothing to compare across the views and nothing to name a result
        file. It aborts here rather than reaching the filename gate, which
        would otherwise report it against an account name the run invented.
        """
        accounts = [
            {"Id": MANAGEMENT, "Name": "management", "Status": "ACTIVE"},
            {"Id": PAYMENTS, "Name": "", "Status": "ACTIVE"},
        ]
        org_client = _org_client(accounts)

        with pytest.raises(
            RuntimeError, match=rf"account\(s\) with no name: {PAYMENTS}"
        ):
            discover_organization(_config(), org_client)


class TestFetchAccountTags:
    """Test _fetch_account_tags directly, below the discover_organization layer."""

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

    @patch("headroom.aws.organization_snapshot.logger")
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

    @patch("headroom.aws.organization_snapshot.logger")
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
