"""Tests for headroom/aws/organization.py."""

from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from headroom.aws.organization import (
    analyze_organization_structure,
    build_organization_hierarchy,
    find_organization_root,
    lookup_account_id_by_name,
)
from headroom.types import (
    AccountOrgPlacement,
    OrganizationHierarchy,
)


def _paginating_org_client(
    ous_by_parent: Dict[str, List[List[Dict[str, str]]]],
    accounts_by_parent: Dict[str, List[List[Dict[str, str]]]],
    calls: Optional[List[Tuple[str, str]]] = None,
) -> Mock:
    """
    Build an Organizations client whose two listings paginate per parent.

    Each dict maps a parent ID to the list of pages that parent's listing
    returns, so a test spells its pagination out rather than relying on the
    order the traversal happens to visit parents in. `calls`, when given,
    records every (operation, parent) pair the traversal issues.
    """
    def get_paginator(operation_name: str) -> Mock:
        paginator = Mock()

        def paginate_op(**kwargs: str) -> List[Dict[str, object]]:
            parent = kwargs["ParentId"]
            if calls is not None:
                calls.append((operation_name, parent))
            if operation_name == "list_organizational_units_for_parent":
                pages = ous_by_parent.get(parent, [[]])
                return [{"OrganizationalUnits": page} for page in pages]
            pages = accounts_by_parent.get(parent, [[]])
            return [{"Accounts": page} for page in pages]

        paginator.paginate.side_effect = paginate_op
        return paginator

    org_client = Mock()
    org_client.get_paginator.side_effect = get_paginator
    return org_client


class TestBuildOrganizationHierarchy:
    """Test build_organization_hierarchy."""

    def test_root_ous_on_page_two_are_retained(self) -> None:
        """A top-level OU past page one was silently dropped."""
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [
                    [{"Id": "ou-1111-11111111", "Name": "Production"}],
                    [{"Id": "ou-2222-22222222", "Name": "Staging"}],
                ],
            },
            accounts_by_parent={},
        )

        hierarchy = build_organization_hierarchy(org_client, "r-1111")

        assert set(hierarchy.organizational_units) == {
            "ou-1111-11111111",
            "ou-2222-22222222",
        }

    def test_nested_ous_on_page_two_are_retained(self) -> None:
        """A nested OU past page one was dropped along with its subtree."""
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [[{"Id": "ou-1111-11111111", "Name": "Production"}]],
                "ou-1111-11111111": [
                    [],
                    [{"Id": "ou-2222-22222222", "Name": "Payments"}],
                ],
            },
            accounts_by_parent={},
        )

        hierarchy = build_organization_hierarchy(org_client, "r-1111")

        payments = hierarchy.organizational_units["ou-2222-22222222"]
        assert payments.parent_ou_id == "ou-1111-11111111"
        assert payments.name == "Payments"
        assert hierarchy.organizational_units["ou-1111-11111111"].child_ous == [
            "ou-2222-22222222"
        ]

    def test_ou_accounts_on_page_two_are_retained(self) -> None:
        """An account past page one of its OU was dropped from placement."""
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [[{"Id": "ou-1111-11111111", "Name": "Production"}]],
            },
            accounts_by_parent={
                "ou-1111-11111111": [
                    [{"Id": "111111111111", "Name": "payments"}],
                    [{"Id": "222222222222", "Name": "billing"}],
                ],
            },
        )

        hierarchy = build_organization_hierarchy(org_client, "r-1111")

        assert set(hierarchy.accounts) == {"111111111111", "222222222222"}
        assert hierarchy.accounts["222222222222"].parent_ou_id == "ou-1111-11111111"
        assert hierarchy.accounts["222222222222"].ou_path == ["Production"]

    def test_root_accounts_on_page_two_are_retained(self) -> None:
        """An account hanging off the root, past page one, was dropped."""
        org_client = _paginating_org_client(
            ous_by_parent={},
            accounts_by_parent={
                "r-1111": [
                    [{"Id": "111111111111", "Name": "management"}],
                    [{"Id": "222222222222", "Name": "sandbox"}],
                ],
            },
        )

        hierarchy = build_organization_hierarchy(org_client, "r-1111")

        sandbox = hierarchy.accounts["222222222222"]
        assert sandbox.parent_ou_id is None
        assert sandbox.ou_path == ["Root"]

    def test_an_empty_intermediate_page_does_not_truncate(self) -> None:
        """
        An empty page mid-listing is not the end of the listing.

        A reader that stopped on the first empty page would lose everything
        after it, which is the same bug as reading page one only, arriving
        later in the sequence.
        """
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [
                    [{"Id": "ou-1111-11111111", "Name": "Production"}],
                    [],
                    [{"Id": "ou-2222-22222222", "Name": "Staging"}],
                ],
            },
            accounts_by_parent={
                "r-1111": [
                    [{"Id": "111111111111", "Name": "management"}],
                    [],
                    [{"Id": "222222222222", "Name": "sandbox"}],
                ],
            },
        )

        hierarchy = build_organization_hierarchy(org_client, "r-1111")

        assert len(hierarchy.organizational_units) == 2
        assert len(hierarchy.accounts) == 2

    def test_each_parent_is_queried_exactly_once_per_listing(self) -> None:
        """
        The old traversal listed every OU's children twice: once on the way
        into the recursion, once again to fill child_ous.
        """
        calls: List[Tuple[str, str]] = []
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [[{"Id": "ou-1111-11111111", "Name": "Production"}]],
                "ou-1111-11111111": [[{"Id": "ou-2222-22222222", "Name": "Payments"}]],
            },
            accounts_by_parent={},
            calls=calls,
        )

        build_organization_hierarchy(org_client, "r-1111")

        assert sorted(calls) == sorted([
            ("list_organizational_units_for_parent", "r-1111"),
            ("list_organizational_units_for_parent", "ou-1111-11111111"),
            ("list_organizational_units_for_parent", "ou-2222-22222222"),
            ("list_accounts_for_parent", "r-1111"),
            ("list_accounts_for_parent", "ou-1111-11111111"),
            ("list_accounts_for_parent", "ou-2222-22222222"),
        ])

    def test_a_later_page_error_aborts_with_no_partial_hierarchy(self) -> None:
        """A failure partway through must not return what it read first."""
        error: object = {"Error": {"Code": "ThrottlingException"}}

        def get_paginator(operation_name: str) -> Mock:
            paginator = Mock()

            def paginate_op(**kwargs: str) -> Iterable[Dict[str, Any]]:
                if operation_name == "list_accounts_for_parent":
                    return [{"Accounts": []}]

                def pages() -> Iterator[Dict[str, Any]]:
                    yield {
                        "OrganizationalUnits": [
                            {"Id": "ou-1111-11111111", "Name": "Production"}
                        ]
                    }
                    raise ClientError(error, "ListOrganizationalUnitsForParent")  # type: ignore[arg-type]

                return pages()

            paginator.paginate.side_effect = paginate_op
            return paginator

        org_client = Mock()
        org_client.get_paginator.side_effect = get_paginator

        with pytest.raises(RuntimeError, match="Failed to list the OUs under r-1111"):
            build_organization_hierarchy(org_client, "r-1111")

    def test_an_account_under_two_parents_aborts(self) -> None:
        """
        One account has one parent. Seeing it twice means the organization
        moved it between pages, and the hierarchy dict would silently keep
        whichever placement was written last.
        """
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [[{"Id": "ou-1111-11111111", "Name": "Production"}]],
            },
            accounts_by_parent={
                "r-1111": [[{"Id": "111111111111", "Name": "payments"}]],
                "ou-1111-11111111": [[{"Id": "111111111111", "Name": "payments"}]],
            },
        )

        with pytest.raises(
            RuntimeError,
            match="111111111111 appears under more than one parent: r-1111 and ou-1111-11111111",
        ):
            build_organization_hierarchy(org_client, "r-1111")

    def test_a_later_accounts_page_error_aborts_with_no_partial_hierarchy(self) -> None:
        """A failure listing accounts partway through must not return what it read first."""
        error: object = {"Error": {"Code": "ThrottlingException"}}

        def get_paginator(operation_name: str) -> Mock:
            paginator = Mock()

            def paginate_op(**kwargs: str) -> Iterable[Dict[str, Any]]:
                if operation_name == "list_organizational_units_for_parent":
                    return [{"OrganizationalUnits": []}]

                def pages() -> Iterator[Dict[str, Any]]:
                    yield {
                        "Accounts": [
                            {"Id": "111111111111", "Name": "payments"}
                        ]
                    }
                    raise ClientError(error, "ListAccountsForParent")  # type: ignore[arg-type]

                return pages()

            paginator.paginate.side_effect = paginate_op
            return paginator

        org_client = Mock()
        org_client.get_paginator.side_effect = get_paginator

        with pytest.raises(RuntimeError, match="Failed to list the accounts under r-1111"):
            build_organization_hierarchy(org_client, "r-1111")

    def test_accounts_are_retained_whatever_their_lifecycle_state(self) -> None:
        """
        SUSPENDED and CLOSED accounts stay in the hierarchy.

        Placement is driven by the check results that exist on disk, not by an
        account's current lifecycle state, so a result written before an
        account closed must still resolve to a placement. Filtering here
        would collapse organization membership into the narrower,
        already-filtered view that get_subaccount_information deliberately
        applies for analysis, and CLAUDE.md calls that collapse out by name.
        """
        org_client = _paginating_org_client(
            ous_by_parent={},
            accounts_by_parent={
                "r-1111": [[
                    {"Id": "111111111111", "Name": "sandbox", "Status": "SUSPENDED"},
                    {"Id": "222222222222", "Name": "retired", "Status": "CLOSED"},
                ]],
            },
        )

        hierarchy = build_organization_hierarchy(org_client, "r-1111")

        assert set(hierarchy.accounts) == {"111111111111", "222222222222"}
        assert hierarchy.accounts["111111111111"].parent_ou_id is None
        assert hierarchy.accounts["111111111111"].ou_path == ["Root"]
        assert hierarchy.accounts["222222222222"].parent_ou_id is None
        assert hierarchy.accounts["222222222222"].ou_path == ["Root"]

    def test_a_parent_reached_twice_aborts(self) -> None:
        """
        An OU listed under two parents would recurse without end. AWS cannot
        produce that, but an OU moved between pages can be observed twice.
        """
        org_client = _paginating_org_client(
            ous_by_parent={
                "r-1111": [[
                    {"Id": "ou-1111-11111111", "Name": "Production"},
                    {"Id": "ou-2222-22222222", "Name": "Staging"},
                ]],
                "ou-1111-11111111": [[{"Id": "ou-3333-33333333", "Name": "Shared"}]],
                "ou-2222-22222222": [[{"Id": "ou-3333-33333333", "Name": "Shared"}]],
            },
            accounts_by_parent={},
        )

        with pytest.raises(RuntimeError, match="ou-3333-33333333 was reached more than once"):
            build_organization_hierarchy(org_client, "r-1111")


class TestOrganizationStructureAnalysis:
    """Test organization structure analysis functions."""

    def test_the_session_adapter_finds_the_root_and_walks_from_it(self) -> None:
        """Kept only until Task 4 deletes analyze_organization_structure."""
        org_client = _paginating_org_client(
            ous_by_parent={"r-1111": [[{"Id": "ou-1111-11111111", "Name": "Production"}]]},
            accounts_by_parent={},
        )
        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": [{"Id": "r-1111"}]}]
        original: Callable[[str], Mock] = org_client.get_paginator.side_effect

        def get_paginator(operation_name: str) -> Mock:
            if operation_name == "list_roots":
                return roots_paginator
            return original(operation_name)

        org_client.get_paginator.side_effect = get_paginator
        session = Mock()
        session.client.return_value = org_client

        hierarchy = analyze_organization_structure(session)

        assert hierarchy.root_id == "r-1111"
        assert "ou-1111-11111111" in hierarchy.organizational_units


class TestLookupAccountIdByName:
    """Test resolution of an account name to an account ID."""

    @staticmethod
    def _hierarchy(names: Dict[str, str]) -> OrganizationHierarchy:
        """Build a flat hierarchy from a mapping of account ID to account name."""
        return OrganizationHierarchy(
            root_id="r-test",
            organizational_units={},
            accounts={
                account_id: AccountOrgPlacement(
                    account_id=account_id,
                    account_name=account_name,
                    parent_ou_id="r-test",
                    ou_path=["Root"],
                )
                for account_id, account_name in names.items()
            },
        )

    def test_matches_name_differing_only_by_case_and_separators(self) -> None:
        """
        A slug-style name resolves to the Organizations account name.

        Organizations names the account "Management Account" while the Name tag
        that result files are written under reads "management-account". Both
        canonicalize to the same form and only one account matches, so the
        lookup resolves rather than failing.
        """
        hierarchy = self._hierarchy({
            "111111111111": "Management Account",
            "222222222222": "Production",
        })

        assert lookup_account_id_by_name("management-account", hierarchy) == "111111111111"

    def test_raises_when_canonical_match_is_ambiguous(self) -> None:
        """
        Two accounts that canonicalize alike are never silently chosen between.

        AWS Organizations does not require account names to be unique, so a
        canonical match can hit more than one account. The error names every
        candidate, leaving the operator to correct the name rather than having
        the lookup pick one arbitrarily.
        """
        hierarchy = self._hierarchy({
            "111111111111": "Management Account",
            "222222222222": "management-account",
        })

        with pytest.raises(RuntimeError) as exc_info:
            lookup_account_id_by_name("Management_Account", hierarchy)

        message = str(exc_info.value)
        assert "matches multiple accounts" in message
        assert "111111111111 ('Management Account')" in message
        assert "222222222222 ('management-account')" in message

    def test_raises_when_exact_name_matches_multiple_accounts(self) -> None:
        """
        Duplicate account names abort instead of resolving to the first found.

        Organizations enforces uniqueness on account email, not on account name,
        so two accounts can carry one name exactly. Returning whichever came
        first in iteration order would attribute a result file to an arbitrary
        account.
        """
        hierarchy = self._hierarchy({
            "111111111111": "Management Account",
            "222222222222": "Management Account",
        })

        with pytest.raises(RuntimeError) as exc_info:
            lookup_account_id_by_name("Management Account", hierarchy)

        message = str(exc_info.value)
        assert "matches multiple accounts in the organization hierarchy: " in message
        assert "111111111111 ('Management Account')" in message
        assert "222222222222 ('Management Account')" in message

    def test_does_not_canonically_match_names_that_canonicalize_to_nothing(self) -> None:
        """
        Names made only of separators share no canonical form worth matching.

        Canonicalization strips every non-alphanumeric character, so unrelated
        punctuation-only names all reduce to the empty string. Treating that as
        a match would attribute a result file to an account that shares nothing
        with it.
        """
        hierarchy = self._hierarchy({"111111111111": "---"})

        with pytest.raises(RuntimeError, match="not found in organization hierarchy"):
            lookup_account_id_by_name("***", hierarchy)

    def test_exact_match_wins_over_a_canonical_match_on_another_account(self) -> None:
        """
        An exact name resolves to its own account, never to a canonical rival.

        Two accounts whose names differ only by case and separators both
        canonicalize alike, so ordering matters: matching exactly first keeps
        each name pointing at its own account instead of raising ambiguity.
        """
        hierarchy = self._hierarchy({
            "111111111111": "management-account",
            "222222222222": "Management Account",
        })

        assert lookup_account_id_by_name("management-account", hierarchy) == "111111111111"
        assert lookup_account_id_by_name("Management Account", hierarchy) == "222222222222"


class TestFindOrganizationRoot:
    """Test find_organization_root."""

    def test_a_root_on_the_second_page_is_found(self) -> None:
        """
        list_roots paginates, so page one is not the whole answer.

        An organization reports one root, but the paginator is free to split
        any listing. Reading only page one turned an organization with a
        root on page two into "No roots found".
        """
        org_client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [
            {"Roots": []},
            {"Roots": [{"Id": "r-1111"}]},
        ]
        org_client.get_paginator.return_value = paginator

        assert find_organization_root(org_client) == "r-1111"

    def test_no_roots_aborts(self) -> None:
        """An organization with no root cannot be traversed."""
        org_client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [{"Roots": []}]
        org_client.get_paginator.return_value = paginator

        with pytest.raises(RuntimeError, match="No roots found in organization"):
            find_organization_root(org_client)

    def test_more_than_one_root_aborts(self) -> None:
        """
        Picking roots[0] from two roots would silently traverse half the
        organization, and which half would depend on page order.
        """
        org_client = Mock()
        paginator = Mock()
        paginator.paginate.return_value = [
            {"Roots": [{"Id": "r-1111"}, {"Id": "r-2222"}]},
        ]
        org_client.get_paginator.return_value = paginator

        with pytest.raises(RuntimeError, match="r-1111, r-2222"):
            find_organization_root(org_client)

    def test_a_later_page_error_aborts(self) -> None:
        """A failure partway through must not return page one's roots."""
        org_client = Mock()
        paginator = Mock()
        error: object = {"Error": {"Code": "AccessDenied"}}

        def pages() -> Iterator[Dict[str, Any]]:
            yield {"Roots": [{"Id": "r-1111"}]}
            raise ClientError(error, "ListRoots")  # type: ignore[arg-type]

        paginator.paginate.return_value = pages()
        org_client.get_paginator.return_value = paginator

        with pytest.raises(RuntimeError, match="Failed to get organization root"):
            find_organization_root(org_client)
