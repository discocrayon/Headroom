"""Tests for headroom/aws/organization.py."""

from typing import Any, Dict, Iterator
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from headroom.aws.organization import (
    analyze_organization_structure,
    create_account_ou_mapping,
    find_organization_root,
    lookup_account_id_by_name,
)
from headroom.types import (
    AccountOrgPlacement,
    OrganizationHierarchy,
    OrganizationalUnit,
)


class TestOrganizationStructureAnalysis:
    """Test organization structure analysis functions."""

    def test_analyze_organization_structure_success(self) -> None:
        """Test successful organization structure analysis."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": [{"Id": "r-1111"}]}]
        mock_org_client.get_paginator.return_value = roots_paginator

        # Mock OU responses
        mock_org_client.list_organizational_units_for_parent.side_effect = [
            # Root level OUs
            {"OrganizationalUnits": [{"Id": "ou-1234", "Name": "Production"}]},
            # Child OUs (empty for simplicity)
            {"OrganizationalUnits": []},
            # Child OUs for Production OU (empty)
            {"OrganizationalUnits": []},
        ]

        # Mock account responses
        mock_org_client.list_accounts_for_parent.side_effect = [
            # Accounts under Production OU
            {"Accounts": [{"Id": "222222222222", "Name": "prod-account"}]},
            # Accounts directly under root (not in any OU)
            {"Accounts": [{"Id": "111111111111", "Name": "management-account"}]},
        ]

        result = analyze_organization_structure(mock_session)

        assert result.root_id == "r-1111"
        assert "ou-1234" in result.organizational_units
        assert "111111111111" in result.accounts
        assert "222222222222" in result.accounts

        # Verify Production OU structure
        prod_ou = result.organizational_units["ou-1234"]
        assert prod_ou.name == "Production"
        assert prod_ou.parent_ou_id is None
        assert "222222222222" in prod_ou.accounts

    def test_analyze_organization_structure_retains_non_active_accounts(self) -> None:
        """
        Non-active accounts must stay in the OU hierarchy.

        The hierarchy resolves account names read back from result files on disk,
        so a result file written before an account closed must still resolve;
        filtering the hierarchy would make lookup_account_id_by_name raise
        RuntimeError for it. Filtering here is also unnecessary, because
        placement is driven by the check results that exist, leaving an account
        with no results already inert. The lifecycle-state filtering applied in
        get_subaccount_information deliberately does not apply here.
        """
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": [{"Id": "r-1111"}]}]
        mock_org_client.get_paginator.return_value = roots_paginator
        mock_org_client.list_organizational_units_for_parent.side_effect = [
            {"OrganizationalUnits": [{"Id": "ou-1234", "Name": "Production"}]},
            {"OrganizationalUnits": []},
            {"OrganizationalUnits": []},
        ]
        mock_org_client.list_accounts_for_parent.side_effect = [
            {"Accounts": [
                {"Id": "222222222222", "Name": "prod-account", "State": "ACTIVE"},
                {"Id": "333333333333", "Name": "closed-account", "State": "CLOSED"},
            ]},
            {"Accounts": [
                {"Id": "111111111111", "Name": "management-account", "State": "ACTIVE"},
            ]},
        ]

        result = analyze_organization_structure(mock_session)

        assert "333333333333" in result.accounts
        assert "333333333333" in result.organizational_units["ou-1234"].accounts
        assert lookup_account_id_by_name("closed-account", result) == "333333333333"

    def test_analyze_organization_structure_no_roots(self) -> None:
        """Test error handling when no roots found."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": []}]
        mock_org_client.get_paginator.return_value = roots_paginator

        with pytest.raises(RuntimeError, match="No roots found in organization"):
            analyze_organization_structure(mock_session)

    def test_analyze_organization_structure_client_error(self) -> None:
        """Test error handling for AWS client errors."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        roots_paginator = Mock()
        roots_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "AWS Error"}},
            "ListRoots"
        )
        mock_org_client.get_paginator.return_value = roots_paginator

        with pytest.raises(RuntimeError, match="Failed to get organization root"):
            analyze_organization_structure(mock_session)

    def test_create_account_ou_mapping(self) -> None:
        """Test account to OU mapping creation."""
        mock_session = Mock()

        # Mock organization hierarchy
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "management-account", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "prod-account", "ou-1234", ["Production"])
            }
        )

        with patch('headroom.aws.organization.analyze_organization_structure', return_value=mock_hierarchy):
            result = create_account_ou_mapping(mock_session)

        assert result["111111111111"] == "r-1111"
        assert result["222222222222"] == "ou-1234"

    def test_analyze_organization_structure_client_error_handling(self) -> None:
        """Test error handling for various AWS client errors."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": [{"Id": "r-1111"}]}]
        mock_org_client.get_paginator.return_value = roots_paginator

        # Mock OU responses with errors
        mock_org_client.list_organizational_units_for_parent.side_effect = [
            # Root level OUs
            {"OrganizationalUnits": [{"Id": "ou-1234", "Name": "Production"}]},
            # Child OUs (empty for simplicity)
            {"OrganizationalUnits": []},
            # Child OUs for Production OU (empty)
            {"OrganizationalUnits": []},
        ]

        # Mock account responses with errors
        mock_org_client.list_accounts_for_parent.side_effect = [
            # First call fails
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Failed to get accounts"}},
                "ListAccountsForParent"
            ),
            # Second call succeeds
            {"Accounts": [{"Id": "111111111111", "Name": "management-account"}]},
        ]

        # Should raise exception on first error
        with pytest.raises(RuntimeError, match="Failed to get accounts/child OUs for OU ou-1234"):
            analyze_organization_structure(mock_session)

    def test_analyze_organization_structure_root_accounts_error(self) -> None:
        """Test error handling when getting accounts under root fails."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": [{"Id": "r-1111"}]}]
        mock_org_client.get_paginator.return_value = roots_paginator

        # Mock OU responses (empty)
        mock_org_client.list_organizational_units_for_parent.return_value = {
            "OrganizationalUnits": []
        }

        # Mock account responses with error for root accounts
        mock_org_client.list_accounts_for_parent.side_effect = [
            # Root accounts call fails
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Failed to get root accounts"}},
                "ListAccountsForParent"
            ),
        ]

        # Should raise exception on error
        with pytest.raises(RuntimeError, match="Failed to get accounts under root"):
            analyze_organization_structure(mock_session)

    def test_analyze_organization_structure_ou_listing_error(self) -> None:
        """Test error handling when listing OUs fails."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        roots_paginator = Mock()
        roots_paginator.paginate.return_value = [{"Roots": [{"Id": "r-1111"}]}]
        mock_org_client.get_paginator.return_value = roots_paginator

        # Mock OU listing failure
        mock_org_client.list_organizational_units_for_parent.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Failed to list OUs"}},
            "ListOrganizationalUnitsForParent"
        )

        # Mock account responses (empty)
        mock_org_client.list_accounts_for_parent.return_value = {
            "Accounts": []
        }

        # Should raise exception on error
        with pytest.raises(RuntimeError, match="Failed to list OUs for parent None"):
            analyze_organization_structure(mock_session)


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
