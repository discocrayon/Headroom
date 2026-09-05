"""
Tests for placement/hierarchy.py module.

Tests hierarchy traversal and placement candidate generation, with emphasis on
the distinction between accounts that live inside an OU and accounts attached
directly to the organization root. A root-parented account has no OU to target,
so it must never be emitted as an OU-level placement candidate.
"""

from typing import List

import pytest

from headroom.placement.hierarchy import HierarchyPlacementAnalyzer, ancestor_ou_ids
from headroom.types import (
    AccountOrgPlacement,
    OrganizationHierarchy,
    OrganizationalUnit,
)

ROOT_ID = "r-aabb"
WORKLOADS_OU_ID = "ou-aabb-workloads"
ROOT_PARENTED_ACCOUNT = "111111111111"
OU_RESIDENT_ACCOUNT = "222222222222"


def make_mixed_hierarchy(root_parent_ou_id: str | None = None) -> OrganizationHierarchy:
    """
    Build a hierarchy with one OU-resident account and one root-parented account.

    The 'sandbox' account hangs directly off the organization root, so it has no
    parent OU. root_parent_ou_id lets a test simulate hierarchies built before
    root-parented accounts recorded None, which stored the root ID instead.
    """
    return OrganizationHierarchy(
        root_id=ROOT_ID,
        organizational_units={
            WORKLOADS_OU_ID: OrganizationalUnit(
                ou_id=WORKLOADS_OU_ID,
                name="Workloads",
                parent_ou_id=None,
                child_ous=[],
                accounts=[OU_RESIDENT_ACCOUNT],
            ),
        },
        accounts={
            ROOT_PARENTED_ACCOUNT: AccountOrgPlacement(
                account_id=ROOT_PARENTED_ACCOUNT,
                account_name="sandbox",
                parent_ou_id=root_parent_ou_id,
                ou_path=["Root"],
            ),
            OU_RESIDENT_ACCOUNT: AccountOrgPlacement(
                account_id=OU_RESIDENT_ACCOUNT,
                account_name="prod",
                parent_ou_id=WORKLOADS_OU_ID,
                ou_path=["Workloads"],
            ),
        },
    )


def make_analyzer(
    root_parent_ou_id: str | None = None
) -> HierarchyPlacementAnalyzer[str]:
    """Build an analyzer over the mixed hierarchy, using account IDs as results."""
    return HierarchyPlacementAnalyzer(make_mixed_hierarchy(root_parent_ou_id))


class TestGroupResultsByOU:
    """Tests for _group_results_by_ou_subtree()."""

    def test_omits_root_parented_accounts_from_ou_grouping(self) -> None:
        """Accounts directly under the root are left out, not grouped as an OU."""
        analyzer = make_analyzer()

        ou_results = analyzer._group_results_by_ou_subtree(
            [ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            lambda r: r
        )

        assert ou_results == {WORKLOADS_OU_ID: [OU_RESIDENT_ACCOUNT]}

    def test_treats_literal_root_id_parent_as_root_parented(self) -> None:
        """A parent_ou_id holding the root ID is still not an OU."""
        analyzer = make_analyzer(root_parent_ou_id=ROOT_ID)

        ou_results = analyzer._group_results_by_ou_subtree(
            [ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            lambda r: r
        )

        assert ou_results == {WORKLOADS_OU_ID: [OU_RESIDENT_ACCOUNT]}

    def test_raises_for_account_missing_from_hierarchy(self) -> None:
        """An unknown account is a hard error, not a silently dropped result."""
        analyzer = make_analyzer()

        with pytest.raises(RuntimeError, match=r"Account \(999999999999\) not found"):
            analyzer._group_results_by_ou_subtree(["999999999999"], lambda r: r)


class TestDeterminePlacement:
    """Tests for determine_placement()."""

    def test_root_safe_short_circuits_to_single_root_candidate(self) -> None:
        """When every account is safe, placement collapses to one root candidate."""
        analyzer = make_analyzer()

        candidates = analyzer.determine_placement(
            check_results=[ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            is_safe_for_root=lambda results: True,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r
        )

        assert len(candidates) == 1
        assert candidates[0].level == "root"
        assert candidates[0].target_id is None

    def test_root_parented_account_becomes_account_candidate_beside_ou(self) -> None:
        """A root-parented account is placed individually, alongside OU candidates."""
        analyzer = make_analyzer()

        candidates = analyzer.determine_placement(
            check_results=[ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r
        )

        by_level = {c.level: c for c in candidates}
        assert set(by_level) == {"ou", "account"}
        assert by_level["ou"].target_id == WORKLOADS_OU_ID
        assert by_level["ou"].affected_accounts == [OU_RESIDENT_ACCOUNT]
        assert by_level["account"].target_id is None
        assert by_level["account"].affected_accounts == [ROOT_PARENTED_ACCOUNT]

    def test_never_emits_the_root_id_as_an_ou_target(self) -> None:
        """Regression: the root ID must never reach an OU-level candidate."""
        analyzer = make_analyzer()

        candidates = analyzer.determine_placement(
            check_results=[ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r
        )

        ou_targets = [c.target_id for c in candidates if c.level == "ou"]
        assert ROOT_ID not in ou_targets

    def test_ou_predicate_is_never_called_with_the_root_id(self) -> None:
        """The OU safety predicate is OU-semantic; it must not receive a root ID."""
        analyzer = make_analyzer()
        seen_ou_ids: List[str] = []

        def record_ou(ou_id: str, results: List[str]) -> bool:
            seen_ou_ids.append(ou_id)
            return True

        analyzer.determine_placement(
            check_results=[ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=record_ou,
            get_account_id=lambda r: r
        )

        assert seen_ou_ids == [WORKLOADS_OU_ID]

    def test_no_safe_ou_falls_back_to_one_candidate_covering_all_accounts(self) -> None:
        """With no safe OU, a single account-level candidate carries every account."""
        analyzer = make_analyzer()

        candidates = analyzer.determine_placement(
            check_results=[ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: False,
            get_account_id=lambda r: r
        )

        assert len(candidates) == 1
        assert candidates[0].level == "account"
        assert candidates[0].target_id is None
        assert candidates[0].affected_accounts == [
            ROOT_PARENTED_ACCOUNT,
            OU_RESIDENT_ACCOUNT,
        ]


LEGACY_OU_ID = "ou-aabb-legacy"
CLEAN_SIBLING_ACCOUNT = "333333333333"
DIRTY_SIBLING_ACCOUNT = "444444444444"


def make_two_ou_hierarchy() -> OrganizationHierarchy:
    """
    Build a hierarchy with two OUs, each holding two accounts.

    Used to check that accounts left uncovered by OU-level placement are still
    offered individually, rather than dropped because some other OU qualified.
    """
    return OrganizationHierarchy(
        root_id=ROOT_ID,
        organizational_units={
            WORKLOADS_OU_ID: OrganizationalUnit(
                ou_id=WORKLOADS_OU_ID,
                name="Workloads",
                parent_ou_id=None,
                child_ous=[],
                accounts=[ROOT_PARENTED_ACCOUNT, OU_RESIDENT_ACCOUNT],
            ),
            LEGACY_OU_ID: OrganizationalUnit(
                ou_id=LEGACY_OU_ID,
                name="Legacy",
                parent_ou_id=None,
                child_ous=[],
                accounts=[CLEAN_SIBLING_ACCOUNT, DIRTY_SIBLING_ACCOUNT],
            ),
        },
        accounts={
            ROOT_PARENTED_ACCOUNT: AccountOrgPlacement(
                ROOT_PARENTED_ACCOUNT, "prod", WORKLOADS_OU_ID, ["Workloads"]
            ),
            OU_RESIDENT_ACCOUNT: AccountOrgPlacement(
                OU_RESIDENT_ACCOUNT, "staging", WORKLOADS_OU_ID, ["Workloads"]
            ),
            CLEAN_SIBLING_ACCOUNT: AccountOrgPlacement(
                CLEAN_SIBLING_ACCOUNT, "legacy-a", LEGACY_OU_ID, ["Legacy"]
            ),
            DIRTY_SIBLING_ACCOUNT: AccountOrgPlacement(
                DIRTY_SIBLING_ACCOUNT, "legacy-b", LEGACY_OU_ID, ["Legacy"]
            ),
        },
    )


class TestUncoveredAccountsAfterOUPlacement:
    """
    Tests that a qualifying OU does not suppress placement for other accounts.

    Placement used to return OU candidates exclusively, so accounts sitting in
    an OU that did not qualify were dropped entirely whenever some other OU did.
    """

    def make_analyzer(self) -> HierarchyPlacementAnalyzer[str]:
        """Build an analyzer over the two-OU hierarchy."""
        return HierarchyPlacementAnalyzer(make_two_ou_hierarchy())

    def only_workloads_is_safe(self, ou_id: str, results: List[str]) -> bool:
        """Qualify the Workloads OU and reject the Legacy OU."""
        return ou_id == WORKLOADS_OU_ID

    def test_accounts_in_unqualified_ou_are_offered_individually(self) -> None:
        """Accounts the OU pass left behind get an account-level candidate."""
        candidates = self.make_analyzer().determine_placement(
            check_results=[
                ROOT_PARENTED_ACCOUNT,
                OU_RESIDENT_ACCOUNT,
                CLEAN_SIBLING_ACCOUNT,
                DIRTY_SIBLING_ACCOUNT,
            ],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=self.only_workloads_is_safe,
            get_account_id=lambda r: r
        )

        account_candidates = [c for c in candidates if c.level == "account"]
        assert len(account_candidates) == 1
        assert account_candidates[0].affected_accounts == [
            CLEAN_SIBLING_ACCOUNT,
            DIRTY_SIBLING_ACCOUNT,
        ]

    def test_qualifying_ou_still_placed_at_ou_level(self) -> None:
        """The OU that qualified keeps its OU-level candidate."""
        candidates = self.make_analyzer().determine_placement(
            check_results=[
                ROOT_PARENTED_ACCOUNT,
                OU_RESIDENT_ACCOUNT,
                CLEAN_SIBLING_ACCOUNT,
                DIRTY_SIBLING_ACCOUNT,
            ],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=self.only_workloads_is_safe,
            get_account_id=lambda r: r
        )

        ou_candidates = [c for c in candidates if c.level == "ou"]
        assert len(ou_candidates) == 1
        assert ou_candidates[0].target_id == WORKLOADS_OU_ID

    def test_accounts_covered_by_an_ou_are_not_offered_again(self) -> None:
        """An account covered at OU level must not also appear account-level."""
        candidates = self.make_analyzer().determine_placement(
            check_results=[
                ROOT_PARENTED_ACCOUNT,
                OU_RESIDENT_ACCOUNT,
                CLEAN_SIBLING_ACCOUNT,
                DIRTY_SIBLING_ACCOUNT,
            ],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=self.only_workloads_is_safe,
            get_account_id=lambda r: r
        )

        account_level = {
            acct
            for c in candidates if c.level == "account"
            for acct in c.affected_accounts
        }
        assert ROOT_PARENTED_ACCOUNT not in account_level
        assert OU_RESIDENT_ACCOUNT not in account_level

    def test_every_account_is_covered_by_exactly_one_candidate(self) -> None:
        """Placement partitions the accounts: none dropped, none duplicated."""
        all_accounts = [
            ROOT_PARENTED_ACCOUNT,
            OU_RESIDENT_ACCOUNT,
            CLEAN_SIBLING_ACCOUNT,
            DIRTY_SIBLING_ACCOUNT,
        ]
        candidates = self.make_analyzer().determine_placement(
            check_results=all_accounts,
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=self.only_workloads_is_safe,
            get_account_id=lambda r: r
        )

        placed = [acct for c in candidates for acct in c.affected_accounts]
        assert sorted(placed) == sorted(all_accounts)

    def test_no_account_candidate_when_every_ou_qualifies(self) -> None:
        """With every account covered at OU level, no account candidate is added."""
        candidates = self.make_analyzer().determine_placement(
            check_results=[
                ROOT_PARENTED_ACCOUNT,
                OU_RESIDENT_ACCOUNT,
                CLEAN_SIBLING_ACCOUNT,
                DIRTY_SIBLING_ACCOUNT,
            ],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r
        )

        assert [c.level for c in candidates] == ["ou", "ou"]


def test_ancestor_ou_ids_walks_up_nearest_first() -> None:
    """The walk names the parent, then its parent, and stops below the root."""
    ous = {
        "ou-1111-11111111": OrganizationalUnit(
            ou_id="ou-1111-11111111",
            name="production",
            parent_ou_id=None,
            child_ous=["ou-1111-22222222"],
            accounts=[],
        ),
        "ou-1111-22222222": OrganizationalUnit(
            ou_id="ou-1111-22222222",
            name="data",
            parent_ou_id="ou-1111-11111111",
            child_ous=[],
            accounts=["111111111111"],
        ),
    }

    assert ancestor_ou_ids("ou-1111-22222222", ous, "r-1111") == [
        "ou-1111-22222222",
        "ou-1111-11111111",
    ]


def test_ancestor_ou_ids_is_empty_for_a_root_parented_account() -> None:
    """An account attached to the root has no OU above it."""
    assert ancestor_ou_ids(None, {}, "r-1111") == []


def test_ancestor_ou_ids_raises_on_a_cycle() -> None:
    """A loop in the parent chain is a broken hierarchy, not a long walk."""
    ous = {
        "ou-1111-11111111": OrganizationalUnit(
            ou_id="ou-1111-11111111",
            name="a",
            parent_ou_id="ou-1111-22222222",
            child_ous=[],
            accounts=[],
        ),
        "ou-1111-22222222": OrganizationalUnit(
            ou_id="ou-1111-22222222",
            name="b",
            parent_ou_id="ou-1111-11111111",
            child_ous=[],
            accounts=[],
        ),
    }

    with pytest.raises(RuntimeError, match="is its own ancestor"):
        ancestor_ou_ids("ou-1111-11111111", ous, "r-1111")
