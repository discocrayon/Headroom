"""
Hierarchy-aware placement analysis.

Provides generic framework for determining policy placement levels (root, OU, account)
based on organization hierarchy and safety predicates. Uses Strategy pattern to
separate hierarchy traversal logic from policy-specific safety criteria.
"""

import logging
from dataclasses import dataclass
from typing import Callable, Dict, Generic, List, Optional, Set, TypeVar

from ..types import OrganizationHierarchy, OrganizationalUnit

logger = logging.getLogger(__name__)

T = TypeVar('T')


def ou_subtree_ids(
    ou_id: str,
    organizational_units: Dict[str, OrganizationalUnit]
) -> List[str]:
    """
    Return the OU followed by every OU beneath it, parents before children.

    A policy attached to an OU applies to every account in that OU and in every
    OU below it, so any question asked about an OU - is it safe, what must its
    allowlist hold - is a question about this whole list.

    Args:
        ou_id: OU to start from
        organizational_units: All OUs in the organization

    Returns:
        OU IDs in the subtree, starting with ou_id

    Raises:
        RuntimeError: If the hierarchy loops
    """
    subtree: List[str] = []
    seen: Set[str] = set()
    pending: List[str] = [ou_id]

    while pending:
        current = pending.pop(0)
        if current in seen:
            raise RuntimeError(
                f"OU hierarchy contains a cycle: {current} appears beneath itself"
            )
        seen.add(current)
        subtree.append(current)

        ou = organizational_units.get(current)
        if ou is None:
            continue
        pending.extend(
            child_id for child_id in ou.child_ous
            if child_id in organizational_units
        )

    return subtree


def accounts_under_ou(
    ou_id: str,
    organization_hierarchy: OrganizationHierarchy
) -> Set[str]:
    """
    Return every account the OU governs, including those in its child OUs.

    Args:
        ou_id: Organizational Unit to look beneath
        organization_hierarchy: Organization structure information

    Returns:
        Set of account IDs in the OU or any OU below it
    """
    subtree = set(
        ou_subtree_ids(ou_id, organization_hierarchy.organizational_units)
    )
    return {
        account_id
        for account_id, account in organization_hierarchy.accounts.items()
        if account.parent_ou_id in subtree
    }


@dataclass
class PlacementCandidate:
    """
    Candidate placement level with associated data.

    Represents a policy placement recommendation at a specific level of the
    organization hierarchy.
    """
    level: str
    target_id: Optional[str]
    affected_accounts: List[str]
    reasoning: str


class HierarchyPlacementAnalyzer(Generic[T]):
    """
    Analyzes organization hierarchy to determine optimal policy placement.

    Uses strategy pattern: caller provides "safety" predicates,
    this class handles hierarchy traversal logic.
    """

    def __init__(self, organization_hierarchy: OrganizationHierarchy):
        """
        Initialize the analyzer with organization hierarchy.

        Args:
            organization_hierarchy: Organization structure with OUs and accounts
        """
        self.org = organization_hierarchy

    def determine_placement(
        self,
        check_results: List[T],
        is_safe_for_root: Callable[[List[T]], bool],
        is_safe_for_ou: Callable[[str, List[T]], bool],
        get_account_id: Callable[[T], str]
    ) -> List[PlacementCandidate]:
        """
        Determine optimal placement using provided safety predicates.

        Template method that handles hierarchy traversal while delegating
        "safety" decisions to provided functions.

        The organization is walked from the top down, so a policy lands on the
        highest OU whose whole subtree is safe and its descendants inherit it
        rather than collecting a second, redundant copy. An OU that is not safe
        hands the question to its child OUs, and every account no OU claimed is
        offered together in one account-level candidate, for the caller to
        filter and split.

        Args:
            check_results: List of check results to analyze
            is_safe_for_root: Predicate to determine if root-level is safe
            is_safe_for_ou: Predicate to determine if OU-level is safe
            get_account_id: Function to extract account ID from result

        Returns:
            List of placement candidates (root, OU, or account level)

        Raises:
            RuntimeError: If account is not found in hierarchy
        """
        if is_safe_for_root(check_results):
            return [PlacementCandidate(
                level="root",
                target_id=None,
                affected_accounts=[get_account_id(r) for r in check_results],
                reasoning="All accounts safe - deploy at root"
            )]

        ou_results = self._group_results_by_ou_subtree(
            check_results,
            get_account_id
        )
        candidates: List[PlacementCandidate] = []
        covered_accounts: Set[str] = set()
        pending = self._top_level_ou_ids()

        while pending:
            ou_id = pending.pop(0)
            subtree_results = ou_results.get(ou_id, [])

            if subtree_results and is_safe_for_ou(ou_id, subtree_results):
                ou_accounts = [get_account_id(r) for r in subtree_results]
                candidates.append(PlacementCandidate(
                    level="ou",
                    target_id=ou_id,
                    affected_accounts=ou_accounts,
                    reasoning=(
                        f"OU-level deployment safe for {len(subtree_results)} accounts"
                    )
                ))
                covered_accounts.update(ou_accounts)
                continue

            ou = self.org.organizational_units.get(ou_id)
            if ou:
                pending.extend(
                    child_id for child_id in ou.child_ous
                    if child_id in self.org.organizational_units
                )

        # Everything an OU did not claim is offered in one account-level
        # candidate, so that one qualifying OU cannot suppress placement for
        # accounts elsewhere. Accounts under the root land here too: they have
        # no OU to inherit from. Callers apply their own safety filter to these
        # accounts and emit one recommendation per account that passes it.
        uncovered_accounts = [
            account_id for account_id in map(get_account_id, check_results)
            if account_id not in covered_accounts
        ]
        if uncovered_accounts:
            candidates.append(PlacementCandidate(
                level="account",
                target_id=None,
                affected_accounts=uncovered_accounts,
                reasoning="Individual account-level deployment"
            ))

        return candidates

    def _top_level_ou_ids(self) -> List[str]:
        """
        Return the OUs that hang directly off the organization root.

        A parent naming something that is not an OU here is the root, which
        build_organization_hierarchy records as None and hierarchies built
        elsewhere sometimes record as the root ID.

        Returns:
            OU IDs directly beneath the root, in hierarchy iteration order
        """
        return [
            ou_id for ou_id, ou in self.org.organizational_units.items()
            if ou.parent_ou_id not in self.org.organizational_units
        ]

    def _ancestor_ou_ids(self, parent_ou_id: Optional[str]) -> List[str]:
        """
        Return an account's parent OU and every OU above it, nearest first.

        Args:
            parent_ou_id: The account's direct parent OU, or None for accounts
                attached to the organization root

        Returns:
            OU IDs governing the account, empty for a root-parented account

        Raises:
            RuntimeError: If the parent chain loops
        """
        ancestors: List[str] = []
        seen: Set[str] = set()
        current = parent_ou_id

        while current is not None and current != self.org.root_id:
            if current in seen:
                raise RuntimeError(
                    f"OU hierarchy contains a cycle: {current} is its own ancestor"
                )
            seen.add(current)
            ancestors.append(current)

            ou = self.org.organizational_units.get(current)
            if ou is None:
                break
            current = ou.parent_ou_id

        return ancestors

    def _group_results_by_ou_subtree(
        self,
        check_results: List[T],
        get_account_id: Callable[[T], str]
    ) -> Dict[str, List[T]]:
        """
        Group results under every OU that governs the account, at any depth.

        An account appears under its parent OU and under each OU above it,
        because a policy attached anywhere along that chain reaches the
        account. Grouping by the immediate parent alone let an OU be declared
        safe on the strength of accounts it shares a level with, while the
        accounts in its child OUs - which the policy would equally reach -
        were never consulted.

        An account attached directly to the organization root belongs to no OU
        and appears nowhere here; the caller places it individually.

        Args:
            check_results: List of check results to group
            get_account_id: Function to extract account ID from result

        Returns:
            Dictionary mapping OU ID to the results in that OU's subtree

        Raises:
            RuntimeError: If account is not found in hierarchy
        """
        ou_results: Dict[str, List[T]] = {}
        for result in check_results:
            account_id = get_account_id(result)
            account_info = self.org.accounts.get(account_id)
            if not account_info:
                raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")
            for ou_id in self._ancestor_ou_ids(account_info.parent_ou_id):
                if ou_id not in ou_results:
                    ou_results[ou_id] = []
                ou_results[ou_id].append(result)
        return ou_results
