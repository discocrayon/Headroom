"""
Hierarchy-aware placement analysis.

Provides generic framework for determining policy placement levels (root, OU, account)
based on organization hierarchy and safety predicates. Uses Strategy pattern to
separate hierarchy traversal logic from policy-specific safety criteria.
"""

import logging
from dataclasses import dataclass
from typing import Callable, Dict, Generic, List, Optional, TypeVar

from ..types import OrganizationHierarchy

logger = logging.getLogger(__name__)

T = TypeVar('T')


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

        ou_results: Dict[str, List[T]] = self._group_results_by_ou(
            check_results,
            get_account_id
        )
        ou_candidates = []

        for ou_id, ou_check_results in ou_results.items():
            if is_safe_for_ou(ou_id, ou_check_results):
                ou_candidates.append(PlacementCandidate(
                    level="ou",
                    target_id=ou_id,
                    affected_accounts=[get_account_id(r) for r in ou_check_results],
                    reasoning=f"OU-level deployment safe for {len(ou_check_results)} accounts"
                ))

        if ou_candidates:
            return ou_candidates

        account_candidates = [
            PlacementCandidate(
                level="account",
                target_id=None,
                affected_accounts=[get_account_id(result)],
                reasoning="Individual account-level deployment"
            )
            for result in check_results
        ]

        return account_candidates

    def _group_results_by_ou(
        self,
        check_results: List[T],
        get_account_id: Callable[[T], str]
    ) -> Dict[str, List[T]]:
        """
        Group check results by parent OU.

        Args:
            check_results: List of check results to group
            get_account_id: Function to extract account ID from result

        Returns:
            Dictionary mapping OU ID to list of check results

        Raises:
            RuntimeError: If account is not found in hierarchy
        """
        ou_results: Dict[str, List[T]] = {}
        for result in check_results:
            account_id = get_account_id(result)
            account_info = self.org.accounts.get(account_id)
            if not account_info:
                raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")
            ou_id = account_info.parent_ou_id
            if ou_id not in ou_results:
                ou_results[ou_id] = []
            ou_results[ou_id].append(result)
        return ou_results
