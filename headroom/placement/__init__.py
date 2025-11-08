"""
Policy placement analysis module.

Provides utilities for determining optimal policy placement levels (root, OU, account)
based on compliance results and organization hierarchy.
"""

from .hierarchy import PlacementCandidate, HierarchyPlacementAnalyzer

__all__ = ["PlacementCandidate", "HierarchyPlacementAnalyzer"]

