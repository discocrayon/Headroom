"""
Shared data types and models for the Headroom application.

This module contains all the data classes used across the application
to avoid circular import issues and provide a single source of truth
for data structures.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union


# Type aliases for JSON-serializable data
JsonDict = Dict[str, object]
"""Type for JSON-serializable dictionaries with runtime-typed values."""

# Type aliases for commonly-used complex types
AccountThirdPartyMap = Dict[str, Set[str]]
"""Mapping of account IDs to sets of third-party account IDs they grant access to."""

GroupedSCPRecommendations = Dict[str, List["SCPPlacementRecommendations"]]
"""Mapping of target IDs (account/OU) to lists of SCP placement recommendations."""

PolicyRecommendation = Union["SCPPlacementRecommendations", "RCPPlacementRecommendations"]
"""Type alias for either SCP or RCP placement recommendations."""


@dataclass
class OrganizationalUnit:
    """Information about an Organizational Unit."""
    ou_id: str
    name: str
    parent_ou_id: Optional[str]
    child_ous: List[str]
    accounts: List[str]


@dataclass
class AccountOrgPlacement:
    """Information about an account's OU placement."""
    account_id: str
    account_name: str
    parent_ou_id: str
    ou_path: List[str]  # Full path from root to account


@dataclass
class OrganizationHierarchy:
    """Complete organization hierarchy structure."""
    root_id: str
    organizational_units: Dict[str, OrganizationalUnit]
    accounts: Dict[str, AccountOrgPlacement]


@dataclass
class CheckResult:
    """
    Base class for all check results.

    Contains fields common to all checks (SCP, RCP, future check types).
    Subclasses should add check-specific fields.
    """
    account_id: str
    account_name: str
    check_name: str


@dataclass
class SCPCheckResult(CheckResult):
    """
    Result from an SCP compliance check.

    SCP checks evaluate whether resources in an account comply with
    organizational policies. They track violations, exemptions, and
    compliant resources.

    TODO: As more SCP checks are added, consider moving check-specific
    fields (like total_instances) to per-check subclasses if the fields
    diverge significantly across different SCP check types.
    """
    violations: int
    exemptions: int
    compliant: int
    compliance_percentage: float
    total_instances: Optional[int] = None
    iam_user_arns: Optional[List[str]] = None


@dataclass
class SCPPlacementRecommendations:
    """SCP placement recommendation for a specific check."""
    check_name: str
    recommended_level: str  # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    compliance_percentage: float
    reasoning: str
    allowed_iam_user_arns: Optional[List[str]] = None


@dataclass
class RCPCheckResult(CheckResult):
    """
    Result from an RCP check (third-party access control).

    RCP checks identify external account access and determine whether
    Resource Control Policies can be safely deployed.

    TODO: As more RCP checks are added, consider creating per-check
    subclasses if fields diverge significantly. For now, all RCP checks
    share the third-party access pattern.
    """
    third_party_account_ids: List[str]
    has_wildcard: bool
    total_roles_analyzed: Optional[int] = None


@dataclass
class RCPParseResult:
    """
    Result from parsing RCP check result files.

    Contains mapping of accounts to their third-party accounts,
    and tracks which accounts have wildcard principals.
    """
    account_third_party_map: AccountThirdPartyMap
    accounts_with_wildcards: Set[str]


@dataclass
class RCPPlacementRecommendations:
    """RCP placement recommendation for third-party access control."""
    check_name: str
    recommended_level: str  # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    third_party_account_ids: List[str]
    reasoning: str
