"""
Shared data types and models for the Headroom application.

This module contains all the data classes used across the application
to avoid circular import issues and provide a single source of truth
for data structures.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set


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
    """Parsed result from a single check file."""
    account_id: str
    account_name: str
    check_name: str
    violations: int
    exemptions: int
    compliant: int
    total_instances: int
    compliance_percentage: float


@dataclass
class SCPPlacementRecommendations:
    """SCP placement recommendation for a specific check."""
    check_name: str
    recommended_level: str  # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    compliance_percentage: float
    reasoning: str


@dataclass
class RCPCheckResult:
    """Parsed result from third-party role access check."""
    account_id: str
    account_name: str
    third_party_account_ids: List[str]
    has_wildcard: bool


@dataclass
class RCPParseResult:
    """
    Result from parsing RCP check result files.

    Contains mapping of accounts to their third-party accounts,
    and tracks which accounts have wildcard principals.
    """
    account_third_party_map: Dict[str, Set[str]]
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
