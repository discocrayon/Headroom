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
    """
    Information about an account's OU placement.

    parent_ou_id is None for accounts attached directly to the organization
    root, which belong to no OU. Such accounts cannot be targeted by an
    OU-level policy; the organization root ID is not a substitute.
    """
    account_id: str
    account_name: str
    parent_ou_id: Optional[str]
    ou_path: List[str]  # Full path from root to account


@dataclass
class OrganizationHierarchy:
    """Complete organization hierarchy structure."""
    root_id: str
    organizational_units: Dict[str, OrganizationalUnit]
    accounts: Dict[str, AccountOrgPlacement]


@dataclass
class AccountInfo:
    """
    An account Headroom will analyze, with its tag-derived metadata.

    `name` is the analysis name: it comes from the configured tag when
    `use_account_name_from_tags` is set and falls back to the account ID, so
    it is deliberately distinct from `AccountOrgPlacement.account_name`, which
    is always the name AWS Organizations reports.
    """
    account_id: str
    environment: str
    name: str
    owner: str


@dataclass(frozen=True)
class OrganizationSnapshot:
    """
    One run's captured view of the organization.

    Built once, by `discover_organization`, and consumed unchanged by the scan
    and by all three Terraform generators. Nothing downstream refreshes
    Organizations data, so every stage reasons about the same organization.

    The outer dataclass is frozen; `hierarchy` still holds dicts and lists.
    Freezing the projections is what prevents a stage substituting its own,
    which is the failure this type exists to remove; deep immutability of the
    hierarchy is a separate concern and not one this change takes on.

    Attributes:
        organization_id: This organization's ID, such as `o-11111111111`
        member_account_ids: Every organization member, including the
            management account, accounts skipped by configuration, and
            accounts in every non-ACTIVE lifecycle state
        analyzable_accounts: The accounts the scan will run against, in the
            order Organizations reported them
        hierarchy: The complete OU tree, retaining every account
    """
    organization_id: str
    member_account_ids: frozenset[str]
    analyzable_accounts: tuple[AccountInfo, ...]
    hierarchy: OrganizationHierarchy


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

    Checks that inform an allowlist carry the values they observed:
    `iam_user_arns` for deny_iam_user_creation, `ami_owners` for
    deny_ec2_ami_owner. A check whose allowlist variable exists in the
    Terraform module but has no field here cannot populate it, and the
    module is enabled with an empty list - which for a Deny statement
    denies everything rather than nothing.

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
    ami_owners: Optional[List[str]] = None


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
    ec2_allowed_ami_owners: Optional[List[str]] = None


@dataclass
class RCPCheckResult(CheckResult):
    """
    One account's findings for one RCP check.

    Attributes:
        third_party_account_ids: Third parties this account's policies allow
        blocks_rcp: True if this check counted a violation, meaning a
            resource names a principal that no allowlist can express and
            the RCP is unsafe to deploy here. A wildcard principal is the
            one case every check flags this way. Federated and
            CanonicalUser principals, which carry no account ID to
            allowlist, are handled per check rather than uniformly: the S3
            analyzer records them as violations, the ECR, KMS, Secrets
            Manager and SQS analyzers raise on them, and the STS analyzer
            raises on a CanonicalUser or on a Federated principal granted
            sts:AssumeRole, so S3 is the only check those two principal
            types can set this flag from
    """
    third_party_account_ids: List[str]
    blocks_rcp: bool


@dataclass
class RCPCheckParseResult:
    """
    Third-party access findings for one RCP check across all accounts.

    Attributes:
        check_name: Name of the RCP check these findings belong to
        account_third_party_map: Accounts that can take this RCP, mapped to
            the third-party accounts their policies grant access to
        accounts_with_blockers: Accounts that cannot take this RCP, because a
            resource policy names a principal that no allowlist can express
    """
    check_name: str
    account_third_party_map: AccountThirdPartyMap
    accounts_with_blockers: Set[str]


@dataclass
class RCPPlacementRecommendations:
    """RCP placement recommendation for third-party access control."""
    check_name: str
    recommended_level: str  # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    third_party_account_ids: List[str]
    reasoning: str
