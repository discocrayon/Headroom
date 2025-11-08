# Refactoring Ideas - Principal Engineer Review

**Last Updated:** 2025-11-08
**Review Type:** Comprehensive Clean Code Architecture Analysis

This document contains architectural improvements and refactoring opportunities identified through a principal engineer-level review of the entire codebase. All recommendations follow Clean Code principles with a focus on DRY, extensibility, and maintainability.

---

## Executive Summary

The codebase demonstrates solid engineering practices with strong type safety, good separation of concerns, and consistent patterns. However, there are **architectural opportunities** for abstraction, several **DRY violations**, and some **structural improvements** that would significantly enhance maintainability and extensibility.

**Key Findings:**
- ✅ **Strengths**: Excellent type safety, good test coverage, consistent naming
- ⚠️ **Opportunities**: Check framework abstraction, session management duplication, parsing pattern duplication
- 🐛 **Issues**: Duplicate file, hardcoded check lists, rigid check architecture

**Estimated Total Impact:**
- Immediate: -110 lines (delete duplicate file)
- Phase 1 (High priority): -300 lines of duplication, +250 lines of abstractions (net: -50 lines, much better architecture)
- Phase 2 (Medium priority): -180 lines, +130 lines
- Phase 3 (Low priority): -30 lines, +1 line
- **Total Net:** -369 lines with significantly better architecture

---

## Priority Summary Table

| Priority | Item | Impact | Effort | LOC Change | Status |
|----------|------|--------|--------|------------|--------|
| 🔴 Critical | Delete duplicate file | High | 1 min | -110 | ✅ DONE |
| 🟠 High | Abstract check framework | Very High | 4 hours | -200, +150 | ✅ DONE |
| 🟠 High | Extract session management | Medium | 1 hour | -53, +28 | ✅ DONE |
| 🟠 High | Registry pattern for checks | High | 3 hours | -100, +80 | ✅ DONE |
| 🟡 Medium | Unify placement analysis | Medium | 3 hours | -150, +100 | ✅ DONE |
| 🟡 Medium | Consolidate print statements | Low | 1 hour | -20, +30 | |
| 🟡 Medium | Simplify config validation | Low | 5 min | -4 | |
| 🟡 Medium | Refactor extract account ID | Low | 5 min | -3 | |
| 🟢 Low | Standardize error messages | Low | 30 min | ~20 | |
| 🟢 Low | Review MIN_ACCOUNTS constant | Low | 5 min | -3 | |
| 🟢 Low | Type alias for Union | Low | 2 min | +1, -2 | |

---

## Critical Issues (Fix Immediately)

### 1. 🔴 ✅ DUPLICATE FILE: check_third_party_assumerole.py exists in TWO locations - COMPLETED

**Location:**
- `/headroom/checks/check_third_party_assumerole.py` (should NOT exist)
- `/headroom/checks/rcps/check_third_party_assumerole.py` (correct location)

**Problem:**
This is a **code debt timebomb**. When someone updates one file, they won't know to update the other. The codebase imports from the nested location (`from .checks.rcps.check_third_party_assumerole`), so the top-level file is dead code.

**Solution:**
```bash
# Delete the duplicate immediately
rm headroom/checks/check_third_party_assumerole.py
```

**Impact:**
- Eliminates 110 lines of dead code
- Prevents future synchronization bugs
- Removes confusion about which file to edit

**Status: ✅ COMPLETED**

---

## High-Priority Architectural Improvements

### 2. 🟠 ✅ Abstract the Check Framework - COMPLETED

**Problem:** The check pattern is repeated across `deny_imds_v1_ec2.py` and `check_third_party_assumerole.py` with nearly identical structure:
1. Call AWS analysis function
2. Process results into categories (violations, exemptions, compliant)
3. Build summary dictionary
4. Write results via `write_check_results()`

**Current Duplication:**
Both checks repeat this ~80 line pattern:

```python
# 1. Analysis
results = get_analysis(session)

# 2. Categorization (different logic but same structure)
violations = []
exemptions = []
compliant = []
for result in results:
    if condition:
        violations.append(...)
    # etc.

# 3. Summary building
summary = {
    "account_name": account_name,
    "account_id": account_id,
    "check": CHECK_NAME,
    # ... check-specific fields
}

# 4. Write results
write_check_results(...)

# 5. Print completion
print(f"Check completed for {account_identifier}: ...")
```

**Proposed Solution:** Create an abstract check framework using Template Method pattern

```python
# headroom/checks/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Generic, List, TypeVar
import boto3

T = TypeVar('T')  # Type of raw analysis result

@dataclass
class CheckResult:
    """Base class for check results."""
    violations: List[Dict[str, Any]]
    exemptions: List[Dict[str, Any]]
    compliant: List[Dict[str, Any]]
    summary: Dict[str, Any]

class BaseCheck(ABC, Generic[T]):
    """
    Abstract base class for all compliance checks.

    Implements template method pattern for check execution.
    Subclasses only need to implement 3 methods:
    - analyze(): Perform AWS API calls
    - categorize_result(): Categorize a single result
    - build_summary_fields(): Build check-specific summary fields
    """

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        exclude_account_ids: bool = False
    ):
        self.check_name = check_name
        self.account_name = account_name
        self.account_id = account_id
        self.results_dir = results_dir
        self.exclude_account_ids = exclude_account_ids

    @abstractmethod
    def analyze(self, session: boto3.Session) -> List[T]:
        """
        Perform AWS API analysis.

        Returns:
            List of raw analysis results
        """

    @abstractmethod
    def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
        """
        Categorize a single result.

        Args:
            result: Single analysis result

        Returns:
            Tuple of (category, result_dict) where category is one of:
            - "violation"
            - "exemption"
            - "compliant"
        """

    @abstractmethod
    def build_summary_fields(self, check_result: CheckResult) -> Dict[str, Any]:
        """
        Build check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """

    def execute(self, session: boto3.Session) -> None:
        """Execute the check (template method)."""
        # 1. Analyze
        raw_results = self.analyze(session)

        # 2. Categorize
        violations = []
        exemptions = []
        compliant = []

        for result in raw_results:
            category, result_dict = self.categorize_result(result)
            if category == "violation":
                violations.append(result_dict)
            elif category == "exemption":
                exemptions.append(result_dict)
            elif category == "compliant":
                compliant.append(result_dict)

        # 3. Build summary
        check_result = CheckResult(
            violations=violations,
            exemptions=exemptions,
            compliant=compliant,
            summary={}
        )

        summary = {
            "account_name": self.account_name,
            "account_id": self.account_id,
            "check": self.check_name,
            **self.build_summary_fields(check_result)
        }
        check_result.summary = summary

        # 4. Write results
        results_data = {
            "summary": summary,
            "violations": violations,
            "exemptions": exemptions,
            "compliant_instances": compliant
        }

        write_check_results(
            check_name=self.check_name,
            account_name=self.account_name,
            account_id=self.account_id,
            results_data=results_data,
            results_base_dir=self.results_dir,
            exclude_account_ids=self.exclude_account_ids
        )

        # 5. Log completion
        account_identifier = f"{self.account_name}_{self.account_id}"
        print(
            f"{self.check_name} completed for {account_identifier}: "
            f"{len(violations)} violations, {len(exemptions)} exemptions, "
            f"{len(compliant)} compliant"
        )


# Example implementation for IMDSv1 check:
class DenyImdsV1Ec2Check(BaseCheck[DenyImdsV1Ec2]):
    """Check for EC2 IMDSv1 compliance."""

    def analyze(self, session: boto3.Session) -> List[DenyImdsV1Ec2]:
        return get_imds_v1_ec2_analysis(session)

    def categorize_result(self, result: DenyImdsV1Ec2) -> tuple[str, Dict[str, Any]]:
        result_dict = {
            "region": result.region,
            "instance_id": result.instance_id,
            "imdsv1_allowed": result.imdsv1_allowed,
            "exemption_tag_present": result.exemption_tag_present
        }

        if result.imdsv1_allowed:
            if result.exemption_tag_present:
                return ("exemption", result_dict)
            else:
                return ("violation", result_dict)
        else:
            return ("compliant", result_dict)

    def build_summary_fields(self, check_result: CheckResult) -> Dict[str, Any]:
        total = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)
        compliant_count = len(check_result.compliant) + len(check_result.exemptions)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_instances": total,
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct
        }


# Usage (maintains backward compatibility):
def check_deny_imds_v1_ec2(
    headroom_session: boto3.Session,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> None:
    check = DenyImdsV1Ec2Check(
        check_name=DENY_IMDS_V1_EC2,
        account_name=account_name,
        account_id=account_id,
        results_dir=results_base_dir,
        exclude_account_ids=exclude_account_ids
    )
    check.execute(headroom_session)
```

**Benefits:**
- **DRY**: Eliminates 80+ lines of duplicated logic per check
- **Extensibility**: New checks only implement 3 methods instead of entire flow
- **Testability**: Can test base logic separately from check-specific logic
- **Type safety**: Generic type parameter ensures type correctness
- **Single Responsibility**: Each check focuses only on its unique logic

**Impact:**
- Reduces each check from ~110 lines to ~50 lines
- Makes adding new checks trivial
- Future checks inherit all improvements to base class
- Easier to add features like retry logic, progress reporting, etc.

**Status: ✅ COMPLETED**

---

### 3. 🟠 ✅ Extract Session Management Pattern - COMPLETED

**Problem:** Session creation pattern is repeated in `analysis.py` three times with slight variations:

```python
# Repeated 3 times:
def get_some_session(config):
    if not account_id:
        return boto3.Session()
    role_arn = f"arn:aws:iam::{account_id}:role/..."
    sts = boto3.client("sts")
    try:
        resp = sts.assume_role(...)
    except ClientError as e:
        raise RuntimeError(f"Failed to assume role: {e}")
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )
```

**Locations:**
- `get_security_analysis_session()` - 17 lines
- `get_management_account_session()` - 22 lines
- `get_headroom_session()` - 14 lines

**Proposed Solution:** Extract common pattern

```python
# headroom/aws/sessions.py (new file)
"""AWS session management utilities."""

import boto3
from botocore.exceptions import ClientError
from typing import Optional


def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[boto3.Session] = None
) -> boto3.Session:
    """
    Assume an IAM role and return a session with temporary credentials.

    Args:
        role_arn: ARN of the role to assume
        session_name: Name for the role session
        base_session: Session to use for assuming role (defaults to boto3.Session())

    Returns:
        boto3 Session with assumed role credentials

    Raises:
        RuntimeError: If role assumption fails
    """
    if base_session is None:
        base_session = boto3.Session()

    sts = base_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to assume role {role_arn}: {e}")

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


# Simplified callers in analysis.py:
def get_security_analysis_session(config: HeadroomConfig) -> boto3.Session:
    """Get session for security analysis account."""
    if not config.security_analysis_account_id:
        return boto3.Session()

    role_arn = f"arn:aws:iam::{config.security_analysis_account_id}:role/OrganizationAccountAccessRole"
    return assume_role(role_arn, "HeadroomSecurityAnalysisSession")


def get_management_account_session(config: HeadroomConfig, security_session: boto3.Session) -> boto3.Session:
    """Get session for management account."""
    if not config.management_account_id:
        raise ValueError("Management_account_id must be set in config")

    role_arn = f"arn:aws:iam::{config.management_account_id}:role/OrgAndAccountInfoReader"
    return assume_role(role_arn, "HeadroomOrgAndAccountInfoReaderSession", security_session)


def get_headroom_session(config: HeadroomConfig, security_session: boto3.Session, account_id: str) -> boto3.Session:
    """Get session for Headroom role in target account."""
    role_arn = f"arn:aws:iam::{account_id}:role/Headroom"
    return assume_role(role_arn, "HeadroomAnalysisSession", security_session)
```

**Benefits:**
- **DRY**: Reduces 53 lines to 28 lines (47% reduction)
- **Single source of truth**: All role assumption logic in one place
- **Easier enhancements**: Add retry logic, timeout handling, or MFA support in one place
- **More testable**: Can mock `assume_role()` instead of AWS STS client
- **Better error handling**: Consistent error messages

**Impact:**
- Immediate code reduction
- Future session creation is trivial
- Easier to add advanced features (assume role with MFA, session caching, etc.)

**Status: ✅ COMPLETED**

---

### 4. 🟠 ✅ Registry Pattern for Checks (Remove Hardcoded Lists) - COMPLETED

**Problem:** Check names are hardcoded in multiple places:

```python
# constants.py - manually maintained list
DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"
CHECK_TYPE_MAP = {
    DENY_IMDS_V1_EC2: "scps",
    THIRD_PARTY_ASSUMEROLE: "rcps",
}

# analysis.py - separate function for each check type
def run_scp_checks(...):
    if not results_exist(..., DENY_IMDS_V1_EC2, ...):
        check_deny_imds_v1_ec2(...)

def run_rcp_checks(...):
    if not results_exist(..., THIRD_PARTY_ASSUMEROLE, ...):
        check_third_party_assumerole(...)

def all_scp_results_exist(...):
    return results_exist(..., DENY_IMDS_V1_EC2, ...)

def all_rcp_results_exist(...):
    return results_exist(..., THIRD_PARTY_ASSUMEROLE, ...)
```

**Problem:** Adding a new check requires modifying 5+ files:
1. Create check file
2. Add constant to `constants.py`
3. Add to `CHECK_TYPE_MAP`
4. Add function to `analysis.py` (`run_scp_checks` or `run_rcp_checks`)
5. Potentially add `all_X_results_exist()` function

**Proposed Solution:** Self-registering checks with registry pattern

```python
# headroom/checks/registry.py (new file)
"""Check registry for auto-discovery of compliance checks."""

from typing import Dict, List, Optional, Type
from .base import BaseCheck

_CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {}


def register_check(check_type: str):
    """
    Decorator to register a check class.

    Args:
        check_type: Type of check ("scps" or "rcps")

    Usage:
        @register_check("scps")
        class MyCheck(BaseCheck):
            CHECK_NAME = "my_check"
            ...
    """
    def decorator(cls: Type[BaseCheck]):
        _CHECK_REGISTRY[cls.CHECK_NAME] = cls
        cls.CHECK_TYPE = check_type
        return cls
    return decorator


def get_check(check_name: str) -> Type[BaseCheck]:
    """Get check class by name."""
    if check_name not in _CHECK_REGISTRY:
        raise ValueError(f"Unknown check: {check_name}")
    return _CHECK_REGISTRY[check_name]


def get_all_checks(check_type: Optional[str] = None) -> List[Type[BaseCheck]]:
    """
    Get all registered checks, optionally filtered by type.

    Args:
        check_type: Filter by check type ("scps" or "rcps"), or None for all

    Returns:
        List of check classes
    """
    if check_type:
        return [cls for cls in _CHECK_REGISTRY.values() if cls.CHECK_TYPE == check_type]
    return list(_CHECK_REGISTRY.values())


def get_check_names(check_type: Optional[str] = None) -> List[str]:
    """Get all check names, optionally filtered by type."""
    checks = get_all_checks(check_type)
    return [cls.CHECK_NAME for cls in checks]


# Usage in check files:
@register_check("scps")
class DenyImdsV1Ec2Check(BaseCheck):
    CHECK_NAME = "deny_imds_v1_ec2"
    # ... implementation


@register_check("rcps")
class ThirdPartyAssumeRoleCheck(BaseCheck):
    CHECK_NAME = "third_party_assumerole"
    # ... implementation


# Simplified analysis.py - generic check runner:
def run_checks_for_type(
    check_type: str,
    session: boto3.Session,
    account_info: AccountInfo,
    config: HeadroomConfig,
    **kwargs
) -> None:
    """
    Run all checks of a given type (scps or rcps).

    This function automatically discovers and runs all registered checks
    of the specified type. No code changes needed when adding new checks.
    """
    checks = get_all_checks(check_type=check_type)

    for check_class in checks:
        if results_exist(
            check_name=check_class.CHECK_NAME,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        ):
            continue

        check = check_class(
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        )
        check.execute(session, **kwargs)


def all_checks_exist(
    check_type: str,
    account_info: AccountInfo,
    config: HeadroomConfig
) -> bool:
    """
    Check if all checks of a given type exist for an account.

    Generic function that works for any check type.
    """
    checks = get_all_checks(check_type=check_type)
    return all(
        results_exist(
            check_name=check_class.CHECK_NAME,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        )
        for check_class in checks
    )


def run_checks(
    security_session: boto3.Session,
    relevant_account_infos: List[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """Run all registered checks against all relevant accounts."""
    for account_info in relevant_account_infos:
        # Check if all results exist
        scp_exist = all_checks_exist("scps", account_info, config)
        rcp_exist = all_checks_exist("rcps", account_info, config)

        if scp_exist and rcp_exist:
            logger.info(f"All results exist for {account_info.name}, skipping")
            continue

        headroom_session = get_headroom_session(config, security_session, account_info.account_id)

        # Run SCP checks
        if not scp_exist:
            run_checks_for_type("scps", headroom_session, account_info, config)

        # Run RCP checks (pass org_account_ids as kwarg)
        if not rcp_exist:
            run_checks_for_type("rcps", headroom_session, account_info, config, org_account_ids=org_account_ids)
```

**Benefits:**
- **Zero-maintenance**: Adding a new check only requires creating the check file with `@register_check` decorator
- **No more hardcoded lists**: Constants automatically derived from check classes
- **Eliminates functions**: No more `all_scp_results_exist()` / `all_rcp_results_exist()` / `run_scp_checks()` / `run_rcp_checks()`
- **Discoverable**: Can list all checks programmatically
- **Type-safe**: Registry maintains type information

**Impact:**
- Eliminates ~100 lines of check coordination code
- Future checks require ZERO changes to `analysis.py` or `constants.py`
- Makes the system truly extensible

**Combined with Item 2 (Check Framework):**
- Add new check = Create single file with 50 lines
- No modifications to any other files
- Check automatically discovered and executed

**Status: ✅ COMPLETED**

---

## Medium-Priority Improvements

### 5. 🟡 Unify Placement Logic Between SCP and RCP

**Problem:** `determine_scp_placement()` and `determine_rcp_placement()` have different structures but share the same conceptual pattern: root→OU→account hierarchy checking.

**Current Duplication:**

Both functions implement the same strategy:
1. Check if root-level deployment is safe
2. Check if OU-level deployment is safe
3. Fall back to account-level deployment

But with duplicated hierarchy traversal logic:

```python
# In determine_scp_placement():
all_accounts_zero_violations = all(result.violations == 0 for result in check_results)
if all_accounts_zero_violations:
    # Root-level recommendation
    ...

# OU level checking - manual grouping
ou_violation_status: Dict[str, Dict[str, int]] = {}
for result in check_results:
    account_info = organization_hierarchy.accounts.get(result.account_id)
    parent_ou_id = account_info.parent_ou_id
    # ... build OU status
safe_ous = [ou_id for ou_id, status in ou_violation_status.items()
            if status["zero_violation_accounts"] == status["total_accounts"]]


# In determine_rcp_placement():
if accounts_with_wildcards:
    return None  # Can't do root level

# OU level checking - similar grouping pattern
ou_account_map: Dict[str, List[str]] = {}
for account_id in account_third_party_map.keys():
    account_info = organization_hierarchy.accounts.get(account_id)
    parent_ou_id = account_info.parent_ou_id
    # ... similar pattern
```

**Proposed Solution:** Extract hierarchy checking logic using Strategy pattern

```python
# headroom/placement/hierarchy.py (new file)
"""Hierarchy-aware placement analysis."""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, TypeVar

from ..types import OrganizationHierarchy

T = TypeVar('T')  # Type of check result


@dataclass
class PlacementCandidate:
    """Candidate placement level with associated data."""
    level: str  # "root", "ou", or "account"
    target_id: Optional[str]  # OU ID for OU level, None for root/account
    affected_accounts: List[str]
    reasoning: str


class HierarchyPlacementAnalyzer:
    """
    Analyzes organization hierarchy to determine optimal policy placement.

    Uses strategy pattern: caller provides "safety" predicates,
    this class handles hierarchy traversal.
    """

    def __init__(self, organization_hierarchy: OrganizationHierarchy):
        self.org = organization_hierarchy

    def determine_placement(
        self,
        check_results: List[T],
        is_safe_for_root: Callable[[List[T]], bool],
        is_safe_for_ou: Callable[[str, List[T]], bool],
        is_safe_for_account: Callable[[str, T], bool],
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
            is_safe_for_account: Predicate to determine if account-level is safe
            get_account_id: Function to extract account ID from result

        Returns:
            List of placement candidates (root, OU, or account level)
        """
        # Check root level
        if is_safe_for_root(check_results):
            return [PlacementCandidate(
                level="root",
                target_id=None,
                affected_accounts=[get_account_id(r) for r in check_results],
                reasoning="All accounts safe - deploy at root"
            )]

        # Check OU level
        ou_results: Dict[str, List[T]] = self._group_results_by_ou(check_results, get_account_id)
        ou_candidates = []

        for ou_id, ou_check_results in ou_results.items():
            if is_safe_for_ou(ou_id, ou_check_results):
                ou_info = self.org.organizational_units.get(ou_id)
                ou_name = ou_info.name if ou_info else ou_id
                ou_candidates.append(PlacementCandidate(
                    level="ou",
                    target_id=ou_id,
                    affected_accounts=[get_account_id(r) for r in ou_check_results],
                    reasoning=f"All accounts in OU '{ou_name}' safe - deploy at OU level"
                ))

        if ou_candidates:
            return ou_candidates

        # Check account level
        account_candidates = []
        for result in check_results:
            account_id = get_account_id(result)
            if is_safe_for_account(account_id, result):
                account_candidates.append(PlacementCandidate(
                    level="account",
                    target_id=None,
                    affected_accounts=[account_id],
                    reasoning="Individual account safe - deploy at account level"
                ))

        return account_candidates if account_candidates else []

    def _group_results_by_ou(
        self,
        check_results: List[T],
        get_account_id: Callable[[T], str]
    ) -> Dict[str, List[T]]:
        """Group check results by parent OU."""
        ou_results: Dict[str, List[T]] = {}
        for result in check_results:
            account_id = get_account_id(result)
            account_info = self.org.accounts.get(account_id)
            if not account_info:
                continue
            ou_id = account_info.parent_ou_id
            if ou_id not in ou_results:
                ou_results[ou_id] = []
            ou_results[ou_id].append(result)
        return ou_results


# Usage in determine_scp_placement():
def determine_scp_placement(
    results_data: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    analyzer = HierarchyPlacementAnalyzer(organization_hierarchy)

    # Group by check name (existing logic)
    check_groups = ...

    recommendations = []
    for check_name, check_results in check_groups.items():
        # Use analyzer with SCP-specific safety predicates
        candidates = analyzer.determine_placement(
            check_results=check_results,
            is_safe_for_root=lambda results: all(r.violations == 0 for r in results),
            is_safe_for_ou=lambda ou_id, results: all(r.violations == 0 for r in results),
            is_safe_for_account=lambda acc_id, result: result.violations == 0,
            get_account_id=lambda r: r.account_id
        )

        # Convert PlacementCandidates to SCPPlacementRecommendations
        for candidate in candidates:
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level=candidate.level,
                target_ou_id=candidate.target_id,
                affected_accounts=candidate.affected_accounts,
                compliance_percentage=100.0,  # From candidate or calculate
                reasoning=candidate.reasoning
            ))

    return recommendations


# Usage in determine_rcp_placement():
def determine_rcp_placement(
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> List[RCPPlacementRecommendations]:
    analyzer = HierarchyPlacementAnalyzer(organization_hierarchy)

    # Convert to list format for analyzer
    results = [
        {"account_id": acc_id, "third_parties": third_parties}
        for acc_id, third_parties in account_third_party_map.items()
    ]

    # Use analyzer with RCP-specific safety predicates
    candidates = analyzer.determine_placement(
        check_results=results,
        is_safe_for_root=lambda results: len(accounts_with_wildcards) == 0,
        is_safe_for_ou=lambda ou_id, results: not _should_skip_ou_for_rcp(ou_id, organization_hierarchy, accounts_with_wildcards),
        is_safe_for_account=lambda acc_id, result: acc_id not in accounts_with_wildcards,
        get_account_id=lambda r: r["account_id"]
    )

    # Convert candidates to RCPPlacementRecommendations...
```

**Benefits:**
- **DRY**: Hierarchy traversal logic extracted (eliminates ~150 lines of duplication)
- **Strategy pattern**: "Safety" criteria made explicit via predicates
- **Separation of concerns**: "Where to place" separated from "Is it safe"
- **Testable**: Can test hierarchy logic separately from policy-specific logic
- **Reduces cognitive load**: Clear responsibility boundaries

**Impact:**
- Easier to add new policy types (e.g., SCPs for S3 bucket policies)
- Hierarchy logic tested once, works for all policy types
- Policy-specific code focuses only on safety criteria

---

### 6. 🟡 Consolidate Print Statements

**Problem:** Multiple places with similar print/logging patterns:

```python
# In check files:
print(f"IMDS v1 check completed for {account_identifier}: {violations} violations...")
print(f"Third-party AssumeRole check completed for {account_identifier}: ...")

# In main.py:
print(f"\n🚨 Configuration Validation Error:\n{e}\n")
print("\n✅ Final Config:")

# In main.py (different error):
print(f"\n🚨 Terraform Generation Error:\n{e}\n")
```

**Proposed Solution:** Centralized output handling

```python
# headroom/output.py (new file)
"""Centralized output handling with consistent formatting."""

import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class OutputHandler:
    """Centralized output handling with consistent formatting."""

    @staticmethod
    def check_completed(check_name: str, account: str, stats: Dict[str, int]) -> None:
        """
        Log check completion with stats.

        Args:
            check_name: Name of the check
            account: Account identifier
            stats: Dictionary with 'violations', 'exemptions', 'compliant' keys
        """
        logger.info(
            f"{check_name} completed for {account}: "
            f"{stats.get('violations', 0)} violations, "
            f"{stats.get('exemptions', 0)} exemptions, "
            f"{stats.get('compliant', 0)} compliant"
        )

    @staticmethod
    def error(title: str, error: Exception) -> None:
        """Print formatted error message."""
        print(f"\n🚨 {title}:\n{error}\n")

    @staticmethod
    def success(title: str, data: Any = None) -> None:
        """Print formatted success message."""
        print(f"\n✅ {title}")
        if data:
            if isinstance(data, dict):
                print(json.dumps(data, indent=2, default=str))
            else:
                print(data)

    @staticmethod
    def section_header(title: str) -> None:
        """Print section header."""
        print("\n" + "=" * 80)
        print(title)
        print("=" * 80)


# Usage in main.py:
try:
    final_config = merge_configs(yaml_config, cli_args)
except (ValueError, TypeError) as e:
    OutputHandler.error("Configuration Error", e)
    exit(1)

OutputHandler.success("Final Config", final_config.model_dump())

# Usage in check base class:
OutputHandler.check_completed(
    self.check_name,
    f"{self.account_name}_{self.account_id}",
    {
        "violations": len(violations),
        "exemptions": len(exemptions),
        "compliant": len(compliant)
    }
)
```

**Benefits:**
- Consistent formatting across entire application
- Single place to change output style
- Easier to add features (colored output, log levels, structured logging)
- Can easily redirect to file or other output stream

**Impact:**
- Reduces ~20 lines of duplicate print statements
- More professional, consistent output

---

### 7. 🟡 Simplify Config Validation

**Problem:** `setup_configuration()` in `main.py` has separate handlers for ValueError and TypeError that do the same thing:

```python
try:
    final_config = merge_configs(yaml_config, cli_args)
except ValueError as e:
    print(f"\n🚨 Configuration Validation Error:\n{e}\n")
    exit(1)
except TypeError as e:
    print(f"\n🚨 Configuration Type Error:\n{e}\n")
    exit(1)
```

**Proposed Solution:** Combine exception handling

```python
def setup_configuration(cli_args: argparse.Namespace, yaml_config: Dict) -> HeadroomConfig:
    """
    Merge and validate configuration from YAML and CLI arguments.

    Args:
        cli_args: Parsed command line arguments
        yaml_config: Configuration loaded from YAML file

    Returns:
        Validated HeadroomConfig object

    Raises:
        SystemExit: If configuration validation fails
    """
    try:
        final_config = merge_configs(yaml_config, cli_args)
    except (ValueError, TypeError) as e:
        print(f"\n🚨 Configuration Error:\n{e}\n")
        exit(1)

    print("\n✅ Final Config:")
    print(final_config.model_dump())

    return final_config
```

**Benefits:**
- Simpler, cleaner code
- Both exceptions need identical handling

**Impact:**
- Reduces 4 lines
- More maintainable

---

### 8. 🟡 Refactor `_extract_account_id_from_result()`

**Problem:** Nested conditionals with multiple return points reduce readability:

```python
def _extract_account_id_from_result(...) -> str:
    account_id: str = summary.get("account_id", "")
    if not account_id:
        account_name = summary.get("account_name", "")
        if not account_name:
            raise RuntimeError(...)
        looked_up_id: str = lookup_account_id_by_name(...)
        return looked_up_id
    return account_id
```

**Proposed Solution:** Use early returns to reduce nesting

```python
def _extract_account_id_from_result(
    summary: Dict[str, Any],
    organization_hierarchy: OrganizationHierarchy,
    result_file: Path
) -> str:
    """
    Extract account ID from result summary or organization hierarchy.

    Universal strategy for both SCP and RCP results:
    1. Try to get account_id directly from summary
    2. If missing, look up account by name in organization hierarchy

    Args:
        summary: The summary dict from the result JSON
        organization_hierarchy: Organization structure for account lookups
        result_file: Path to result file (for error messages)

    Returns:
        Account ID string

    Raises:
        RuntimeError: If account ID cannot be determined
    """
    # Happy path: account_id present
    account_id: str = summary.get("account_id", "")
    if account_id:
        return account_id

    # Fallback: look up by account name
    account_name = summary.get("account_name", "")
    if not account_name:
        raise RuntimeError(
            f"Result file {result_file} missing both account_id and account_name in summary"
        )

    return lookup_account_id_by_name(
        account_name,
        organization_hierarchy,
        str(result_file)
    )
```

**Benefits:**
- Reduces cognitive complexity from 4 to 2
- Eliminates unnecessary variable `looked_up_id`
- Clearer flow: handle simple case first, then complex case
- Better follows "guard clause" pattern

**Impact:**
- Reduces 3 lines
- Much more readable

---

## Low-Priority / Style Improvements

### 9. 🟢 Standardize Error Messages

**Problem:** Inconsistent capitalization in error messages:

```python
# Capital
"Failed to assume role: {e}"
"Failed to parse result file {result_file}: {e}"

# Lowercase
"management_account_id must be set in config"
```

**Proposed Solution:** Standardize on capital letter for all error messages

**Impact:**
- Professional consistency
- ~20 files to update
- Quick find-and-replace

---

### 10. 🟢 Review MIN_ACCOUNTS_FOR_OU_LEVEL_RCP Constant

**Location:** `generate_rcps.py:29`

```python
MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 1
```

**Comment says:** "Set to 1 to allow OU-level RCPs even for single-account OUs"

**Problem:** A threshold of 1 has no effect (always allows). The code does:

```python
if len(ou_account_ids) < MIN_ACCOUNTS_FOR_OU_LEVEL_RCP:
    continue
```

With `MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 1`, this only skips OUs with 0 accounts (which wouldn't be in the map anyway).

**Proposed Solution:** Either:
1. Remove the constant and check (simplify code)
2. Change to meaningful value (e.g., 2 or 3)
3. Make it configurable if there's a future use case

**Impact:**
- Reduces 3 lines
- Removes confusion

---

### 11. 🟢 Type Alias for Union in `print_policy_recommendations()`

**Location:** `parse_results.py:325`

```python
def print_policy_recommendations(
    recommendations: Sequence[Union[SCPPlacementRecommendations, RCPPlacementRecommendations]],
    organization_hierarchy: OrganizationHierarchy,
    title: str = "SCP/RCP PLACEMENT RECOMMENDATIONS"
) -> None:
```

**Proposed Solution:** Add type alias

```python
# In types.py
PolicyRecommendation = Union[SCPPlacementRecommendations, RCPPlacementRecommendations]

# Usage:
def print_policy_recommendations(
    recommendations: Sequence[PolicyRecommendation],
    organization_hierarchy: OrganizationHierarchy,
    title: str = "SCP/RCP PLACEMENT RECOMMENDATIONS"
) -> None:
```

**Benefits:**
- More readable
- Reusable if pattern appears elsewhere

**Impact:**
- +1 line in types.py
- -2 characters in function signature
- Improved readability

---

## Architecture Observations

### ✅ What's Working Well

1. **Separation of Concerns**
   - Clear separation between AWS API interactions (`aws/`), business logic (`checks/`, `parse_results.py`), Terraform generation (`terraform/`), and configuration (`config.py`, `usage.py`)

2. **Type Safety**
   - Excellent use of `dataclasses` for structured data
   - Type hints everywhere
   - boto3-stubs for AWS SDK types
   - mypy validation

3. **Testability**
   - Pure functions
   - Dependency injection via sessions
   - Clear input/output contracts

4. **Consistent Patterns**
   - Terraform generation follows same pattern for SCPs and RCPs
   - Result parsing follows same pattern
   - File structure mirrors conceptual organization

5. **Documentation**
   - Docstrings on all public functions
   - Type hints serve as inline documentation
   - Clear module-level docstrings

---

## Strategic Recommendation

### Incremental Implementation Plan

**Phase 1: Week 1 - Critical + High Priority (Items 1-4)**

1. **Day 1:** Delete duplicate file (Item 1) - 5 minutes
2. **Day 1:** Extract session management (Item 3) - 1 hour
   - Create `aws/sessions.py`
   - Refactor existing functions
   - Run tests
3. **Days 2-3:** Abstract check framework (Item 2) - 4 hours
   - Create `checks/base.py`
   - Refactor `deny_imds_v1_ec2.py`
   - Refactor `check_third_party_assumerole.py`
   - Run tests
4. **Days 4-5:** Implement registry pattern (Item 4) - 3 hours
   - Create `checks/registry.py`
   - Add decorators to checks
   - Refactor `analysis.py`
   - Run tests

**Result:** Codebase becomes extensible - adding new checks goes from 5-file change to 1-file change

**Phase 2: Week 2 - Medium Priority (Items 5-8)**

1. **Days 1-2:** Extract placement analysis (Item 5) - 3 hours
2. **Day 3:** Consolidate output (Item 6) - 1 hour
3. **Day 3:** Small refactorings (Items 7-8) - 15 minutes

**Result:** Further DRY improvements, better separation of concerns

**Phase 3: Week 3 - Low Priority + Documentation (Items 9-11)**

1. **Day 1:** Standardize error messages (Item 9) - 30 minutes
2. **Day 1:** Review constants (Item 10) - 5 minutes
3. **Day 1:** Type alias (Item 11) - 2 minutes
4. **Days 2-3:** Update documentation
   - Update README with new patterns
   - Add architecture diagrams
   - Update this file with completion status

**Result:** Professional, consistent codebase ready for team scaling

---

## Philosophical Note on Clean Code

Your codebase is **already good**. These recommendations are about moving from **good to great**:

- ✅ You have **no spaghetti code**
- ✅ You have **strong type safety**
- ✅ You have **good separation of concerns**
- ⚠️ You have **tactical duplication** that can become **strategic abstractions**

### The Key Insight

**The check pattern is your core abstraction.** Everything else (sessions, parsing, terraform generation) supports checks. By making checks first-class abstractions, you make the entire system more maintainable.

Think of it like combining design patterns:
- **Template Method**: `BaseCheck` defines the skeleton
- **Strategy Pattern**: Each check implements its unique logic
- **Registry Pattern**: Checks self-register, no hardcoding

This is **principal engineer thinking**: Identify the core abstraction, make it explicit, everything else becomes simpler.

### Benefits of This Approach

1. **Extensibility**: Add new check = Create one file
2. **Maintainability**: Bug fixes to check logic = Fix once in base class
3. **Discoverability**: New team members see pattern immediately
4. **Scalability**: System scales to 10x more checks without code changes

---

## How to Use This Document

1. **Prioritize**: Start with Critical, then High, then Medium, then Low
2. **Incremental**: Implement one item at a time with tests passing
3. **Document**: Update this file when items are completed
4. **Reference**: Link to this document in code reviews

## Testing Checklist

After each refactoring:
- [ ] All tests pass (`tox`)
- [ ] 100% code coverage maintained
- [ ] No mypy errors
- [ ] All pre-commit checks pass
- [ ] Documentation updated (if needed)
- [ ] `conversation_history.md` updated with details

---

*Generated by Principal Engineer Review - 2025-11-08*
