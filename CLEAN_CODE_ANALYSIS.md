# Clean Code Analysis - Headroom Codebase

**Date:** November 15, 2025
**Reviewer:** Principal Software Engineer
**Methodology:** Based on Robert C. Martin's "Clean Code" principles

## Executive Summary

Overall, this codebase demonstrates **good software engineering practices**. The code is well-structured with clear separation of concerns, strong type annotations, and good use of design patterns (Template Method, Strategy, Registry). However, there are opportunities for improvement in several areas detailed below.

**Strengths:**
- Excellent use of type hints throughout
- Good abstraction and design patterns
- Clear module organization
- Comprehensive docstrings
- Strong separation of concerns

**Areas for Improvement:**
- Function complexity (some functions too long)
- Code duplication in similar operations
- Magic strings and numbers
- Some functions do more than one thing
- Inconsistent abstraction levels

---

## 1. Functions Should Be Small and Do One Thing

### 🔴 Issue: `determine_scp_placement()` in `parse_results.py` (lines 183-279)

**Problem:** This 96-line function violates the Single Responsibility Principle. It:
1. Groups results by check name
2. Looks up account IDs
3. Filters safe results
4. Analyzes placement with HierarchyPlacementAnalyzer
5. Handles deny_iam_user_creation special case
6. Constructs three different types of recommendations (root, OU, account)

**Recommendation:**
```python
def determine_scp_placement(
    results_data: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """Determine optimal SCP placement using provided hierarchy."""
    recommendations: List[SCPPlacementRecommendations] = []
    analyzer = HierarchyPlacementAnalyzer(organization_hierarchy)

    check_groups = _group_results_by_check_name(results_data)

    for check_name, check_results in check_groups.items():
        _ensure_account_ids_present(check_results, organization_hierarchy)
        check_recommendations = _determine_check_placement(
            check_name,
            check_results,
            analyzer
        )
        recommendations.extend(check_recommendations)

    return recommendations

def _determine_check_placement(
    check_name: str,
    check_results: List[SCPCheckResult],
    analyzer: HierarchyPlacementAnalyzer
) -> List[SCPPlacementRecommendations]:
    """Determine placement for a single check."""
    safe_results = [r for r in check_results if r.violations == 0]

    if not safe_results:
        return [_create_no_deployment_recommendation(check_name)]

    candidates = analyzer.determine_placement(
        check_results=check_results,
        is_safe_for_root=lambda results: all(r.violations == 0 for r in results),
        is_safe_for_ou=lambda ou_id, results: all(r.violations == 0 for r in results),
        get_account_id=lambda r: r.account_id
    )

    return _build_recommendations_from_candidates(
        check_name,
        candidates,
        check_results,
        safe_results
    )
```

### 🔴 Issue: `run_checks()` in `analysis.py` (lines 287-329)

**Problem:** This function orchestrates multiple concerns:
- Iterates through accounts
- Checks if results exist for both SCP and RCP
- Logs status
- Assumes roles
- Conditionally runs checks

**Recommendation:** Extract helper functions:
```python
def run_checks(
    security_session: boto3.Session,
    relevant_account_infos: List[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """Run security checks against all relevant accounts."""
    for account_info in relevant_account_infos:
        _process_account_checks(
            account_info,
            security_session,
            config,
            org_account_ids
        )

def _process_account_checks(
    account_info: AccountInfo,
    security_session: boto3.Session,
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """Process checks for a single account."""
    account_identifier = _get_account_identifier(account_info)

    if _all_checks_complete(account_info, config):
        logger.info(f"All results already exist for account {account_identifier}, skipping checks")
        return

    logger.info(f"Running checks for account: {account_identifier}")

    headroom_session = get_headroom_session(
        config,
        security_session,
        account_info.account_id
    )

    _run_incomplete_checks(
        account_info,
        headroom_session,
        config,
        org_account_ids
    )

    logger.info(f"Checks completed for account: {account_identifier}")

def _all_checks_complete(
    account_info: AccountInfo,
    config: HeadroomConfig
) -> bool:
    """Check if all checks are complete for an account."""
    return (
        all_check_results_exist("scps", account_info, config) and
        all_check_results_exist("rcps", account_info, config)
    )

def _get_account_identifier(account_info: AccountInfo) -> str:
    """Get display identifier for an account."""
    return f"{account_info.name}_{account_info.account_id}"
```

---

## 2. Magic Strings and Numbers

### 🔴 Issue: String Literals Throughout Codebase

**Problem:** Magic strings like "scps", "rcps", "root", "ou", "account", "violation", "exemption", "compliant" appear throughout.

**Current State:**
```python
# In multiple files:
check_names = get_check_names("scps")
check_classes = get_all_check_classes("rcps")
if rec.recommended_level == "root":
    ...
elif rec.recommended_level == "ou":
    ...
if category == "violation":
    ...
```

**Recommendation:** Create an enums module:
```python
# headroom/enums.py
from enum import Enum

class CheckType(str, Enum):
    """Types of compliance checks."""
    SCPS = "scps"
    RCPS = "rcps"

class PlacementLevel(str, Enum):
    """Policy placement levels in organization hierarchy."""
    ROOT = "root"
    OU = "ou"
    ACCOUNT = "account"
    NONE = "none"

class CheckCategory(str, Enum):
    """Categorization of check results."""
    VIOLATION = "violation"
    EXEMPTION = "exemption"
    COMPLIANT = "compliant"
```

**Usage:**
```python
check_names = get_check_names(CheckType.SCPS)
if rec.recommended_level == PlacementLevel.ROOT:
    ...
if category == CheckCategory.VIOLATION:
    ...
```

### 🔴 Issue: Magic Numbers in `_build_scp_terraform_module()`

**Problem:** Line 76 in `generate_scps.py`:
```python
if rec.compliance_percentage == 100.0:
```

**Recommendation:**
```python
# constants.py
FULL_COMPLIANCE_PERCENTAGE = 100.0

# Usage:
if rec.compliance_percentage == FULL_COMPLIANCE_PERCENTAGE:
```

---

## 3. Code Duplication (DRY Principle)

### 🔴 Issue: Repeated Account Identifier String Formatting

**Locations:**
- `analysis.py` line 309: `f"{account_info.name}_{account_info.account_id}"`
- `analysis.py` line 190: Same pattern in `base.py`
- Multiple test files

**Recommendation:** Create a utility function:
```python
# types.py or utils.py
def format_account_identifier(account_name: str, account_id: str) -> str:
    """
    Format a consistent account identifier string.

    Args:
        account_name: Account name
        account_id: Account ID

    Returns:
        Formatted identifier string
    """
    return f"{account_name}_{account_id}"
```

### 🔴 Issue: Duplicated Result File Path Logic

**Problem:** Similar logic in `write_results.py` appears in multiple functions:
- `get_results_dir()` (lines 99-116)
- `get_results_path()` (lines 119-146)
- `results_exist()` (lines 149-189)

**Recommendation:** Create a `ResultFilePathResolver` class:
```python
class ResultFilePathResolver:
    """Resolves file paths for check results."""

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_base_dir: str,
        exclude_account_ids: bool = False
    ):
        self.check_name = check_name
        self.account_name = account_name
        self.account_id = account_id
        self.results_base_dir = results_base_dir
        self.exclude_account_ids = exclude_account_ids

    def get_check_directory(self) -> str:
        """Get directory for this check type."""
        check_type_map = get_check_type_map()
        check_type = check_type_map.get(self.check_name)
        if not check_type:
            raise ValueError(f"Unknown check name: {self.check_name}")
        return f"{self.results_base_dir}/{check_type}/{self.check_name}"

    def get_file_path(self) -> Path:
        """Get file path for results."""
        results_dir = self.get_check_directory()
        filename = self._build_filename()
        return Path(results_dir) / filename

    def exists(self) -> bool:
        """Check if result file exists (checks both formats)."""
        return (
            self.get_file_path().exists() or
            self._get_alternate_path().exists()
        )

    def _build_filename(self) -> str:
        """Build filename based on configuration."""
        if self.exclude_account_ids:
            account_identifier = self.account_name
        else:
            account_identifier = format_account_identifier(
                self.account_name,
                self.account_id
            )
        return f"{account_identifier}.json"

    def _get_alternate_path(self) -> Path:
        """Get alternate format path for backward compatibility."""
        # Create new resolver with inverted exclude_account_ids
        alternate = ResultFilePathResolver(
            self.check_name,
            self.account_name,
            self.account_id,
            self.results_base_dir,
            not self.exclude_account_ids
        )
        return alternate.get_file_path()
```

### 🔴 Issue: Repeated Terraform Module Building Pattern

**Problem:** Similar patterns in:
- `generate_scps.py`: `_generate_account_scp_terraform()`, `_generate_ou_scp_terraform()`, `_generate_root_scp_terraform()`
- `generate_rcps.py`: Similar pattern (not shown but likely exists)

**Recommendation:** Create a more generic builder:
```python
@dataclass
class TerraformModuleConfig:
    """Configuration for Terraform module generation."""
    module_name: str
    target_id_reference: str
    recommendations: List[PolicyRecommendation]
    comment: str
    output_filename: str

class TerraformModuleGenerator:
    """Generates Terraform module configurations."""

    def __init__(self, organization_hierarchy: OrganizationHierarchy):
        self.org_hierarchy = organization_hierarchy

    def generate_for_account(
        self,
        account_id: str,
        recommendations: List[SCPPlacementRecommendations]
    ) -> TerraformModuleConfig:
        """Generate config for account-level module."""
        account_info = self._get_account_info(account_id)
        safe_name = make_safe_variable_name(account_info.account_name)

        return TerraformModuleConfig(
            module_name=f"scps_{safe_name}",
            target_id_reference=f"local.{safe_name}_account_id",
            recommendations=recommendations,
            comment=account_info.account_name,
            output_filename=f"{safe_name}_scps.tf"
        )

    def generate_for_ou(
        self,
        ou_id: str,
        recommendations: List[SCPPlacementRecommendations]
    ) -> TerraformModuleConfig:
        """Generate config for OU-level module."""
        ou_info = self._get_ou_info(ou_id)
        safe_name = make_safe_variable_name(ou_info.name)

        return TerraformModuleConfig(
            module_name=f"scps_{safe_name}_ou",
            target_id_reference=f"local.top_level_{safe_name}_ou_id",
            recommendations=recommendations,
            comment=f"OU {ou_info.name}",
            output_filename=f"{safe_name}_ou_scps.tf"
        )

    def generate_for_root(
        self,
        recommendations: List[SCPPlacementRecommendations]
    ) -> TerraformModuleConfig:
        """Generate config for root-level module."""
        return TerraformModuleConfig(
            module_name="scps_root",
            target_id_reference="local.root_ou_id",
            recommendations=recommendations,
            comment="Organization Root",
            output_filename="root_scps.tf"
        )
```

---

## 4. Functions at Different Levels of Abstraction

### 🔴 Issue: `_build_scp_terraform_module()` in `generate_scps.py`

**Problem:** This function mixes high-level orchestration with low-level string building:

```python
def _build_scp_terraform_module(...):
    # High-level: collect enabled checks
    enabled_checks = set()
    for rec in recommendations:
        if rec.compliance_percentage == 100.0:
            check_name_terraform = rec.check_name.replace("-", "_")
            enabled_checks.add(check_name_terraform)

    # Low-level: string concatenation
    terraform_content += "  # EC2\n"
    deny_ec2_ami_owner = "deny_ec2_ami_owner" in enabled_checks
    terraform_content += f"  deny_ec2_ami_owner = {str(deny_ec2_ami_owner).lower()}\n"

    # Mid-level: conditional logic
    if deny_ec2_ami_owner:
        allowed_ami_owners = []
        for rec in recommendations:
            if rec.check_name.replace("-", "_") == "deny_ec2_ami_owner" and rec.allowed_ami_owners:
                allowed_ami_owners = rec.allowed_ami_owners
                break
```

**Recommendation:** Separate into distinct abstraction layers:
```python
def _build_scp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[SCPPlacementRecommendations],
    comment: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """Build Terraform module call for SCP deployment (high-level orchestration)."""
    config = _extract_scp_configuration(recommendations, organization_hierarchy)
    return _render_scp_terraform(module_name, target_id_reference, comment, config)

def _extract_scp_configuration(
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy
) -> Dict[str, Any]:
    """Extract SCP configuration from recommendations (mid-level logic)."""
    enabled_checks = _get_enabled_checks(recommendations)

    return {
        "deny_ec2_ami_owner": "deny_ec2_ami_owner" in enabled_checks,
        "allowed_ami_owners": _get_allowed_ami_owners(recommendations),
        "deny_imds_v1_ec2": "deny_imds_v1_ec2" in enabled_checks,
        "deny_eks_create_cluster_without_tag": "deny_eks_create_cluster_without_tag" in enabled_checks,
        "deny_iam_user_creation": "deny_iam_user_creation" in enabled_checks,
        "allowed_iam_users": _get_allowed_iam_users(recommendations, organization_hierarchy),
        "deny_rds_unencrypted": "deny_rds_unencrypted" in enabled_checks,
    }

def _get_enabled_checks(
    recommendations: List[SCPPlacementRecommendations]
) -> Set[str]:
    """Get set of enabled check names."""
    enabled = set()
    for rec in recommendations:
        if rec.compliance_percentage == FULL_COMPLIANCE_PERCENTAGE:
            check_name_terraform = rec.check_name.replace("-", "_")
            enabled.add(check_name_terraform)
    return enabled

def _get_allowed_ami_owners(
    recommendations: List[SCPPlacementRecommendations]
) -> List[str]:
    """Extract allowed AMI owners from recommendations."""
    for rec in recommendations:
        check_name = rec.check_name.replace("-", "_")
        if check_name == "deny_ec2_ami_owner" and rec.allowed_ami_owners:
            return rec.allowed_ami_owners
    return []

def _render_scp_terraform(
    module_name: str,
    target_id_reference: str,
    comment: str,
    config: Dict[str, Any]
) -> str:
    """Render Terraform content from configuration (low-level string building)."""
    lines = [
        f"# Auto-generated SCP Terraform configuration for {comment}",
        "# Generated by Headroom based on compliance analysis",
        "",
        f'module "{module_name}" {{',
        '  source = "../modules/scps"',
        f"  target_id = {target_id_reference}",
        "",
        "  # EC2",
        f"  deny_ec2_ami_owner = {str(config['deny_ec2_ami_owner']).lower()}",
    ]

    if config['deny_ec2_ami_owner'] and config['allowed_ami_owners']:
        lines.append("  allowed_ami_owners = [")
        for owner in config['allowed_ami_owners']:
            lines.append(f'    "{owner}",')
        lines.append("  ]")
    elif config['deny_ec2_ami_owner']:
        lines.append("  allowed_ami_owners = []")

    lines.extend([
        f"  deny_imds_v1_ec2 = {str(config['deny_imds_v1_ec2']).lower()}",
        "",
        "  # EKS",
        f"  deny_eks_create_cluster_without_tag = {str(config['deny_eks_create_cluster_without_tag']).lower()}",
        "",
        "  # IAM",
        f"  deny_iam_user_creation = {str(config['deny_iam_user_creation']).lower()}",
    ])

    if config['deny_iam_user_creation'] and config['allowed_iam_users']:
        lines.append("  allowed_iam_users = [")
        for arn in config['allowed_iam_users']:
            lines.append(f'    "{arn}",')
        lines.append("  ]")
    elif config['deny_iam_user_creation']:
        lines.append("  allowed_iam_users = []")

    lines.extend([
        "",
        "  # RDS",
        f"  deny_rds_unencrypted = {str(config['deny_rds_unencrypted']).lower()}",
        "}",
    ])

    return "\n".join(lines) + "\n"
```

---

## 5. Inconsistent Naming Conventions

### 🔴 Issue: Mixing Conventions for Boolean Returns

**Problem:**
- `results_exist()` - good (returns boolean)
- `all_check_results_exist()` - good (returns boolean)
- `get_all_organization_account_ids()` - returns Set (not clear from name)

**Recommendation:** Use consistent prefixes:
- `is_*` or `has_*` for boolean functions
- `get_*` for retrieval functions
- `fetch_*` for API calls
- `calculate_*` or `compute_*` for computations

### 🔴 Issue: Inconsistent Function Naming for Similar Operations

**Current:**
```python
parse_scp_results()  # Returns List[SCPPlacementRecommendations]
parse_rcp_result_files()  # Returns RCPParseResult
determine_scp_placement()  # Returns List[SCPPlacementRecommendations]
determine_rcp_placement()  # Returns List[RCPPlacementRecommendations]
```

**Recommendation:** More consistent naming:
```python
# Parse = read and structure data
parse_scp_result_files()  # Returns List[SCPCheckResult]
parse_rcp_result_files()  # Returns RCPParseResult

# Analyze = process and make recommendations
analyze_scp_placement()  # Returns List[SCPPlacementRecommendations]
analyze_rcp_placement()  # Returns List[RCPPlacementRecommendations]
```

---

## 6. Long Parameter Lists

### 🔴 Issue: Multiple Functions with 5+ Parameters

**Examples:**
```python
# write_results.py
def write_check_results(
    check_name: str,
    account_name: str,
    account_id: str,
    results_data: Dict[str, Any],
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> None:

def get_results_path(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> Path:
```

**Recommendation:** Create parameter objects (already following user's rule about not overengineering):
```python
@dataclass
class CheckContext:
    """Context for a check execution."""
    check_name: str
    account_name: str
    account_id: str

@dataclass
class ResultsConfig:
    """Configuration for results storage."""
    base_dir: str
    exclude_account_ids: bool = False

# Simplified signatures:
def write_check_results(
    context: CheckContext,
    results_data: Dict[str, Any],
    config: ResultsConfig
) -> None:

def get_results_path(
    context: CheckContext,
    config: ResultsConfig
) -> Path:
```

---

## 7. Comments That Could Be Code

### 🟡 Issue: Descriptive Comments in `_build_scp_terraform_module()`

**Current:**
```python
# EC2
terraform_content += "  # EC2\n"
deny_ec2_ami_owner = "deny_ec2_ami_owner" in enabled_checks

# EKS
terraform_content += "  # EKS\n"
deny_eks_create_cluster_without_tag = ...

# IAM
terraform_content += "  # IAM\n"
deny_iam_user_creation = ...
```

**Recommendation:** The service grouping suggests these should be separate functions:
```python
def _build_ec2_section(enabled_checks: Set[str], recommendations: List[...]) -> str:
    """Build EC2 section of Terraform configuration."""
    lines = ["  # EC2"]

    deny_ec2_ami_owner = "deny_ec2_ami_owner" in enabled_checks
    lines.append(f"  deny_ec2_ami_owner = {str(deny_ec2_ami_owner).lower()}")

    if deny_ec2_ami_owner:
        allowed_owners = _extract_allowed_ami_owners(recommendations)
        if allowed_owners:
            lines.append("  allowed_ami_owners = [")
            lines.extend(f'    "{owner}",' for owner in allowed_owners)
            lines.append("  ]")
        else:
            lines.append("  allowed_ami_owners = []")

    deny_imds_v1_ec2 = "deny_imds_v1_ec2" in enabled_checks
    lines.append(f"  deny_imds_v1_ec2 = {str(deny_imds_v1_ec2).lower()}")

    return "\n".join(lines)

def _build_eks_section(enabled_checks: Set[str]) -> str:
    """Build EKS section of Terraform configuration."""
    ...

def _build_iam_section(
    enabled_checks: Set[str],
    recommendations: List[...],
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """Build IAM section of Terraform configuration."""
    ...
```

---

## 8. Error Handling Improvements

### 🟡 Issue: Broad Exception Catching

**Current in `main.py` (line 186):**
```python
except (ValueError, RuntimeError, ClientError) as e:
    OutputHandler.error("Terraform Generation Error", e)
    exit(1)
```

**Recommendation:** While the user's rule says "always catch the specific exceptions", this is already specific. However, consider:
1. Different handling for different errors
2. More context in error messages

```python
except ValueError as e:
    OutputHandler.error("Configuration Error", e)
    logger.error(f"Invalid configuration: {e}", exc_info=True)
    exit(1)
except RuntimeError as e:
    OutputHandler.error("Runtime Error", e)
    logger.error(f"Runtime error during Terraform generation: {e}", exc_info=True)
    exit(1)
except ClientError as e:
    error_code = e.response['Error']['Code']
    OutputHandler.error(f"AWS API Error ({error_code})", e)
    logger.error(f"AWS API error: {e}", exc_info=True)
    exit(1)
```

### 🟡 Issue: Silent Error Handling in `_fetch_account_tags()`

**Current in `analysis.py` (lines 74-76):**
```python
except ClientError as e:
    logger.warning(f"Could not fetch tags for account {account_name} ({account_id}): {e}")
    return {}
```

**Consideration:** Is returning empty dict the right behavior? Consider:
```python
except ClientError as e:
    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
    if error_code == 'AccessDeniedException':
        logger.warning(
            f"Access denied fetching tags for account {account_name} ({account_id}). "
            f"Account will use default values."
        )
    else:
        logger.error(
            f"Unexpected error fetching tags for account {account_name} ({account_id}): {e}",
            exc_info=True
        )
    return {}
```

---

## 9. Potential Performance Issues

### 🟡 Issue: O(n²) Loop in `determine_scp_placement()`

**Current in `parse_results.py` (lines 237-240):**
```python
for result in check_results:
    if result.account_id in candidate.affected_accounts and result.iam_user_arns:
        iam_user_arns_set.update(result.iam_user_arns)
```

**Problem:** For each candidate, iterating through all check_results. If you have many results, this gets expensive.

**Recommendation:** Pre-build lookup map:
```python
# Before the loop
account_to_iam_arns: Dict[str, Set[str]] = {}
for result in check_results:
    if result.iam_user_arns:
        account_to_iam_arns[result.account_id] = set(result.iam_user_arns)

# Inside the loop
if check_name == "deny_iam_user_creation":
    iam_user_arns_set = set()
    for account_id in candidate.affected_accounts:
        if account_id in account_to_iam_arns:
            iam_user_arns_set.update(account_to_iam_arns[account_id])
    allowed_iam_user_arns = sorted(list(iam_user_arns_set)) if iam_user_arns_set else []
```

---

## 10. Type Annotations Could Be More Specific

### 🟡 Issue: Using `Any` in Type Hints

**Current in `parse_results.py` (line 1):**
```python
from typing import Any, Dict, List, Sequence
```

**Examples:**
```python
def _load_result_file_json(result_file: Path) -> Dict[str, Any]:
```

**Recommendation:** While `Dict[str, Any]` is sometimes necessary for JSON, consider creating TypedDict for well-known structures:
```python
from typing import TypedDict, NotRequired

class CheckResultSummary(TypedDict):
    """Type definition for check result summary section."""
    account_id: NotRequired[str]  # Optional field
    account_name: str
    check: str
    violations: int
    exemptions: int
    compliant: int
    total_instances: NotRequired[int]
    compliance_percentage: float

def _load_result_file_json(result_file: Path) -> Dict[str, Any]:
    """Load JSON with dynamic structure."""
    # This is fine for truly dynamic JSON

def _extract_summary(data: Dict[str, Any]) -> CheckResultSummary:
    """Extract typed summary from raw data."""
    return data.get("summary", {})
```

---

## 11. Dataclasses vs. Pydantic Models

### 🟡 Issue: Mixing dataclasses and Pydantic models

**Current:**
- `config.py` uses Pydantic BaseModel
- `types.py` uses @dataclass
- `analysis.py` line 19 uses @dataclass

**Recommendation:** Consider consistency:

**Option A: All Pydantic** (Better validation, worse performance)
```python
from pydantic import BaseModel

class OrganizationalUnit(BaseModel):
    ou_id: str
    name: str
    parent_ou_id: Optional[str]
    child_ous: List[str]
    accounts: List[str]

    class Config:
        frozen = True  # Make immutable like dataclass
```

**Option B: All dataclasses** (Better performance, less validation)
```python
# Keep as is for simple data containers
# Use Pydantic only for config/validation at boundaries
```

**Recommendation:** Your current approach is fine. Pydantic for configuration (external input), dataclasses for internal structures is a good pattern.

---

## 12. Missing Abstractions

### 🟡 Issue: Account ID Extraction Pattern Repeated

**Pattern seen in:**
- `analysis.py`: Building account identifiers
- `parse_results.py`: Extracting account IDs from results
- `write_results.py`: Building filenames with account IDs

**Recommendation:** Create an AccountIdentifier value object:
```python
@dataclass(frozen=True)
class AccountIdentifier:
    """Value object for account identification."""
    account_id: str
    account_name: str

    def as_string(self, include_id: bool = True) -> str:
        """Format as string."""
        if include_id:
            return f"{self.account_name}_{self.account_id}"
        return self.account_name

    def as_safe_terraform_name(self) -> str:
        """Format as Terraform-safe variable name."""
        return make_safe_variable_name(self.account_name)

    @classmethod
    def from_account_info(cls, info: AccountInfo) -> 'AccountIdentifier':
        """Create from AccountInfo."""
        return cls(
            account_id=info.account_id,
            account_name=info.name
        )
```

---

## 13. Testing Concerns

### 🔴 Issue: Functions Hard to Test in Isolation

**Example: `_build_scp_terraform_module()` in `generate_scps.py`**

This function:
- Builds string content
- Has conditional logic based on check types
- Depends on organization hierarchy for ARN transformation
- Returns a 140-line string

**Problem:** Hard to verify correctness without string comparison.

**Recommendation:** Use composition and testable components:
```python
@dataclass
class TerraformModule:
    """Structured representation of Terraform module."""
    name: str
    source: str
    target_id: str
    parameters: Dict[str, Any]

    def render(self) -> str:
        """Render to Terraform HCL."""
        lines = [
            f'module "{self.name}" {{',
            f'  source = "{self.source}"',
            f'  target_id = {self.target_id}',
            ""
        ]

        for key, value in self.parameters.items():
            lines.append(self._render_parameter(key, value))

        lines.append("}")
        return "\n".join(lines)

    def _render_parameter(self, key: str, value: Any) -> str:
        """Render a single parameter."""
        if isinstance(value, bool):
            return f"  {key} = {str(value).lower()}"
        elif isinstance(value, list):
            if not value:
                return f"  {key} = []"
            items = [f'    "{item}",' for item in value]
            return f"  {key} = [\n" + "\n".join(items) + "\n  ]"
        elif isinstance(value, str):
            return f'  {key} = "{value}"'
        else:
            return f"  {key} = {value}"

# Now you can test structure separately from rendering:
def test_terraform_module_with_list_parameter():
    module = TerraformModule(
        name="test_module",
        source="../modules/test",
        target_id="local.test_id",
        parameters={"allowed_items": ["item1", "item2"]}
    )

    rendered = module.render()

    assert 'module "test_module"' in rendered
    assert 'allowed_items = [' in rendered
    assert '"item1",' in rendered
```

---

## 14. Documentation Improvements

### ✅ Good: Most functions have docstrings

### 🟡 Could Be Better: Some docstrings are too detailed

**Example in `main.py` (lines 93-108):**
```python
def ensure_org_info_symlink(rcps_dir: str, scps_dir: str) -> None:
    """
    Create symlink from rcps/grab_org_info.tf to scps/grab_org_info.tf.

    The grab_org_info.tf file contains shared organization structure data sources
    needed by both SCP and RCP modules. This function ensures the symlink exists
    in the RCP directory.

    Args:
        rcps_dir: RCP directory path where symlink should be created
        scps_dir: SCP directory path (contains the actual grab_org_info.tf file)
    """
    rcps_path = Path(rcps_dir)
    rcps_path.mkdir(parents=True, exist_ok=True)
    _create_org_info_symlink(rcps_path, scps_dir)
```

**Issue:** The function does almost nothing except call another function. The docstring is longer than the code.

**Recommendation:**
```python
def ensure_org_info_symlink(rcps_dir: str, scps_dir: str) -> None:
    """Ensure RCP directory has symlink to SCP org info file."""
    rcps_path = Path(rcps_dir)
    rcps_path.mkdir(parents=True, exist_ok=True)
    _create_org_info_symlink(rcps_path, scps_dir)
```

The detailed explanation belongs in `_create_org_info_symlink()` or module-level docstring.

---

## 15. Positive Patterns Worth Highlighting

### ✅ Excellent: Template Method Pattern in `BaseCheck`

The `base.py` implementation is textbook Clean Code:
- Abstract base class defines algorithm structure
- Subclasses implement specific steps
- Single Responsibility: each method does one thing
- Open/Closed: Can add new checks without modifying base

### ✅ Excellent: Registry Pattern in `checks/registry.py`

- Auto-discovery of checks
- No hardcoded lists
- Easy to add new checks
- Follows Open/Closed Principle

### ✅ Excellent: Strategy Pattern in `HierarchyPlacementAnalyzer`

- Separates hierarchy traversal from business rules
- Highly reusable
- Well-tested
- Clear abstractions

### ✅ Excellent: Type Annotations Throughout

The codebase has comprehensive type hints, making it easy to understand interfaces and catch errors early.

### ✅ Excellent: Separation of Concerns

Clear module boundaries:
- `aws/` - AWS API interactions
- `checks/` - Compliance checks
- `terraform/` - Terraform generation
- `placement/` - Placement logic

---

## Priority Recommendations

### High Priority (Do These First):
1. **Extract magic strings to enums** - Quick win, prevents bugs
2. **Break up large functions** - `determine_scp_placement()`, `run_checks()`, `_build_scp_terraform_module()`
3. **Create ResultFilePathResolver class** - Reduces duplication
4. **Extract account identifier formatting** - Used everywhere

### Medium Priority:
5. **Improve Terraform generation testability** - Separate structure from rendering
6. **Add performance optimization** - Pre-build lookup maps
7. **Consistent function naming** - `parse_*`, `analyze_*`, `fetch_*`
8. **Create parameter objects** - Reduce long parameter lists

### Low Priority (Nice to Have):
9. **TypedDict for JSON structures** - Better type safety
10. **Simplify docstrings** - Remove redundant comments
11. **More specific error handling** - Different messages per error type

---

## Conclusion

This is a **well-architected codebase** with good separation of concerns, strong typing, and excellent use of design patterns. The main areas for improvement are:

1. **Function size** - Several functions are too long and do multiple things
2. **Code duplication** - Similar patterns repeated across modules
3. **Magic strings** - Should be replaced with enums or constants
4. **Testability** - Some functions are hard to test due to mixing concerns

These are typical issues in growing codebases and can be addressed incrementally through refactoring.

**Overall Grade: B+**

The codebase demonstrates solid software engineering principles. With the recommended refactorings, it would be an A-grade enterprise codebase.
