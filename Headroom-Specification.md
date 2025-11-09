# Headroom - AWS Multi-Account Security Analysis Tool
## Product Specification

**Version:** 5.0
**Last Updated:** 2025-11-09

---

## Executive Summary

**Headroom** is a Python CLI tool for AWS multi-account security analysis with Service Control Policy (SCP) and Resource Control Policy (RCP) audit capabilities. The tool provides "audit mode" for SCPs/RCPs, enabling security teams to analyze AWS Organizations environments and auto-generate Terraform configurations for policy deployment.

**Core Value Proposition:** Ever want audit mode for SCPs / RCPs? Well now you can.

**Usage Philosophy:** Bare-bones prevention-focused CLI tool. No more getting flooded with thousands of reactive CSPM findings, stop the bleeding where possible.

**Disclaimer:** Don't run this in production / do so at your own risk! :)

**Current State Coverage:** Should always be checked. CloudTrail is only sometimes checked.

---

## Product Capabilities

### 1. Configuration Management
- Hybrid YAML + CLI configuration with CLI override capability
- Pydantic-based validation with strict type checking
- Optional security_analysis_account_id for running from management account vs running directly from security analysis account

### 2. AWS Multi-Account Integration
- Secure cross-account access via IAM role assumption
- AWS Organizations integration for account discovery and metadata
- Tag-based account information extraction (environment/owner default to "unknown", name defaults to account ID)
- Session management with proper credential handling

### 3. SCP Compliance Analysis
- **EC2 IMDS v1 Check:** Multi-region scanning with exemption tag support
- **IAM User Creation Check:** Automatic allowlist generation from discovered users
- Modular check framework with self-registration pattern
- JSON result generation with detailed compliance metrics

### 4. RCP Compliance Analysis
- **Third-Party AssumeRole Check:** IAM trust policy analysis across organization
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated)
- Organization baseline comparison for external account detection

### 5. Policy Placement Intelligence
- Organization structure analysis for optimal policy deployment levels
- Greatest common denominator logic for safe SCP deployment
- Union strategy for RCP third-party account allowlists
- Automatic OU and root-level recommendations when safe

### 6. Terraform Auto-Generation
- AWS Organizations data source generation with validation
- SCP Terraform modules with automatic allowlist integration
- RCP Terraform modules with third-party account allowlists
- Multi-level deployment (root, OU, account) based on compliance analysis

---

## Technical Architecture

### Module Organization

```
headroom/
├── __init__.py
├── __main__.py              # Entry point
├── config.py                # Configuration models
├── constants.py             # Check names and type mappings
├── main.py                  # Orchestration
├── usage.py                 # CLI parsing
├── analysis.py              # Check execution
├── parse_results.py         # SCP placement analysis
├── write_results.py         # Result file management
├── output.py                # User-facing output
├── types.py                 # Shared data models
├── aws/
│   ├── ec2.py              # EC2 analysis
│   ├── iam/
│   │   ├── roles.py        # Trust policy analysis (RCP)
│   │   └── users.py        # User enumeration (SCP)
│   ├── organization.py     # Organizations API integration
│   └── sessions.py         # Session management
├── checks/
│   ├── base.py             # BaseCheck abstract class
│   ├── registry.py         # Check registration system
│   ├── scps/
│   │   ├── deny_imds_v1_ec2.py
│   │   └── deny_iam_user_creation.py
│   └── rcps/
│       └── check_third_party_assumerole.py
├── placement/
│   └── hierarchy.py        # OU hierarchy analysis
└── terraform/
    ├── generate_org_info.py
    ├── generate_scps.py
    ├── generate_rcps.py
    └── utils.py
```

### Data Flow

1. **Configuration:** Load YAML → merge with CLI args → validate with Pydantic
2. **AWS Setup:** Assume security analysis role (if specified) → assume OrgAndAccountInfoReader in management account
3. **Account Discovery:** Query Organizations API → extract account metadata with tags → filter management account
4. **Analysis:** For each account:
   - Check if all results already exist (skip if so)
   - Assume Headroom role in target account
   - Run all registered SCP checks
   - Run all registered RCP checks
   - Write JSON results to `{results_dir}/{check_type}/{check_name}/`
5. **Placement:** Parse all result files → analyze org structure → determine policy levels
6. **Generation:** Generate `grab_org_info.tf` + SCP Terraform files + RCP Terraform files

---

## Data Models

### Core Configuration Models

```python
# config.py

DEFAULT_RESULTS_DIR = "test_environment/headroom_results"
DEFAULT_SCPS_DIR = "test_environment/scps"
DEFAULT_RCPS_DIR = "test_environment/rcps"

class AccountTagLayout(BaseModel):
    environment: str  # Tag key for environment (e.g., "Environment")
    name: str         # Tag key for account name (e.g., "Name")
    owner: str        # Tag key for owner (e.g., "Owner")

class HeadroomConfig(BaseModel):
    management_account_id: Optional[str]                 # Required for org access
    security_analysis_account_id: Optional[str]          # Optional, for cross-account execution
    exclude_account_ids: bool = False                    # Redact IDs in results
    use_account_name_from_tags: bool                     # Use tag vs AWS account name
    account_tag_layout: AccountTagLayout
    results_dir: str = DEFAULT_RESULTS_DIR
    scps_dir: str = DEFAULT_SCPS_DIR
    rcps_dir: str = DEFAULT_RCPS_DIR
```

### Organization Structure Models

```python
# types.py

@dataclass
class OrganizationalUnit:
    ou_id: str
    name: str
    parent_ou_id: Optional[str]       # None for root
    child_ous: List[str]              # Direct child OU IDs
    accounts: List[str]               # Direct child account IDs

@dataclass
class AccountOrgPlacement:
    account_id: str
    account_name: str
    parent_ou_id: str                 # Direct parent OU
    ou_path: List[str]                # Full path from root to account

@dataclass
class OrganizationHierarchy:
    root_id: str
    organizational_units: Dict[str, OrganizationalUnit]   # Keyed by OU ID
    accounts: Dict[str, AccountOrgPlacement]              # Keyed by account ID
```

### Check Result Models

```python
# types.py

@dataclass
class CheckResult:
    """Base class for all check results."""
    account_id: str
    account_name: str
    check_name: str

@dataclass
class SCPCheckResult(CheckResult):
    """SCP check result with compliance metrics."""
    violations: int
    exemptions: int
    compliant: int
    compliance_percentage: float
    total_instances: Optional[int] = None          # For instance-based checks
    iam_user_arns: Optional[List[str]] = None      # For IAM user checks

@dataclass
class RCPCheckResult(CheckResult):
    """RCP check result for third-party access control."""
    third_party_account_ids: List[str]
    has_wildcard: bool
    total_roles_analyzed: Optional[int] = None
```

### Placement Recommendation Models

```python
# types.py

@dataclass
class SCPPlacementRecommendations:
    check_name: str
    recommended_level: str                        # "root", "ou", or "account"
    target_ou_id: Optional[str]                   # None for root/account level
    affected_accounts: List[str]                  # Account IDs covered
    compliance_percentage: float
    reasoning: str
    allowed_iam_user_arns: Optional[List[str]] = None  # For IAM user checks

@dataclass
class RCPPlacementRecommendations:
    check_name: str
    recommended_level: str                        # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    third_party_account_ids: List[str]            # Unioned third-party IDs
    reasoning: str

@dataclass
class RCPParseResult:
    """Result from parsing RCP check files."""
    account_third_party_map: Dict[str, Set[str]]  # account_id -> third_party_ids
    accounts_with_wildcards: Set[str]             # Accounts to exclude
```

### Check-Specific Data Models

```python
# aws/ec2.py
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool                # True if IMDSv1 enabled (violation)
    exemption_tag_present: bool         # True if ExemptFromIMDSv2 tag exists

# aws/iam/users.py
@dataclass
class IamUserAnalysis:
    user_name: str
    user_arn: str
    path: str                           # IAM path (e.g., "/", "/admins/")

# aws/iam/roles.py
@dataclass
class TrustPolicyAnalysis:
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]   # Non-org account IDs
    has_wildcard_principal: bool        # True if Principal: "*"
```

---

## Configuration System

### Configuration Schema

```yaml
management_account_id: string                # Required for org access
security_analysis_account_id: string         # Optional (omit if running from security account)
exclude_account_ids: boolean                 # Redact account IDs in results
use_account_name_from_tags: boolean          # Use tag for name vs AWS account name
results_dir: string                          # Default: test_environment/headroom_results
scps_dir: string                             # Default: test_environment/scps
rcps_dir: string                             # Default: test_environment/rcps
account_tag_layout:
  environment: string                        # Optional tag, fallback: "unknown"
  name: string                               # Optional tag, used when use_account_name_from_tags=true
  owner: string                              # Optional tag, fallback: "unknown"
```

### Configuration Loading Logic

1. Parse CLI arguments (required `--config` flag)
2. Load YAML file with graceful degradation to empty dict
3. Merge YAML with CLI overrides (CLI takes precedence)
4. Validate with Pydantic (raises ValueError/TypeError on failure)
5. Handle missing fields with defaults from config.py constants

### CLI Arguments

```bash
--config CONFIG                            # Required: path to YAML
--results-dir DIR                          # Optional: override results_dir
--scps-dir DIR                             # Optional: override scps_dir
--rcps-dir DIR                             # Optional: override rcps_dir
--management-account-id ID                 # Optional: override management_account_id
--security-analysis-account-id ID          # Optional: override security_analysis_account_id
--exclude-account-ids                      # Optional: flag to redact IDs
```

---

## Check Framework

### BaseCheck Abstract Class

     ```python
# checks/base.py

class BaseCheck(ABC, Generic[T]):
    """
    Template Method pattern for all checks.
    
    Type parameter T: the analysis result type (e.g., DenyImdsV1Ec2)
    """
    
    # Set by @register_check decorator
    CHECK_NAME: str
    CHECK_TYPE: str
    
    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        exclude_account_ids: bool = False,
        **kwargs: Any,  # RCP checks use org_account_ids
    ) -> None:
        """Initialize check with common parameters."""
        
    @abstractmethod
    def analyze(self, session: boto3.Session) -> List[T]:
        """
        Perform AWS API calls to gather data.
        
        Returns: List of raw analysis results
        """
        
    @abstractmethod
    def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
        """
        Categorize single result into violation/exemption/compliant.
        
        Returns: ("violation"|"exemption"|"compliant", result_dict)
        """
        
    @abstractmethod
    def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """
        Build check-specific summary fields.
        
        Returns: Dict with fields like total_instances, compliance_percentage
        """
        
    def execute(self, session: boto3.Session) -> None:
        """
        Template method orchestrating check execution:
        1. Call analyze() to get raw results
        2. Categorize each result via categorize_result()
        3. Build summary with base fields + check-specific fields
        4. Write JSON results to disk
        5. Print completion message
    """
```

### CategorizedCheckResult

```python
@dataclass
class CategorizedCheckResult:
    violations: List[Dict[str, Any]]      # Non-compliant resources
    exemptions: List[Dict[str, Any]]      # Exempted resources
    compliant: List[Dict[str, Any]]       # Compliant resources
    summary: Dict[str, Any]               # Summary metadata
```

### Registry Pattern

```python
# checks/registry.py

_CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {}

def register_check(check_type: str, check_name: str) -> Callable:
    """
    Decorator to register check class.
    
    Usage:
        @register_check("scps", "deny_imds_v1_ec2")
        class DenyImdsV1Ec2Check(BaseCheck[DenyImdsV1Ec2]):
            ...
    
    Side effects:
    - Stores class in _CHECK_REGISTRY[check_name]
    - Sets class attributes CHECK_NAME and CHECK_TYPE
    - Calls register_check_type() to update constants.CHECK_TYPE_MAP
    """

def get_check_class(check_name: str) -> Type[BaseCheck]:
    """Retrieve check class by name (raises ValueError if unknown)."""

def get_all_check_classes(check_type: Optional[str] = None) -> List[Type[BaseCheck]]:
    """Get all registered checks, optionally filtered by type ("scps" or "rcps")."""

def get_check_names(check_type: str) -> List[str]:
    """Get all check names for a given type."""
```

### Check Discovery

```python
# checks/__init__.py

# These imports trigger decorator execution and register checks
from .rcps import check_third_party_assumerole  # noqa: F401
from .scps import deny_imds_v1_ec2              # noqa: F401
from .scps import deny_iam_user_creation        # noqa: F401
```

**Critical:** Without these imports, decorators never execute and checks won't register.

---

## SCP Checks

### Deny IMDSv1 (EC2)

**Purpose:** Identify EC2 instances with IMDSv1 enabled (violation) or exempted via tag.

**Data Model:**
```python
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool                # True = violation
    exemption_tag_present: bool         # True = exempted
```

**Analysis Function:**
```python
# aws/ec2.py
def get_imds_v1_ec2_analysis(session: boto3.Session) -> List[DenyImdsV1Ec2]:
    """
    Scan all regions for EC2 instances.
    
    Algorithm:
    1. Describe all regions with describe_regions()
    2. For each region, create EC2 client
    3. Use paginator to describe_instances (handles pagination)
    4. Filter out terminated instances
    5. Check HttpTokens: "optional" = IMDSv1 allowed
    6. Check for ExemptFromIMDSv2 tag (case-insensitive)
    7. Return DenyImdsV1Ec2 for each instance
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: DenyImdsV1Ec2) -> tuple[str, Dict[str, Any]]:
    result_dict = asdict(result)
    
    if result.imdsv1_allowed and result.exemption_tag_present:
        return ("exemption", result_dict)
    elif result.imdsv1_allowed:
        return ("violation", result_dict)
    else:
        return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    total = len(violations) + len(exemptions) + len(compliant)
    compliant_count = len(exemptions) + len(compliant)
    compliance_pct = (compliant_count / total * 100) if total > 0 else 100.0
    
    return {
        "total_instances": total,
        "violations": len(violations),
        "exemptions": len(exemptions),
        "compliant": len(compliant),
        "compliance_percentage": round(compliance_pct, 2)
    }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_imds_v1_ec2",
    "total_instances": 0,
    "violations": 0,
    "exemptions": 0,
    "compliant": 0,
    "compliance_percentage": 100.0
  },
  "violations": [
    {"region": "us-east-1", "instance_id": "i-xxx", "imdsv1_allowed": true, "exemption_tag_present": false}
  ],
  "exemptions": [],
  "compliant_instances": []
}
```

### Deny IAM User Creation

**Purpose:** Discover all IAM users and generate allowlists to prevent creation of unauthorized users.

**Data Model:**
```python
@dataclass
class IamUserAnalysis:
    user_name: str
    user_arn: str
    path: str
```

**Analysis Function:**
```python
# aws/iam/users.py
def get_iam_users_analysis(session: boto3.Session) -> List[IamUserAnalysis]:
    """
    List all IAM users in account.
    
    Algorithm:
    1. Create IAM client
    2. Use paginator for list_users() (handles pagination)
    3. Extract UserName, Arn, Path for each user
    4. Return IamUserAnalysis for all users
    
    Note: No filtering - pure enumeration for allowlist generation
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: IamUserAnalysis) -> tuple[str, Dict[str, Any]]:
    result_dict = {
        "user_name": result.user_name,
        "user_arn": result.user_arn,
        "path": result.path,
    }
    # All users marked as "compliant" (we're listing for allowlist)
    return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    return {
        "total_users": len(check_result.compliant),
        "users": [user["user_arn"] for user in check_result.compliant]
    }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_iam_user_creation",
    "total_users": 0,
    "users": [
      "arn:aws:iam::111111111111:user/terraform-user"
    ]
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {"user_name": "terraform-user", "user_arn": "arn:aws:iam::111111111111:user/terraform-user", "path": "/"}
  ]
}
```

---

## RCP Checks

### Third-Party AssumeRole

**Purpose:** Analyze IAM role trust policies to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
@dataclass
class TrustPolicyAnalysis:
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]    # External to organization
    has_wildcard_principal: bool         # True if Principal: "*"
```

**Analysis Function:**
```python
# aws/iam/roles.py

ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service", "Federated"}

def analyze_iam_roles_trust_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[TrustPolicyAnalysis]:
    """
    Analyze all IAM role trust policies for third-party access.
    
    Algorithm:
    1. List all roles with paginator (list_roles)
    2. For each role, get AssumeRolePolicyDocument
    3. Parse JSON policy document
    4. For each Statement, check if Action is sts:AssumeRole
    5. Extract account IDs from Principal field
    6. Detect wildcard principals
    7. Filter to third-party accounts (not in org_account_ids)
    8. Return TrustPolicyAnalysis for roles with third-party or wildcards
    
    Raises:
    - UnknownPrincipalTypeError: if principal type not in ALLOWED_PRINCIPAL_TYPES
    - InvalidFederatedPrincipalError: if Federated principal uses sts:AssumeRole
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:iam::123456789012:..." or "123456789012"
    - List: recursively process each item
    - Dict: process AWS/Service/Federated keys
    - Mixed: {"AWS": [...], "Service": "..."}
    
    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Validate but skip (e.g., lambda.amazonaws.com)
    - Federated: Validate action is not sts:AssumeRole, skip
    - Unknown: Raise UnknownPrincipalTypeError
    
    Validation:
    - Federated principals must use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity
    - All principal types must be in ALLOWED_PRINCIPAL_TYPES
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""
```

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when principal type is not in ALLOWED_PRINCIPAL_TYPES."""

class InvalidFederatedPrincipalError(Exception):
    """Raised when Federated principal uses sts:AssumeRole."""
```

**Check Implementation:**
```python
# checks/rcps/check_third_party_assumerole.py

class ThirdPartyAssumeRoleCheck(BaseCheck[TrustPolicyAnalysis]):
    def __init__(self, org_account_ids: Set[str], **kwargs):
        super().__init__(**kwargs)
        self.org_account_ids = org_account_ids
    
    def analyze(self, session):
        return analyze_iam_roles_trust_policies(session, self.org_account_ids)
    
    def categorize_result(self, result):
        # Roles with wildcards are "violations"
        # Roles with third-party access are "compliant" (expected patterns)
        if result.has_wildcard_principal:
            return ("violation", ...)
        else:
            return ("compliant", ...)
    
    def build_summary_fields(self, check_result):
        # Aggregate unique third-party account IDs
        # Count roles with wildcards as violations
        return {
            "total_roles_analyzed": total,
            "roles_third_parties_can_access": len(third_party_roles),
            "roles_with_wildcards": len(violations),
            "unique_third_party_accounts": list(unique_third_parties),
            "violations": len(violations)
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "third_party_assumerole",
    "total_roles_analyzed": 0,
    "roles_third_parties_can_access": 0,
    "roles_with_wildcards": 0,
    "unique_third_party_accounts": [],
    "violations": 0
  },
  "violations": [
    {"role_name": "WildcardRole", "role_arn": "arn:..."}
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "role_name": "CrossAccountRole",
      "role_arn": "arn:...",
      "third_party_account_ids": ["999999999999"]
    }
  ]
}
```

---

## Results Processing

### Common Parsing Patterns

Both SCP and RCP parsers share these patterns:

**Directory Structure:**
```
{results_dir}/{check_type}/{check_name}/*.json

Examples:
- {results_dir}/scps/deny_imds_v1_ec2/account-name_111111111111.json
- {results_dir}/rcps/third_party_assumerole/account-name_111111111111.json
```

**JSON Parsing:**
```python
try:
    with open(result_file, 'r') as f:
        data = json.load(f)
    # ... processing ...
except (json.JSONDecodeError, KeyError) as e:
    raise RuntimeError(f"Failed to parse result file {result_file}: {e}")
```

**Summary Extraction:**
```python
summary = data.get("summary", {})
account_id = summary.get("account_id", "")
account_name = summary.get("account_name", "")
```

**Account ID Fallback:**
```python
# When account_id missing (exclude_account_ids=True)
if not account_id:
    account_id = lookup_account_id_by_name(
        account_name,
        organization_hierarchy,
        context="result file"
    )
```

**Shared Utility Function:**
```python
# aws/organization.py
def lookup_account_id_by_name(
    account_name: str,
    organization_hierarchy: OrganizationHierarchy,
    context: str = "result file"
) -> str:
    """
    Look up account ID by name in organization hierarchy.
    
    Raises: RuntimeError if account not found
    """
    for acc_id, acc_info in organization_hierarchy.accounts.items():
        if acc_info.account_name == account_name:
            logger.info(f"Looked up account_id {acc_id} for '{account_name}'")
            return acc_id
    raise RuntimeError(f"Account '{account_name}' from {context} not found")
```

### SCP Results Parsing

```python
# parse_results.py

def parse_scp_result_files(
    results_dir: str,
    exclude_rcp_checks: bool = True
) -> List[SCPCheckResult]:
    """
    Parse all SCP check result files.
    
    Algorithm:
    1. Look for {results_dir}/scps/ subdirectory
    2. Iterate through all check directories in scps/
    3. Skip non-directory files
    4. If exclude_rcp_checks, skip checks in RCP_CHECK_NAMES
    5. For each JSON file in check directory:
       - Parse JSON
       - Extract summary fields
       - Handle missing account_id via lookup
       - Create SCPCheckResult
    6. Return flat list of all results
    
    Returns: List[SCPCheckResult]
    """
```

**Extracted Fields:**
```python
SCPCheckResult(
    account_id=account_id,
    account_name=summary.get("account_name", ""),
    check_name=summary.get("check", check_name),
    violations=summary.get("violations", 0),
    exemptions=summary.get("exemptions", 0),
    compliant=summary.get("compliant", 0),
    total_instances=summary.get("total_instances", 0),
    compliance_percentage=summary.get("compliance_percentage", 0.0),
    iam_user_arns=summary.get("users", None)  # For deny_iam_user_creation
)
```

### RCP Results Parsing

```python
# terraform/generate_rcps.py

def parse_rcp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> RCPParseResult:
    """
    Parse RCP check result files for third-party AssumeRole check.
    
    Algorithm:
    1. Get check directory using get_results_dir(THIRD_PARTY_ASSUMEROLE, results_dir)
    2. Verify directory exists (raise RuntimeError if not)
    3. For each JSON file:
       - Parse JSON
       - Extract summary
       - Get unique_third_party_accounts and roles_with_wildcards
       - Handle missing account_id via lookup
       - If roles_with_wildcards > 0:
         - Add to accounts_with_wildcards set
         - Skip (don't add to account_third_party_map)
       - Else:
         - Add account_id -> set(third_party_accounts) to map
    4. Return RCPParseResult
    
    Returns: RCPParseResult(account_third_party_map, accounts_with_wildcards)
    
    Note: Accounts with wildcards are excluded from account_third_party_map
    to prevent unsafe RCP generation
    """
```

---

## Placement Logic

### SCP Placement Algorithm

```python
# parse_results.py

def determine_scp_placement(
    results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Determine optimal SCP placement levels using zero-violation principle.
    
    Algorithm:
    1. Group results by check_name
    2. For each check:
       a. Filter to 100% compliant accounts (compliance_percentage == 100.0)
       b. If NO compliant accounts: return empty list for this check
       c. Try root level:
          - If ALL org accounts are compliant: recommend root
       d. Try OU level:
          - For each OU, check if ALL accounts in OU are compliant
          - Recommend OU-level for OUs where all accounts compliant
       e. Account level:
          - For remaining compliant accounts, recommend account-level
       f. For deny_iam_user_creation check:
          - Union all IAM user ARNs from affected accounts
          - Un-redact ARNs (replace "REDACTED" with actual account_id)
          - Attach to allowed_iam_user_arns field
    3. Return List[SCPPlacementRecommendations]
    
    Safety Principle: Only deploy at levels with 100% compliance (zero violations)
    """
```

**Un-Redaction Logic for IAM User ARNs:**
```python
# When exclude_account_ids=True, ARNs contain "REDACTED"
# Example: "arn:aws:iam::REDACTED:user/terraform-user"

# Un-redaction algorithm:
for arn in iam_user_arns:
    if "REDACTED" in arn:
        # Replace REDACTED with actual account_id
        un_redacted_arn = arn.replace("REDACTED", account_id)
    else:
        un_redacted_arn = arn
```

**Union Logic for IAM User ARNs:**
```python
# For root/OU level SCPs, union all IAM user ARNs from affected accounts

all_user_arns = set()
for account_id in affected_accounts:
    account_result = get_result_for_account(account_id, check_name)
    if account_result.iam_user_arns:
        # Un-redact each ARN
        for arn in account_result.iam_user_arns:
            un_redacted = un_redact_arn(arn, account_id)
            all_user_arns.add(un_redacted)

# Sort for consistent ordering
allowed_iam_user_arns = sorted(all_user_arns)
```

### RCP Placement Algorithm

```python
# terraform/generate_rcps.py

def determine_rcp_placement(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Determine optimal RCP placement levels using union strategy.
    
    Algorithm:
    1. Try root level:
       - Check: NO accounts have wildcards (len(accounts_with_wildcards) == 0)
       - If safe: union ALL third-party IDs from all accounts
       - Affected accounts: ALL accounts in organization
       - Return single root-level recommendation
    
    2. Try OU level (if root not safe):
       - For each OU:
         - Get all accounts in OU
         - Check: NO accounts in OU have wildcards
         - If safe: union third-party IDs from accounts in OU
         - Affected accounts: accounts in OU (excluding wildcard accounts)
         - Single-account OUs: Still get OU-level recommendations
    
    3. Account level (for accounts with wildcards):
       - Accounts with wildcards are EXCLUDED from all recommendations
       - Static analysis cannot determine safe principals
    
    Union Strategy Rationale:
    - Third-party IDs can be safely combined into single allowlist
    - Account A trusts [111], Account B trusts [222] → allowlist [111, 222]
    - More permissive than requiring identical sets
    - Still safe because RCPs use allowlists (approved principals)
    
    Critical Safety Rules:
    - Root RCP ONLY if NO accounts have wildcards
    - OU RCP ONLY if NO accounts in that OU have wildcards
    - Affected accounts includes ALL accounts at that level (not just eligible ones)
    
    Returns: List[RCPPlacementRecommendations]
    """
```

---

## Terraform Generation

### Organization Info Generation

```python
# terraform/generate_org_info.py

def generate_terraform_org_info(
    session: boto3.Session,
    output_path: str
) -> None:
    """
    Generate grab_org_info.tf with AWS Organizations data sources.
    
    Algorithm:
    1. Call analyze_organization_structure() to get OrganizationHierarchy
    2. Generate data sources:
       - aws_organizations_organization for root
       - aws_organizations_organizational_units for each level
       - aws_organizations_organizational_unit_child_accounts for each OU
    3. Generate locals with validation:
       - validation_check_root: ensure exactly 1 root
       - root_ou_id: data.aws_organizations_organization.org.roots[0].id
       - For each OU:
         - validation_check_{ou_name}_ou: ensure exactly 1 match
         - top_level_{ou_name}_ou_id: filtered OU ID
       - For each account:
         - validation_check_{account_name}_account: ensure exactly 1 match
         - {account_name}_account_id: filtered account ID
    4. Write to {scps_dir}/grab_org_info.tf
    
    Validation Pattern:
    validation_check = (length(filter_result) == 1) ? 
        "All good. This is a no-op." : 
        error("[Error] Expected exactly 1 X, found ${length(filter_result)}")
    """
```

**Generated Terraform Structure:**
```hcl
# Auto-generated by Headroom

data "aws_organizations_organization" "org" {}

data "aws_organizations_organizational_units" "root_ou" {
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

data "aws_organizations_organizational_unit_child_accounts" "production_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Production"
  ][0]
}

locals {
  # Validation
  validation_check_root = (length(data.aws_organizations_organization.org.roots) == 1) ? 
    "All good." : error("[Error] Expected 1 root, found ${length(...)}")
  
  # Root
  root_ou_id = data.aws_organizations_organization.org.roots[0].id
  
  # OUs
  validation_check_production_ou = (length([for ou in ... if ou.name == "Production"]) == 1) ? 
    "All good." : error("[Error] Expected 1 Production OU")
  
  top_level_production_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Production"
  ][0]
  
  # Accounts
  validation_check_prod_account_account = ...
  
  prod_account_account_id = [
    for account in data...production_accounts.accounts :
    account.id if account.name == "prod-account"
  ][0]
}
```

### SCP Terraform Generation

     ```python
# terraform/generate_scps.py

def generate_scp_terraform(
    recommendations: List[SCPPlacementRecommendations],
         organization_hierarchy: OrganizationHierarchy,
    output_dir: str
) -> None:
    """
    Generate SCP Terraform files based on placement recommendations.
    
    Algorithm:
    1. Filter to 100% compliant recommendations only
    2. Group by recommended_level (root/ou/account)
    3. For each group, generate Terraform file:
       - Root: root_scps.tf
       - OU: {ou_name}_ou_scps.tf
       - Account: {account_name}_scps.tf
    4. For each file:
       - Generate module call with target_id reference
       - Add boolean flags for each check (organized by category)
       - For deny_iam_user_creation:
         - Transform ARNs: replace account IDs with ${local.X_account_id}
         - Add allowed_iam_users list
    5. Write to {scps_dir}/
    
    ARN Transformation Algorithm:
    1. Parse ARN: arn:aws:iam::ACCOUNT_ID:user/PATH/NAME
    2. Look up account by ID in organization_hierarchy
    3. Generate safe variable name: account_name_account_id
    4. Replace: arn:aws:iam::${local.account_name_account_id}:user/PATH/NAME
    """
```

**Generated SCP Terraform Structure:**
```hcl
# Auto-generated SCP Terraform for root
# Generated by Headroom

module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  # EC2
  deny_imds_v1_ec2 = true

  # IAM
  deny_iam_user_creation = true
  allowed_iam_users = [
    "arn:aws:iam::${local.fort_knox_account_id}:user/terraform-user",
    "arn:aws:iam::${local.security_tooling_account_id}:user/cicd-user"
  ]
}
```

**SCP Module Structure:**
```hcl
# modules/scps/variables.tf

variable "deny_imds_v1_ec2" {
  type = bool
}

variable "deny_iam_user_creation" {
  type = bool
}

variable "allowed_iam_users" {
  type        = list(string)
  default     = []
  description = "IAM user ARNs allowed to be created"
}
```

```hcl
# modules/scps/locals.tf

locals {
  statements = [
    {
      include = var.deny_imds_v1_ec2,
      statement = {
        Action = "ec2:RunInstances"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      }
    },
    {
      include = var.deny_iam_user_creation,
      statement = {
        Action = "iam:CreateUser"
        NotResource = var.allowed_iam_users
      }
    }
  ]
  
  # Filter to included statements
  enabled_statements = [for s in local.statements : s.statement if s.include]
}
```

### RCP Terraform Generation

```python
# terraform/generate_rcps.py

def generate_rcp_terraform(
    recommendations: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_dir: str
) -> None:
    """
    Generate RCP Terraform files based on placement recommendations.
    
    Algorithm:
    1. Group by recommended_level (root/ou/account)
    2. For each group, generate Terraform file:
       - Root: root_rcps.tf
       - OU: {ou_name}_ou_rcps.tf
       - Account: {account_name}_rcps.tf
    3. For each file:
       - Generate module call with target_id reference
       - Add third_party_assumerole_account_ids_allowlist
       - Third-party IDs are already unioned by placement logic
    4. Write to {rcps_dir}/
    """
```

**Generated RCP Terraform Structure:**
```hcl
# Auto-generated RCP Terraform for root
# Generated by Headroom

module "rcps_root" {
  source = "../modules/rcps"
  target_id = local.root_ou_id

  third_party_assumerole_account_ids_allowlist = [
    "999999999999",
    "888888888888"
  ]
}
```

**RCP Module Structure:**
```hcl
# modules/rcps/variables.tf

variable "third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Third-party account IDs approved for AssumeRole"
}
```

```hcl
# modules/rcps/locals.tf

locals {
  rcp_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnforceOrgIdentities"
        Effect = "Deny"
        Action = "sts:AssumeRole"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
          }
          StringNotEqualsIfExists = {
            "aws:PrincipalAccount" = var.third_party_assumerole_account_ids_allowlist
          }
          StringNotEquals = {
            "aws:PrincipalType" = "Service"
          }
          Bool = {
            "dp:exclude:identity" = false
          }
        }
      }
    ]
  }
}
```

**RCP Policy Logic:**
Denies `sts:AssumeRole` EXCEPT:
1. Principals from organization (`aws:PrincipalOrgID`)
2. Principals from allowlisted third-party accounts (`aws:PrincipalAccount`)
3. AWS service principals (`aws:PrincipalType = "Service"`)
4. Resources tagged with `dp:exclude:identity: true`

---

## AWS Integration

### Session Management

```python
# aws/sessions.py

def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[boto3.Session] = None
) -> boto3.Session:
    """
    Assume IAM role and return session with temporary credentials.
    
    Algorithm:
    1. Create STS client from base_session (or new session if None)
    2. Call sts.assume_role(RoleArn, RoleSessionName)
    3. Extract Credentials from response
    4. Create new boto3.Session with temporary credentials
    5. Return new session
    
    Raises: ClientError if role assumption fails
    """
```

**Role Assumption Pattern:**
```python
# analysis.py

def get_security_analysis_session(config: HeadroomConfig) -> boto3.Session:
    """
    Get session for security analysis account.
    
    If security_analysis_account_id is specified:
        Assume OrganizationAccountAccessRole in that account
    Else:
        Return default boto3.Session() (running from security account)
    """

def get_management_account_session(
    config: HeadroomConfig,
    session: boto3.Session
) -> boto3.Session:
    """
    Assume OrgAndAccountInfoReader in management account.
    
    Role ARN: arn:aws:iam::{management_account_id}:role/OrgAndAccountInfoReader
    Session name: HeadroomManagementAccountSession
    """

def get_headroom_session(
    account_id: str,
    config: HeadroomConfig
) -> boto3.Session:
    """
    Assume Headroom role in target account for analysis.
    
    Role ARN: arn:aws:iam::{account_id}:role/Headroom
    Session name: Headroom-{account_id}
    Base session: security_analysis_session
    """
```

### Organization Integration

```python
# aws/organization.py

def analyze_organization_structure(
    session: boto3.Session
) -> OrganizationHierarchy:
    """
    Analyze complete AWS Organizations structure.
    
    Algorithm:
    1. Get organization via describe_organization()
    2. Extract root_id from roots[0].id
    3. Recursively list all OUs via list_organizational_units_for_parent()
    4. For each OU:
       - Get child OUs (recursive)
       - Get child accounts via list_accounts_for_parent()
       - Build OrganizationalUnit object
    5. Build account placement information:
       - Determine parent_ou_id
       - Calculate ou_path (root to account)
    6. Return OrganizationHierarchy
    """

def get_account_info(
    session: boto3.Session,
    config: HeadroomConfig
) -> List[AccountInfo]:
    """
    Get account information with tag-based metadata.
    
    Algorithm:
    1. List all accounts via list_accounts()
    2. Filter out management account
    3. For each account:
       - Get tags via list_tags_for_resource()
       - Extract environment (default "unknown")
       - Extract owner (default "unknown")
       - Extract name:
         - If use_account_name_from_tags: use tag (default account_id)
         - Else: use account.Name from API (default account_id)
    4. Return List[AccountInfo]
    """

@dataclass
class AccountInfo:
    account_id: str
    environment: str       # From tags, default "unknown"
    name: str             # From tags/API, default account_id
    owner: str            # From tags, default "unknown"
```

### EC2 Integration

```python
# aws/ec2.py

def get_imds_v1_ec2_analysis(
    session: boto3.Session
) -> List[DenyImdsV1Ec2]:
    """
    Scan all regions for EC2 instances with IMDSv1.
    
    Algorithm:
    1. Get all regions via ec2.describe_regions()
    2. For each region:
       a. Create regional EC2 client
       b. Use paginator for describe_instances
       c. For each instance:
          - Skip if state is "terminated"
          - Check MetadataOptions.HttpTokens: "optional" = IMDSv1 allowed
          - Check for ExemptFromIMDSv2 tag (case-insensitive)
          - Create DenyImdsV1Ec2 result
    3. Return all results
    
    Pagination: Handles accounts with many instances
    """
```

### IAM Integration

```python
# aws/iam/users.py

def get_iam_users_analysis(
    session: boto3.Session
) -> List[IamUserAnalysis]:
    """
    List all IAM users in account.
    
    Algorithm:
    1. Create IAM client
    2. Use paginator for list_users()
    3. For each user, extract UserName, Arn, Path
    4. Return List[IamUserAnalysis]
    
    Pagination: Handles accounts with many users
    """

# aws/iam/roles.py

def analyze_iam_roles_trust_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[TrustPolicyAnalysis]:
    """
    Analyze IAM role trust policies for third-party access.
    
    (See detailed algorithm in RCP Checks section above)
    
    Pagination: Handles accounts with many roles
    Exception Handling: Specific exceptions only (ClientError, json.JSONDecodeError)
    Fail-Loud: All exceptions logged with context and re-raised
    """
```

---

## Check Execution Flow

### Generic Check Execution

```python
# analysis.py

def run_checks_for_type(
    check_type: str,
    headroom_session: boto3.Session,
    account_info: AccountInfo,
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """
    Execute all checks of a given type for single account.
    
    Algorithm:
    1. Get all check classes for type via registry.get_all_check_classes(check_type)
    2. For each check class:
       a. Get check_name from class.CHECK_NAME
       b. Check if results already exist via results_exist()
       c. If exists: skip
       d. Instantiate check with common parameters + org_account_ids
       e. Call check.execute(headroom_session)
    
    Check instantiation uses **kwargs pattern:
    - SCP checks ignore org_account_ids
    - RCP checks use org_account_ids
    """

def run_checks(
    subaccounts: List[AccountInfo],
    config: HeadroomConfig,
    session: boto3.Session
) -> None:
    """
    Run all checks across all accounts.
    
    Algorithm:
    1. Get all organization account IDs via get_all_organization_account_ids()
    2. For each account:
       a. Check if all SCP results exist via all_check_results_exist("scps", ...)
       b. Check if all RCP results exist via all_check_results_exist("rcps", ...)
       c. If both exist: skip entire account
       d. Get Headroom session via get_headroom_session()
       e. Run SCP checks via run_checks_for_type("scps", ...)
       f. Run RCP checks via run_checks_for_type("rcps", ...)
    """
```

### Results Skip Logic

```python
# write_results.py

def results_exist(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False
) -> bool:
    """
    Check if results file exists for check + account.
    
    Algorithm:
    1. Get expected path via get_results_path()
    2. Check if file exists
    3. Also check alternate format (with/without account_id)
    4. Return True if either format exists
    
    Backward Compatibility: Checks both filename formats
    """

def get_results_path(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False
) -> Path:
    """
    Get path for results file.
    
    Format:
    - With IDs: {results_dir}/{check_type}/{check_name}/{account_name}_{account_id}.json
    - Without IDs: {results_dir}/{check_type}/{check_name}/{account_name}.json
    """

def get_results_dir(
    check_name: str,
    results_base_dir: str
) -> str:
    """
    Get directory for check results.
    
    Format: {results_base_dir}/{check_type}/{check_name}
    
    check_type determined via CHECK_TYPE_MAP from constants.py
    """
```

---

## Constants and Registration

### Constants Module

```python
# constants.py

DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"
DENY_IAM_USER_CREATION = "deny_iam_user_creation"
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"

_CHECK_TYPE_MAP: Dict[str, str] = {}

def register_check_type(check_name: str, check_type: str) -> None:
    """
    Register check type in CHECK_TYPE_MAP.
    
    Called by @register_check decorator.
    """
    _CHECK_TYPE_MAP[check_name] = check_type

def get_check_type_map() -> Dict[str, str]:
    """
    Get CHECK_TYPE_MAP (lazily loads checks if needed).
    
    Ensures all checks are registered before returning map.
    """
    if not _CHECK_TYPE_MAP:
        import headroom.checks  # noqa: F401
    return _CHECK_TYPE_MAP

# Derived sets
SCP_CHECK_NAMES = {DENY_IMDS_V1_EC2, DENY_IAM_USER_CREATION}
RCP_CHECK_NAMES = {THIRD_PARTY_ASSUMEROLE}
```

### Dynamic Registration Flow

1. `checks/__init__.py` imports all check modules
2. Module imports trigger class definitions
3. Class definitions have `@register_check` decorators
4. Decorators execute immediately upon class definition
5. Decorator calls `register_check_type()` to update `_CHECK_TYPE_MAP`
6. Decorator stores class in `_CHECK_REGISTRY`
7. Later, `get_all_check_classes()` retrieves registered checks

---

## Output System

### OutputHandler Class

```python
# output.py

class OutputHandler:
    """Centralized handler for user-facing output."""

    @staticmethod
    def check_completed(
        check_name: str,
        account_identifier: str,
        data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Print check completion with statistics."""
        print(f"✅ Completed {check_name} for account {account_identifier}")
        if data:
        violations = data.get("violations", 0)
        exemptions = data.get("exemptions", 0)
        compliant = data.get("compliant", 0)
        print(f"   Violations: {violations}, Exemptions: {exemptions}, Compliant: {compliant}")

    @staticmethod
    def error(title: str, error: Exception) -> None:
        """Print error message."""
        print(f"\n🚨 {title}:\n{error}\n")

    @staticmethod
    def success(title: str, data: Any) -> None:
        """Print success message."""
        print(f"\n✅ {title}:")
        print(data)

    @staticmethod
    def section_header(title: str) -> None:
        """Print section header."""
        print(f"\n{'='*80}")
        print(f"{title}")
        print(f"{'='*80}\n")
```

---

## Safety Principles

### SCP Deployment Safety

**Zero-Violation Principle:**
- Only deploy SCPs at levels where ALL accounts have 100% compliance
- Ensures policies won't break existing compliant resources
- Accounts with violations receive account-specific recommendations
- Compliance is measured as: (compliant + exemptions) / total * 100

**Placement Hierarchy:**
1. **Root Level:** Recommended when ALL accounts in org are 100% compliant
2. **OU Level:** Recommended when ALL accounts in specific OU are 100% compliant
3. **Account Level:** Recommended for individual compliant accounts

### RCP Deployment Safety

**Wildcard Exclusion:**
- Accounts with wildcard principals (`"Principal": "*"`) are excluded from RCP generation
- Static analysis cannot determine actual assuming principals from wildcards
- Avoids OU-level RCPs if ANY account in OU has wildcards
- Avoids root-level RCPs if ANY account in organization has wildcards

**Union Strategy:**
- Third-party account IDs combined (unioned) at each level
- More permissive than requiring identical sets across accounts
- Still safe because RCPs use allowlists (approved principals)
- Example: Account A trusts [111], Account B trusts [222] → RCP allowlist [111, 222]

**Placement Hierarchy:**
1. **Root Level:** Only if NO accounts have wildcards; unions ALL third-party IDs
2. **OU Level:** Only if NO accounts in OU have wildcards; unions OU third-party IDs
3. **Account Level:** Wildcard accounts excluded; no RCP generated

---

## Quality Standards

### Testing Requirements
- **Coverage:** 100% (370 tests, 1277 statements in headroom/)
- **Test Categories:**
  - Unit tests for individual functions
  - Integration tests for end-to-end workflows
  - Error path testing for exception handling
  - Mock integration for AWS services
- **Test Organization:** Centralized fixtures with `autouse=True` for mock dependencies
- **Test Naming:** Descriptive BDD-style names (`test_<action>_when_<condition>`)

### Type Safety
- **Mypy:** Strict mode with no untyped definitions
- **Type Annotations:** All functions, methods, and variables annotated
- **Generics:** Used in BaseCheck for type-safe check implementations
- **Type Aliases:** `PolicyRecommendation`, `AccountThirdPartyMap`, etc.

### Code Standards
- **Python Version:** 3.13
- **Pre-commit Hooks:**
  - flake8: Linting
  - autopep8: Auto-formatting
  - autoflake: Remove unused imports
  - trailing-whitespace: Remove trailing whitespace
  - end-of-file-fixer: Ensure files end with newline
- **Import Organization:** All imports at top level (no dynamic imports)
- **Function Structure:** No nested functions (minimize indentation)
- **Continuation:** Use parentheses for multi-line statements (no backslash-newline)

### Error Handling
- **Specific Exceptions:** Always catch specific types (ClientError, json.JSONDecodeError, etc.)
- **Fail-Loud Philosophy:** Never silence errors; all exceptions logged with context and re-raised
- **No Generic Catches:** Never `except Exception:` - always specify what can fail
- **No Silent Fallbacks:** Avoid defensive programming that hides configuration/permission issues

---

## Usage

### Installation

```bash
pip install -r requirements.txt
```

### Running Analysis

```bash
# Basic usage
python -m headroom --config config.yaml

# With custom directories
python -m headroom --config config.yaml \
  --results-dir ./my_results \
  --scps-dir ./my_scps \
  --rcps-dir ./my_rcps

# Excluding account IDs from results
python -m headroom --config config.yaml --exclude-account-ids

# Override account IDs via CLI
python -m headroom --config config.yaml \
  --management-account-id 222222222222 \
  --security-analysis-account-id 111111111111
```

### Running Tests

```bash
# Run all tests with coverage
tox

# Run specific test file
pytest tests/test_analysis.py -v

# Type checking
mypy headroom/ tests/
```

---

## IAM Role Requirements

### OrganizationAccountAccessRole
- **Location:** Security analysis account
- **Required:** Only if running from management account
- **Not Required:** If running directly from security analysis account
- **Trusted By:** Management account (or wherever you run Headroom from)
- **Purpose:** Initial role assumption to enter security analysis account

### OrgAndAccountInfoReader
- **Location:** Management account
- **Required:** Always
- **Trusted By:** Security analysis account
- **Permissions:**
  - `organizations:ListAccounts`
  - `organizations:ListTagsForResource`
  - `organizations:DescribeOrganization`
  - `organizations:ListOrganizationalUnitsForParent`
  - `organizations:ListAccountsForParent`
- **Purpose:** Query Organizations API for account discovery and hierarchy analysis

### Headroom
- **Location:** All accounts (including management, excluding security analysis if running from there)
- **Required:** Always
- **Trusted By:** Security analysis account
- **Permissions:**
  - **EC2:** `ec2:DescribeRegions`, `ec2:DescribeInstances`
  - **IAM:** `iam:ListUsers`, `iam:ListRoles`, `iam:GetRole`
- **Purpose:** Execute compliance checks in each account

---

## Result Structure

### Directory Layout

```
{results_dir}/
├── scps/
│   ├── deny_imds_v1_ec2/
│   │   ├── account-name_111111111111.json
│   │   ├── another-account_222222222222.json
│   │   └── ...
│   └── deny_iam_user_creation/
│       ├── account-name_111111111111.json
│       └── ...
└── rcps/
    └── third_party_assumerole/
        ├── account-name_111111111111.json
        └── ...
```

### Result File Format

**Common Structure:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "string",
    ...check-specific fields...
  },
  "violations": [...],
  "exemptions": [...],
  "compliant_instances": [...]
}
```

---

## Future Roadmap

- Additional SCP checks (S3, VPC, CloudFormation, etc.)
- CloudTrail historical analysis for wildcard principal resolution
- OU-based account filtering (filter by OU, environment, owner)
- Metrics-based decision making for policy deployment
- GitHub Actions integration for CI/CD pipelines
- Advanced SCP deployment strategies (phased rollout, canary deployments)

---

*This specification describes the complete Headroom product as of version 5.0.*
