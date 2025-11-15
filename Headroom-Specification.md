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
- **RDS Encryption Check:** Multi-region RDS instance and Aurora cluster encryption analysis
- Modular check framework with self-registration pattern
- JSON result generation with detailed compliance metrics

### 4. RCP Compliance Analysis
- **Third-Party AssumeRole Check:** IAM trust policy analysis across organization
- **AOSS Third-Party Access Check:** OpenSearch Serverless data access policy analysis
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated) for IAM trust policies
- Organization baseline comparison for external account detection
- Multi-region scanning for AOSS collections and indexes
- Action-level tracking for third-party AOSS permissions

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
│   ├── aoss.py             # OpenSearch Serverless analysis
│   ├── ec2.py              # EC2 analysis
│   ├── rds.py              # RDS analysis
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
│   │   ├── deny_iam_user_creation.py
│   │   └── deny_rds_unencrypted.py
│   └── rcps/
│       ├── deny_third_party_assumerole.py
│       └── deny_aoss_third_party_access.py
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

# aws/rds.py
@dataclass
class DenyRdsUnencrypted:
    db_identifier: str
    db_type: str
    region: str
    engine: str
    encrypted: bool
    db_arn: str

# aws/iam/roles.py
@dataclass
class TrustPolicyAnalysis:
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]   # Non-org account IDs
    has_wildcard_principal: bool        # True if Principal: "*"

# aws/aoss.py
@dataclass
class AossResourcePolicyAnalysis:
    resource_name: str                  # Collection or index name
    resource_type: str                  # "collection" or "index"
    resource_arn: str                   # Full ARN of AOSS resource
    policy_name: str                    # Name of the access policy
    third_party_account_ids: Set[str]   # Non-org account IDs
    allowed_actions: List[str]          # AOSS actions allowed for third-parties
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

def _discover_and_register_checks() -> None:
    """
    Automatically discover and import all check modules.

    Walks through scps/ and rcps/ directories and imports all Python files.
    This triggers the @register_check decorator, which registers checks in
    the registry.
    """
    checks_dir = Path(__file__).parent

    for check_type in ["scps", "rcps"]:
        check_type_dir = checks_dir / check_type

        for module_info in pkgutil.iter_modules([str(check_type_dir)]):
            module_name = f"headroom.checks.{check_type}.{module_info.name}"
            importlib.import_module(module_name)


_discover_and_register_checks()
```

**Key Benefits:**
- No manual imports required when adding new checks
- Simply create check file in scps/ or rcps/ directory
- @register_check decorator runs automatically on import
- Zero chance of forgetting to register a new check

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

### Deny RDS Unencrypted

**Purpose:** Identify RDS databases (instances and Aurora clusters) without encryption at rest enabled.

**Data Model:**
```python
@dataclass
class DenyRdsUnencrypted:
    db_identifier: str       # Database identifier (instance or cluster)
    db_type: str             # "instance" or "cluster"
    region: str              # AWS region
    engine: str              # Database engine (mysql, postgres, aurora, etc.)
    encrypted: bool          # True if storage encryption enabled
    db_arn: str              # Full ARN of the database resource
```

**Analysis Function:**
```python
# aws/rds.py
def get_rds_unencrypted_analysis(session: boto3.Session) -> List[DenyRdsUnencrypted]:
    """
    Scan all regions for RDS instances and Aurora clusters.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. Analyze RDS instances via describe_db_instances() (paginated)
       b. Analyze Aurora clusters via describe_db_clusters() (paginated)
       c. Check StorageEncrypted field
       d. Create DenyRdsUnencrypted result for each database
    3. Return all results across all regions
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: DenyRdsUnencrypted) -> tuple[str, Dict[str, Any]]:
    result_dict = {
        "db_identifier": result.db_identifier,
        "db_type": result.db_type,
        "region": result.region,
        "engine": result.engine,
        "encrypted": result.encrypted,
        "db_arn": result.db_arn,
    }

    if not result.encrypted:
        return ("violation", result_dict)
    else:
        return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    total = len(check_result.violations) + len(check_result.compliant)
    compliant_count = len(check_result.compliant)
    compliance_pct = (compliant_count / total * 100) if total > 0 else 100.0

    return {
        "total_databases": total,
        "violations": len(check_result.violations),
        "compliant": len(check_result.compliant),
        "compliance_percentage": round(compliance_pct, 2)
    }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_rds_unencrypted",
    "total_databases": 2,
    "violations": 1,
    "compliant": 1,
    "compliance_percentage": 50.0
  },
  "violations": [
    {
      "db_identifier": "unencrypted-db",
      "db_type": "instance",
      "region": "us-east-1",
      "engine": "mysql",
      "encrypted": false,
      "db_arn": "arn:aws:rds:us-east-1:111111111111:db:unencrypted-db"
    }
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "db_identifier": "encrypted-cluster",
      "db_type": "cluster",
      "region": "us-west-2",
      "engine": "aurora-postgresql",
      "encrypted": true,
      "db_arn": "arn:aws:rds:us-west-2:111111111111:cluster:encrypted-cluster"
    }
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

### AOSS Third-Party Access

**Purpose:** Analyze OpenSearch Serverless data access policies to identify third-party (non-org) account access to collections and indexes.

**Data Model:**
```python
@dataclass
class AossResourcePolicyAnalysis:
    resource_name: str                  # Collection or index name
    resource_type: str                  # \"collection\" or \"index\"
    resource_arn: str                   # Full ARN of AOSS resource
    policy_name: str                    # Name of the access policy
    third_party_account_ids: Set[str]   # External to organization
    allowed_actions: List[str]          # AOSS actions allowed for third-parties
```

**Analysis Function:**
```python
# aws/aoss.py

def analyze_aoss_resource_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[AossResourcePolicyAnalysis]:
    \"\"\"
    Analyze AOSS data access policies for third-party access.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. List all data access policies via list_access_policies()
       b. Get each policy's details via get_access_policy()
       c. Parse policy JSON to extract principals and permissions
       d. Extract account IDs from principals
       e. Filter to third-party accounts (not in org)
       f. Track which actions are allowed for each third-party account
       g. Create AossResourcePolicyAnalysis for each resource
    3. Return all findings across all regions

    Raises:
    - ClientError: If AWS API calls fail
    - ValueError: If ResourceType field is missing from policy rule
    \"\"\"

def _extract_account_ids_from_principals(principals: List[str]) -> Set[str]:
    \"\"\"
    Extract AWS account IDs from AOSS policy principals.

    Handles:
    - ARN format: arn:aws:iam::123456789012:root
    - Plain format: 123456789012

    Returns: Set of 12-digit account IDs
    \"\"\"

def _analyze_access_policy(
    policy_name: str,
    policy_document: str,
    org_account_ids: Set[str],
    region: str,
    account_id: str,
) -> List[AossResourcePolicyAnalysis]:
    \"\"\"
    Analyze a single AOSS access policy for third-party access.

    AOSS Policy Structure:
    - List of policy statements
    - Each statement has Principal list and Rules list
    - Each rule has Resource, ResourceType, and Permission fields

    Resource Parsing:
    - e.g. collection/my-collection --> my-collection
    - e.g. index/my-collection/* --> my-collection

    Fail-Loud: Raises ValueError if ResourceType field is missing
    \"\"\"
```

**Check Implementation:**
```python
# checks/rcps/deny_aoss_third_party_access.py

class DenyAossThirdPartyAccessCheck(BaseCheck[AossResourcePolicyAnalysis]):
    def __init__(self, org_account_ids: Set[str], **kwargs):
        super().__init__(**kwargs)
        self.org_account_ids = org_account_ids
        self.all_third_party_accounts: Set[str] = set()
        self.actions_by_account: Dict[str, Set[str]] = {}

    def analyze(self, session):
        return analyze_aoss_resource_policies(session, self.org_account_ids)

    def categorize_result(self, result):
        # All third-party access categorized as \"compliant\" (allowlisting pattern)
        # Track accounts and actions for summary aggregation
        self.all_third_party_accounts.update(result.third_party_account_ids)
        for account_id in result.third_party_account_ids:
            if account_id not in self.actions_by_account:
                self.actions_by_account[account_id] = set()
            self.actions_by_account[account_id].update(result.allowed_actions)
        return (\"compliant\", ...)

    def build_summary_fields(self, check_result):
        # Convert actions sets to sorted lists for JSON serialization
        return {
            \"total_resources_with_third_party_access\": total,
            \"third_party_account_count\": len(self.all_third_party_accounts),
            \"unique_third_party_accounts\": sorted(self.all_third_party_accounts),
            \"actions_by_third_party_account\": {
                account: sorted(actions)
                for account, actions in self.actions_by_account.items()
            }
        }
```

**Result JSON Schema:**
```json
{
  \"summary\": {
    \"account_name\": \"string\",
    \"account_id\": \"string\",
    \"check\": \"deny_aoss_third_party_access\",
    \"total_resources_with_third_party_access\": 2,
    \"third_party_account_count\": 2,
    \"unique_third_party_accounts\": [\"999888777666\", \"111222333444\"],
    \"actions_by_third_party_account\": {
      \"999888777666\": [\"aoss:ReadDocument\", \"aoss:WriteDocument\"],
      \"111222333444\": [\"aoss:ReadDocument\"]
    }
  },
  \"violations\": [],
  \"exemptions\": [],
  \"resources_with_third_party_access\": [
    {
      \"resource_name\": \"analytics-collection\",
      \"resource_type\": \"collection\",
      \"resource_arn\": \"arn:aws:aoss:us-east-1:111111111111:collection/analytics-collection\",
      \"policy_name\": \"vendor-access-policy\",
      \"third_party_account_ids\": [\"999888777666\"],
      \"allowed_actions\": [\"aoss:ReadDocument\", \"aoss:WriteDocument\"]
    },
    {
      \"resource_name\": \"logs-index\",
      \"resource_type\": \"index\",
      \"resource_arn\": \"arn:aws:aoss:us-west-2:111111111111:index/logs-index\",
      \"policy_name\": \"partner-access-policy\",
      \"third_party_account_ids\": [\"111222333444\"],
      \"allowed_actions\": [\"aoss:ReadDocument\"]
    }
  ]
}
```

**Custom Result Structure:**
The AOSS check uses a custom `_build_results_data()` method to rename \"compliant_instances\" to \"resources_with_third_party_access\" for better clarity.

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

**See:** Test Environment section for complete generated examples in `test_environment/scps/grab_org_info.tf` and `test_environment/rcps/grab_org_info.tf`.

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

**See:** Test Environment section for complete module documentation and usage examples in `test_environment/modules/scps/`.

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

**See:** Test Environment section for complete module documentation and usage examples in `test_environment/modules/rcps/`.

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
DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"
DENY_AOSS_THIRD_PARTY_ACCESS = "deny_aoss_third_party_access"

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
SCP_CHECK_NAMES = {DENY_IMDS_V1_EC2, DENY_IAM_USER_CREATION, DENY_RDS_UNENCRYPTED}
RCP_CHECK_NAMES = {THIRD_PARTY_ASSUMEROLE, DENY_AOSS_THIRD_PARTY_ACCESS}
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
- **Coverage:** 100% (432 tests covering all code paths)
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

## Test Environment & Live Integration

### Overview

The `test_environment/` directory contains a complete, reproducible AWS Organizations environment for live integration testing. Unlike unit tests in `tests/`, this is real infrastructure deployed to AWS that demonstrates Headroom's end-to-end functionality.

**Purpose:**
- Live integration testing against actual AWS resources
- Reproducible demo environment deployable by anyone with an AWS Organizations setup
- Source of truth for example outputs in `test_environment/headroom_results/`
- Documentation-by-example showing complete workflow: infrastructure → analysis → generated Terraform

**Key Characteristics:**
- Real AWS Organizations with multiple accounts and OUs
- Intentionally created violations, exemptions, and compliant resources
- Test scenarios covering all SCP and RCP checks
- Generated Terraform demonstrating placement recommendations

### Directory Structure

```
test_environment/
├── accounts.tf                          # AWS Organizations accounts
├── organizational_units.tf              # OU hierarchy
├── providers.tf                         # Provider configuration with account aliases
├── data.tf                              # Organization data sources
├── variables.tf                         # Input variables
├── terraform.tfvars.example             # Example variable values
├── org_and_account_info_reader.tf       # Management account IAM role
├── headroom_roles.tf                    # Headroom roles in all accounts
├── test_deny_iam_user_creation.tf       # IAM users for testing
├── test_deny_third_party_assumerole.tf  # IAM roles with trust policies
├── account_scps.tf                      # Account-level SCP attachments (if any)
├── modules/
│   ├── headroom_role/                   # Reusable Headroom role module
│   ├── scps/                            # Production SCP module
│   └── rcps/                            # Production RCP module
├── scps/                                # Generated SCP Terraform
│   ├── grab_org_info.tf                 # Auto-generated org data sources
│   ├── root_scps.tf                     # Root-level SCPs
│   ├── {ou_name}_ou_scps.tf            # OU-level SCPs
│   └── {account_name}_scps.tf          # Account-level SCPs
├── rcps/                                # Generated RCP Terraform
│   ├── grab_org_info.tf                 # Auto-generated org data sources
│   ├── {ou_name}_ou_rcps.tf            # OU-level RCPs
│   └── {account_name}_rcps.tf          # Account-level RCPs
├── headroom_results/                    # JSON analysis results
│   ├── scps/
│   │   ├── deny_imds_v1_ec2/
│   │   │   └── {account_name}.json
│   │   ├── deny_iam_user_creation/
│   │   │   └── {account_name}.json
│   │   └── deny_rds_unencrypted/
│   │       └── {account_name}.json
│   └── rcps/
│       ├── deny_aoss_third_party_access/
│       │   └── {account_name}.json
│       └── third_party_assumerole/
│           └── {account_name}.json
├── test_deny_imds_v1_ec2/               # EC2 instances (expensive, separate directory)
│   ├── README.md                        # Cost warnings and usage
│   ├── providers.tf                     # Cross-account providers
│   ├── data.tf                          # AMI data sources
│   └── ec2_instances.tf                 # Test EC2 instances
└── test_deny_rds_unencrypted/           # RDS instances/clusters (expensive, separate directory)
    ├── README.md                        # Cost warnings and usage
    ├── providers.tf                     # Cross-account providers
    ├── data.tf                          # Organization data sources
    └── rds_resources.tf                 # Test RDS databases
```

### Organization Structure

The test environment creates the following AWS Organizations hierarchy:

```
AWS Organization (Management Account: 222222222222)
│
├── Root OU (r-xxxx)
│   │
│   ├── High Value Assets OU (ou-xxxx-xxxxxxxx)
│   │   ├── fort-knox (Production Account)
│   │   │   - Environment: production
│   │   │   - Owner: Cloud Architecture
│   │   │   - Category: high_value_assets
│   │   │   - IAM Users: 1 (github-actions with /service/ path)
│   │   │   - IAM Roles: 1 (WildcardRole - violation)
│   │   │   - EC2 Instances: 0-1 (test-imdsv1-exempt when testing)
│   │   │
│   │   └── security-tooling (Security Analysis Account: 111111111111)
│   │       - Environment: production
│   │       - Owner: Security
│   │       - Category: high_value_assets
│   │       - IAM Users: 1 (cicd-deployer with /automation/ path)
│   │       - IAM Roles: 0 (service principals only)
│   │       - EC2 Instances: 0
│   │       - Note: This is where Headroom executes from
│   │
│   ├── Shared Services OU (ou-xxxx-xxxxxxxx)
│   │   └── shared-foo-bar (Shared Services Account)
│   │       - Environment: production
│   │       - Owner: Traffic
│   │       - Category: shared_services
│   │       - IAM Users: 1 (legacy-developer with / path)
│   │       - IAM Roles: 15 (extensive third-party trust policy testing)
│   │       - EC2 Instances: 0-1 (test-imdsv1-enabled when testing)
│   │       - Third-Party Accounts: 11 unique external accounts
│   │       - Wildcards: 1 role (WildcardRole)
│   │
│   └── Acme Acquisition OU (ou-xxxx-xxxxxxxx)
│       └── acme-co (Acquired Company Account)
│           - Environment: production
│           - Owner: SRE
│           - Category: acme_acquisition
│           - IAM Users: 2 (terraform-user, temp-contractor with /contractors/ path)
│           - IAM Roles: 1 (ThirdPartyVendorA)
│           - EC2 Instances: 0-1 (test-imdsv2-only when testing)
│           - Third-Party Accounts: 1 (CrowdStrike: 749430749651)
```

**Account ID Mapping:**
- Management Account: 222222222222
- Security Tooling: 111111111111
- Fort Knox: (dynamically created)
- Shared Foo Bar: (dynamically created)
- Acme Co: (dynamically created)

### Infrastructure Components

#### Root-Level Terraform Files

**`accounts.tf`**
```hcl
# Creates AWS Organizations accounts with tags
resource "aws_organizations_account" "fort_knox" {
  name      = "fort-knox"
  email     = "user+fort-knox@example.com"
  parent_id = aws_organizations_organizational_unit.high_value_assets.id

  tags = {
    Environment = "production"
    Owner       = "Cloud Architecture"
    Category    = "high_value_assets"
  }
}
# ... similar for security_tooling, shared_foo_bar, acme_co
```

**Purpose:** Creates member accounts and assigns them to OUs. Tags provide metadata for account information extraction.

**`organizational_units.tf`**
```hcl
# Creates OUs under organization root
resource "aws_organizations_organizational_unit" "high_value_assets" {
  name      = "high_value_assets"
  parent_id = data.aws_organizations_organization.current.roots[0].id
}
# ... similar for shared_services, acme_acquisition
```

**Purpose:** Establishes OU hierarchy for testing placement recommendations.

**`providers.tf`**
```hcl
# Provider aliases for cross-account resource creation
provider "aws" {
  alias  = "fort_knox"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.fort_knox.id}:role/OrganizationAccountAccessRole"
  }
}
# ... similar for security_tooling, shared_foo_bar, acme_co
```

**Purpose:** Enables Terraform to create resources in member accounts by assuming `OrganizationAccountAccessRole`.

**`data.tf`**
```hcl
data "aws_organizations_organization" "current" {}
data "aws_caller_identity" "current" {}
```

**Purpose:** Retrieves organization root ID and management account information.

**`variables.tf`**
```hcl
variable "base_email" {
  type        = string
  description = "Email for AWS accounts"
}
```

**Purpose:** Base email for account creation (uses + addressing: `user+account-name@domain.com`).

**`org_and_account_info_reader.tf`**

Role in management account that Headroom uses to query AWS Organizations API.

**Permissions:**
- `organizations:ListAccounts`
- `organizations:ListTagsForResource`
- `organizations:DescribeOrganization`
- `organizations:ListOrganizationalUnitsForParent`
- `organizations:ListAccountsForParent`

**Trust Policy:** Trusts security-tooling account (111111111111).

**`headroom_roles.tf`**

Deploys `Headroom` role to all member accounts using the `modules/headroom_role` module.

```hcl
module "headroom_role_fort_knox" {
  source = "./modules/headroom_role"
  providers = {
    aws = aws.fort_knox
  }
  account_id_to_trust = aws_organizations_account.security_tooling.id
}
# ... similar for other accounts
```

### Test Scenario Files

#### IAM User Creation Test (`test_deny_iam_user_creation.tf`)

Creates IAM users across accounts to test `deny_iam_user_creation` SCP check and allowlist generation.

**Test Users:**

| Account | User Name | Path | Purpose |
|---------|-----------|------|---------|
| acme-co | terraform-user | `/` | Standard automation user |
| acme-co | temp-contractor | `/contractors/` | Non-root path testing |
| fort-knox | github-actions | `/service/` | Service account pattern |
| shared-foo-bar | legacy-developer | `/` | Human user pattern |
| security-tooling | cicd-deployer | `/automation/` | CI/CD automation |

**Expected Behavior:**
- All users discovered by IAM user analysis
- ARNs collected into allowlist
- Root-level SCP generated with `allowed_iam_users` parameter
- ARN transformation: account IDs replaced with `${local.X_account_id}` references

**Example Generated Allowlist:**
```hcl
allowed_iam_users = [
  "arn:aws:iam::${local.acme_co_account_id}:user/contractors/temp-contractor",
  "arn:aws:iam::${local.acme_co_account_id}:user/terraform-user",
  "arn:aws:iam::${local.fort_knox_account_id}:user/service/github-actions",
  "arn:aws:iam::${local.security_tooling_account_id}:user/automation/cicd-deployer",
  "arn:aws:iam::${local.shared_foo_bar_account_id}:user/legacy-developer",
]
```

#### Third-Party AssumeRole Test (`test_deny_third_party_assumerole.tf`)

Creates IAM roles with diverse trust policy patterns to test RCP third-party detection.

**Test Roles (15 total in shared-foo-bar, 1 in acme-co, 1 in fort-knox):**

| Role Name | Account | Trust Policy | Third-Party IDs | Purpose |
|-----------|---------|--------------|-----------------|---------|
| ThirdPartyVendorA | acme-co | CrowdStrike | 749430749651 | Simple third-party |
| ThirdPartyVendorB | shared-foo-bar | Barracuda + Check Point | 758245563457, 517716713836 | Multiple third-parties |
| WildcardRole | fort-knox | `Principal: "*"` | N/A (wildcard) | Wildcard detection |
| LambdaExecutionRole | shared-foo-bar | `Service: lambda.amazonaws.com` | N/A (service) | Service principal skip |
| MultiServiceRole | shared-foo-bar | Multiple services | N/A (services) | Service array handling |
| MixedPrincipalsRole | shared-foo-bar | CyberArk + EC2 service | 365761988620 | Mixed AWS + Service |
| SAMLFederationRole | shared-foo-bar | SAML provider | N/A (federated) | Federated SAML |
| OIDCFederationRole | shared-foo-bar | GitHub OIDC | N/A (federated) | Federated OIDC |
| OrgAccountCrossAccess | shared-foo-bar | Duckbill Group | 151784055945 | Org-external account |
| ComplexMultiStatementRole | shared-foo-bar | Forcepoint + Lambda | 062897671886 | Multi-statement |
| ThirdPartyUserRole | shared-foo-bar | Sophos w/ ExternalId | 978576646331 | ExternalId condition |
| PlainAccountIdRole | shared-foo-bar | Vectra (plain ID) | 081802104111 | Plain account ID format |
| MixedFormatsRole | shared-foo-bar | Ermetic + Zesty | 672188301118, 242987662583 | ARN + plain ID mix |
| ConditionalThirdPartyRole | shared-foo-bar | Duckbill w/ ExternalId | 151784055945 | Conditional trust |
| UltraComplexRole | shared-foo-bar | Check Point + CrowdStrike + ECS + SAML | 292230061137, 749430749651 | Complex multi-statement |

**Third-Party Account IDs (Real Vendors):**
- 749430749651: CrowdStrike
- 758245563457: Barracuda
- 517716713836: Check Point
- 365761988620: CyberArk
- 062897671886: Forcepoint
- 978576646331: Sophos
- 081802104111: Vectra
- 672188301118: Ermetic
- 242987662583: Zesty
- 151784055945: Duckbill Group
- 292230061137: Check Point (additional account)

**All Roles Attached Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*"
  }]
}
```

**Rationale:** Roles are intentionally "useless" (deny-all policy) and exist solely for trust policy analysis.

**Expected Behavior:**
- Wildcard role (fort-knox) flagged as violation
- Fort-knox account excluded from RCP generation
- Shared-foo-bar: 11 unique third-party accounts detected
- Acme-co: 1 third-party account (CrowdStrike)
- OU-level RCP not possible (fort-knox has wildcard)
- Account-level RCPs generated for compliant accounts

#### EC2 IMDSv1 Test (`test_deny_imds_v1_ec2/`)

**⚠️ Cost Warning:** This directory is **separate** because EC2 instances incur ongoing costs. Instances should only be created during active testing.

**Cost:** ~$0.0174/hour (~$12.54/month) for 3 t2.nano instances.

**Test Instances:**

| Instance | Account | IMDS Config | Tags | Expected Result |
|----------|---------|-------------|------|-----------------|
| test-imdsv1-enabled | shared-foo-bar | `http_tokens = "optional"` | `Name` only | **Violation** |
| test-imdsv2-only | acme-co | `http_tokens = "required"` | `Name` only | Compliant |
| test-imdsv1-exempt | fort-knox | `http_tokens = "optional"` | `Name`, `ExemptFromIMDSv2 = "true"` | **Exemption** |

**Separate Directory Structure:**
```
test_deny_imds_v1_ec2/
├── README.md         # Cost warnings and usage instructions
├── providers.tf      # Cross-account providers (reuses org account IDs)
├── data.tf          # AMI data source (Amazon Linux 2023)
└── ec2_instances.tf # Instance definitions
```

**Usage Pattern:**
```bash
# Only when testing
cd test_deny_imds_v1_ec2/
terraform init
terraform apply

# Run Headroom analysis
cd ..
python -m headroom --config config.yaml

# Destroy immediately after testing
cd test_deny_imds_v1_ec2/
terraform destroy
```

**AMI Selection:** Uses latest Amazon Linux 2023 (free tier eligible, HVM, EBS).

### Modules

#### `modules/headroom_role/`

Reusable module for deploying Headroom IAM role across accounts.

**Files:**
- `main.tf`: Role resource and policy attachments
- `variables.tf`: `account_id_to_trust` input
- `outputs.tf`: Role ARN and name
- `versions.tf`: Terraform version constraints

**Permissions:**
- `ViewOnlyAccess` (AWS managed policy): Read-only access to most services
- `SecurityAudit` (AWS managed policy): Security-focused read permissions

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Action": "sts:AssumeRole",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::{account_id_to_trust}:root"
    }
  }]
}
```

**Rationale:** Security tooling accounts commonly have broad read access across organization.

#### `modules/scps/`

Production-ready SCP module used by generated Terraform files.

**Files:**
- `scps.tf`: Policy resource and attachments
- `locals.tf`: Statement filtering logic
- `variables.tf`: Boolean flags and allowlists
- `README.md`: Usage documentation

**Key Variables:**
```hcl
variable "target_id" {
  type        = string
  description = "OU ID or account ID to attach SCP"
}

variable "deny_imds_v1_ec2" {
  type    = bool
  default = false
}

variable "deny_iam_user_creation" {
  type    = bool
  default = false
}

variable "allowed_iam_users" {
  type        = list(string)
  default     = []
  description = "IAM user ARNs allowed to be created"
}
```

**Statement Filtering Logic:**
```hcl
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

  enabled_statements = [for s in local.statements : s.statement if s.include]
}
```

**See:** [modules/scps/README.md](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/scps#scps-module)

#### `modules/rcps/`

Production-ready RCP module used by generated Terraform files.

**Files:**
- `rcps.tf`: Policy resource and attachments
- `locals.tf`: RCP policy document
- `data.tf`: Organization data source
- `variables.tf`: Allowlist configuration
- `README.md`: Usage documentation

**Key Variables:**
```hcl
variable "target_id" {
  type        = string
  description = "OU ID or account ID to attach RCP"
}

variable "enforce_assume_role_org_identities" {
  type    = bool
  default = false
}

variable "third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Third-party account IDs approved for AssumeRole"
}
```

**RCP Policy Logic:**

Denies `sts:AssumeRole` EXCEPT:
1. Principals from organization (`aws:PrincipalOrgID`)
2. Principals from allowlisted third-party accounts (`aws:PrincipalAccount`)
3. AWS service principals (`aws:PrincipalType = "Service"`)
4. Resources tagged with `dp:exclude:identity: true`

**See:** [modules/rcps/README.md](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/rcps#rcps-module)

### Generated Outputs

#### `scps/` Directory (Generated by Headroom)

**`grab_org_info.tf`**

Auto-generated Organization data sources with validation logic.

```hcl
# Auto-generated by Headroom

data "aws_organizations_organization" "org" {}

data "aws_organizations_organizational_units" "root_ou" {
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

data "aws_organizations_organizational_unit_child_accounts" "high_value_assets_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "high_value_assets"
  ][0]
}

locals {
  # Root validation
  validation_check_root = (length(data.aws_organizations_organization.org.roots) == 1) ?
    "All good. This is a no-op." :
    error("[Error] Expected exactly 1 root, found ${length(data.aws_organizations_organization.org.roots)}")

  root_ou_id = data.aws_organizations_organization.org.roots[0].id

  # OU validation
  validation_check_high_value_assets_ou = (length([
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "high_value_assets"
  ]) == 1) ? "All good." : error("[Error] Expected 1 high_value_assets OU")

  top_level_high_value_assets_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "high_value_assets"
  ][0]

  # Account validation
  validation_check_fort_knox_account = (length([
    for account in data.aws_organizations_organizational_unit_child_accounts.high_value_assets_accounts.accounts :
    account.id if account.name == "fort-knox"
  ]) == 1) ? "All good." : error("[Error] Expected 1 fort-knox account")

  fort_knox_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.high_value_assets_accounts.accounts :
    account.id if account.name == "fort-knox"
  ][0]
}
```

**Purpose:** Provides locals for SCP Terraform files to reference; validates organization structure at plan time.

**`root_scps.tf`**

Example of root-level SCP deployment (generated when all accounts 100% compliant).

```hcl
# Auto-generated SCP Terraform configuration for Organization Root
# Generated by Headroom based on compliance analysis

module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  # EC2
  deny_imds_v1_ec2 = false

  # IAM
  deny_iam_user_creation = true
  allowed_iam_users = [
    "arn:aws:iam::${local.fort_knox_account_id}:user/service/github-actions",
    "arn:aws:iam::${local.security_tooling_account_id}:user/automation/cicd-deployer",
    "arn:aws:iam::${local.acme_co_account_id}:user/contractors/temp-contractor",
    "arn:aws:iam::${local.acme_co_account_id}:user/terraform-user",
    "arn:aws:iam::${local.shared_foo_bar_account_id}:user/legacy-developer",
  ]
}
```

**Note:** `deny_imds_v1_ec2 = false` because EC2 test instances create violations. In real environment with 100% compliance, this would be `true`.

**`{ou_name}_ou_scps.tf`**

Example of OU-level SCP deployment.

```hcl
# Auto-generated SCP Terraform configuration for high_value_assets OU
# Generated by Headroom based on compliance analysis

module "scps_high_value_assets_ou" {
  source = "../modules/scps"
  target_id = local.top_level_high_value_assets_ou_id

  # EC2
  deny_imds_v1_ec2 = true

  # IAM
  deny_iam_user_creation = false
}
```

**`{account_name}_scps.tf`**

Example of account-level SCP deployment.

```hcl
# Auto-generated SCP Terraform configuration for fort-knox
# Generated by Headroom based on compliance analysis

module "scps_fort_knox" {
  source = "../modules/scps"
  target_id = local.fort_knox_account_id

  # EC2
  deny_imds_v1_ec2 = true

  # IAM
  deny_iam_user_creation = false
}
```

#### `rcps/` Directory (Generated by Headroom)

**`grab_org_info.tf`**

Identical structure to `scps/grab_org_info.tf` (Organization data sources with validation).

**`{ou_name}_ou_rcps.tf`**

Example of OU-level RCP deployment (union of third-party accounts).

```hcl
# Auto-generated RCP Terraform configuration for acme_acquisition OU
# Generated by Headroom based on IAM trust policy analysis
# Union of third-party accounts from all accounts in this OU

module "rcps_acme_acquisition_ou" {
  source = "../modules/rcps"
  target_id = local.top_level_acme_acquisition_ou_id

  # third_party_assumerole
  enforce_assume_role_org_identities = true
  third_party_assumerole_account_ids_allowlist = [
    "749430749651",
  ]
}
```

**Note:** Only contains CrowdStrike (749430749651) because acme-co is the only account in this OU and it only trusts CrowdStrike.

**`{account_name}_rcps.tf`**

Example of account-level RCP deployment.

```hcl
# Auto-generated RCP Terraform configuration for shared-foo-bar
# Generated by Headroom based on IAM trust policy analysis

module "rcps_shared_foo_bar" {
  source = "../modules/rcps"
  target_id = local.shared_foo_bar_account_id

  # third_party_assumerole
  enforce_assume_role_org_identities = true
  third_party_assumerole_account_ids_allowlist = [
    "062897671886",
    "081802104111",
    "151784055945",
    "242987662583",
    "292230061137",
    "365761988620",
    "517716713836",
    "672188301118",
    "749430749651",
    "758245563457",
    "978576646331",
  ]
}
```

**Note:** Contains all 11 third-party accounts detected in shared-foo-bar's IAM roles.

#### `headroom_results/` Directory (Generated by Headroom)

**Directory Structure:**
```
headroom_results/
├── scps/
│   ├── deny_imds_v1_ec2/
│   │   ├── acme-co.json
│   │   ├── fort-knox.json
│   │   ├── security-tooling.json
│   │   └── shared-foo-bar.json
│   └── deny_iam_user_creation/
│       ├── acme-co.json
│       ├── fort-knox.json
│       ├── security-tooling.json
│       └── shared-foo-bar.json
└── rcps/
    └── third_party_assumerole/
        ├── acme-co.json
        ├── fort-knox.json
        ├── security-tooling.json
        └── shared-foo-bar.json
```

**Example: `scps/deny_imds_v1_ec2/acme-co.json`**
```json
{
  "summary": {
    "account_name": "acme-co",
    "check": "deny_imds_v1_ec2",
    "total_instances": 1,
    "violations": 0,
    "exemptions": 0,
    "compliant": 1,
    "compliance_percentage": 100.0
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {
      "region": "us-east-1",
      "instance_id": "i-0028862fcc86a6d7c",
      "imdsv1_allowed": false,
      "exemption_tag_present": false
    }
  ]
}
```

**Example: `scps/deny_iam_user_creation/acme-co.json`**
```json
{
  "summary": {
    "account_name": "acme-co",
    "check": "deny_iam_user_creation",
    "total_users": 2,
    "users": [
      "arn:aws:iam::REDACTED:user/contractors/temp-contractor",
      "arn:aws:iam::REDACTED:user/terraform-user"
    ]
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {
      "user_name": "temp-contractor",
      "user_arn": "arn:aws:iam::REDACTED:user/contractors/temp-contractor",
      "path": "/contractors/"
    },
    {
      "user_name": "terraform-user",
      "user_arn": "arn:aws:iam::REDACTED:user/terraform-user",
      "path": "/"
    }
  ]
}
```

**Note:** ARNs show `REDACTED` because example results were generated with `exclude_account_ids: true` in config.

**Example: `rcps/third_party_assumerole/shared-foo-bar.json`**
```json
{
  "summary": {
    "account_name": "shared-foo-bar",
    "check": "third_party_assumerole",
    "total_roles_analyzed": 11,
    "roles_third_parties_can_access": 10,
    "roles_with_wildcards": 1,
    "violations": 1,
    "unique_third_party_accounts": [
      "062897671886",
      "081802104111",
      "151784055945",
      "242987662583",
      "292230061137",
      "365761988620",
      "517716713836",
      "672188301118",
      "749430749651",
      "758245563457",
      "978576646331"
    ],
    "third_party_account_count": 11
  },
  "roles_third_parties_can_access": [
    {
      "role_name": "ThirdPartyVendorA",
      "role_arn": "arn:aws:iam::REDACTED:role/ThirdPartyVendorA",
      "third_party_account_ids": ["749430749651"],
      "has_wildcard_principal": false
    }
  ],
  "roles_with_wildcards": [
    {
      "role_name": "WildcardRole",
      "role_arn": "arn:aws:iam::REDACTED:role/WildcardRole",
      "third_party_account_ids": [],
      "has_wildcard_principal": true
    }
  ]
}
```

### Reproducibility Guide

#### Prerequisites

1. AWS Organizations with management account access
2. Terraform installed (v1.0+)
3. AWS CLI configured with management account credentials
4. Python 3.13+ with requirements installed
5. Headroom configuration file

#### Initial Setup

**Step 1: Configure Variables**

```bash
cd test_environment/
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
base_email = "your-email+aws@example.com"
```

**Note:** Uses email + addressing to create unique emails per account.

**Step 2: Deploy Core Infrastructure**

```bash
terraform init
terraform plan
terraform apply
```

This creates:
- 3 organizational units
- 4 member accounts
- OrgAndAccountInfoReader role in management account
- Headroom roles in all member accounts
- Test IAM users
- Test IAM roles with trust policies

**Expected Time:** 10-15 minutes (account creation is slow).

**Step 3: Configure Headroom**

Create `my_config.yaml` in repo root:
```yaml
management_account_id: '222222222222'  # Your management account ID
exclude_account_ids: false
use_account_name_from_tags: false

account_tag_layout:
  environment: 'Environment'
  name: 'Name'
  owner: 'Owner'
```

**Note:** Omit `security_analysis_account_id` if running from security-tooling account.

#### Running Headroom Analysis

**Step 1: Execute Headroom**

```bash
# From repo root
python -m headroom --config my_config.yaml
```

**Expected Output:**
```
================================================================================
SCP/RCP PLACEMENT RECOMMENDATIONS
================================================================================

Check: deny_iam_user_creation
Recommended Level: ROOT
Affected Accounts: 4
Compliance: 100.0%
Reasoning: All accounts in organization have zero violations - safe to deploy at root level
----------------------------------------

Check: third_party_assumerole
Recommended Level: OU
Affected Target: acme_acquisition (ou-xxxx-xxxxxxxx)
Affected Accounts: 1
Third-Party Accounts: 1
Reasoning: All accounts under this OU allow the same third-party accounts with no violations - safe for OU-level RCP
----------------------------------------
```

**Step 2: Verify Generated Files**

Check that files were created:
```bash
ls test_environment/scps/
# grab_org_info.tf
# root_scps.tf
# high_value_assets_ou_scps.tf  (if applicable)

ls test_environment/rcps/
# grab_org_info.tf
# acme_acquisition_ou_rcps.tf
# security_tooling_rcps.tf

ls test_environment/headroom_results/scps/deny_iam_user_creation/
# acme-co.json
# fort-knox.json
# security-tooling.json
# shared-foo-bar.json
```

**Step 3: Review Results**

Compare generated files with examples in repository:
- `test_environment/scps/root_scps.tf`
- `test_environment/rcps/acme_acquisition_ou_rcps.tf`
- `test_environment/headroom_results/scps/deny_iam_user_creation/acme-co.json`

#### Testing EC2 IMDSv1 Check (Optional)

**⚠️ Warning:** Creates billable EC2 instances (~$12.54/month if left running).

```bash
cd test_environment/test_deny_imds_v1_ec2/
terraform init
terraform apply

# Run Headroom again
cd ../..
python -m headroom --config my_config.yaml

# Check updated results
cat test_environment/headroom_results/scps/deny_imds_v1_ec2/acme-co.json

# Destroy instances immediately
cd test_environment/test_deny_imds_v1_ec2/
terraform destroy
```

**Expected Results:**
- `acme-co`: 1 compliant instance (IMDSv2 required)
- `fort-knox`: 1 exemption (IMDSv1 allowed but tagged)
- `shared-foo-bar`: 1 violation (IMDSv1 allowed, no exemption)

#### Cleanup

**Destroy Member Account Resources:**
```bash
cd test_environment/test_deny_imds_v1_ec2/
terraform destroy  # If EC2 instances exist

cd ..
terraform destroy -target=aws_iam_user.terraform_user
terraform destroy -target=aws_iam_user.github_actions
terraform destroy -target=aws_iam_user.legacy_developer
terraform destroy -target=aws_iam_user.cicd_deployer
terraform destroy -target=aws_iam_user.temp_contractor
terraform destroy -target=aws_iam_role.third_party_vendor_a
terraform destroy -target=aws_iam_role.wildcard_role
# ... repeat for all IAM roles
```

**Note:** AWS Organizations accounts cannot be deleted via Terraform or API. Must be deleted manually via AWS Console:
1. Remove all resources from accounts
2. Close accounts via AWS Organizations console
3. Wait 90 days for account closure to complete

### Expected Test Scenarios & Results

#### Scenario 1: All Accounts Compliant (IAM Users)

**Initial State:** 5 IAM users across 4 accounts, no violations.

**Expected Results:**
- Root-level SCP recommended
- All 5 user ARNs in allowlist
- ARNs transformed with `${local.X_account_id}` references
- Compliance: 100%

**Generated File:** `scps/root_scps.tf`

#### Scenario 2: Third-Party Access without Wildcards (acme-co)

**Initial State:** 1 role trusting CrowdStrike, no wildcards.

**Expected Results:**
- OU-level RCP recommended (if other accounts in OU also compliant)
- Third-party allowlist: `["749430749651"]`
- Compliance: 100%

**Generated File:** `rcps/acme_acquisition_ou_rcps.tf`

#### Scenario 3: Wildcard Principal Detection (fort-knox)

**Initial State:** 1 role with `Principal: "*"` wildcard.

**Expected Results:**
- Account excluded from RCP generation
- Violation flagged in results JSON
- OU-level RCP not possible if fort-knox in same OU
- CloudTrail analysis recommended (future feature)

**Generated File:** None (account excluded due to wildcard).

#### Scenario 4: EC2 IMDSv1 with Exemptions (fort-knox)

**Initial State:** 1 EC2 instance with IMDSv1 enabled + `ExemptFromIMDSv2` tag.

**Expected Results:**
- Instance categorized as "exemption"
- Account compliance: 100%
- Compliance calculation: (exemptions + compliant) / total
- Eligible for OU or root-level SCP

**Generated File:** `scps/high_value_assets_ou_scps.tf` (if all accounts in OU compliant).

#### Scenario 5: Multiple Third-Party Accounts (shared-foo-bar)

**Initial State:** 15 roles trusting 11 unique third-party accounts + 1 wildcard.

**Expected Results:**
- Account excluded from OU/root RCPs due to wildcard
- Account-level RCP generated for account (excluding wildcard role)
- All 11 third-party IDs in allowlist
- Wildcard violation flagged

**Generated File:** `rcps/shared_foo_bar_rcps.tf` (account-level only).

### Integration with Development Workflow

#### Unit Tests vs Live Integration

| Aspect | Unit Tests (`tests/`) | Live Integration (`test_environment/`) |
|--------|----------------------|----------------------------------------|
| Execution | Mocked AWS API calls | Real AWS API calls |
| Speed | Fast (~10 seconds) | Slow (~5 minutes) |
| Cost | Free | ~$0 (without EC2) or ~$12/month (with EC2) |
| Coverage | Function-level | End-to-end workflow |
| Purpose | Verify code correctness | Verify AWS integration |
| CI/CD | Runs on every commit | Manual execution |

#### When to Update Test Environment

1. **New Check Added:** Add test scenarios in `test_deny_{check_name}.tf`
2. **Policy Changes:** Update `modules/scps/` or `modules/rcps/` and regenerate
3. **Organization Structure Changes:** Modify `organizational_units.tf` and `accounts.tf`
4. **Breaking Changes:** Rebuild from scratch to verify reproducibility
5. **Documentation Updates:** Regenerate example outputs for README.md

#### Committing Generated Files

**Philosophy:** Generated files are committed to demonstrate tool output and provide documentation.

**What to Commit:**
- `scps/*.tf` (generated SCP Terraform)
- `rcps/*.tf` (generated RCP Terraform)
- `headroom_results/**/*.json` (JSON analysis results)

**What NOT to Commit:**
- `terraform.tfstate` (contains sensitive account IDs)
- `terraform.tfvars` (contains personal email)
- `test_deny_imds_v1_ec2/terraform.tfstate` (EC2 instance IDs)

**Gitignore Pattern:**
```
test_environment/terraform.tfstate*
test_environment/test_deny_imds_v1_ec2/terraform.tfstate*
test_environment/terraform.tfvars
```

#### Documentation-by-Example

The test environment serves as executable documentation:

1. **README.md Examples:** Code blocks reference actual generated files
2. **Module READMEs:** Point to test environment usage patterns
3. **Specification:** References test environment for concrete examples
4. **Onboarding:** New contributors deploy test environment to understand workflow

### Cost Considerations

#### Ongoing Costs (Without EC2)

- **AWS Organizations:** Free
- **IAM Roles:** Free
- **IAM Users:** Free
- **Data Sources:** Free (query costs negligible)

**Total: $0/month**

#### Ongoing Costs (With EC2 Instances)

- **3x t2.nano instances:** ~$12.54/month
- **Data Transfer:** Negligible (no network traffic)
- **EBS Volumes:** Included with t2.nano

**Total: ~$12.54/month** (if instances left running)

**Recommendation:** Keep EC2 instances destroyed except during active testing.

#### One-Time Costs

- **AWS Account Creation:** Free
- **Terraform State Storage:** Free (local state)
- **API Calls:** Negligible (covered by free tier)

#### Cost Optimization Tips

1. Destroy EC2 instances immediately after testing
2. Use `terraform.tfstate` locally (no S3 costs)
3. Run Headroom infrequently (API calls are cheap but not free)
4. Close unused member accounts after testing (90-day process)

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
- **Reference Implementation:** See `test_environment/org_and_account_info_reader.tf`

### Headroom
- **Location:** All accounts (including management, excluding security analysis if running from there)
- **Required:** Always
- **Trusted By:** Security analysis account
- **Permissions:**
  - **EC2:** `ec2:DescribeRegions`, `ec2:DescribeInstances`
  - **IAM:** `iam:ListUsers`, `iam:ListRoles`, `iam:GetRole`
- **Purpose:** Execute compliance checks in each account
- **Reference Implementation:** See `test_environment/modules/headroom_role/` and `test_environment/headroom_roles.tf`

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

**See:** Test Environment section for complete example result files in `test_environment/headroom_results/`.

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
