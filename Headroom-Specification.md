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
- **EC2 IMDS v1 Check:** Multi-region scanning, with exemptions read from the IAM role each instance runs as
- **IAM User Creation Check:** Automatic allowlist generation from discovered users
- **RDS Encryption Check:** Multi-region RDS instance and Aurora cluster encryption analysis
- **SAML Provider Guardrail:** Blocks custom IAM SAML providers so only a single AWS SSO-managed provider exists per account
- Modular check framework with self-registration pattern
- JSON result generation with detailed compliance metrics

#### Check: `deny_iam_saml_provider_not_aws_sso`

- **Objective:** Eliminate custom IAM SAML providers so the companion SCP can unconditionally deny `iam:CreateSAMLProvider`
- **Allowed State:** Zero SAML providers or exactly one AWS SSO-managed provider whose ARN matches `arn:aws:iam::<ACCOUNT_ID>:saml-provider/AWSSSO_<INSTANCE_ID>_<REGION>`
- **Violation States:**
  - More than one SAML provider exists
  - Any provider ARN does not begin with the AWS SSO prefix described above
- **AWS APIs:** `iam:ListSAMLProviders` (read-only; covered by AWS managed `ViewOnlyAccess`)
- **Analysis Output:** Per-provider findings with `arn`, `name`, `create_date`, `valid_until`, and `violation_reason` derived from the rules above
- **Summary Metrics:** `total_saml_providers`, `awssso_provider_count`, `non_awssso_provider_count`, `violating_provider_arns`, `allowed_provider_arn`
- **Terraform Impact:** Generates an SCP statement that denies `iam:CreateSAMLProvider` (no conditions) with explanatory comments; goal placement is organization root because enforcement is universal
- **Why deny everyone?** `AWSServiceRoleForSSO` creates the official provider when accounts join IAM Identity Center and is not affected by SCPs, so a blanket deny only affects custom provider creation attempts
- **Testing Requirements:** Unit tests for AWS enumeration helper, check categorization covering compliant, excess AWSSSO, and non-AWSSSO cases; generator tests confirming Terraform statement, and integration test ensuring placement logic handles new check

### 4. RCP Compliance Analysis
- **STS Third-Party AssumeRole Check:** IAM trust policy analysis across organization
- **S3 Third-Party Access Check:** S3 bucket policy analysis for third-party access
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated, CanonicalUser)
- Federated and CanonicalUser principal detection to prevent breaking SSO/SAML access
- Action and resource tracking for third-party S3 access patterns
- **ECR Third-Party Access Check:** ECR repository resource policy analysis across organization
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated) for IAM trust policies
- Organization baseline comparison for external account detection
- Multi-region ECR repository scanning with pagination support
- ECR actions tracking per third-party account

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
│   ├── ecr.py              # ECR repository policy analysis
│   ├── rds.py              # RDS analysis
│   ├── s3.py               # S3 bucket policy analysis
│   ├── iam/
│   │   ├── roles.py        # Trust policy analysis (RCP)
│   │   └── users.py        # User enumeration (SCP)
│   ├── organization.py     # Organizations API integration
│   └── sessions.py         # Session management
├── checks/
│   ├── base.py             # BaseCheck abstract class
│   ├── registry.py         # Check registration system
│   ├── scps/
│   │   ├── deny_ec2_imds_v1.py
│   │   ├── deny_iam_user_creation.py
│   │   └── deny_rds_unencrypted.py
│   └── rcps/
│       ├── deny_deny_sts_third_party_assumerole.py
│       ├── deny_s3_third_party_access.py
│       └── deny_ecr_third_party_access.py
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
3. **Account Discovery:** Query Organizations API → extract account metadata with tags → filter management account → filter to ACTIVE accounts only
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
    ami_owners: Optional[List[str]] = None         # For the AMI owner check

@dataclass
class RCPCheckResult(CheckResult):
    """RCP check result for third-party access control."""
    third_party_account_ids: List[str]
    blocks_rcp: bool  # True if a principal here defeats any allowlist
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
    allowed_iam_user_arns: Optional[List[str]] = None   # For IAM user checks
    ec2_allowed_ami_owners: Optional[List[str]] = None  # For the AMI owner check

@dataclass
class RCPPlacementRecommendations:
    check_name: str
    recommended_level: str                        # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    third_party_account_ids: List[str]            # Unioned third-party IDs
    reasoning: str

@dataclass
class RCPCheckParseResult:
    """Third-party access findings for one RCP check, across every account."""
    check_name: str                               # Which RCP check this is
    account_third_party_map: Dict[str, Set[str]]  # account_id -> third_party_ids
    accounts_with_blockers: Set[str]              # Accounts that cannot take this RCP
```

### Check-Specific Data Models

```python
# aws/ec2.py
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool                # True if IMDSv1 enabled (violation)
    exemption_tag_present: bool         # True if the INSTANCE is tagged

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

# aws/ecr.py
@dataclass
class ECRRepositoryPolicyAnalysis:
    repository_name: str
    repository_arn: str
    region: str
    third_party_account_ids: Set[str]   # Non-org account IDs
    actions_by_account: Dict[str, List[str]]  # Account ID -> allowed actions
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
        @register_check("scps", "deny_ec2_imds_v1")
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

**Purpose:** Decide whether an account can take the `deny_ec2_imds_v1` SCP, by
counting the EC2 instances that permit IMDSv1 without carrying the exemption
tag.

**Scope - launches, not the running fleet.** The SCP carries one statement,
`DenyRunInstancesMetadataHttpTokensOptional`, evaluated against a
`RunInstances` request. Every instance the scan sees has already launched, so
none of them can be denied by it. An IMDSv1 instance is counted as evidence
that the *next* launch in that account would be denied, which is what makes
the account not yet ready for the policy. The instances themselves are
expected to be migrated to IMDSv2; the SCP exists to stop new ones appearing
while that happens.

A `DenyRoleDeliveryLessThan2` statement, denying any API call made with
credentials fetched over IMDSv1, previously shared this variable. It was
removed rather than split into its own: one variable gating two statements
meant one scan verdict licensing two kinds of evidence, and a role-tagged
IMDSv1 instance was reported as a clean exemption while the surviving
statement - which reads no role tag - would have denied that account's next
launch. Covering the running fleet again means a new variable with its own
verdict, not a second statement on this one.

**Data Model:**
```python
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool                # True = violation
    exemption_tag_present: bool         # True = exempted
```

**Exemption Dimension:** The statement exempts a launch through
`aws:RequestTag/ExemptFromIMDSv2`. That key is populated from the
`TagSpecifications` of the `RunInstances` call, and the same entry puts the
tag on the instance the call creates - so the scan reads the **instance's**
tag as the observable trace of the request tag, and as evidence that a
relaunch will carry it again.

Measured with `RunInstances --dry-run` under the shipped statement:

```
tokens=optional, no tag                  DENY
tokens=optional, ExemptFromIMDSv2=true   allow
tokens=optional, ExemptFromIMDSv2=True   DENY
tokens=required, no tag                  allow
```

A tag on the instance's IAM **role** exempts nothing. `aws:PrincipalTag`
belonged to `DenyRoleDeliveryLessThan2`, which is no longer generated.

**Tag matching:** the key and the value are matched differently, and the scan
follows both. IAM matches condition key names without regard to case, and the
tag key after the slash is part of the name, so `exemptfromimdsv2` is exempt.
The value is compared with `StringNotEquals`, which is case-sensitive, so
`True` is not exempt and must not be reported exempt. An instance carrying the
key twice in cases that differ raises: AWS documents that as an unexpected
condition failure rather than a match on one of them, so guessing which one
IAM lands on would invent the exemption status of a live workload.

**The proxy is imperfect, and that is accepted.** A tag applied after launch
with `CreateTags`, or an instance whose Terraform never declares the tag,
wears the tag while its relaunch carries none - and the scan then reports an
exemption for a launch enforcement denies. Headroom takes the tag as a
declaration of intent rather than a prediction; keeping it effective across a
recreation is the operator's responsibility.

**Analysis Function:**
```python
# aws/ec2.py
def get_imds_v1_ec2_analysis(session: boto3.Session) -> List[DenyImdsV1Ec2]:
    """
    Scan all regions for EC2 instances.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region, create EC2 client
    3. Use paginator to describe_instances (handles pagination)
    4. Filter out terminated instances
    5. IMDSv1 is allowed when HttpTokens is "optional", whatever HttpEndpoint
       says, because the SCP tests HttpTokens either way
    6. Read the instance's ExemptFromIMDSv2 tag, key matched without regard
       to case and value exactly; raise if the key appears twice in cases
       that differ
    7. Return DenyImdsV1Ec2 for each instance
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: DenyImdsV1Ec2) -> tuple[str, Dict[str, Any]]:
    result_dict = asdict(result)

    if result.imdsv1_allowed and result.exemption_tag_present:
        return ("exemption", result_dict)
    if result.imdsv1_allowed:
        return ("violation", result_dict)
    return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    total = len(violations) + len(exemptions) + len(compliant)
    # An exemption counts as compliant: the SCP spares that launch.
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
    "check": "deny_ec2_imds_v1",
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
    1. Get all enabled regions via get_all_regions()
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

### ECR Third-Party Access

**Purpose:** Analyze ECR repository resource policies to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
@dataclass
class ECRRepositoryPolicyAnalysis:
    repository_name: str
    repository_arn: str
    region: str
    third_party_account_ids: Set[str]         # External to organization
    actions_by_account: Dict[str, List[str]]  # Account ID -> allowed ECR actions
    has_wildcard_principal: bool              # True if Principal: "*"
```

**Analysis Function:**
```python
# aws/ecr.py

FAIL_FAST_PRINCIPAL_TYPES = {"Federated"}

def analyze_ecr_repository_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[ECRRepositoryPolicyAnalysis]:
    """
    Analyze all ECR repository policies for third-party access.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Create regional ECR client
       b. Use paginator for describe_repositories
       c. For each repository, call get_repository_policy
       d. Parse JSON policy document
       e. For each Statement, check if Action contains ecr:*
       f. Extract account IDs from Principal field
       g. Track specific ECR actions allowed per account
       h. Detect wildcard principals
       i. Filter to third-party accounts (not in org_account_ids)
    3. Return ECRRepositoryPolicyAnalysis for repos with third-party or wildcards

    Multi-Region: Scans all enabled AWS regions
    Pagination: Handles accounts with many ECR repositories

    Raises:
    - UnsupportedPrincipalTypeError: if Federated principal encountered (fail-fast)
    - ClientError: if non-RepositoryPolicyNotFoundException error occurs
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:iam::111111111111:..." or "111111111111"
    - List: recursively process each item
    - Dict: process AWS/Service/Federated keys
    - Mixed: {"AWS": [...], "Service": "..."}

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Skip (e.g., ecr.amazonaws.com)
    - Federated: Raise UnsupportedPrincipalTypeError (fail-fast)

    Fail-Fast Validation:
    - Federated principals are unsupported in ECR resource policies
    - Immediately raises exception to prevent unsafe RCP generation
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _normalize_actions(actions: Any) -> List[str]:
    """Normalize actions to list format."""
```

**Custom Exceptions:**
```python
class UnsupportedPrincipalTypeError(Exception):
    """Raised when Federated or other unsupported principal type encountered."""
```

**Check Implementation:**
```python
# checks/rcps/deny_ecr_third_party_access.py

class DenyECRThirdPartyAccessCheck(BaseCheck[ECRRepositoryPolicyAnalysis]):
    def __init__(self, org_account_ids: Set[str], **kwargs):
        super().__init__(**kwargs)
        self.org_account_ids = org_account_ids
        self.all_third_party_accounts: Set[str] = set()
        self.all_actions_by_account: Dict[str, List[str]] = {}

    def analyze(self, session):
        return analyze_ecr_repository_policies(session, self.org_account_ids)

    def categorize_result(self, result):
        # Repositories with wildcards are "violations"
        # Repositories with third-party access are "compliant" (expected patterns)
        if result.has_wildcard_principal:
            return ("violation", ...)
        else:
            # Track third-party accounts and actions globally
            self.all_third_party_accounts.update(result.third_party_account_ids)
            for account_id, actions in result.actions_by_account.items():
                if account_id not in self.all_actions_by_account:
                    self.all_actions_by_account[account_id] = []
                self.all_actions_by_account[account_id].extend(actions)
            return ("compliant", ...)

    def build_summary_fields(self, check_result):
        # Aggregate unique third-party account IDs and actions
        # Count repositories with wildcards as violations
        actions_by_account_sorted = {
            account_id: sorted(list(set(actions)))
            for account_id, actions in self.all_actions_by_account.items()
        }
        return {
            "total_repositories_analyzed": total,
            "repositories_third_parties_can_access": len(compliant),
            "repositories_with_wildcards": len(violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_account": actions_by_account_sorted,
            "violations": len(violations)
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_ecr_third_party_access",
    "total_repositories_analyzed": 0,
    "repositories_third_parties_can_access": 0,
    "repositories_with_wildcards": 0,
    "unique_third_party_accounts": [],
    "third_party_account_count": 0,
    "actions_by_account": {
      "464622532012": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    },
    "violations": 0
  },
  "violations": [
    {
      "repository_name": "WildcardRepo",
      "repository_arn": "arn:...",
      "region": "us-east-1"
    }
  ],
  "exemptions": [],
  "repositories_third_parties_can_access": [
    {
      "repository_name": "DatadogRepo",
      "repository_arn": "arn:...",
      "region": "us-east-1",
      "third_party_account_ids": ["464622532012"],
      "actions_by_account": {
        "464622532012": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      }
    }
  ]
}
```

### STS Third-Party AssumeRole

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
    4. For each Allow Statement, decide whether it grants sts:AssumeRole
       (see Action Matching below)
    5. Extract account IDs from Principal field
    6. Detect wildcard principals
    7. Filter to third-party accounts (not in org_account_ids)
    8. Return TrustPolicyAnalysis for roles with third-party or wildcards

    Raises:
    - UnknownPrincipalTypeError: if principal type not in ALLOWED_PRINCIPAL_TYPES
    - InvalidFederatedPrincipalError: if Federated principal uses sts:AssumeRole
    - MalformedStatementError: if a statement names both Action and NotAction,
      or neither
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:iam::111111111111:..." or "111111111111"
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

**Action Matching:**

This is the only analyzer that decides anything from a statement's actions;
the S3, SQS, KMS, ECR and Secrets Manager analyzers read every Allow statement
and record actions for reporting only. Because a statement this one fails to
recognize is dropped in silence - no violation, no error, the account merely
absent from the allowlist that keeps it reachable - the match must follow IAM's
own rules rather than compare strings:

- **Case-insensitive.** IAM documents `iam:ListAccessKeys` and
  `IAM:listaccesskeys` as the same action.
- **`*` and `?` expand anywhere in the name**, not just as a whole-action
  wildcard. `sts:*`, `sts:Assume*`, `sts:*Role` and `sts:AssumeRol?` all cover
  `sts:AssumeRole`. Character classes are not IAM syntax and are matched
  literally.
- **`NotAction` inverts the test.** An Allow statement with `NotAction` grants
  every action its patterns do not cover, so it grants `sts:AssumeRole` unless
  one of them matches it.
- **Exactly one of `Action` and `NotAction`.** A statement carrying both, or
  neither, raises `MalformedStatementError`. IAM would not have stored it, and
  either guess misstates who can assume the role.

The `InvalidFederatedPrincipalError` guard deliberately keeps an exact match
instead. A Federated principal paired with `sts:*` is sloppy rather than
wrong - AWS does not let a federated identity call plain `AssumeRole` - and
aborting a run over it would cost more than it catches.

**Principal ARNs:**

Account IDs come from `AWS_ARN_ACCOUNT_ID_PATTERN`, which constrains neither
the partition nor the service segment. A trust policy principal may be an STS
session ARN (`arn:aws:sts::{account}:assumed-role/{role}/{session}` or
`.../federated-user/{name}`) as readily as an IAM one, and GovCloud and China
ARNs carry account IDs that matter just as much. Pinning either segment drops
the account silently.

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when principal type is not in ALLOWED_PRINCIPAL_TYPES."""

class InvalidFederatedPrincipalError(Exception):
    """Raised when Federated principal uses sts:AssumeRole."""
```

**Check Implementation:**
```python
# checks/rcps/check_deny_sts_third_party_assumerole.py

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
    "check": "deny_sts_third_party_assumerole",
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

### S3 Third-Party Access

**Purpose:** Analyze S3 bucket policies to identify third-party (non-org) account access, Federated/CanonicalUser principals, and wildcard principals.

**Data Model:**
```python
@dataclass
class S3BucketPolicyAnalysis:
    bucket_name: str
    bucket_arn: str
    third_party_account_ids: Set[str]          # External to organization
    has_wildcard_principal: bool               # True if Principal: "*"
    has_non_account_principals: bool           # True if Federated or CanonicalUser
    actions_by_account: Dict[str, Set[str]]    # account_id -> allowed S3 actions
```

**Analysis Function:**
```python
# aws/s3.py

# S3 supports CanonicalUser in addition to base principal types
ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES | {"CanonicalUser"}

def analyze_s3_bucket_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[S3BucketPolicyAnalysis]:
    """
    Analyze all S3 bucket policies for third-party access.

    Algorithm:
    1. List all buckets with paginator (list_buckets)
    2. For each bucket, get bucket policy (get_bucket_policy)
    3. Parse JSON policy document
    4. For each Allow statement:
       - Check if Principal contains wildcard
       - Check if Principal contains Federated or CanonicalUser types
       - Extract account IDs from Principal field
       - Extract allowed actions
       - Filter to third-party accounts (not in org_account_ids)
       - Track which actions each third-party account can perform
    5. Return S3BucketPolicyAnalysis for buckets with findings

    Raises:
    - UnknownPrincipalTypeError: if principal type not in ALLOWED_PRINCIPAL_TYPES
    - UnsupportedPrincipalTypeError: if Federated/CanonicalUser prevents RCP deployment
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:s3:::bucket" or "111111111111"
    - List: recursively process each item
    - Dict: process AWS/Service/Federated/CanonicalUser keys
    - Mixed: {"AWS": [...], "Federated": "..."}

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Validate but skip (e.g., cloudtrail.amazonaws.com)
    - Federated: Skip (track separately via has_non_account_principals)
    - CanonicalUser: Skip (track separately via has_non_account_principals)
    - Unknown: Raise UnknownPrincipalTypeError
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _has_non_account_principals(principal: Any) -> bool:
    """
    Check if principal contains Federated or CanonicalUser types.

    These principal types cannot be represented as account IDs, so an RCP that
    uses aws:PrincipalAccount for allowlisting would break their access.
    """

def _normalize_actions(action: Any) -> Set[str]:
    """Normalize action field to a set of action strings."""
```

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when principal type is not in ALLOWED_PRINCIPAL_TYPES."""

class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a bucket policy contains principal types that can't be handled by RCP.

    Federated and CanonicalUser principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """
```

**Check Implementation:**
```python
# checks/rcps/deny_s3_third_party_access.py

class DenyS3ThirdPartyAccessCheck(BaseCheck[S3BucketPolicyAnalysis]):
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_s3_third_party_access",
    "total_buckets_analyzed": 0,
    "buckets_with_third_party_access": 0,
    "buckets_with_wildcards": 0,
    "buckets_with_non_account_principals": 0,
    "unique_third_party_accounts": [],
    "actions_by_third_party_account": {
      "999999999999": ["s3:GetObject", "s3:PutObject"]
    },
    "buckets_by_third_party_account": {
      "999999999999": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::another-bucket"]
    },
    "violations": 0
  },
  "violations": [
    {
      "bucket_name": "wildcard-bucket",
      "bucket_arn": "arn:aws:s3:::wildcard-bucket",
      "has_wildcard_principal": true,
      "has_non_account_principals": false
    },
    {
      "bucket_name": "federated-bucket",
      "bucket_arn": "arn:aws:s3:::federated-bucket",
      "has_wildcard_principal": false,
      "has_non_account_principals": true
    }
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "bucket_name": "third-party-bucket",
      "bucket_arn": "arn:aws:s3:::third-party-bucket",
      "third_party_account_ids": ["999999999999"],
      "has_wildcard_principal": false,
      "has_non_account_principals": false,
      "actions_by_account": {
        "999999999999": ["s3:GetObject", "s3:PutObject"]
      }
    }
  ]
}
```

**Principal Type Matrix:**

| Principal Type | Example | Account ID Extraction | RCP Compatible | Categorization |
|----------------|---------|----------------------|----------------|----------------|
| AWS Account | `arn:aws:iam::111111111111:root` | ✅ Extract 111111111111 | ✅ COMPLIANT | Can be allowlisted |
| Wildcard | `"*"` | ❌ None | ❌ VIOLATION | Can't deploy RCP safely |
| Federated (SAML/OIDC) | `arn:aws:iam::111111111111:saml-provider/MyProvider` | ⚠️ Extract 111111111111 but not the accessing principal | ❌ VIOLATION | Would break SSO access |
| CanonicalUser | `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be` | ❌ None | ❌ VIOLATION | Would break access |
| Service | `cloudtrail.amazonaws.com` | ❌ None (skip) | ✅ EXEMPT | RCP has `aws:PrincipalIsAWSService` check |

**Safety Rationale:**

The RCP uses `aws:PrincipalAccount` condition for allowlisting. This only works for AWS account principals:
- ✅ **AWS Account principals:** Have account IDs → can be allowlisted
- ❌ **Federated principals:** The account ID in the SAML/OIDC provider ARN is NOT the accessing principal (it's the account hosting the provider)
- ❌ **CanonicalUser principals:** S3-specific IDs with no account ID → cannot be allowlisted
- ✅ **Service principals:** Exempt via `aws:PrincipalIsAWSService = "false"` condition

**Deployment Safety:**
- Accounts with wildcard principals → excluded from the S3 RCP
- Buckets with Federated/CanonicalUser principals → marked as violations
- Only buckets with account-based third-party access → used for allowlist generation
- RCP policy includes `aws:ResourceTag/dp:exclude:identity = "true"` condition to exempt tagged buckets

## Results Processing

### Common Parsing Patterns

Both SCP and RCP parsers share these patterns:

**Directory Structure:**
```
{results_dir}/{check_type}/{check_name}/*.json

Examples:
- {results_dir}/scps/deny_ec2_imds_v1/account-name_111111111111.json
- {results_dir}/rcps/deny_sts_third_party_assumerole/account-name_111111111111.json
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

Result files are written under the name selected by `use_account_name_from_tags`,
while the hierarchy always holds the AWS Organizations account name. A Name tag
of `management-account` against an account Organizations calls `Management
Account` must still resolve, so the lookup matches exactly first and then retries with
case and separators ignored, using the same canonicalization as Terraform
identifiers (`make_safe_variable_name`).

Organizations enforces uniqueness on account email, not on account name, so
either stage can match more than one account. Resolution requires exactly one
match at a stage; anything else raises rather than attributing results to an
arbitrary account. A name that canonicalizes to the empty string (only
separators) is never canonically matched, since every such name reduces alike.

| Stage | Matches | Behavior |
|-------|---------|----------|
| Exact | 1 | Return the account ID, log at info |
| Exact | >1 | Raise, listing every candidate ID and name |
| Canonical | 1 | Return the account ID, log at warning with both names |
| Canonical | >1 | Raise, listing every candidate ID and name |
| Neither | 0 | Raise `Account name '<name>' from <context> not found in organization hierarchy` |

```python
# aws/organization.py
def lookup_account_id_by_name(
    account_name: str,
    organization_hierarchy: OrganizationHierarchy,
    context: str = "result file"
) -> str:
    """
    Look up account ID by name in organization hierarchy.

    Raises: RuntimeError if the name matches no account or several
    """
    exact_matches = [
        (acc_id, acc_info.account_name)
        for acc_id, acc_info in organization_hierarchy.accounts.items()
        if acc_info.account_name == account_name
    ]
    if len(exact_matches) == 1:
        return exact_matches[0][0]
    if exact_matches:
        raise RuntimeError(f"Account name '{account_name}' from {context} matches ...")

    canonical_name = make_safe_variable_name(account_name)
    canonical_matches: List[Tuple[str, str]] = []
    if canonical_name:
        canonical_matches = [
            (acc_id, acc_info.account_name)
            for acc_id, acc_info in organization_hierarchy.accounts.items()
            if make_safe_variable_name(acc_info.account_name) == canonical_name
        ]
    if len(canonical_matches) == 1:
        logger.warning(f"'{account_name}' resolved by ignoring case and separators")
        return canonical_matches[0][0]
    if canonical_matches:
        raise RuntimeError(f"Account name '{account_name}' from {context} matches ...")

    raise RuntimeError(
        f"Account name '{account_name}' from {context} not found in organization hierarchy"
    )
```

### SCP Results Parsing

```python
# parse_results.py

def parse_scp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPCheckResult]:
    """
    Parse all SCP check result files.

    Results are organized as: {results_dir}/scps/{check_name}/*.json
    RCP results live under rcps/, so there is nothing to filter out here.

    Algorithm:
    1. Look for {results_dir}/scps/ subdirectory
    2. Iterate through all check directories in scps/
    3. Skip non-directory files
    4. For each JSON file in check directory:
       - Parse JSON
       - Extract summary fields
       - Handle missing account_id via lookup
       - Create SCPCheckResult
    5. Return flat list of all results

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
) -> List[RCPCheckParseResult]:
    """
    Parse result files for every registered RCP check.

    Results are organized as: {results_dir}/rcps/{check_name}/*.json

    Algorithm:
    1. For each check name in sorted(get_check_names("rcps")):
       a. Get check directory using get_results_dir(check_name, results_dir)
       b. If the directory does not exist: record check_name as missing,
          skip to the next check
       c. For each JSON file in the directory:
          - Parse JSON, extract summary
          - Handle missing account_id via lookup
          - Cross-check summary["check"] against check_name (a file with
            no "check" field is presumed to match); raise RuntimeError on
            a mismatch
          - Require summary["violations"] (never defaulted); raise
            RuntimeError if absent
          - blocks_rcp = summary["violations"] > 0
          - If blocks_rcp: add account_id to this check's
            accounts_with_blockers
          - Else: add account_id -> set(unique_third_party_accounts) to
            this check's account_third_party_map
       d. Append an RCPCheckParseResult for this check to the result list
    2. If any registered check's directory was missing: raise a single
       RuntimeError naming every missing check
    3. Return the list of RCPCheckParseResult, one per registered RCP check

    Returns: List[RCPCheckParseResult], one per registered RCP check

    Note: A check directory that exists but is empty is not an error - it
    yields an RCPCheckParseResult with no findings, indistinguishable from
    a check that ran and found nothing. Only an absent directory is an
    error, since that is indistinguishable from a check that was silently
    dropped.
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
       d. Try OU level, walking the hierarchy from the top down:
          - An OU is safe when EVERY account in its subtree is compliant -
            the accounts directly in it and the accounts in its child OUs,
            because the policy reaches all of them
          - Recommend OU-level at the highest safe OU and stop descending;
            its child OUs inherit the policy rather than collecting a second
            copy of it
          - An unsafe OU hands the question to its child OUs
       e. Account level:
          - For remaining compliant accounts, recommend account-level
          - compliance_percentage is 100.0, as at every other level: the
            affected accounts are the zero-violation subset. The share of the
            organization those accounts represent goes in `reasoning`, where
            it describes reach rather than gating deployment
       f. For deny_iam_user_creation check:
          - Union all IAM user ARNs from affected accounts, which for an
            OU-level recommendation is the OU's whole subtree
          - Un-redact ARNs (replace "REDACTED" with actual account_id)
          - Attach to allowed_iam_user_arns field
       g. For deny_ec2_ami_owner check:
          - Union all AMI owners from affected accounts
          - Attach to ec2_allowed_ami_owners field
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
    parse_results: List[RCPCheckParseResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Determine optimal RCP placement levels using union strategy.

    Algorithm:
    1. For each RCPCheckParseResult in parse_results (each check runs
       independently, against only its own accounts_with_blockers):
       a. Accounts in this check's accounts_with_blockers were already
          excluded from account_third_party_map by parse_rcp_result_files,
          so they need no further filtering here
       b. If account_third_party_map is empty: no recommendations for this check
       c. Try root level:
          - Check: NO accounts have this check's own blockers (len(accounts_with_blockers) == 0)
          - If safe: union ALL third-party IDs from this check's account_third_party_map
          - Affected accounts: ALL accounts in organization
          - Root-level recommendation is the only recommendation returned for this check
       d. Try OU level (if root not safe), walking from the top down:
          - For each OU:
            - Check: NO account in the OU's SUBTREE - the OU and every OU
              below it - is in this check's accounts_with_blockers
            - If safe: union third-party IDs from this check's
              account_third_party_map for every account in that subtree, and
              stop descending; the child OUs inherit the policy
            - Single-account OUs: Still get OU-level recommendations
       e. Account level:
          - Every account still in this check's account_third_party_map after OU-level coverage gets its own account-level recommendation
    2. Return the recommendations from every check, concatenated

    Union Strategy Rationale:
    - Third-party IDs can be safely combined into single allowlist
    - Account A trusts [111], Account B trusts [222] → allowlist [111, 222]
    - More permissive than requiring identical sets
    - Still safe because RCPs use allowlists (approved principals)

    Critical Safety Rules:
    - Root RCP for a check ONLY if NO accounts have that check's own blockers
    - OU RCP for a check ONLY if NO accounts in that OU have that check's own blockers
    - A blocker is check-specific: an account blocking the S3 RCP can still receive placement for every other check
    - Affected accounts includes ALL accounts at that level (not just eligible ones)

    Returns: List[RCPPlacementRecommendations], concatenated across every registered RCP check
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
    2. Name every OU for its path down from the root ({ou_path} below), so
       two OUs sharing a name under different parents stay apart. Colliding
       or reserved names abort the run.
    3. Generate data sources:
       - aws_organizations_organization for root
       - aws_organizations_organizational_units for the root's children, and
         one per OU that has child OUs, parented by that OU's own ID local -
         this chain is what resolves an OU at any depth
       - aws_organizations_organizational_unit_child_accounts for each OU that
         holds accounts, parented by that OU's own ID local
    4. Generate locals with validation:
       - validation_check_root: ensure exactly 1 root
       - root_ou_id: data.aws_organizations_organization.org.roots[0].id
       - For each OU, at every depth:
         - validation_check_{ou_path}_ou: ensure exactly 1 match
         - {ou_path}_ou_id: filtered OU ID
       - For each account:
         - validation_check_{account_name}_account: ensure exactly 1 match
         - {account_name}_account_id: filtered account ID, searched in the
           account's OWN parent OU. The child-accounts data source lists an
           OU's immediate children only, so searching the top-level OU above
           a nested account finds nothing.
    5. Write to {scps_dir}/grab_org_info.tf

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
  parent_id = local.production_ou_id
}

# Emitted because Production has child OUs; this is what lets a nested OU be
# resolved without hardcoding its ID.
data "aws_organizations_organizational_units" "production_children" {
  parent_id = local.production_ou_id
}

data "aws_organizations_organizational_unit_child_accounts" "production_payments_accounts" {
  parent_id = local.production_payments_ou_id
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

  production_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Production"
  ][0]

  # A nested OU is found among its own parent's children
  production_payments_ou_id = [
    for ou in data.aws_organizations_organizational_units.production_children.children :
    ou.id if ou.name == "Payments"
  ][0]

  # Accounts
  validation_check_prod_account_account = ...

  prod_account_account_id = [
    for account in data...production_accounts.accounts :
    account.id if account.name == "prod-account"
  ][0]

  # A nested account is found in its own OU, not the top-level OU above it
  payments_core_account_id = [
    for account in data...production_payments_accounts.accounts :
    account.id if account.name == "payments-core"
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
) -> TerraformPlan:
    """
    Generate SCP Terraform files based on placement recommendations.

    Algorithm:
    1. Group by recommended_level (root/ou/account); a "none" recommendation
       is not a placement and is dropped here
    2. For each group, RENDER a Terraform file into the plan, writing nothing:
       - Root: root_scps.tf
       - OU: {ou_path}_ou_scps.tf
       - Account: {account_name}_scps.tf
    3. For each file:
       - Open with GENERATED_MARKER, the line reconciliation claims it by
       - Generate module call with target_id reference
       - Add boolean flags for each check (organized by category)
       - For deny_iam_user_creation:
         - Transform ARNs: replace account IDs with ${local.X_account_id}
         - Add allowed_iam_users list
       - For deny_ec2_ami_owner:
         - Add ec2_allowed_ami_owners list
         - Leave the policy off if that list is empty (see Allowlist Guard
           below)
    4. Write the completed plan to {scps_dir}/, skipping any file whose
       content already matches
    5. Return the plan, which the caller reconciles the directory against
       (see Reconciliation below)

    An empty recommendation list is a plan for an empty directory, not an
    early return.

    ARN Transformation Algorithm:
    1. Parse ARN: arn:aws:iam::ACCOUNT_ID:user/PATH/NAME
    2. Look up account by ID in organization_hierarchy
    3. Generate safe variable name: account_name_account_id
    4. Replace: arn:aws:iam::${local.account_name_account_id}:user/PATH/NAME
    """
```

**Reconciliation:**

Generation produces the complete desired state of the Terraform directory,
not an increment on top of whatever is already there. Terraform loads every
`.tf` file in a directory, so a file a previous run wrote and this run did not
stays deployed: the run "succeeded" while the organization keeps enforcing a
placement that no longer exists.

The failure has a silent form and a loud one. A renamed or deleted target
takes its `local.<name>_ou_id` declaration out of `grab_org_info.tf` with it,
so its orphaned policy file fails at `terraform plan` on an undeclared local.
A target that still exists but dropped out of the recommendations keeps a
declared local, so its stale file applies cleanly and forever. The worst case
is an OU-level check that moves down to individual accounts because a new
account under that OU started violating it: without reconciliation the OU-wide
attachment survives and keeps denying the very account whose violation forced
the move.

`main()` reconciles once, after both workflows return, over the union of:

| Source | Contributes |
|---|---|
| `handle_scp_workflow` | Every path in the SCP plan |
| `handle_rcp_workflow` | Every path in the RCP plan |
| `generate_terraform_org_info` | `{scps_dir}/grab_org_info.tf` |

Every generated `.tf` in either directory that the union omits is deleted.
Reconciling after both workflows - rather than inside each - is what keeps a
raise anywhere in generation from deleting anything: the previous output stays
whole, complete, and deployable.

**What counts as Headroom's file:** the first line, matched exactly:

```
# Code generated by Headroom. DO NOT EDIT.
```

Rendered unconditionally by `TerraformModule.render()` and by the org-info
header, and checked with `find_managed_files()`. Three alternatives were
rejected:

| Signal | Why not |
|---|---|
| Filename pattern (`*_scps.tf`) | Claims a hand-written `custom_scps.tf` sitting in the same directory |
| Manifest file | Separate state. Lose it and every generated file is an orphan; let it go stale and it names files that were never ours |
| Substring search for "Generated by Headroom" | `scps/README.md` opens with "All of these files are auto-generated by Headroom." and would be deleted |

Symlinks are excluded before the marker is even read: `rcps/grab_org_info.tf`
points at the real file in `scps/`, so following it finds the marker and
deletes a link Headroom is responsible for maintaining. Non-`.tf` files and
subdirectories (`.terraform/`, modules) are never candidates.

**Empty is not the same as unknown:**

Deleting every policy file is the correct response to a run that placed
nothing, and it is also exactly how a broken run would present - wrong
credentials, a mistyped `results_dir`, an analysis that wrote nothing. Reading
zero result files therefore aborts rather than reconciles, because a fail-open
here removes security controls organization-wide on the next `apply`:

| Condition | Response |
|---|---|
| Result files parsed, placement produced no recommendations | Empty plan; managed files deleted |
| `parse_scp_result_files` returned nothing | `RuntimeError` from `analyze_scp_compliance` |
| Every RCP check's directory exists but nothing was read from any of them | `RuntimeError` from `handle_rcp_workflow` |
| An RCP check's directory is missing entirely | `RuntimeError` from `parse_rcp_result_files` |

The RCP discriminator needs both halves of a parse result. An account cleared
for a check lands in `account_third_party_map`; an account blocked from it
lands in `accounts_with_blockers`. Only when both are empty for every check
was nothing read at all - an organization where every account blocks every
check has an empty map too, and that is evidence.

**Allowlist Guard:**

A check whose SCP statement is scoped by an allowlist is only safe to enable
once that allowlist is populated. `deny_ec2_ami_owner` denies
`ec2:RunInstances` unless `ec2:Owner` matches `ec2_allowed_ami_owners`, so an
empty list denies every launch rather than none of them - the exact inversion
of what a check reporting 100% compliance is asserting. Rendering
`ec2_allowed_ami_owners = []` is therefore never correct.

Two things reach that state, and they are not the same condition:

1. **No instance in the affected accounts had a resolvable AMI owner.** An
   account running no instances is safe for the placement and observes
   nothing. The module renders `deny_ec2_ami_owner = false` with a comment
   naming the reason, and the rest of the organization still generates.
   Aborting here would let one empty account stop every unrelated check.
2. **A result file predates AMI owner collection.** Its summary carries no
   `unique_ami_owners` key. Parsing raises, naming the file: after parsing
   this is indistinguishable from case 1, and treating it as case 1 would
   build the allowlist from whatever the other accounts happened to observe.

The value collected for that allowlist is the one `ec2:Owner` will hold - the
AMI's `ImageOwnerAlias` where it has one, its numeric `OwnerId` otherwise.
Collecting `OwnerId` alone yields an allowlist that denies the very AMI the
scan observed; see `documentation/CHECKS.md` for the dry-run measurements.

This exists because the collected owners had no path into the recommendation:
`SCPCheckResult` carried no field for them, so every run enabled the SCP at the
highest compliant level with an empty allowlist. A check that adds an allowlist
variable to `modules/scps` must add the matching field on `SCPCheckResult`,
populate it in `parse_scp_result_files`, and union it in the placement
builders; the module variable alone does nothing.

**Generated SCP Terraform Structure:**
```hcl
# Auto-generated SCP Terraform for root
# Generated by Headroom

module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  # EC2
  deny_ec2_imds_v1 = true

  # IAM
  deny_iam_user_creation = true
  iam_allowed_users = [
    "arn:aws:iam::${local.fort_knox_account_id}:user/terraform-user",
    "arn:aws:iam::${local.security_tooling_account_id}:user/cicd-user"
  ]
}
```

**SCP Module Structure:**
```hcl
# modules/scps/variables.tf

variable "deny_ec2_imds_v1" {
  type = bool
}

variable "deny_iam_user_creation" {
  type = bool
}

variable "iam_allowed_users" {
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
      include = var.deny_ec2_imds_v1,
      statement = {
        Action = "ec2:RunInstances"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens"          = "required"
            "aws:RequestTag/ExemptFromIMDSv2" = "true"
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
) -> TerraformPlan:
    """
    Generate RCP Terraform files based on placement recommendations.

    Algorithm:
    1. Group by recommended_level (root/ou/account)
    2. For each group, RENDER a Terraform file into the plan, writing nothing:
       - Root: root_rcps.tf
       - OU: {ou_path}_ou_rcps.tf
       - Account: {account_name}_rcps.tf
    3. For each file:
       - Open with GENERATED_MARKER, the line reconciliation claims it by
       - Generate module call with target_id reference
       - For each registered RCP check, in `RCP_TERRAFORM_VARIABLES` order:
         if this target has a recommendation for that check, emit its enable
         flag as true with its third-party allowlist variable; otherwise emit
         the enable flag as false and omit the allowlist
       - Third-party IDs are already unioned by placement logic
    4. Write the completed plan to {rcps_dir}/, skipping any file whose
       content already matches
    5. Return the plan, which the caller reconciles the directory against
       (see Reconciliation under SCP Terraform Generation)

    An empty recommendation list is a plan for an empty directory, not an
    early return.
    """
```

**`RCP_TERRAFORM_VARIABLES`:**

The renderer never branches on a check name. `RCP_TERRAFORM_VARIABLES` maps
each registered RCP check to the three things a module call needs from it: the
section comment, the boolean enable variable, and the list variable holding
its third-party allowlist. `_build_rcp_terraform_module` iterates the table, so
the table's order fixes the order parameters are rendered in - alphabetical by
service: ECR, KMS, S3, Secrets Manager, SQS, STS - and adding a check requires
no edit to the renderer itself.

The table is the one place a new RCP check must be declared by hand; parsing
and placement are already driven by the check registry. A registered check with
no table entry is collected on every run and then dropped at render time,
emitting no module parameters at all. Because `modules/rcps` declares every
`deny_*` flag without a default, the omission surfaces as a `terraform plan`
failure on a missing required variable rather than as a silently disabled
check. `test_table_covers_every_registered_rcp_check` asserts the table's keys
equal `get_check_names("rcps")` and fails by name in CI, before any Terraform
runs.

**Generated RCP Terraform Structure:**
```hcl
# Auto-generated RCP Terraform configuration for Organization Root
# Generated by Headroom based on third-party account analysis

module "rcps_root" {
  source = "../modules/rcps"
  target_id = local.root_ou_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "888888888888",
    "999999999999",
  ]
}
```

**RCP Module Structure:**
```hcl
# modules/rcps/variables.tf

# One enable flag + one allowlist variable per registered RCP check,
# alphabetical by service: ECR, KMS, S3, Secrets Manager, SQS, STS.
#
# STS is shown below. ECR, KMS, S3 and SQS follow exactly this shape.
# Secrets Manager does not: its allowlist is named
# `secrets_manager_third_party_account_ids_allowlist`, with no `_access_`
# segment, while its enable flag `deny_secrets_manager_third_party_access`
# keeps the segment. Deriving the allowlist name from the pattern produces
# `secrets_manager_third_party_access_account_ids_allowlist`, which
# `terraform plan` rejects with "An argument named ... is not expected here".
# Do not normalize it.

variable "deny_sts_third_party_assumerole" {
  type        = bool
  description = "Deny STS AssumeRole from third-party accounts except those in the allowlist."
}

variable "sts_third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to assume roles in this target ID."
}
```

```hcl
# modules/rcps/locals.tf

locals {
  # One entry per registered RCP check, each gated by its own boolean. An
  # entry whose `include` is false is dropped from the document; it never
  # permits anything. This is what lets six checks placed at different
  # levels compose without one weakening another.
  possible_rcp_1_statements = [
    # var.deny_ecr_third_party_access
    # -->
    # Sid: DenyECRThirdPartyAccess
    {
      include = var.deny_ecr_third_party_access,
      statement = {
        "Sid"       = "DenyECRThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "ecr:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.ecr_third_party_access_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },

    # KMS, S3, Secrets Manager and SQS entries follow, each with its own
    # include flag, Sid, service action prefix and allowlist variable.

    # var.deny_sts_third_party_assumerole
    # -->
    # Sid: DenySTSThirdPartyAssumeRole
    {
      include = var.deny_sts_third_party_assumerole,
      statement = {
        "Sid"       = "DenySTSThirdPartyAssumeRole"
        "Principal" = "*"
        "Action" = [
          "sts:AssumeRole",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.sts_third_party_assumerole_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
  ]

  # Keep only the statements whose flag is true
  included_rcp_1_deny_statements = [
    for rcp_1_deny_statement in local.possible_rcp_1_statements :
    rcp_1_deny_statement.statement if rcp_1_deny_statement.include
  ]

  # Effect is merged in rather than repeated on every statement
  rcp_1_policy = {
    "Version" = "2012-10-17"
    "Statement" = [
      for statement in local.included_rcp_1_deny_statements :
      merge(statement, { Effect = "Deny" })
    ]
  }

  # jsonencode(jsondecode(...)) minimizes the rendered document
  rcp_1_content = jsonencode(
    jsondecode(data.aws_iam_policy_document.rcp_1.json)
  )

  # Validate the RCP maximum length at plan time rather than apply time
  rcp_length_1 = length(local.rcp_1_content)
  validation_check_1 = (local.rcp_length_1 <= 5120) ? "All good. This is a no-op." : error("[Error] String length exceeds 5120 characters, right now it is ${local.rcp_length_1}")
}

data "aws_iam_policy_document" "rcp_1" {
  source_policy_documents = [jsonencode(local.rcp_1_policy)]
}
```

**RCP Policy Logic:**

Each included statement denies its own service's actions - `ecr:*`, `kms:*`,
`s3:*`, `secretsmanager:*`, `sqs:*`, or `sts:AssumeRole` - EXCEPT when:
1. The principal belongs to the organization (`aws:PrincipalOrgID`)
2. The principal belongs to an allowlisted third-party account
   (`aws:PrincipalAccount`, against that statement's own allowlist variable)
3. The caller is an AWS service
   (`BoolIfExists { "aws:PrincipalIsAWSService" = "false" }`)
4. The resource carries the tag `dp:exclude:identity = "true"`
   (`aws:ResourceTag/dp:exclude:identity`)

Conditions 1, 2 and 4 share one `StringNotEqualsIfExists` block and condition 3
is a separate `BoolIfExists`. A `Condition` map ANDs its blocks, so a statement
denies only a principal for which none of the four exceptions hold at once:
outside the organization, absent from that statement's allowlist, not an AWS
service, and acting on an untagged resource.

A check whose `deny_*` flag is `false` contributes no statement at all, so
checks placed at different levels of the hierarchy never weaken one another.

**Known limitation - one 5,120-character policy per target:**

`modules/rcps/rcps.tf` creates exactly one `aws_organizations_policy`, `rcp_1`,
so every included statement shares a single RCP document. `locals.tf` computes
`rcp_length_1 = length(local.rcp_1_content)`, and `validation_check_1` calls
`error()` at plan time when that exceeds 5120, the AWS maximum length for an
RCP.

Until all six checks were wired through to Terraform, only STS could ever
render `true` in a real run, so at most one statement was included and the
budget was never approached. With six statements includable simultaneously the
scaffolding alone costs roughly 1,900 of the 5,120 characters, and each
additional twelve-digit account ID costs about 14 more, leaving room for a
couple of hundred allowlist entries across all six lists combined. A large
enough organization will hit the plan-time error.

Splitting across a second policy is deliberately not implemented: changes to
`modules/rcps/` are a non-goal for the generator, and a loud failure at plan
time is the correct outcome - the alternative is silently truncating an
allowlist and denying access the organization depends on.

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
    3. Filter out accounts not in the ACTIVE lifecycle state
       (see "Account Lifecycle State Filtering" below)
    4. For each remaining account:
       - Get tags via list_tags_for_resource()
       - Extract environment (default "unknown")
       - Extract owner (default "unknown")
       - Extract name:
         - If use_account_name_from_tags: use tag (default account_id)
         - Else: use account.Name from API (default account_id)
    5. Return List[AccountInfo]
    """

@dataclass
class AccountInfo:
    account_id: str
    environment: str       # From tags, default "unknown"
    name: str             # From tags/API, default account_id
    owner: str            # From tags, default "unknown"
```

#### Account Lifecycle State Filtering

Only accounts in the `ACTIVE` lifecycle state are analyzed. AWS Organizations
reports an account's lifecycle position through two fields on the `Account`
object:

| Field | Values | Status |
|-------|--------|--------|
| `State` | `PENDING_ACTIVATION`, `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE`, `CLOSED` | Current |
| `Status` | `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE` | Retired 2026-09-09 |

`State` is authoritative; `Status` is a fallback for SDKs released before
2025-09-09, which do not model `State` (botocore drops unmodeled fields from
responses). Because the retiring `Status` value `SUSPENDED` covers both of the
`State` values `SUSPENDED` and `CLOSED`, allowlisting `ACTIVE` skips exactly the
same accounts under either field, which makes the retirement a non-event.

| State | Analyzed | Reason |
|-------|----------|--------|
| `ACTIVE` | Yes | Fully operational |
| `CLOSED` | No | Role assumption is impossible; AWS removes the account from the organization 90 days after closure |
| `SUSPENDED` | No | AWS has restricted access, so API calls fail |
| `PENDING_ACTIVATION` | No | Sign-up was never completed, so the account is unusable |
| `PENDING_CLOSURE` | No | Still functional, but leaving the organization, so it must not hold back an organization-wide recommendation |

Without this filtering a single closed account aborts an entire run, because
`run_checks()` does not catch the `ClientError` that `assume_role` raises,
losing the results of every account later in the list.

**An indeterminate state aborts the run.** An account reporting neither field
raises `RuntimeError` naming the remediation. That cause is environment-wide
rather than per-account: an SDK too old to model `State` once `Status` has been
retired makes every account report nothing. Continuing would attempt every closed
account and then fail inside `assume_role` with an `AccessDenied` that names none
of the real cause, so the failure belongs at the point the information is
actually missing.

**An unrecognized state also aborts the run.** A `State` value absent from both
`ACTIVE` and the skip set means AWS has added a lifecycle state, and neither
guess is safe: analyzing an account that turns out to be unusable burns the run
on a downstream error that explains nothing, while skipping one that is usable
drops it from the compliance picture that gates policy deployment. The error
names the offending value and the constant to update.

The governing principle is therefore uniform - **never guess at an account's
lifecycle state.** A state that is known and analyzable is analyzed, a state that
is known and unusable is skipped, and anything else stops the run.

The cost of that uniformity is that a state AWS adds would break runs, so
`test_every_state_aws_defines_is_classified` asserts that `ACTIVE` plus the skip
set exactly covers `AccountStateType`, the SDK's own enumeration of the field.
A new AWS state therefore surfaces as a CI failure naming the state when
`boto3-stubs` is upgraded, rather than as a failed run in production.

**Scope.** This filtering applies only to the account list that drives
per-account checks. It deliberately does **not** apply to:

- `get_all_organization_account_ids()`, the organization-membership oracle for
  the third-party RCP checks. A closed account remains an organization member
  until AWS removes it, and organization-based RCP conditions still match it, so
  filtering here would reclassify a recently-closed sibling account as a third
  party and produce false positive findings.
- `analyze_organization_structure()`, which resolves account names read back
  from result files on disk. A result file written before an account closed must
  still resolve, and placement is driven by the results that exist, which leaves
  an account with no results already inert.

### Region Discovery

Every regional check resolves its region list through one helper,
`aws/helpers.get_all_regions()`, which calls `ec2:DescribeRegions` with no
arguments.

Calling it with no arguments is the entire contract. The default response
contains only the regions **enabled for the account** and omits every
`not-opted-in` region:

| `OptInStatus` | Meaning | Returned by default |
|---------------|---------|---------------------|
| `opt-in-not-required` | Enabled for every account | Yes |
| `opted-in` | Opt-in region the account has enabled | Yes |
| `not-opted-in` | Opt-in region the account has not enabled | No |

**Never pass `AllRegions=True`.** Per the EC2 API it "indicates whether to
display all Regions, including Regions that are disabled for your account".
Because every caller builds a per-region client from this list, each disabled
region added would become a doomed API call against a region that cannot hold
resources. Headroom has no interest in analyzing a disabled region, so the
cheapest correct behaviour is to never learn about one.
`test_only_enabled_regions_are_requested` asserts the exact call signature, so
adding the argument fails the suite rather than the run.

An enabled region is not a guarantee that a given service is available there.
Handling a missing regional endpoint is the caller's concern. Note that an
absent endpoint raises `EndpointConnectionError`, which is not a `ClientError`
subclass, so an `except ClientError` never catches it.

#### Credentials in Opt-In Regions

Reaching an enabled region also needs credentials AWS will honour there. Session
tokens issued by the **global** STS endpoint, `sts.amazonaws.com`, are valid only
in regions that are enabled by default, so an opt-in region rejects them:

```
An error occurred (AuthFailure) when calling the DescribeInstances operation:
AWS was not able to validate the provided access credentials
```

botocore reaches that endpoint by default. Its `sts_regional_endpoints` setting
defaults to `legacy`, which rewrites the STS endpoint whenever the session's
region is one of botocore's `LEGACY_GLOBAL_STS_REGIONS` -- the regions that
predate opt-in regions, `us-east-1` and `us-west-2` among them. An operator
running Headroom from `us-west-2` therefore mints unusable credentials without
having configured anything wrong.

Headroom does not depend on the operator's configuration for this.
`aws/sessions.new_session()` is the only place in the package that constructs a
boto3 `Session`, and it sets `sts_regional_endpoints = regional` on every one.
`assume_role()` builds its STS client in an explicit region and stamps that
region onto the session it returns, so a chained assumption -- base account to
security analysis account to member account -- stays regional at every hop. When
no region resolves, `assume_role()` raises instead of picking one, on the same
grounds as every other guess Headroom refuses to make.

`test_only_the_sessions_module_constructs_a_session` fails the suite if any
module builds a `Session` directly. A direct construction silently reinherits the
`legacy` default, and nothing in a mocked test suite notices; the break surfaces
only once a scan reaches an opt-in region.

#### Unreadable Regions

**A region that cannot be read aborts the run.** Every regional analysis raises
on a `ClientError` rather than contributing an empty result, because an empty
result is exactly what a genuinely empty region produces. Nothing downstream can
distinguish "this region holds no findings" from "this region was never read",
and both feed generated policy:

| Check type | Consequence of a silently unread region |
|------------|------------------------------------------|
| RCP third-party access | The allowlist omits partners whose resources live only in that region, so deploying the RCP denies them |
| SCP compliance | The region contributes no violations, so an OU looks clean and a policy is recommended on incomplete evidence |

The single exception is a resource that has been **deleted between listing it and
reading it**. That is the one benign read failure: the resource is gone, so it
holds no policy and can grant nobody access. Those error codes are named
explicitly - `QUEUE_GONE_ERROR_CODES` in `aws/sqs.py` and
`FUNCTION_GONE_ERROR_CODE` in `aws/lambda_functions.py` - and every other code
propagates.

This requires the `Headroom` role to be **exempt from region-allowlist SCPs**.
Region enablement is independent of SCPs, so a region denied by
`aws:RequestedRegion` is still enabled, still returned by `DescribeRegions`, and
still scanned. Without the exemption every run would abort in the denied
regions. With it, an `AccessDenied` unambiguously means a missing permission.
See `documentation/SETUP.md`.

Recovery is cheap because the abort is not a rollback. `run_checks_for_type()`
consults `results_exist()` per check per account, so every result already written
to disk is kept and skipped on the next run: fix the permission, re-run, and the
scan resumes where it stopped.

Routing all callers through the single helper is required by `AP-006: Not Using
Existing Helpers` in `HOW_TO_ADD_A_CHECK.md`, which names duplicated region
discovery as the anti-pattern. It keeps the enabled-regions guarantee in one
place instead of restating it at each call site.

### EC2 Integration

```python
# aws/ec2.py

def get_imds_v1_ec2_analysis(
    session: boto3.Session
) -> List[DenyImdsV1Ec2]:
    """
    Scan all regions for EC2 instances with IMDSv1.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Create regional EC2 client
       b. Use paginator for describe_instances
       c. For each instance:
          - Skip if state is "terminated"
          - IMDSv1 is allowed when MetadataOptions.HttpTokens is "optional",
            whatever MetadataOptions.HttpEndpoint says
          - Record the instance profile ARN, if any
    3. Resolve each distinct instance profile to its role, once per account,
       and exempt on that role's ExemptFromIMDSv2 tag
    4. Return all results

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

### SAML Provider Integration

```python
# aws/iam/saml_providers.py

@dataclass
class SamlProviderAnalysis:
    arn: str
    name: str
    create_date: datetime.datetime | None
    valid_until: datetime.datetime | None

def get_saml_providers_analysis(
    session: boto3.Session,
) -> List[SamlProviderAnalysis]:
    """
    Enumerate IAM SAML providers.

    Algorithm:
    1. Create IAM client
    2. Call list_saml_providers()
    3. For each entry:
       - Record ARN
       - Derive provider name from ARN suffix
       - Capture CreateDate and ValidUntil if present
    4. Return List[SamlProviderAnalysis]

    Pagination: API does not paginate (single response)
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

    Error handling is deliberately absent: a failure aborts the entire run
    rather than being logged and skipped. A partial run is more dangerous than no
    run, because this output drives SCP and RCP deployment and an account skipped
    for a transient error is indistinguishable in the results from an account
    with zero violations, so swallowing the error could green-light a policy that
    breaks it. Accounts that genuinely cannot be analyzed are excluded earlier,
    by lifecycle state in `get_subaccount_information`.
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

# SCP Checks (alphabetical by service)
DENY_EC2_AMI_OWNER = "deny_ec2_ami_owner"
DENY_EC2_IMDS_V1 = "deny_ec2_imds_v1"
DENY_EC2_PUBLIC_IP = "deny_ec2_public_ip"
DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG = "deny_eks_create_cluster_without_tag"
DENY_IAM_USER_CREATION = "deny_iam_user_creation"
DENY_IAM_SAML_PROVIDER_NOT_AWS_SSO = "deny_iam_saml_provider_not_aws_sso"
DENY_LAMBDA_AUTH_TYPE_NONE = "deny_lambda_auth_type_none"
DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"

# RCP Checks (alphabetical by service)
DENY_ECR_THIRD_PARTY_ACCESS = "deny_ecr_third_party_access"
DENY_KMS_THIRD_PARTY_ACCESS = "deny_kms_third_party_access"
DENY_S3_THIRD_PARTY_ACCESS = "deny_s3_third_party_access"
DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS = "deny_secrets_manager_third_party_access"
DENY_SQS_THIRD_PARTY_ACCESS = "deny_sqs_third_party_access"
DENY_STS_THIRD_PARTY_ASSUMEROLE = "deny_sts_third_party_assumerole"

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

# No static SCP/RCP name sets exist. get_check_type_map() is the single
# source of truth for which type a check belongs to, populated by
# @register_check at import time.
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
3. **Account Level:** Recommended for individual compliant accounts, and
   enabled in those accounts' files. A recommendation reaching a module is
   itself the signal to enable the policy, because `affected_accounts` is the
   zero-violation subset at every level

### RCP Deployment Safety

**Blocker Exclusion:**
- An account is excluded from a check's RCP generation whenever that check's own violations count is nonzero; each check defines what counts as a violation for its own resource type (see `documentation/CHECKS.md`)
- Static analysis cannot always determine the actual principals a resource policy would grant access to
- Placement runs once per check, each against only that check's own blocked accounts, so a blocker for one RCP (e.g. S3) never suppresses placement for another (e.g. STS)
- Avoids OU-level RCP for a check if ANY account beneath that OU is blocked for that check, including accounts inside its child OUs, because the policy reaches them too
- Avoids root-level RCP for a check if ANY account in the organization is blocked for that check

**Union Strategy:**
- Third-party account IDs combined (unioned) at each level
- More permissive than requiring identical sets across accounts
- Still safe because RCPs use allowlists (approved principals)
- Example: Account A trusts [111], Account B trusts [222] → RCP allowlist [111, 222]

**Placement Hierarchy:**
1. **Root Level:** Only if NO accounts have that check's own blockers; unions ALL third-party IDs
2. **OU Level:** Only if NO accounts in OU have that check's own blockers; unions OU third-party IDs
3. **Account Level:** Blocked accounts excluded; no RCP generated for them

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
├── test_deny_deny_sts_third_party_assumerole.tf  # IAM roles with trust policies
├── account_scps.tf                      # Account-level SCP attachments (if any)
├── modules/
│   ├── headroom_role/                   # Reusable Headroom role module
│   ├── scps/                            # Production SCP module
│   └── rcps/                            # Production RCP module
├── scps/                                # Generated SCP Terraform
│   ├── grab_org_info.tf                 # Auto-generated org data sources
│   ├── root_scps.tf                     # Root-level SCPs
│   ├── {ou_path}_ou_scps.tf            # OU-level SCPs, named for the OU's
│   │                                   # path from the root (production,
│   │                                   # production_payments, ...)
│   └── {account_name}_scps.tf          # Account-level SCPs
├── rcps/                                # Generated RCP Terraform
│   ├── grab_org_info.tf                 # Auto-generated org data sources
│   ├── {ou_path}_ou_rcps.tf            # OU-level RCPs
│   └── {account_name}_rcps.tf          # Account-level RCPs
├── headroom_results/                    # JSON analysis results
│   ├── scps/
│   │   ├── deny_ec2_imds_v1/
│   │   │   └── {account_name}.json
│   │   ├── deny_iam_user_creation/
│   │   │   └── {account_name}.json
│   │   └── deny_rds_unencrypted/
│   │       └── {account_name}.json
│   └── rcps/
│       └── deny_sts_third_party_assumerole/
│           └── {account_name}.json
├── test_deny_ec2_imds_v1/               # EC2 instances (expensive, separate directory)
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
iam_allowed_users = [
  "arn:aws:iam::${local.acme_co_account_id}:user/contractors/temp-contractor",
  "arn:aws:iam::${local.acme_co_account_id}:user/terraform-user",
  "arn:aws:iam::${local.fort_knox_account_id}:user/service/github-actions",
  "arn:aws:iam::${local.security_tooling_account_id}:user/automation/cicd-deployer",
  "arn:aws:iam::${local.shared_foo_bar_account_id}:user/legacy-developer",
]
```

#### STS Third-Party AssumeRole Test (`test_deny_deny_sts_third_party_assumerole.tf`)

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
- Wildcard role (fort-knox) flagged as a violation of
  `deny_sts_third_party_assumerole`
- Fort-knox excluded from that one check's RCP placement. The wildcard sits in
  an IAM role trust policy, which says nothing about the account's ECR, KMS,
  S3, Secrets Manager or SQS resource policies, so fort-knox still receives
  recommendations for those five checks
- Shared-foo-bar: 11 unique third-party accounts detected
- Acme-co: 1 third-party account (CrowdStrike)
- OU-level STS RCP not possible while fort-knox is in the OU; the OU stays
  eligible for the other five checks
- Account-level RCPs generated for accounts with no blocker for the check
  being placed

#### EC2 IMDSv1 Test (`test_deny_ec2_imds_v1/`)

**⚠️ Cost Warning:** This directory is **separate** because EC2 instances incur ongoing costs. Instances should only be created during active testing.

**Cost:** ~$0.029/hour (~$20.90/month) for 5 t2.nano instances.

**Test Instances:**

| Instance | Account | IMDS Config | Exemption tag | Expected Result |
|----------|---------|-------------|---------------|-----------------|
| test-imdsv1-enabled | shared-foo-bar | `http_tokens = "optional"` | none | **Violation** |
| test-imdsv2-only | acme-co | `http_tokens = "required"` | none | Compliant |
| test-imdsv1-exempt | fort-knox | `http_tokens = "optional"` | on its IAM **role** | **Exemption** |
| test-imdsv1-instance-tagged-only | shared-foo-bar | `http_tokens = "optional"` | on the **instance** | **Violation** |
| test-imds-disabled-tokens-optional | acme-co | `http_endpoint = "disabled"`, `http_tokens = "optional"` | none | **Violation** |

The last two are the regression cases. An instance tag exempts nothing, because
no statement in the policy reads instance tags. An instance with the metadata
endpoint disabled is still a violation while its tokens are optional, matching
how `deny_ec2_imds_hop_limit` counts its hop limit. The SCP reads the launch
request, where turning the endpoint off leaves `HttpTokens` unnamed and
`ec2:MetadataHttpTokens` absent for `StringNotEquals` to fire on - confirmed
denied by dry run against a live account. The remedy is to name
`HttpTokens=required` anyway, which AWS accepts alongside a disabled endpoint
and which changes no behaviour.

**Separate Directory Structure:**
```
test_deny_ec2_imds_v1/
├── README.md         # Cost warnings and usage instructions
├── providers.tf      # Cross-account providers (reuses org account IDs)
├── data.tf          # AMI data source (Amazon Linux 2023)
└── ec2_instances.tf # Instance definitions
```

**Usage Pattern:**
```bash
# Only when testing
cd test_deny_ec2_imds_v1/
terraform init
terraform apply

# Run Headroom analysis
cd ..
python -m headroom --config config.yaml

# Destroy immediately after testing
cd test_deny_ec2_imds_v1/
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

variable "deny_ec2_imds_v1" {
  type    = bool
  default = false
}

variable "deny_iam_user_creation" {
  type    = bool
  default = false
}

variable "iam_allowed_users" {
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
      include = var.deny_ec2_imds_v1,
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
  description = "Organization account, root, or unit."
}

# One enable flag + one allowlist variable per registered RCP check,
# alphabetical by service: ECR, KMS, S3, Secrets Manager, SQS, STS.
#
# STS is shown below. ECR, KMS, S3 and SQS follow exactly this shape.
# Secrets Manager does not: its allowlist is named
# `secrets_manager_third_party_account_ids_allowlist`, with no `_access_`
# segment, while its enable flag `deny_secrets_manager_third_party_access`
# keeps the segment. Deriving the allowlist name from the pattern produces
# `secrets_manager_third_party_access_account_ids_allowlist`, which
# `terraform plan` rejects with "An argument named ... is not expected here".
# Do not normalize it.

variable "deny_sts_third_party_assumerole" {
  type        = bool
  description = "Deny STS AssumeRole from third-party accounts except those in the allowlist."
}

variable "sts_third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to assume roles in this target ID."
}
```

**RCP Policy Logic:**

Each included statement denies its own service's actions - `ecr:*`, `kms:*`,
`s3:*`, `secretsmanager:*`, `sqs:*`, or `sts:AssumeRole` - EXCEPT when:
1. The principal belongs to the organization (`aws:PrincipalOrgID`)
2. The principal belongs to an allowlisted third-party account
   (`aws:PrincipalAccount`, against that statement's own allowlist variable)
3. The caller is an AWS service
   (`BoolIfExists { "aws:PrincipalIsAWSService" = "false" }`)
4. The resource carries the tag `dp:exclude:identity = "true"`
   (`aws:ResourceTag/dp:exclude:identity`)

Conditions 1, 2 and 4 share one `StringNotEqualsIfExists` block and condition 3
is a separate `BoolIfExists`. A `Condition` map ANDs its blocks, so a statement
denies only a principal for which none of the four exceptions hold at once:
outside the organization, absent from that statement's allowlist, not an AWS
service, and acting on an untagged resource.

A check whose `deny_*` flag is `false` contributes no statement at all, so
checks placed at different levels of the hierarchy never weaken one another.

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
  parent_id = local.high_value_assets_ou_id
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

  high_value_assets_ou_id = [
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
  deny_ec2_imds_v1 = false

  # IAM
  deny_iam_user_creation = true
  iam_allowed_users = [
    "arn:aws:iam::${local.fort_knox_account_id}:user/service/github-actions",
    "arn:aws:iam::${local.security_tooling_account_id}:user/automation/cicd-deployer",
    "arn:aws:iam::${local.acme_co_account_id}:user/contractors/temp-contractor",
    "arn:aws:iam::${local.acme_co_account_id}:user/terraform-user",
    "arn:aws:iam::${local.shared_foo_bar_account_id}:user/legacy-developer",
  ]
}
```

**Note:** `deny_ec2_imds_v1 = false` because EC2 test instances create violations. In real environment with 100% compliance, this would be `true`.

**`{ou_path}_ou_scps.tf`**

Example of OU-level SCP deployment.

```hcl
# Auto-generated SCP Terraform configuration for high_value_assets OU
# Generated by Headroom based on compliance analysis

module "scps_high_value_assets_ou" {
  source = "../modules/scps"
  target_id = local.high_value_assets_ou_id

  # EC2
  deny_ec2_imds_v1 = true

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
  deny_ec2_imds_v1 = true

  # IAM
  deny_iam_user_creation = false
}
```

#### `rcps/` Directory (Generated by Headroom)

**`grab_org_info.tf`**

Identical structure to `scps/grab_org_info.tf` (Organization data sources with validation).

**`{ou_path}_ou_rcps.tf`**

Example of OU-level RCP deployment (union of third-party accounts).

```hcl
# Auto-generated RCP Terraform configuration for acme_acquisition OU
# Generated by Headroom based on third-party account analysis

module "rcps_acme_acquisition_ou" {
  source = "../modules/rcps"
  target_id = local.acme_acquisition_ou_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "749430749651",
  ]
}
```

**Note:** Only contains CrowdStrike (749430749651) because acme-co is the only account in this OU and it only trusts CrowdStrike.

**`{account_name}_rcps.tf`**

Example of account-level RCP deployment.

```hcl
# Auto-generated RCP Terraform configuration for shared-foo-bar
# Generated by Headroom based on third-party account analysis

module "rcps_shared_foo_bar" {
  source = "../modules/rcps"
  target_id = local.shared_foo_bar_account_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
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
│   ├── deny_ec2_imds_v1/
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
    └── deny_sts_third_party_assumerole/
        ├── acme-co.json
        ├── fort-knox.json
        ├── security-tooling.json
        └── shared-foo-bar.json
```

**Example: `scps/deny_ec2_imds_v1/acme-co.json`**
```json
{
  "summary": {
    "account_name": "acme-co",
    "check": "deny_ec2_imds_v1",
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
      "instance_id": "i-fake0acmeco000001",
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

**Example: `rcps/deny_sts_third_party_assumerole/shared-foo-bar.json`**
```json
{
  "summary": {
    "account_name": "shared-foo-bar",
    "check": "deny_sts_third_party_assumerole",
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

Check: deny_sts_third_party_assumerole
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
cd test_environment/test_deny_ec2_imds_v1/
terraform init
terraform apply

# Run Headroom again
cd ../..
python -m headroom --config my_config.yaml

# Check updated results
cat test_environment/headroom_results/scps/deny_ec2_imds_v1/acme-co.json

# Destroy instances immediately
cd test_environment/test_deny_ec2_imds_v1/
terraform destroy
```

**Expected Results:**
- `acme-co`: 1 compliant instance (IMDSv2 required)
- `fort-knox`: 1 exemption (IMDSv1 allowed but tagged)
- `shared-foo-bar`: 1 violation (IMDSv1 allowed, no exemption)

#### Cleanup

**Destroy Member Account Resources:**
```bash
cd test_environment/test_deny_ec2_imds_v1/
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
- Violation flagged in the `deny_sts_third_party_assumerole` results JSON
- Account excluded from that check's RCP placement at every level. Placement
  runs once per check against only that check's blocked accounts, and a
  trust-policy wildcard blocks STS alone
- OU-level STS RCP not possible if fort-knox is in the OU; the OU remains
  eligible for the other five checks
- The other five checks write a result file for fort-knox like any other
  account and place it normally
- CloudTrail analysis recommended (future feature)

**Generated File:** Whichever file covers fort-knox for the five checks it does
not block - the root file, its OU file, or `rcps/fort_knox_rcps.tf` at account
level, depending on where each check places. Only the STS statement is switched
off for it; one wildcard no longer excludes the account from every RCP.

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
- Wildcard violation flagged for `deny_sts_third_party_assumerole`
- Account excluded from STS RCP placement at every level, account level
  included: a blocked account is kept out of that check's
  `account_third_party_map` entirely, so none of its 11 trust-policy
  third-party IDs reach an STS allowlist
- The wildcard is in a trust policy, so it blocks STS only. The ECR, KMS, S3,
  Secrets Manager and SQS checks place shared-foo-bar normally, and the
  third-party IDs those checks find do reach their allowlists

**Generated File:** Whichever file covers shared-foo-bar for the five checks it
does not block. No file carries an STS statement for this account.

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
- `test_deny_ec2_imds_v1/terraform.tfstate` (EC2 instance IDs)

**Gitignore Pattern:**
```
test_environment/terraform.tfstate*
test_environment/test_deny_ec2_imds_v1/terraform.tfstate*
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
  - **IAM:** `iam:ListUsers`, `iam:ListRoles` (both covered by AWS managed `SecurityAudit`, which grants `iam:Get*` and `iam:List*`)
- **Purpose:** Execute compliance checks in each account
- **Reference Implementation:** See `test_environment/modules/headroom_role/` and `test_environment/headroom_roles.tf`

---

## Result Structure

### Directory Layout

```
{results_dir}/
├── scps/
│   ├── deny_ec2_imds_v1/
│   │   ├── account-name_111111111111.json
│   │   ├── another-account_222222222222.json
│   │   └── ...
│   └── deny_iam_user_creation/
│       ├── account-name_111111111111.json
│       └── ...
└── rcps/
    └── deny_sts_third_party_assumerole/
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
