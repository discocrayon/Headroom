# How to Add a New Check to Headroom

**Version:** 1.0
**Last Updated:** 2025-11-09

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Code Quality Standards](#code-quality-standards)
- [Phase 0: Planning & Design](#phase-0-planning--design)
- [Phase 1: Python Implementation](#phase-1-python-implementation)
- [Phase 2: Terraform Module Updates](#phase-2-terraform-module-updates)
- [Phase 3: Terraform Generation Updates](#phase-3-terraform-generation-updates)
- [Phase 4: Testing](#phase-4-testing)
- [Phase 5: Test Environment Infrastructure](#phase-5-test-environment-infrastructure)
- [Phase 6: End-to-End Testing](#phase-6-end-to-end-testing)
- [Phase 7: Documentation](#phase-7-documentation)
- [Complete Checklist](#complete-checklist)
- [Quick Reference](#quick-reference)
- [Common Pitfalls](#common-pitfalls)

---

## Overview

This guide walks you through adding a new compliance check to Headroom, from initial planning through production deployment. Each check analyzes AWS resources for compliance with Service Control Policies (SCPs) or Resource Control Policies (RCPs).

**What You'll Build:**
1. AWS resource analysis function
2. Check class with categorization logic
3. Terraform module integration
4. Automated Terraform generation
5. Comprehensive test suite
6. Test environment infrastructure
7. Complete documentation

**Example Check:** Throughout this guide, we'll use `deny_rds_unencrypted` as a concrete example, which detects RDS databases without encryption at rest.

**Time Estimate:** 4-8 hours for a complete implementation

---

## Prerequisites

**Knowledge Requirements:**
- Python 3.13+ (dataclasses, type hints, boto3)
- AWS services and IAM policies
- Terraform (HCL syntax, modules, data sources)
- pytest for unit testing
- Git for version control

**Tools Required:**
- AWS CLI configured with appropriate credentials
- Python development environment with Headroom dependencies
- Terraform 1.0+
- Access to AWS Organizations test environment

**Existing Code Familiarity:**
- Review existing checks:
  - `headroom/checks/scps/deny_ec2_imds_v1.py`
  - `headroom/checks/scps/deny_iam_user_creation.py`
  - `headroom/checks/rcps/deny_third_party_assumerole.py`
- Understand `headroom/checks/base.py` (BaseCheck pattern)
- Review `documentation/POLICY_TAXONOMY.md` for policy patterns

---

## Code Quality Standards

**Critical:** All code MUST meet these standards before being considered complete.

### Production Code Requirements

**Complete Implementation:**
- Write production-ready code, not prototypes or sketches
- All functions fully implemented with proper error handling
- No TODO comments or placeholder implementations
- Code must be deployment-ready

**Type Safety:**
- Add complete type annotations to ALL functions, methods, and variables
- All mypy type checks MUST pass with strict mode
- Use `typing` module for complex types (List, Dict, Optional, Set, etc.)
- No use of `Any` type (makes code worse, not better)

**Imports:**
- ALL imports at top of file (never inside functions)
- No dynamic imports (no runtime `__import__` or `importlib`)
- Group imports: stdlib, third-party, local (PEP 8)

**Exception Handling:**
- NEVER use bare `except:` or `except Exception:`
- Always catch specific exceptions (ClientError, ValueError, KeyError, etc.)
- Fail-loud philosophy: let exceptions propagate with context

### Code Structure Standards

**DRY (Don't Repeat Yourself):**
- Extract duplicate code into shared functions
- No copy-paste of logic across functions
- Use helper functions for repeated patterns
- After implementation, analyze for DRY violations

**Function Design:**
- Single Responsibility Principle: one function = one purpose
- Keep functions small (typically 10-30 lines)
- Extract complex logic into separate functions
- Functions should do ONE thing well

**Indentation Minimization:**
- Use early returns to avoid nested if statements
- Use `continue` in loops to reduce indentation
- Prefer guard clauses at function start
- Think like Clean Code principles
- After implementation, check for indentation reduction opportunities

**Example of Good Structure:**
```python
def process_resources(resources: List[Resource]) -> List[Result]:
    """Process resources with minimal indentation."""
    if not resources:
        return []  # Early return

    results = []
    for resource in resources:
        if not resource.is_valid():
            continue  # Skip invalid, reduces nesting

        if resource.requires_special_handling():
            result = _handle_special_case(resource)
        else:
            result = _handle_normal_case(resource)

        results.append(result)

    return results
```

### Documentation Standards

**Docstrings (PEP 257):**
- Multi-line docstrings for ALL public functions and classes
- Include Args, Returns, Raises sections
- Add Algorithm section for complex logic
- First line is summary, then blank line, then details

**Example:**
```python
def analyze_databases(
    session: boto3.Session,
    region: str
) -> List[DatabaseResult]:
    """
    Analyze databases in specified region.

    Algorithm:
    1. List all databases via paginator
    2. Check encryption status
    3. Check exemption tags
    4. Return analysis results

    Args:
        session: boto3 Session for target account
        region: AWS region to analyze

    Returns:
        List of DatabaseResult objects

    Raises:
        ClientError: If AWS API calls fail
    """
```

**Naming:**
- Use descriptive, clear names (no abbreviations)
- Functions: `verb_noun` (get_users, check_encryption)
- Variables: descriptive nouns (database_results, not db_res)
- Constants: UPPER_SNAKE_CASE
- Classes: PascalCase
- After implementation, verify naming is clear and consistent

**Fake Account IDs:**
- Always use `111111111111` for fake/example account IDs
- NEVER use `123456789012` (old AWS documentation convention)
- This applies to: docstrings, tests, examples, documentation
- Keeps codebase consistent and easier to search/replace

### Testing Requirements

**Test Coverage:**
- 100% coverage for all new code (verified via pytest --cov)
- Test all code paths (if/else branches, try/except)
- Test edge cases explicitly
- No untested code paths

**Test Scenarios:**
- Mixed compliance (violations + exemptions + compliant)
- All compliant
- All violations
- Empty results (no resources found)
- API errors and exceptions
- Each categorization path
- Summary field calculations

**Test Data Standards:**
- Use `111111111111` for account IDs (not `123456789012`)
- Use consistent fake account IDs: `111111111111`, `222222222222`, `333333333333`
- Use descriptive resource identifiers (e.g., `test-db`, `encrypted-instance`)
- ARN format: `arn:aws:service:region:111111111111:resource-type/resource-name`

**🚨 CRITICAL - DO NOT Pollute test_environment/ in Tests:**
- **NEVER use `test_environment/headroom_results/` as `results_dir` in tests**
- **ALWAYS use `temp_results_dir` fixture or `tempfile.mkdtemp()` for test output**
- **NEVER use `DEFAULT_RESULTS_DIR` in tests** (it points to test_environment/)
- Tests that write to test_environment/ pollute the actual results directory
- Use temporary directories that are automatically cleaned up after tests

### Code Quality Tools

**Must Pass All:**
- `mypy headroom/ tests/` - No type errors
- `flake8` - No linting errors (via pre-commit or tox)
- `autopep8` - Auto-formatting applied
- `autoflake` - Unused imports removed
- `tox` - All quality checks pass

**Pre-commit Hooks:**
- trailing-whitespace: No trailing spaces
- end-of-file-fixer: Files end with newline
- No stray blank lines

### Edge Case Handling

**Must Handle:**
- Empty results (no resources)
- Missing fields in API responses
- Pagination with single page
- Pagination with many pages
- API rate limiting / throttling
- Permission errors
- Network errors
- Malformed data
- After implementation, verify all edge cases handled

### Final Quality Checks

Before considering implementation complete:

1. **DRY Analysis:** Search for duplicate code, extract to functions
2. **Indentation Review:** Look for opportunities to reduce nesting
3. **Edge Case Verification:** Confirm all edge cases have tests
4. **Naming Consistency:** Ensure all names are clear and follow conventions
5. **Type Coverage:** Verify every function has complete type annotations
6. **Documentation:** Check all docstrings follow PEP 257
7. **Tool Validation:** Run tox and confirm all checks pass

---

## Phase 0: Planning & Design

### Step 0.1: Determine Check Type

**Decision Tree:**

```
Question: What are you analyzing?
├─ AWS Resources (EC2, RDS, S3, etc.)
│  └─ Check Type: SCP
│     └─ Focus: "What resources exist that violate policy?"
│     └─ Example: Unencrypted RDS databases
│
└─ IAM Trust Policies / Access Control
   └─ Check Type: RCP
      └─ Focus: "Who can access what?"
      └─ Example: Third-party role assumptions
```

**SCP Checks:**
- Detect resources that would violate preventative policies
- Examples: EC2 instances, RDS databases, IAM users, S3 buckets
- Result: List of compliant/exempt/violating resources
- Output: Allowlists for Pattern 5, exemption tracking for Pattern 4

**RCP Checks:**
- Analyze IAM trust policies for access control
- Examples: Cross-account access, third-party principals
- Result: Allowlists of approved external accounts
- Output: Third-party account ID lists

**For This Guide:** We're creating an **SCP check** for RDS encryption.

### Step 0.2: Map to Policy Pattern

Reference `documentation/POLICY_TAXONOMY.md` to determine which pattern applies:

| Pattern | Name | Description | Use Case |
|---------|------|-------------|----------|
| 1 | Absolute Deny | Deny unconditionally | Never-allowed actions |
| 2 | Conditional Deny | Deny unless condition met | Enforce standards (encryption, tagging) |
| 3 | Module Tag / Paved Road | Allow blessed automation | Encourage correct IaC patterns |
| 4 | Exception Tag Allow | Exempt via tag | Explicit exemptions for edge cases |
| 5a | Account-Level Allowlist | Approved principals | Third-party vendor access |
| 5b | Resource ARN Allowlist | Approved resources | Grandfathered resources |
| 6 | Composition | Multiple patterns combined | Complex requirements |

**Example Decision:**
```
Check: deny_rds_unencrypted
Pattern: Pattern 2 (Conditional Deny)
Rationale: Deny RDS creation unless encrypted, enforcing encryption standard
```

### Step 0.3: Define Check Characteristics

**IMPORTANT:** Consult the AWS Service Authorization Reference for your service to identify the correct actions, resources, and condition keys:
- **Service Authorization Reference:** https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html
- **For RDS:** https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html

This reference provides:
- All available API actions for the service
- Resource types and ARN formats
- Condition keys specific to the service (e.g., `rds:StorageEncrypted`)
- **Which condition keys apply to which actions** (the most critical part!)

**🚨 CRITICAL WARNING - Condition Key Support 🚨**

**DO NOT assume a condition key is supported by an action based on:**
- Web searches
- Blog posts
- Stack Overflow answers
- Logical reasoning ("it should support this key")
- Other AWS documentation

**ONLY rely on the Service Authorization Reference table.** Each action row has a "Condition keys" column that explicitly lists ALL supported condition keys. If a condition key is not listed for an action, it CANNOT be used with that action in an IAM policy.

**Real Example - RDS StorageEncrypted:**
- ✅ `rds:CreateDBCluster` - explicitly lists `rds:StorageEncrypted`
- ✅ `rds:RestoreDBClusterFromS3` - explicitly lists `rds:StorageEncrypted`
- ✅ `rds:CreateBlueGreenDeployment` - explicitly lists `rds:StorageEncrypted`
- ❌ `rds:CreateDBInstance` - does NOT list `rds:StorageEncrypted` (only has `rds:ManageMasterUserPassword`, `rds:PubliclyAccessible`)
- ❌ `rds:RestoreDBInstanceFromDBSnapshot` - does NOT list `rds:StorageEncrypted`
- ❌ `rds:RestoreDBClusterFromSnapshot` - does NOT list `rds:StorageEncrypted`

This discovery was made by reading the actual reference documentation, not by making assumptions.

**Manual Testing for Undocumented Keys:**

In rare cases, you may want to include an action that doesn't explicitly list the condition key in the reference, especially if it's critical for security coverage. For `deny_rds_unencrypted`, we included `rds:CreateDBInstance` as a "special exception" despite it not being documented, because:
1. It's critical for protecting standalone RDS instances
2. Using the `Bool` operator means it fails safe (if unsupported, the Deny won't apply)
3. Manual testing confirmed it DOES work despite not being documented

**If you include undocumented actions, you MUST:**
1. Document the rationale in the Terraform policy comments
2. Manually test that the SCP actually blocks the action when the condition is not met
3. Update documentation with "✅ MANUALLY TESTED" confirmation
4. Accept that AWS could remove support in the future without notice

For `rds:CreateDBInstance`, we deployed the SCP to a test account and confirmed that attempting to create an unencrypted RDS instance was blocked with an explicit permissions error. This validation is documented in the policy comments.

Create a specification document for your check:

```markdown
## Check Specification: deny_rds_unencrypted

**Check Name:** deny_rds_unencrypted (snake_case)
**Check Type:** SCP
**Policy Pattern:** Pattern 2 (Conditional Deny)

**AWS Service:** RDS (Relational Database Service)
**Service Authorization Reference:** https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html

**API Calls Required:**
- rds:DescribeDBInstances (list all RDS instances)
- rds:DescribeDBClusters (list Aurora clusters)

**IAM Permissions:**
- Covered by ViewOnlyAccess managed policy

**Policy Actions to Deny:**
Only 3 actions confirmed to explicitly list rds:StorageEncrypted as a supported condition key:
- rds:CreateDBCluster (create new Aurora/DocumentDB cluster)
- rds:RestoreDBClusterFromS3 (restore cluster from S3 backup)
- rds:CreateBlueGreenDeployment (create blue-green deployment)

**Special Exception (Undocumented but Manually Tested):**
- rds:CreateDBInstance (create standalone RDS instance) - NOT listed in Service Authorization Reference but ✅ MANUALLY TESTED and confirmed to work

**Condition Key:**
- rds:StorageEncrypted (Boolean) - checked during instance/cluster creation

**CRITICAL:** The following common RDS actions do NOT support rds:StorageEncrypted (not included in policy):
- rds:RestoreDBInstanceFromDBSnapshot
- rds:RestoreDBClusterFromSnapshot
- rds:RestoreDBInstanceToPointInTime
- rds:RestoreDBClusterToPointInTime

**Coverage:**
The policy enforces encryption for new RDS instances (CreateDBInstance) and Aurora/DocumentDB clusters (CreateDBCluster). Restoration operations are not covered due to lack of documented condition key support.

**Exemption Mechanism:**
- None (strict enforcement)

**Category:** RDS (new service category)

**Terraform Module Variable:**
- deny_rds_unencrypted (boolean)

**Expected Violations:**
- RDS instances with StorageEncrypted = false
- Aurora clusters with StorageEncrypted = false

**Expected Compliant:**
- Encrypted instances/clusters
```

---

## Phase 1: Python Implementation

### Step 1.1: Add Check Name Constant

**File:** `headroom/constants.py`

Add your check name to the constants module:

```python
# Check name constants
DENY_IMDS_V1_EC2 = "deny_ec2_imds_v1"
DENY_IAM_USER_CREATION = "deny_iam_user_creation"
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"
DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"  # ADD THIS LINE
```

**Naming Convention Rules:**
- **Format:** `{action}_{aws_service}_{specific_check}`
  - Examples: `deny_ec2_imds_v1`, `deny_rds_unencrypted`, `deny_s3_third_party_access`
- **Action prefixes:** deny_, enforce_, require_
- **AWS service:** Always include the AWS service name (ec2, rds, iam, s3, etc.) immediately after the action
- **Specific check:** Describe what specifically is being checked or denied
- Use snake_case (lowercase with underscores)
- Be descriptive but concise
- Match filename (minus extension)

**Why This Convention:**
- **Discoverability:** Grouping by service (e.g., all `deny_ec2_*` checks) makes it easy to find related checks
- **Clarity:** Immediately clear which AWS service the check targets
- **Consistency:** Standardized structure across all checks
- **Alphabetical sorting:** Checks naturally group by service when sorted

**Bad Examples (old convention):**
- ❌ `deny_imds_v1_ec2` - service at the end makes discovery harder
- ❌ `imds_v1_check` - missing action prefix
- ❌ `ec2check` - not snake_case, unclear

**Good Examples:**
- ✅ `deny_ec2_imds_v1` - action, service, then specific check
- ✅ `deny_rds_unencrypted` - clear service (RDS) and check (unencrypted)
- ✅ `deny_iam_user_creation` - IAM service, user creation check

### Step 1.2: Create Data Model

**File:** `headroom/aws/rds.py` (new file)

Create a dataclass to represent analysis results:

```python
"""AWS RDS analysis functions for Headroom checks."""

from dataclasses import dataclass
from typing import List, Optional
import boto3
import logging

logger = logging.getLogger(__name__)


@dataclass
class DenyRdsUnencrypted:
    """
    Data model for RDS encryption analysis.

    Attributes:
        db_identifier: Database identifier (instance or cluster)
        db_type: Type of database ("instance" or "cluster")
        region: AWS region where database exists
        engine: Database engine (mysql, postgres, aurora, etc.)
        encrypted: True if storage encryption is enabled
        db_arn: Full ARN of the database resource
    """
    db_identifier: str
    db_type: str  # "instance" or "cluster"
    region: str
    engine: str
    encrypted: bool
    db_arn: str


def get_rds_unencrypted_analysis(
    session: boto3.Session
) -> List[DenyRdsUnencrypted]:
    """
    Analyze RDS instances and clusters for encryption configuration.

    Algorithm:
    1. Get all enabled regions from EC2
    2. For each region:
       a. Analyze RDS instances via describe_db_instances()
       b. Analyze Aurora clusters via describe_db_clusters()
       c. Check encryption status (StorageEncrypted field)
       d. Create DenyRdsUnencrypted results
    3. Return all results across all regions

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyRdsUnencrypted analysis results

    Raises:
        ClientError: If AWS API calls fail
    """
    ec2_client = session.client("ec2")
    all_results = []

    # Get all regions (including opt-in regions that may be disabled)
    # We intentionally scan all regions to detect resources in any region
    regions_response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in regions_response["Regions"]]

    for region in regions:
        logger.info(f"Analyzing RDS resources in {region}")
        regional_results = _analyze_rds_in_region(session, region)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} total RDS resources "
        f"across {len(regions)} regions"
    )
    return all_results


def _analyze_rds_in_region(
    session: boto3.Session,
    region: str
) -> List[DenyRdsUnencrypted]:
    """
    Analyze RDS resources in a specific region.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze

    Returns:
        List of DenyRdsUnencrypted results for this region
    """
    rds_client = session.client("rds", region_name=region)
    results = []

    try:
        # Analyze RDS instances
        instance_paginator = rds_client.get_paginator("describe_db_instances")
        for page in instance_paginator.paginate():
            for instance in page.get("DBInstances", []):
                result = _analyze_rds_instance(rds_client, instance, region)
                results.append(result)

        # Analyze Aurora clusters
        cluster_paginator = rds_client.get_paginator("describe_db_clusters")
        for page in cluster_paginator.paginate():
            for cluster in page.get("DBClusters", []):
                result = _analyze_rds_cluster(rds_client, cluster, region)
                results.append(result)

    except Exception as e:
        logger.error(f"Failed to analyze RDS in region {region}: {e}")
        raise

    return results


def _analyze_rds_instance(
    rds_client: any,
    instance: dict,
    region: str
) -> DenyRdsUnencrypted:
    """
    Analyze single RDS instance for encryption.

    Args:
        rds_client: Boto3 RDS client
        instance: DB instance dict from describe_db_instances
        region: AWS region

    Returns:
        DenyRdsUnencrypted result for this instance
    """
    db_identifier = instance["DBInstanceIdentifier"]
    db_arn = instance["DBInstanceArn"]
    encrypted = instance.get("StorageEncrypted", False)
    engine = instance.get("Engine", "unknown")

    return DenyRdsUnencrypted(
        db_identifier=db_identifier,
        db_type="instance",
        region=region,
        engine=engine,
        encrypted=encrypted,
        db_arn=db_arn
    )


def _analyze_rds_cluster(
    rds_client: any,
    cluster: dict,
    region: str
) -> DenyRdsUnencrypted:
    """
    Analyze single Aurora cluster for encryption.

    Args:
        rds_client: Boto3 RDS client
        cluster: DB cluster dict from describe_db_clusters
        region: AWS region

    Returns:
        DenyRdsUnencrypted result for this cluster
    """
    db_identifier = cluster["DBClusterIdentifier"]
    db_arn = cluster["DBClusterArn"]
    encrypted = cluster.get("StorageEncrypted", False)
    engine = cluster.get("Engine", "unknown")

    return DenyRdsUnencrypted(
        db_identifier=db_identifier,
        db_type="cluster",
        region=region,
        engine=engine,
        encrypted=encrypted,
        db_arn=db_arn
    )
```

**Key Points:**
- Use `@dataclass` for data models
- Include comprehensive docstrings with Algorithm sections
- Handle pagination for AWS API calls
- **Region Scanning:** Use `describe_regions()` WITHOUT filters - intentionally scan all regions including opt-in regions that may be disabled to ensure complete visibility
- Log at appropriate levels (info, warning, error)
- Let exceptions propagate (fail-loud philosophy)
- Use type hints for all parameters and returns

### Step 1.3: Create Check Class

**File:** `headroom/checks/scps/deny_rds_unencrypted.py` (new file)

Implement the check class using the Template Method pattern from BaseCheck:

```python
"""Check for RDS databases that violate the deny_rds_unencrypted SCP."""

from typing import Any, Dict, List

import boto3

from ...aws.rds import DenyRdsUnencrypted, get_rds_unencrypted_analysis
from ...constants import DENY_RDS_UNENCRYPTED
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_RDS_UNENCRYPTED)
class DenyRdsUnencryptedCheck(BaseCheck[DenyRdsUnencrypted]):
    """
    Check for RDS databases that would be blocked by deny_rds_unencrypted SCP.

    This check identifies:
    - RDS instances and Aurora clusters without encryption (violations)
    - Encrypted databases (compliant)
    - Overall compliance status for the account
    """

    def analyze(self, session: boto3.Session) -> List[DenyRdsUnencrypted]:
        """
        Analyze RDS databases for encryption configuration.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyRdsUnencrypted analysis results
        """
        return get_rds_unencrypted_analysis(session)

    def categorize_result(
        self,
        result: DenyRdsUnencrypted
    ) -> tuple[str, Dict[str, Any]]:
        """
        Categorize a single RDS encryption result.

        Args:
            result: Single DenyRdsUnencrypted analysis result

        Returns:
            Tuple of (category, result_dict) where category is:
            - "violation": Unencrypted database
            - "compliant": Encryption enabled
        """
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

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build RDS encryption check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_databases": total,
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
```

**BaseCheck Methods You MUST Implement:**
1. `analyze(session)` - Fetch data from AWS
2. `categorize_result(result)` - Map to violation/compliant (or exemption if Pattern 4)
3. `build_summary_fields(check_result)` - Generate check-specific stats

**The Template Method (`execute()`) Handles:**
- Calling your `analyze()` method
- Calling `categorize_result()` for each result
- Building summary with `build_summary_fields()`
- Writing JSON to disk
- Printing completion message

### Step 1.4: Verify Check Registration

**File:** `headroom/checks/__init__.py`

**No manual registration required!** The check discovery system automatically finds and imports all check modules in the `scps/` and `rcps/` directories when the package is loaded.

Verify your check is registered:

```bash
python -c "from headroom.checks.registry import get_check_names; print(sorted(get_check_names()))"
# Should include 'deny_rds_unencrypted' in the list
```

**How It Works:**
- When `headroom.checks` is imported, `_discover_and_register_checks()` automatically runs
- It walks through `scps/` and `rcps/` directories using `pkgutil.iter_modules()`
- It imports all Python files (excluding `__init__.py`)
- The `@register_check` decorator executes when each module is imported
- Your check is automatically registered in `_CHECK_REGISTRY`

**No Maintenance Required:**
- Simply create your check file in the appropriate directory (`scps/` or `rcps/`)
- No need to edit `__init__.py` or any other registration code
- Zero chance of forgetting to register a new check

---

## Phase 2: Terraform Module Updates

### Step 2.1: Add Module Variable

**File:** `test_environment/modules/scps/variables.tf`

Add a boolean variable for your check:

```hcl
# ... existing variables ...

# RDS  # ADD THIS SECTION

variable "deny_rds_unencrypted" {
  type        = bool
  description = "Deny creation of RDS instances and clusters without encryption at rest"
}
```

**Variable Naming Rules:**
- Match check name exactly (underscores, not hyphens)
- Use `bool` type for enable/disable flags
- Add descriptive documentation
- Be consistent with existing check variables (no `nullable` attribute for booleans)

**For Allowlist Variables (Pattern 5b):**
```hcl
variable "allowed_rds_databases" {
  type        = list(string)
  default     = []
  description = "List of RDS database ARNs that are allowed to exist unencrypted"
}
```

### Step 2.2: Add Policy Statement to Module

**File:** `test_environment/modules/scps/locals.tf`

**IMPORTANT:** Before writing your policy, consult the AWS Service Authorization Reference for your service to ensure you're using the correct actions and condition keys:
- **RDS:** https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html
- **EC2:** https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
- **IAM:** https://docs.aws.amazon.com/service-authorization/latest/reference/list_identityandaccessmanagement.html
- **Full list:** https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html

Add your policy statement to the conditional statement list:

```hcl
locals {
  possible_scp_1_denies = [
    # ... existing statements ...

    # var.deny_rds_unencrypted
    # -->
    # Sid: DenyRdsUnencrypted
    # Denies creation of unencrypted RDS databases and clusters
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html
    # Only actions confirmed to explicitly list rds:StorageEncrypted as a supported condition key
    {
      include = var.deny_rds_unencrypted,
      statement = {
        Action = [
          "rds:CreateDBInstance",
          "rds:CreateDBCluster",
          "rds:RestoreDBInstanceFromDBSnapshot",
          "rds:RestoreDBClusterFromSnapshot"
        ]
        Resource = "*"
        Condition = {
          "Bool" = {
            "rds:StorageEncrypted" = "false"
          }
        }
      }
    },
  ]
  # ... rest of locals ...
}
```

**Policy Statement Rules:**
- **Check the AWS Service Authorization Reference first** to verify actions and condition keys
- Include the service authorization reference URL as a comment in your policy
- Use `include` field tied to your variable
- Put actual policy in `statement` field
- Don't include `Effect` (added automatically as "Deny")
- Match AWS policy syntax exactly
- Test policy logic carefully

**Common Condition Keys:**
- `StringEquals`, `StringNotEquals`
- `Bool`
- `NumericLessThan`, `NumericGreaterThan`
- `aws:RequestTag/TagKey`
- `aws:ResourceTag/TagKey`
- `aws:PrincipalTag/TagKey`

---

## Phase 3: Terraform Generation Updates

### Step 3.1: Update SCP Terraform Generation

**File:** `headroom/terraform/generate_scps.py`

Find the `_build_scp_terraform_module` function and add your service category:

```python
def _build_scp_terraform_module(...):
    # ... existing code to collect enabled checks ...

    # EC2
    terraform_content += "  # EC2\n"
    deny_ec2_imds_v1 = "deny_ec2_imds_v1" in enabled_checks
    terraform_content += f"  deny_ec2_imds_v1 = {str(deny_ec2_imds_v1).lower()}\n"
    terraform_content += "\n"

    # IAM
    terraform_content += "  # IAM\n"
    deny_iam_user_creation = "deny_iam_user_creation" in enabled_checks
    terraform_content += f"  deny_iam_user_creation = {str(deny_iam_user_creation).lower()}\n"

    if deny_iam_user_creation:
        # ... IAM user allowlist logic ...

    terraform_content += "\n"

    # RDS  # ADD THIS ENTIRE SECTION
    terraform_content += "  # RDS\n"
    deny_rds_unencrypted = "deny_rds_unencrypted" in enabled_checks
    terraform_content += f"  deny_rds_unencrypted = {str(deny_rds_unencrypted).lower()}\n"

    terraform_content += "}\n"
    return terraform_content
```

**Key Points:**
- Add service category comment (e.g., `# RDS`)
- Check if check name is in `enabled_checks` set
- Generate boolean variable assignment
- Maintain alphabetical category ordering (EC2, IAM, RDS, S3, etc.)
- Add blank line between categories for readability

**For Checks with Allowlists:**
```python
    # RDS
    terraform_content += "  # RDS\n"
    deny_rds_unencrypted = "deny_rds_unencrypted" in enabled_checks
    terraform_content += f"  deny_rds_unencrypted = {str(deny_rds_unencrypted).lower()}\n"

    if deny_rds_unencrypted:
        # Get allowlist from recommendations
        allowed_rds_arns = []
        for rec in recommendations:
            if rec.check_name.replace("-", "_") == "deny_rds_unencrypted" and rec.allowed_rds_arns:
                allowed_rds_arns = rec.allowed_rds_arns
                break

        if allowed_rds_arns:
            terraform_content += "  allowed_rds_databases = [\n"
            for arn in allowed_rds_arns:
                transformed_arn = _replace_account_id_in_arn(arn, organization_hierarchy)
                terraform_content += f'    "{transformed_arn}",\n'
            terraform_content += "  ]\n"
```

### Step 3.2: For RCP Checks

If creating an RCP check, modify `headroom/terraform/generate_rcps.py` instead:

```python
def _build_rcp_terraform_module(...):
    terraform_content = f'''# Auto-generated RCP Terraform configuration for {comment}
# Generated by Headroom based on IAM trust policy analysis

module "{module_name}" {{
  source = "../modules/rcps"
  target_id = {target_id_reference}

'''

    # Add your RCP boolean and allowlist logic here
    # RCPs typically always have allowlists of account IDs

    terraform_content += "}\n"
    return terraform_content
```

---

## Phase 4: Testing

### Step 4.1: Write Check Unit Tests

**File:** `tests/test_checks_deny_rds_unencrypted.py` (new file)

Create comprehensive unit tests for your check class:

```python
"""
Tests for headroom.checks.scps.deny_rds_unencrypted module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.scps.deny_rds_unencrypted import DenyRdsUnencryptedCheck
from headroom.constants import DENY_RDS_UNENCRYPTED
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.rds import DenyRdsUnencrypted


class TestCheckDenyRdsUnencrypted:
    """Test deny_rds_unencrypted check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_rds_results_mixed(self) -> List[DenyRdsUnencrypted]:
        """Create sample RDS results with mixed compliance status."""
        return [
            DenyRdsUnencrypted(
                db_identifier="encrypted-db",
                db_type="instance",
                region="us-east-1",
                engine="postgres",
                encrypted=True,
                db_arn="arn:aws:rds:us-east-1:111111111111:db:encrypted-db"
            ),
            DenyRdsUnencrypted(
                db_identifier="unencrypted-db",
                db_type="instance",
                region="us-east-1",
                engine="mysql",
                encrypted=False,
                db_arn="arn:aws:rds:us-east-1:111111111111:db:unencrypted-db"
            ),
        ]

    def test_check_deny_rds_unencrypted_mixed_results(
        self,
        sample_rds_results_mixed: List[DenyRdsUnencrypted],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.scps.deny_rds_unencrypted.get_rds_unencrypted_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_rds_results_mixed

            check = DenyRdsUnencryptedCheck(
                check_name=DENY_RDS_UNENCRYPTED,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
            )
            check.execute(mock_session)

            # Verify write_check_results was called
            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[0][0]

            # Verify categorization
            assert len(results_data["violations"]) == 1
            assert len(results_data["compliant_instances"]) == 1

            # Verify summary fields
            summary = results_data["summary"]
            assert summary["total_databases"] == 2
            assert summary["violations"] == 1
            assert summary["compliant"] == 1
            assert summary["compliance_percentage"] == pytest.approx(50.0, rel=0.01)

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
    ) -> None:
        """Test check with all databases compliant."""
        mock_session = MagicMock()

        all_compliant = [
            DenyRdsUnencrypted(
                db_identifier="encrypted-db-1",
                db_type="instance",
                region="us-east-1",
                engine="postgres",
                encrypted=True,
                db_arn="arn:aws:rds:us-east-1:111111111111:db:encrypted-db-1"
            ),
        ]

        with (
            patch("headroom.checks.scps.deny_rds_unencrypted.get_rds_unencrypted_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyRdsUnencryptedCheck(
                check_name=DENY_RDS_UNENCRYPTED,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["compliance_percentage"] == 100.0
            assert summary["violations"] == 0

    def test_categorize_result_violation(self) -> None:
        """Test categorization of violation."""
        check = DenyRdsUnencryptedCheck(
            check_name=DENY_RDS_UNENCRYPTED,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
        )

        result = DenyRdsUnencrypted(
            db_identifier="unencrypted-db",
            db_type="instance",
            region="us-east-1",
            engine="mysql",
            encrypted=False,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:unencrypted-db"
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["encrypted"] is False

    def test_categorize_result_compliant(self) -> None:
        """Test categorization of compliant."""
        check = DenyRdsUnencryptedCheck(
            check_name=DENY_RDS_UNENCRYPTED,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
        )

        result = DenyRdsUnencrypted(
            db_identifier="encrypted-db",
            db_type="instance",
            region="us-east-1",
            engine="postgres",
            encrypted=True,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:encrypted-db"
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["encrypted"] is True
```

### Step 4.2: Write AWS Analysis Function Tests

**File:** `tests/test_aws_rds.py` (new file)

Test the AWS API interaction layer:

```python
"""Tests for headroom.aws.rds module."""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from headroom.aws.rds import (
    DenyRdsUnencrypted,
    get_rds_unencrypted_analysis
)


class TestGetRdsUnencryptedAnalysis:
    """Test get_rds_unencrypted_analysis function."""

    def test_get_rds_unencrypted_analysis_success(self) -> None:
        """Test successful RDS analysis with instances and clusters."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_rds_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "rds": mock_rds_client,
        }.get(service)

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        # Mock RDS instances
        instance_paginator = MagicMock()
        instance_paginator.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "test-db",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:test-db",
                        "StorageEncrypted": True,
                        "Engine": "postgres"
                    }
                ]
            }
        ]

        # Mock RDS clusters
        cluster_paginator = MagicMock()
        cluster_paginator.paginate.return_value = [
            {
                "DBClusters": [
                    {
                        "DBClusterIdentifier": "test-cluster",
                        "DBClusterArn": "arn:aws:rds:us-east-1:111111111111:cluster:test-cluster",
                        "StorageEncrypted": False,
                        "Engine": "aurora-mysql"
                    }
                ]
            }
        ]

        mock_rds_client.get_paginator.side_effect = lambda operation: {
            "describe_db_instances": instance_paginator,
            "describe_db_clusters": cluster_paginator,
        }.get(operation)

        results = get_rds_unencrypted_analysis(mock_session)

        assert len(results) == 2
        assert results[0].db_identifier == "test-db"
        assert results[0].encrypted is True
        assert results[1].db_identifier == "test-cluster"
        assert results[1].encrypted is False
```

### Step 4.3: Run Tests and Verify Coverage

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_checks_deny_rds_unencrypted.py -v

# Run with coverage
pytest tests/ --cov=headroom --cov-report=html --cov-report=term

# Check coverage for your new files specifically
pytest tests/test_checks_deny_rds_unencrypted.py tests/test_aws_rds.py \
  --cov=headroom/checks/scps/deny_rds_unencrypted.py \
  --cov=headroom/aws/rds.py \
  --cov-report=term-missing

# Run type checking
mypy headroom/ tests/

# Run all quality checks
tox
```

**Coverage Target:** Aim for 100% coverage on new code

---

## Phase 5: Test Environment Infrastructure

### Step 5.1: Create Test Resources

**File:** `test_environment/test_deny_rds_unencrypted.tf` (new file)

Create test RDS resources demonstrating all scenarios:

```hcl
# Test RDS databases for deny_rds_unencrypted SCP functionality testing

# Database 1: Encrypted RDS instance (compliant)
resource "aws_db_instance" "encrypted_postgres" {
  provider = aws.acme_co

  identifier     = "headroom-test-encrypted"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  storage_encrypted     = true

  username = "testadmin"
  password = "temporary-password-change-me"  # Change in production

  skip_final_snapshot = true

  tags = {
    Purpose = "Headroom RDS encryption test - compliant"
  }
}

# Database 2: Unencrypted Aurora cluster (violation)
resource "aws_rds_cluster" "unencrypted_violation" {
  provider = aws.shared_foo_bar

  cluster_identifier = "headroom-test-violation"
  engine             = "aurora-mysql"
  engine_version     = "8.0.mysql_aurora.3.02.0"

  master_username = "testadmin"
  master_password = "temporary-password-change-me"

  storage_encrypted = false

  skip_final_snapshot = true

  tags = {
    Purpose = "Headroom RDS encryption test - intentional violation"
  }
}

# Note: RDS instances incur costs (~$15-20/month for t3.micro)
# Destroy these resources after testing
```

**Cost Warning:** Add a README explaining costs:

**File:** `test_environment/test_deny_rds_unencrypted/README.md`

```markdown
# RDS Encryption Test

⚠️ **COST WARNING:** RDS instances incur ongoing costs even when idle.

## Cost Estimate

- 2x db.t3.micro instances: ~$15-20/month
- Storage (20GB each): ~$5/month
- **Total: ~$20-25/month if left running**

## Usage

```bash
# Deploy test RDS instances
cd test_environment/
terraform apply -target=aws_db_instance.encrypted_postgres \
                -target=aws_rds_cluster.unencrypted_violation

# Run Headroom analysis
cd ..
python -m headroom --config my_config.yaml

# DESTROY immediately after testing
cd test_environment/
terraform destroy -target=aws_db_instance.encrypted_postgres \
                  -target=aws_rds_cluster.unencrypted_violation
```

## Test Scenarios

| Database | Account | Type | Encrypted | Expected Result |
|----------|---------|------|-----------|-----------------|
| encrypted-postgres | acme-co | instance | Yes | Compliant |
| unencrypted-violation | shared-foo-bar | cluster | No | Violation |
```

### Step 5.2: Update Headroom Role Permissions (if needed)

**File:** `test_environment/modules/headroom_role/main.tf`

ViewOnlyAccess typically covers RDS read operations, but verify:

```hcl
resource "aws_iam_role" "headroom" {
  name = "Headroom"

  # ... trust policy ...

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/ViewOnlyAccess",  # Includes RDS read
    "arn:aws:iam::aws:policy/SecurityAudit",
  ]
}

# ViewOnlyAccess includes rds:DescribeDBInstances and rds:DescribeDBClusters
# No additional permissions needed for this check
```

### Step 5.3: Deploy Test Infrastructure

```bash
cd test_environment/
terraform plan
terraform apply

# Verify resources created
aws rds describe-db-instances --profile acme-co
aws rds describe-db-clusters --profile shared-foo-bar

# Wait for RDS instances to become available (5-10 minutes)
```

---

## Phase 6: End-to-End Testing

### Step 6.1: Run Headroom Against Test Environment

```bash
# From repo root
python -m headroom --config my_config.yaml
```

**Expected Output:**
```
================================================================================
RUNNING CHECKS
================================================================================

Scanning account: acme-co (111111111111)
✅ Completed deny_rds_unencrypted for account acme-co
   Violations: 0, Compliant: 1

Scanning account: fort-knox (222222222222)
✅ Completed deny_rds_unencrypted for account fort-knox
   Violations: 0, Compliant: 0

Scanning account: shared-foo-bar (333333333333)
✅ Completed deny_rds_unencrypted for account shared-foo-bar
   Violations: 1, Compliant: 0

================================================================================
SCP/RCP PLACEMENT RECOMMENDATIONS
================================================================================

Check: deny_rds_unencrypted
Recommended Level: ACCOUNT
Affected Accounts: 1 (acme-co)
Compliance: 100.0%
Reasoning: Only one account has 100% compliance - deploy at account level
```

### Step 6.2: Verify Results Files

```bash
ls test_environment/headroom_results/scps/deny_rds_unencrypted/
# acme-co.json
# fort-knox.json
# security-tooling.json
# shared-foo-bar.json

cat test_environment/headroom_results/scps/deny_rds_unencrypted/acme-co.json
```

**Expected JSON Structure:**
```json
{
  "summary": {
    "account_name": "acme-co",
    "account_id": "111111111111",
    "check": "deny_rds_unencrypted",
    "total_databases": 1,
    "violations": 0,
    "compliant": 1,
    "compliance_percentage": 100.0
  },
  "violations": [],
  "compliant_instances": [
    {
      "db_identifier": "headroom-test-encrypted",
      "db_type": "instance",
      "region": "us-east-1",
      "engine": "postgres",
      "encrypted": true,
      "db_arn": "arn:aws:rds:us-east-1:111111111111:db:headroom-test-encrypted"
    }
  ]
}
```

### Step 6.3: Verify Terraform Generation

```bash
ls test_environment/scps/
# Should see updated or new files with deny_rds_unencrypted

cat test_environment/scps/acme_co_scps.tf
```

**Expected Generated Terraform:**
```hcl
# Auto-generated SCP Terraform configuration for acme-co
# Generated by Headroom based on compliance analysis

module "scps_acme_co" {
  source = "../modules/scps"
  target_id = local.acme_co_account_id

  # EC2
  deny_ec2_imds_v1 = false

  # IAM
  deny_iam_user_creation = false

  # RDS
  deny_rds_unencrypted = true  # NEW - 100% compliant
}
```

### Step 6.4: Validate Generated Terraform

```bash
cd test_environment/scps/
terraform validate
terraform plan

# Should show valid plan with new SCP module calls
```

---

## Phase 7: Documentation

### Step 7.1: Update POLICY_TAXONOMY.md

**File:** `documentation/POLICY_TAXONOMY.md`

Add your check as an example of the policy pattern:

```markdown
### Pattern 2 Example: `deny_rds_unencrypted`

**Check:** `headroom/checks/scps/deny_rds_unencrypted.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines X-Y

This check identifies RDS databases (instances and Aurora clusters) without
encryption at rest enabled. The SCP denies database creation and restoration
operations unless encryption is enabled.

**Policy Structure:**
- Deny `rds:CreateDBInstance`, `rds:CreateDBCluster`, restoration operations
- Unless `rds:StorageEncrypted` equals "true"

**Headroom's Role:** Scans all accounts and reports existing databases with
their encryption status. This informs deployment decisions and identifies
resources that would be impacted by the SCP.
```

### Step 7.2: Update Headroom-Specification.md

**File:** `Headroom-Specification.md`

Add comprehensive documentation of your check:

```markdown
### Deny RDS Unencrypted

**Purpose:** Identify RDS databases and Aurora clusters without encryption at rest enabled.

**Data Model:**
\`\`\`python
@dataclass
class DenyRdsUnencrypted:
    db_identifier: str  # Database identifier
    db_type: str        # "instance" or "cluster"
    region: str         # AWS region
    engine: str         # Database engine
    encrypted: bool     # True if storage encryption enabled
    db_arn: str         # Full database ARN
\`\`\`

**Analysis Function:**
\`\`\`python
def get_rds_unencrypted_analysis(session: boto3.Session) -> List[DenyRdsUnencrypted]:
    """
    Scan all regions for RDS databases.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. Describe all instances via describe_db_instances() (paginated)
       b. Describe all clusters via describe_db_clusters() (paginated)
       c. Check StorageEncrypted field
       d. Create DenyRdsUnencrypted result
    3. Return all results across all regions
    """
\`\`\`

**Categorization Logic:**
\`\`\`python
def categorize_result(self, result: DenyRdsUnencrypted) -> tuple[str, Dict[str, Any]]:
    if not result.encrypted:
        return ("violation", result_dict)
    else:
        return ("compliant", result_dict)
\`\`\`

**Summary Fields:**
\`\`\`python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    total = len(violations) + len(compliant)
    compliant_count = len(compliant)
    compliance_pct = (compliant_count / total * 100) if total > 0 else 100.0

    return {
        "total_databases": total,
        "violations": len(violations),
        "compliant": len(compliant),
        "compliance_percentage": round(compliance_pct, 2)
    }
\`\`\`

**Result JSON Schema:**
\`\`\`json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_rds_unencrypted",
    "total_databases": 0,
    "violations": 0,
    "compliant": 0,
    "compliance_percentage": 100.0
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
  "compliant_instances": []
}
\`\`\`
```

### Step 7.3: Update Module README

**File:** `test_environment/modules/scps/README.md`

Document the new variable and policy:

```markdown
## Variables

### RDS

#### `deny_rds_unencrypted`
- **Type:** `bool`
- **Required:** Yes
- **Description:** Enable SCP to deny creation of RDS instances and Aurora clusters without encryption at rest

**Policy Pattern:** Conditional Deny (Pattern 2)

**Actions Denied:**
- `rds:CreateDBInstance`
- `rds:CreateDBCluster`
- `rds:RestoreDBInstanceFromDBSnapshot`
- `rds:RestoreDBClusterFromSnapshot`

**Exemption Mechanism:** None (strict enforcement of encryption)

**Example:**
\`\`\`hcl
module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  deny_rds_unencrypted = true
}
\`\`\`

**Testing:** See `test_environment/test_deny_rds_unencrypted.tf` for test scenarios
```

### Step 7.4: Create Test Environment README

**File:** `test_environment/test_deny_rds_unencrypted/README.md`

Document the test infrastructure and usage:

```markdown
# RDS Encryption Test

Tests `deny_rds_unencrypted` SCP check functionality.

⚠️ **COST WARNING:** RDS instances incur ongoing costs even when idle.

## Cost Estimate

- 2x db.t3.micro instances: ~$15-20/month
- Storage (20GB each @ $0.115/GB-month): ~$5/month
- **Total: ~$20-25/month if left running**

## Test Scenarios

| Database | Account | Type | Engine | Encrypted | Expected Result |
|----------|---------|------|--------|-----------|-----------------|
| encrypted-postgres | acme-co | instance | postgres | Yes | Compliant |
| unencrypted-violation | shared-foo-bar | cluster | aurora-mysql | No | Violation |

## Usage

### Deploy Test Resources

```bash
cd test_environment/
terraform apply -target=aws_db_instance.encrypted_postgres \
                -target=aws_rds_cluster.unencrypted_violation

# Wait 5-10 minutes for databases to become available
```

### Run Headroom Analysis

```bash
cd ..
python -m headroom --config my_config.yaml

# Verify results
cat test_environment/headroom_results/scps/deny_rds_unencrypted/acme-co.json
```

### Cleanup (IMPORTANT)

```bash
cd test_environment/
terraform destroy -target=aws_db_instance.encrypted_postgres \
                  -target=aws_rds_cluster.unencrypted_violation
```

## Expected Results

**acme-co:** 1 compliant database (encrypted-postgres)
**shared-foo-bar:** 1 violation (unencrypted-violation)

## Troubleshooting

**Database creation slow:** RDS instances take 5-10 minutes to become available
**Headroom timeout:** Ensure databases are in "available" status before running
**Permission errors:** Verify Headroom role has `rds:DescribeDBInstances`, `rds:DescribeDBClusters`
```

### Step 7.5: Update Conversation History

**File:** `conversation_history.md`

Append a summary of this check addition (append to end of file):

```markdown
## 2025-11-09 - Added deny_rds_unencrypted Check

**Type:** SCP check
**Pattern:** Pattern 2 (Conditional Deny)

**Files Created:**
- `headroom/aws/rds.py` - RDS analysis functions
- `headroom/checks/scps/deny_rds_unencrypted.py` - Check implementation
- `tests/test_aws_rds.py` - AWS analysis tests
- `tests/test_checks_deny_rds_unencrypted.py` - Check tests
- `test_environment/test_deny_rds_unencrypted.tf` - Test infrastructure
- `test_environment/test_deny_rds_unencrypted/README.md` - Test documentation

**Files Modified:**
- `headroom/constants.py` - Added DENY_RDS_UNENCRYPTED constant
- `headroom/checks/__init__.py` - Added import for registration
- `headroom/terraform/generate_scps.py` - Added RDS category generation
- `test_environment/modules/scps/variables.tf` - Added deny_rds_unencrypted variable
- `test_environment/modules/scps/locals.tf` - Added RDS encryption policy statement
- `test_environment/modules/scps/README.md` - Documented new variable
- `documentation/POLICY_TAXONOMY.md` - Added deny_rds_unencrypted example
- `Headroom-Specification.md` - Added comprehensive check documentation

**Test Coverage:** 100% for new code (verified via pytest --cov)
**Test Results:** All tests passing (pytest + tox)
**E2E Testing:** Successfully tested with test environment RDS resources

**Deployment Notes:**
- RDS test resources cost ~$22-37/month if left running
- Test databases take 5-10 minutes to become available
- Remember to destroy test resources after testing
```

---

## Complete Checklist

Use this checklist when adding any new check:

### Planning Phase
- [ ] Determined check type (SCP or RCP)
- [ ] Mapped to policy pattern from POLICY_TAXONOMY.md
- [ ] Defined check characteristics (name, service, APIs, permissions)
- [ ] Created check specification document
- [ ] Identified exemption mechanism (if Pattern 4)
- [ ] Identified allowlist requirements (if Pattern 5)

### Python Implementation
- [ ] Added check name constant to `headroom/constants.py`
- [ ] Created data model dataclass in `headroom/aws/{service}.py`
- [ ] Implemented AWS analysis function with:
  - [ ] Proper pagination for list operations
  - [ ] Multi-region support (if applicable)
  - [ ] Error handling and logging
  - [ ] Type hints for all parameters/returns
  - [ ] Comprehensive docstrings with Algorithm sections
- [ ] Created check class in `headroom/checks/{scps|rcps}/{check_name}.py`:
  - [ ] Inherits from `BaseCheck[T]`
  - [ ] Decorated with `@register_check()`
  - [ ] Implemented `analyze()` method
  - [ ] Implemented `categorize_result()` method
  - [ ] Implemented `build_summary_fields()` method
- [ ] Verified check is automatically registered (no manual import needed)

### Terraform Modules
- [ ] Added boolean variable to `test_environment/modules/{scps|rcps}/variables.tf`
- [ ] Added allowlist variable (if Pattern 5)
- [ ] Added policy statement to `test_environment/modules/{scps|rcps}/locals.tf`:
  - [ ] Used `include` field tied to variable
  - [ ] Verified policy syntax matches AWS format
  - [ ] Tested condition logic
  - [ ] Added descriptive comments

### Terraform Generation
- [ ] Updated `headroom/terraform/generate_scps.py` or `generate_rcps.py`:
  - [ ] Added service category comment
  - [ ] Added check boolean generation
  - [ ] Added allowlist generation (if applicable)
  - [ ] Maintained alphabetical category ordering
  - [ ] Added blank lines between categories

### Unit Tests
- [ ] Created `tests/test_checks_{check_name}.py`:
  - [ ] Test mixed compliance scenario
  - [ ] Test all-compliant scenario
  - [ ] Test all-violations scenario
  - [ ] Test empty results scenario
  - [ ] Test each categorization path
  - [ ] Test summary field calculation
- [ ] Created `tests/test_aws_{service}.py` (if new service):
  - [ ] Test successful analysis
  - [ ] Test with empty results
  - [ ] Test error handling
  - [ ] Test pagination scenarios
  - [ ] Test exemption tag detection
- [ ] All tests pass: `pytest tests/ -v`
- [ ] Achieved 100% coverage on new code: `pytest --cov`
- [ ] Type checks pass: `mypy headroom/ tests/`
- [ ] Linting passes: `tox`

### Test Environment
- [ ] Created `test_environment/test_{check_name}.tf`:
  - [ ] Created compliant test resources
  - [ ] Created exemption test resources (if Pattern 4)
  - [ ] Created violation test resources
  - [ ] Added cost warnings for expensive resources
  - [ ] Used provider aliases for cross-account deployment
- [ ] Created `test_environment/test_{check_name}/README.md`:
  - [ ] Documented test scenarios
  - [ ] Included cost estimates
  - [ ] Provided usage instructions
  - [ ] Added cleanup commands
- [ ] Updated Headroom role permissions (if needed)
- [ ] Deployed test infrastructure: `terraform apply`
- [ ] Verified resources created successfully

### End-to-End Testing
- [ ] Ran Headroom against test environment
- [ ] Verified results JSON files created
- [ ] Verified summary fields accurate
- [ ] Verified categorization correct (violations/exemptions/compliant)
- [ ] Verified Terraform files generated
- [ ] Verified module calls include new check
- [ ] Verified boolean flags correct (true/false)
- [ ] Verified allowlists populated (if applicable)
- [ ] Validated generated Terraform: `terraform validate`
- [ ] Planned generated Terraform: `terraform plan`

### Documentation
- [ ] Updated `documentation/POLICY_TAXONOMY.md`:
  - [ ] Added check as pattern example
  - [ ] Explained policy structure
  - [ ] Described Headroom's role
- [ ] Updated `Headroom-Specification.md`:
  - [ ] Added check overview
  - [ ] Documented data model
  - [ ] Documented analysis function
  - [ ] Documented categorization logic
  - [ ] Included result JSON schema
- [ ] Updated `test_environment/modules/{scps|rcps}/README.md`:
  - [ ] Documented new variable
  - [ ] Explained policy pattern
  - [ ] Provided usage example
  - [ ] Linked to test scenarios
- [ ] Updated `conversation_history.md`:
  - [ ] Added date and summary
  - [ ] Listed files created/modified
  - [ ] Noted test coverage
  - [ ] Included deployment notes

### Code Quality Verification
- [ ] **DRY Analysis:**
  - [ ] Searched for duplicate code patterns
  - [ ] Extracted repeated logic into shared functions
  - [ ] No copy-paste code between functions
  - [ ] Helper functions used for common patterns
- [ ] **Indentation Review:**
  - [ ] Used early returns to reduce nesting
  - [ ] Used `continue` in loops where appropriate
  - [ ] Guard clauses at function start
  - [ ] Maximum indentation depth minimized
- [ ] **Type Annotations:**
  - [ ] ALL functions have complete type hints
  - [ ] ALL parameters typed
  - [ ] ALL return types specified
  - [ ] No use of `Any` type
  - [ ] `mypy headroom/ tests/` passes with no errors
- [ ] **Import Organization:**
  - [ ] All imports at top of file
  - [ ] No dynamic imports
  - [ ] Grouped: stdlib, third-party, local
  - [ ] No imports inside functions
- [ ] **Exception Handling:**
  - [ ] No bare `except:` statements
  - [ ] No `except Exception:` statements
  - [ ] All exceptions caught are specific (ClientError, ValueError, etc.)
  - [ ] Exceptions propagate with context
- [ ] **Function Design:**
  - [ ] Each function has single responsibility
  - [ ] Functions are small (typically 10-30 lines)
  - [ ] Complex logic extracted to separate functions
  - [ ] Function names clearly describe purpose
- [ ] **Documentation:**
  - [ ] All public functions have multi-line docstrings
  - [ ] Docstrings follow PEP 257
  - [ ] Include Args, Returns, Raises sections
  - [ ] Algorithm sections for complex logic
- [ ] **Naming Conventions:**
  - [ ] Functions: verb_noun format
  - [ ] Variables: descriptive nouns (no abbreviations)
  - [ ] Constants: UPPER_SNAKE_CASE
  - [ ] Classes: PascalCase
  - [ ] All names clear and consistent
- [ ] **Edge Cases:**
  - [ ] Empty results handled
  - [ ] Missing fields handled
  - [ ] API errors handled
  - [ ] All edge cases have tests
- [ ] **Code Quality Tools:**
  - [ ] `tox` passes all checks
  - [ ] `mypy headroom/ tests/` - no errors
  - [ ] `flake8` - no linting errors
  - [ ] `autopep8` - formatting applied
  - [ ] `autoflake` - unused imports removed
  - [ ] No trailing whitespace
  - [ ] Files end with newline
  - [ ] No stray blank lines

### Final Verification
- [ ] Clean git status (no untracked files)
- [ ] All generated Terraform committed
- [ ] Documentation complete and accurate
- [ ] Test resources destroyed (if expensive)
- [ ] 100% test coverage verified for new code
- [ ] All quality checks passed (see Code Quality Verification above)
- [ ] Code review completed
- [ ] Ready for production use

---

## Quick Reference: File Checklist

### New Files to Create

**Python Implementation:**
- `headroom/aws/{service}.py` (if new service)
- `headroom/checks/{scps|rcps}/{check_name}.py`

**Tests:**
- `tests/test_checks_{check_name}.py`
- `tests/test_aws_{service}.py` (if new service)

**Test Environment:**
- `test_environment/test_{check_name}.tf`
- `test_environment/test_{check_name}/README.md` (if expensive/complex)

### Files to Modify

**Python:**
- `headroom/constants.py` - Add check name constant
- `headroom/checks/__init__.py` - Add import for registration
- `headroom/terraform/generate_scps.py` OR `generate_rcps.py` - Add generation logic

**Terraform Modules:**
- `test_environment/modules/{scps|rcps}/variables.tf` - Add variable(s)
- `test_environment/modules/{scps|rcps}/locals.tf` - Add policy statement
- `test_environment/modules/{scps|rcps}/README.md` - Document variable
- `test_environment/modules/headroom_role/main.tf` - Add permissions (if needed)

**Documentation:**
- `documentation/POLICY_TAXONOMY.md` - Add pattern example
- `Headroom-Specification.md` - Add check documentation
- `conversation_history.md` - Append check addition summary

### Generated Files (Committed)

**Terraform:**
- `test_environment/{scps|rcps}/*_{scps|rcps}.tf` (updated)
- `test_environment/{scps|rcps}/grab_org_info.tf` (potentially updated)

**Results:**
- `test_environment/headroom_results/{scps|rcps}/{check_name}/*.json`

**IMPORTANT:** Do NOT manually create or edit files in `test_environment/headroom_results/` or `test_environment/{scps|rcps}/`. Let Headroom generate these files when it runs. After Headroom generates them, commit the generated files to git.

---

## Common Pitfalls

### 1. Check File Not in Correct Directory

**Symptom:** Check not discovered, not executed
**Cause:** Check file placed in wrong location or has invalid Python filename
**Fix:**
- Ensure check file is in `headroom/checks/scps/` or `headroom/checks/rcps/`
- Use valid Python filename (no hyphens, must end with `.py`)
- Verify check is registered: `python -c "from headroom.checks.registry import get_check_names; print(get_check_names())"`

### 2. Not Updating Terraform Generation

**Symptom:** Terraform files generated without new check
**Location:** `headroom/terraform/generate_scps.py` or `generate_rcps.py`
**Fix:** Add hardcoded category and boolean generation

### 3. Mismatched Check Names

**Symptom:** Check results not parsed correctly, KeyError in results processing
**Issue:** Using hyphens in some places, underscores in others
**Fix:** Use underscores everywhere:
- Python: `deny_rds_unencrypted`
- Constants: `DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"`
- Terraform: `deny_rds_unencrypted = true`
- Files: `deny_rds_unencrypted.py`, `deny_rds_unencrypted.json`

### 4. Missing @register_check Decorator

**Symptom:** `RuntimeError: Unknown check type for check_name` or check not found in registry
**Cause:** `@register_check` decorator not present or has wrong parameters
**Fix:**
1. Ensure decorator present: `@register_check("scps", DENY_RDS_UNENCRYPTED)`
2. Verify check type ("scps" or "rcps") matches directory
3. Verify CHECK_NAME constant matches everywhere
4. Confirm import works: `python -c "from headroom.checks.registry import get_check_names; print(get_check_names())"`

### 5. Terraform Module Variable Without Correct Default

**Symptom:** Terraform plan requires value unexpectedly
**SCP Variables:** Should NOT have defaults (must be explicit)
**RCP Allowlists:** Should have `default = []`
**Fix:**
```hcl
# SCP boolean - NO default
variable "deny_rds_unencrypted" {
  type = bool
}

# RCP allowlist - WITH default
variable "third_party_account_ids" {
  type    = list(string)
  default = []  # Safe default for allowlists
}
```

### 6. Incorrect Categorization Logic

**Symptom:** Violations marked as compliant or vice versa
**Common Mistakes:**
- Reversed boolean logic
- Wrong order of conditions
- Missing edge cases
**Fix:** Review categorization carefully:
```python
if not result.encrypted:  # BAD state first
    if result.exemption_tag_present:  # Then check exemption
        return ("exemption", result_dict)
    else:
        return ("violation", result_dict)
else:  # GOOD state
    return ("compliant", result_dict)
```

### 7. Not Handling AWS API Pagination

**Symptom:** Only first page of results returned (100 items)
**Issue:** Not using paginators for list operations
**Fix:**
```python
# WRONG - only gets first page
response = rds_client.describe_db_instances()
instances = response.get("DBInstances", [])

# RIGHT - gets all pages
paginator = rds_client.get_paginator("describe_db_instances")
for page in paginator.paginate():
    instances = page.get("DBInstances", [])
    # Process each page...
```

### 8. Insufficient IAM Permissions

**Symptom:** `ClientError: User: ... is not authorized to perform: ...`
**Locations to Check:**
- `test_environment/modules/headroom_role/main.tf`
- ViewOnlyAccess managed policy coverage
**Fix:** Add specific permissions if ViewOnlyAccess insufficient

### 9. Category Placement in Terraform Generation

**Symptom:** Generated Terraform has checks in wrong/inconsistent order
**Issue:** Not following alphabetical service ordering
**Fix:** Maintain this order: EC2, IAM, RDS, S3, VPC, etc.

### 10. Test Environment Resource Naming Conflicts

**Symptom:** `terraform apply` fails with "already exists"
**Issue:** Resource names not unique across accounts/regions
**Fix:**
```hcl
# BAD - may conflict
identifier = "test-db"

# GOOD - includes account context
identifier = "headroom-test-${var.purpose}-${data.aws_caller_identity.current.account_id}"
```

### 11. Forgetting Multi-Region Support

**Symptom:** Only finding resources in default region
**Issue:** Not iterating through all regions
**Fix:**
```python
# Get all regions (including opt-in regions that may be disabled)
# We intentionally scan all regions to detect resources in any region
ec2_client = session.client("ec2")
regions_response = ec2_client.describe_regions()
regions = [r["RegionName"] for r in regions_response["Regions"]]

# Analyze in each region
for region in regions:
    regional_client = session.client("rds", region_name=region)
    # ... analysis ...
```

**Note:** Do NOT filter regions by opt-in-status. We intentionally scan all regions to ensure complete visibility, even if some API calls may fail for disabled regions.

### 12. Incorrect Summary Field Calculation

**Symptom:** Compliance percentage wrong, counts don't add up
**Common Issues:**
- Not including exemptions in compliant count
- Division by zero
- Wrong rounding
**Fix:**
```python
total = len(violations) + len(exemptions) + len(compliant)
compliant_count = len(compliant) + len(exemptions)  # Include exemptions!
compliance_pct = (compliant_count / total * 100) if total > 0 else 100.0  # Handle empty
```

### 13. Not Testing Edge Cases

**Symptom:** Tests pass but real execution fails
**Missing Test Cases:**
- Empty results (no resources found)
- All violations
- All exemptions
- All compliant
- Mixed scenarios
- API errors
- Permission errors

### 14. Documentation Out of Sync

**Symptom:** Documentation doesn't match implementation
**Prevention:**
- Update documentation immediately after code changes
- Review all docs files in checklist
- Test code examples in documentation
- Keep line number references updated

### 15. Expensive Test Resources Left Running

**Symptom:** Unexpected AWS bill
**Prevention:**
- Add cost warnings to README
- Document cleanup commands prominently
- Use terraform destroy --target immediately after testing
- Set up billing alerts
- Consider using separate test account

---

## Lessons Learned from deny_rds_unencrypted Implementation

These lessons were learned during the implementation of the `deny_rds_unencrypted` check (November 2025). Study these to avoid common mistakes.

### Lesson 1: Test Environment Pollution

**Problem:** Tests were writing files to `test_environment/headroom_results/` instead of temporary directories, polluting the actual results directory with test artifacts like `prod-account_111111111111.json`.

**Root Causes:**
- Used `DEFAULT_RESULTS_DIR` constant in tests (points to test_environment/)
- Hardcoded `results_dir="test_environment/headroom_results"`
- `HeadroomConfig` fixture didn't specify temporary `results_dir`

**Solution:**
- **ALWAYS** use `temp_results_dir` fixture or `tempfile.mkdtemp()` in tests
- **NEVER** use `DEFAULT_RESULTS_DIR` in test code
- **NEVER** hardcode paths to `test_environment/` in tests
- Configure fixtures to use temporary directories

**Prevention:**
- Run full test suite and check for new files in test_environment/
- Review all test files to ensure they use temporary directories
- Added explicit warning in testing standards section

### Lesson 2: AWS IAM Condition Key Documentation

**Problem:** Initially included 8 RDS actions in the SCP based on web searches, but only 3 actions actually support the `rds:StorageEncrypted` condition key according to AWS Service Authorization Reference.

**Incorrect Assumptions:**
- Web searches suggested `rds:CreateDBInstance` supports `rds:StorageEncrypted` (it doesn't, per documentation)
- Logical reasoning ("if cluster creation supports it, instance creation should too") was wrong
- Blog posts and Stack Overflow answers were unreliable

**Verification Process:**
1. Accessed official AWS Service Authorization Reference using MCP server
2. Read complete list of RDS actions and their condition key columns
3. Found only 3 actions explicitly list `rds:StorageEncrypted`:
   - `rds:CreateDBCluster` ✅
   - `rds:RestoreDBClusterFromS3` ✅
   - `rds:CreateBlueGreenDeployment` ✅
4. Confirmed `rds:CreateDBInstance` does NOT list it ❌

**Solution:**
- **ONLY** trust the AWS Service Authorization Reference table
- Condition key must be explicitly listed in the action's "Condition keys" column
- If not listed, it is NOT supported (even if it seems logical)

**Special Exception:**
Included `rds:CreateDBInstance` anyway as a special exception because:
- It's critical for protecting standalone RDS instances
- Using `Bool` operator fails safe (if unsupported, Deny won't apply)
- Manual testing confirmed it DOES work despite not being documented
- Documented with "✅ MANUALLY TESTED" confirmation in policy comments

**Prevention:**
- Always verify condition keys in Service Authorization Reference
- Document any undocumented actions as "special exceptions"
- Manually test special exceptions and document test results
- Added critical warning section in Phase 0, Step 0.3

### Lesson 3: Bool Condition Operator Behavior

**Problem:** Initially misunderstood how `Bool` operator behaves when the condition key is missing from the request context.

**Incorrect Understanding:**
"If the Bool condition key is missing, the condition fails, and the Deny applies."

**Correct Understanding:**
- The `Bool` operator expects the key to exist in the context
- If the key is missing, the condition evaluates to `false`
- In a `Deny` statement, `false` means the Deny does NOT apply
- The action is allowed (not denied)

**Example:**
```json
{
  "Effect": "Deny",
  "Action": "rds:CreateDBInstance",
  "Condition": {
    "Bool": {
      "rds:StorageEncrypted": "false"
    }
  }
}
```

**Behavior:**
- If `rds:StorageEncrypted` = "false" → Condition is true → Deny applies → Action denied ✅
- If `rds:StorageEncrypted` = "true" → Condition is false → Deny doesn't apply → Action allowed ✅
- If `rds:StorageEncrypted` is missing → Condition is false → Deny doesn't apply → Action allowed ⚠️

**Implication for Undocumented Actions:**
Including `rds:CreateDBInstance` (which doesn't document support for `rds:StorageEncrypted`) is safe:
- If condition key IS supported: Policy works as intended
- If condition key is NOT supported: Key will be missing, Deny won't apply, action is allowed
- Zero risk, potential benefit

**Prevention:**
- Understand condition operator semantics before writing policies
- Document condition operator behavior in policy comments
- Consider fail-safe vs. fail-secure behavior when choosing operators

### Lesson 4: Terraform Provider Inheritance

**Problem:** Test environment Terraform initially had incorrect comment stating "Provider configurations are inherited from parent directory" when they are not.

**Incorrect Assumption:**
Terraform providers automatically inherit from parent directory configurations.

**Correct Behavior:**
- Each Terraform working directory needs explicit provider configuration
- Providers are NOT inherited from parent directories
- Must define all providers (including aliased ones) in each directory

**Solution:**
- Explicitly define all AWS providers in `test_environment/test_deny_rds_unencrypted/providers.tf`
- Use `aws_organizations_*` data sources to dynamically retrieve account IDs
- Configure aliased providers for cross-account access

**Prevention:**
- Always explicitly define providers in each Terraform directory
- Don't assume provider inheritance
- Use data sources for dynamic configuration

### Lesson 5: ARN Account ID Redaction with Region Field

**Problem:** The `_redact_account_ids_from_arns()` regex pattern only matched ARNs without a region field (e.g., IAM ARNs), so RDS ARNs were not redacted.

**Original Regex:**
```python
(arn:aws:[^:]+::)(\d{12})(:)
```
This matches: `arn:aws:iam::123456789012:user/name`

**Problem:**
RDS ARNs have a region field: `arn:aws:rds:us-east-1:123456789012:db:name`
The pattern expects two colons before the account ID, but RDS has region between them.

**Fixed Regex:**
```python
(arn:aws:[^:]+:[^:]*:)(\d{12})(:)
```
The `[^:]*:` allows for optional region field (zero or more non-colon characters followed by colon).

**Solution:**
- Updated regex pattern in `headroom/write_results.py`
- Added test `test_redact_arns_with_region()` to verify RDS-style ARNs
- Both IAM-style and RDS-style ARNs now correctly redacted

**Prevention:**
- Consider all ARN formats when writing regex patterns
- Test with multiple ARN styles (with/without region, with/without account)
- Add explicit test cases for each ARN format

### Lesson 6: Consistent Fake Account IDs

**Problem:** Documentation examples sometimes used `123456789012` (old AWS convention) instead of the codebase standard `111111111111`.

**Decision:**
- Use `111111111111` consistently across all code, tests, and documentation
- Never use `123456789012` (old AWS documentation convention)
- Use consistent series: `111111111111`, `222222222222`, `333333333333`

**Rationale:**
- `111111111111` is clearly fake (repeating 1s)
- `123456789012` looks realistic and could be confused with real account
- Consistency makes search/replace easier
- Easier to identify example vs. real account IDs

**Prevention:**
- Added explicit guidance in Testing Requirements section
- Updated all docstring examples to use `111111111111`
- Added to Test Data Standards section

---

## Tips for Success

1. **Start Small:** Implement simplest version first, add features incrementally
2. **Test Early:** Write tests alongside implementation, not after
3. **Follow Patterns:** Copy from existing checks (deny_ec2_imds_v1, deny_iam_user_creation)
4. **Quality First:** Run `tox` frequently during development, not just at the end
5. **Type Everything:** Add type hints as you write code, not as an afterthought
6. **DRY Continuously:** Refactor duplicate code immediately when you see it
7. **Minimize Nesting:** Use early returns and continue statements liberally
8. **Read Errors Carefully:** Error messages often point directly to the issue
9. **Log Appropriately:** Helps debug issues in production
10. **Document As You Go:** Write docstrings as you write functions
11. **Test Edge Cases:** Think about what could go wrong and test it
12. **Clean Up:** Remove test resources, commit clean git state
13. **Review Your Code:** Use the Code Quality Verification checklist before submitting
14. **Ask for Review:** Get feedback on design before implementing everything
15. **Celebrate:** Adding a check is a significant contribution!

**Final Quality Pass:**
After completing implementation, do a quality review:
- Search for duplicate code → extract to functions
- Look for deep nesting → add early returns
- Check all edge cases → add tests
- Verify all names → ensure clarity
- Run `tox` → confirm all checks pass

---

**End of Guide**

For questions or issues, refer to:
- Existing checks in `headroom/checks/scps/` and `headroom/checks/rcps/`
- `documentation/POLICY_TAXONOMY.md` for policy patterns
- `Headroom-Specification.md` for architecture details
- Test files in `tests/` for examples

Good luck! 🚀
