# Headroom - AWS Multi-Account Security Analysis Tool
## Product Design Requirements (PDR)

**Version:** 4.3
**Created:** 2025-10-26
**Last Updated:** 2025-11-06
**Status:** Implementation Complete (Foundation + SCP Analysis + Results Processing + Code Quality Optimization + Terraform Generation + SCP Auto-Generation + RCP Analysis + RCP Auto-Generation + RCP Placement Optimization + RCP Union Strategy + Critical Bug Fixes + Architectural Organization)

---

## Executive Summary

**Headroom** is a Python CLI tool designed for AWS multi-account security analysis with Service Control Policy (SCP) audit capabilities. The tool provides "audit mode" for SCPs/RCPs, enabling security teams to analyze AWS Organizations environments without making changes to production systems.

**Core Value Proposition:** Ever want audit mode for SCPs / RCPs? Well now you can.

**Usage Philosophy:** This is intended as a bare-bones prevention-focused CLI tool. No more getting flooded with thousands of reactive CSPM findings, stop the bleeding where possible.

**Disclaimer:** Don't run this in production / do so at your own risk! :)

**Current State Coverage:** Should always be checked. CloudTrail is only sometimes checked.

---

## Product Requirements

### PR-001: CLI-Based Configuration System

**Requirement:** The system MUST provide a hybrid configuration approach combining YAML configuration files with CLI argument overrides.

**Implementation Specifications:**
- **Primary Configuration:** YAML file specified via required `--config` flag
- **Override Capability:** CLI arguments override YAML values when provided
- **Validation:** Pydantic-based configuration validation with strict type checking
- **Error Handling:** Comprehensive error reporting for missing/invalid configurations

**Configuration Schema:**
```yaml
management_account_id: string (optional)         # AWS Organizations management account
security_analysis_account_id: string (optional)  # Account for running analysis; only required if running from management account
exclude_account_ids: boolean                      # Exclude account IDs from result files and filenames
use_account_name_from_tags: boolean              # If true, use account tag for name; if false, use AWS account name
results_dir: string (optional)                   # Base directory for results (default: test_environment/headroom_results)
scps_dir: string (optional)                      # Base directory for SCP Terraform files (default: test_environment/scps)
rcps_dir: string (optional)                      # Base directory for RCP Terraform files (default: test_environment/rcps)
account_tag_layout:
  environment: string   # Tag key for environment identification (optional tag, falls back to "unknown")
  name: string         # Tag key for account name (optional tag, used when use_account_name_from_tags is true)
  owner: string        # Tag key for account owner (optional tag, falls back to "unknown")
```

**Note on security_analysis_account_id:** This field is optional and should only be specified if you are running Headroom from the management account (or any account other than the security analysis account itself). If omitted, Headroom assumes it is already running in the security analysis account and will use the current AWS credentials directly.

### PR-002: AWS Multi-Account Integration Pattern

**Requirement:** The system MUST implement secure cross-account access for AWS Organizations analysis.

**Implementation Specifications:**

**Phase 1: Security Analysis Account Access (Conditional)**
- If `security_analysis_account_id` is specified: Assume `OrganizationAccountAccessRole` in the designated security analysis account
- If `security_analysis_account_id` is omitted: Assume the tool is already running in the security analysis account and use current AWS credentials
- **Use Case 1 (Recommended):** Run from the security analysis account with omitted `security_analysis_account_id`
- **Use Case 2:** Run from the management account with specified `security_analysis_account_id`
- Proper AWS STS session management and credential handling

**Phase 2: Management Account Integration**
- Use security analysis session to assume `OrgAndAccountInfoReader` role in management account
- Retrieve comprehensive organization account information including tags
- Filter out management account from analysis to focus on member accounts in scope of SCPs/RCPs

**AWS IAM Role Requirements:**
- `OrganizationAccountAccessRole`: In security analysis account, **only required if running from the management account**. Not needed if running directly from the security analysis account.
- `OrgAndAccountInfoReader`: Role with permissions for `organizations:ListAccounts` and `organizations:ListTagsForResource` inside of management account, which trusts the security analysis account to assume it.
- `Headroom`: Role in all accounts, for the analysis code to use.
- See `test_environment/` for the exact Terraform of these roles, except `OrganizationAccountAccessRole` which has not been imported.

### PR-003: Account Information Extraction

**Requirement:** The system MUST extract and structure account information from AWS Organizations with configurable data sources.

**Data Extraction Capabilities:**
- **Account Metadata:** Account ID, native account name from AWS Organizations API
- **Tag-Based Information:** Configurable extraction of environment, name, and owner from account tags
- **Flexible Naming:** Support for using either AWS account name or custom tag-based naming
- **Error Resilience:** Graceful handling of missing tags or API access errors

**Data Structure:**
```python
@dataclass
class AccountInfo:
    account_id: str
    environment: str    # From tags with "unknown" fallback
    name: str          # From tags/API with account_id fallback
    owner: str         # From tags with "unknown" fallback
```

**Fallback Strategy:**
- **Environment:** Uses tag value, defaults to "unknown" if not present
- **Name:** Uses tag value or AWS account name, defaults to `account_id` if neither available
- **Owner:** Uses tag value, defaults to "unknown" if not present

**Data Integrity:** All fields are required (non-Optional) ensuring consistent data structure across the application.

### PR-004: Application Architecture

**Requirement:** The system MUST implement a modular, maintainable architecture supporting future extensibility.

**Module Organization:**
- **`main.py`**: Entry point orchestrating configuration, analysis, results processing, and Terraform generation flow
- **`config.py`**: Pydantic models for configuration validation (`HeadroomConfig`, `AccountTagLayout`) and default directory constants
- **`usage.py`**: CLI parsing, YAML loading, and configuration merging logic
- **`analysis.py`**: AWS integration, security analysis implementation, check execution optimization, and organization account ID retrieval
- **`parse_results.py`**: SCP/RCP compliance results analysis and organization structure processing
- **`write_results.py`**: JSON result file writing, path resolution, and results existence checking with `CHECK_TYPE_MAP` for organizing results by policy type
- **`types.py`**: Shared data models and type definitions for organization hierarchy, SCP recommendations, and RCP placement recommendations
- **`aws/`**: AWS service integration modules
  - **`ec2.py`**: EC2 service integration and analysis functions
  - **`iam.py`**: IAM trust policy analysis and third-party account detection
  - **`organization.py`**: AWS Organizations API integration and hierarchy analysis
- **`checks/`**: SCP/RCP compliance check implementations organized by policy type
  - **`scps/`**: Service Control Policy check implementations
    - **`deny_imds_v1_ec2.py`**: EC2 IMDS v1 compliance check implementation
  - **`rcps/`**: Resource Control Policy check implementations
    - **`check_third_party_assumerole.py`**: IAM trust policy third-party AssumeRole access check
- **`terraform/`**: Terraform configuration generation modules
  - **`generate_org_info.py`**: AWS Organizations structure data source generation
  - **`generate_scps.py`**: SCP deployment configuration generation
  - **`generate_rcps.py`**: RCP deployment configuration generation
  - **`utils.py`**: Shared Terraform utilities (safe variable name generation)
- **`__main__.py`**: Python module entry point for `python -m headroom` execution

**Error Handling Strategy:**
- Specific exception catching (no bare `except Exception`)
- User-friendly error messages with proper formatting
- Graceful exit with appropriate status codes
- Comprehensive logging for debugging and audit trails

### PR-005: Development Quality Standards

**Requirement:** The system MUST maintain exceptional code quality and reliability standards.

**Quality Metrics:**
- **Test Coverage:** 100% coverage required for both source (`headroom/`) and test (`tests/`) directories
- **Type Safety:** Strict mypy configuration with no untyped definitions allowed
- **Code Standards:** Pre-commit hooks enforcing autoflake, flake8, and autopep8
- **Python Version:** Target Python 3.13

**Testing Strategy:**
- **Unit Tests:** Comprehensive coverage of individual functions and classes
- **Integration Tests:** End-to-end workflow testing from CLI to analysis
- **Error Path Testing:** Extensive testing of error conditions and edge cases
- **Mock Integration:** AWS services mocked for reliable, fast testing

**Code Quality Enhancements (COMPLETED):**
- **Import Organization:** All imports moved to top level, eliminating dynamic imports
- **Function Structure:** Nested functions extracted to module level to minimize indentation
- **Formatting Standards:** Backslash-newline continuations eliminated using parentheses in with statements
- **Test Architecture:** Pytest best practices with centralized mock fixtures using `autouse=True`
- **DRY Compliance:** Eliminated repetitive `@patch` decorators through fixture-based mocking
- **Modern Python:** Consistent formatting following current Python style guidelines

**Testing Architecture Improvements:**
- **Centralized Mocking:** `mock_dependencies` fixture with `autouse=True` for all integration tests
- **Clean Test Signatures:** Test methods simplified from 7-8 parameters to 2-3 parameters
- **Maintainable Mocks:** Single fixture location for all mock management
- **Comprehensive Coverage:** 120 tests with 100% coverage including edge cases and error conditions

### PR-006: SCP Compliance Analysis Engine

**Requirement:** The system MUST provide comprehensive SCP compliance analysis across multi-account environments with detailed result reporting.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**Analysis Architecture:**
- **Account Filtering:** `get_relevant_subaccounts()` function (currently returns all accounts, extensible for OU/environment/owner filtering)
- **Cross-Account Sessions:** `get_headroom_session()` function assumes `Headroom` role in each target account
- **Check Orchestration:** `run_checks()` function coordinates execution of all enabled SCP checks across filtered accounts
- **Static Imports:** All check imports declared at module level to eliminate dynamic imports and improve reliability

**SCP Check Framework:**
- **Modular Structure:** Individual check functions in `headroom/checks/` directory for each SCP policy
- **AWS Integration:** Library functions in `headroom/aws/` directory for performant, paginated AWS API calls
- **Data Models:** Structured dataclasses for each check type with comprehensive compliance attributes
- **Error Resilience:** Graceful handling of AWS API failures and missing resources

**Implemented Check: EC2 IMDS v1 Analysis**

**Data Model:**
```python
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool        # True if IMDSv1 enabled (violation)
    exemption_tag_present: bool # True if ExemptFromIMDSv2 tag exists
```

**Analysis Function:**
- `get_imds_v1_ec2_analysis(session: boto3.Session) -> List[DenyImdsV1Ec2]`
- Multi-region EC2 instance scanning with pagination support
- Filters out terminated instances
- Case-insensitive exemption tag checking (`ExemptFromIMDSv2`)
- Fallback region support for comprehensive coverage

**Check Function:**
- `check_deny_imds_v1_ec2(headroom_session: boto3.Session, account_name: str, account_id: str, results_base_dir: str, exclude_account_ids: bool = False)`
- Generates structured JSON results with compliance metrics using `write_check_results()` from `write_results.py`
- Console output with violation/exemption/compliant counts
- Directory structure: `{results_base_dir}/deny_imds_v1_ec2/` (default: `test_environment/headroom_results/deny_imds_v1_ec2/`)

**Result Management (via `write_results.py`):**
- **Output Format:** JSON files per check per account in configured `results_dir` (default: `test_environment/headroom_results/`)
- **File Structure:** `{check_name}/{account_name}_{account_id}.json` or `{check_name}/{account_name}.json` if `exclude_account_ids=True`
- **Compliance Metrics:** Summary with violation counts, exemptions, compliance percentages
- **Detailed Results:** Separate arrays for violations, exemptions, and compliant instances
- **Metadata:** Account name, account identifier, check name, and totals
- **Key Functions:**
  - `write_check_results()`: Write results to JSON file
  - `results_exist()`: Check if results file already exists (supports both filename formats)
  - `get_results_dir()`: Get directory path for a check
  - `get_results_path()`: Get file path for a specific account's results

**JSON Result Structure:**
```json
{
  "summary": {
    "account_name": "account-name",
    "account_id": "111111111111",
    "check": "deny_imds_v1_ec2",
    "total_instances": 10,
    "violations": 3,
    "exemptions": 2,
    "compliant": 5,
    "compliance_percentage": 70.0
  },
  "violations": [...],
  "exemptions": [...],
  "compliant_instances": [...]
}
```

**SCP Integration:**
- Maps to `deny_imds_v1_ec2` variable in `test_environment/modules/scps/variables.tf`
- Corresponds to SCP statements in `test_environment/modules/scps/locals.tf`
- Supports exemption patterns via `ExemptFromIMDSv2` tag (case-insensitive)
- Provides audit trail for SCP policy effectiveness assessment

### PR-007: SCP/RCP Compliance Results Analysis

**Requirement:** The system MUST analyze results in `test_environment/headroom_results` and determine the highest organizational level (root, OU, account) where SCPs/RCPs can be safely deployed without breaking existing violations. This ensures policies are deployed at the most restrictive level possible while maintaining zero violations.

**Implementation Specifications:**

**Analysis Architecture:**
- **Results Parsing:** `parse_results.py` module processes JSON result files from `test_environment/headroom_results/`
- **SCP/RCP Separation:** `parse_result_files()` excludes RCP checks by default to prevent RCP checks from generating SCP Terraform
- **RCP Check Filtering:** `RCP_CHECK_NAMES = {"third_party_role_access"}` identifies checks to exclude from SCP analysis
- **Organization Structure Analysis:** Function to analyze AWS Organizations OU hierarchy and account relationships
- **Account-to-OU Mapping:** Function to create comprehensive mapping of accounts to their direct parent OUs
- **Greatest Common Denominator Logic:** Function to determine optimal SCP/RCP placement level (root, OU, or account-specific)
- **Terraform Generation:** `generate_terraform.py` module generates Terraform configuration files for organization structure data
- **Missing Account ID Lookup:** When `exclude_account_ids=True`, accounts are looked up by name in the organization hierarchy

**Results Parsing Implementation:**

The system implements two separate but structurally similar parsing flows for SCP and RCP checks. Understanding these patterns is critical for reproducing the implementation.

**Common Parsing Patterns (SCP and RCP):**

Both parsers share the following implementation patterns:

1. **Directory Structure Expectation:**
   - Both expect results in: `{results_dir}/{check_name}/*.json`
   - Both use `Path(results_dir)` for path operations
   - Both iterate through check subdirectories

2. **File Iteration:**
   - Both use `check_dir.glob("*.json")` to find result files
   - Both process one JSON file per account per check

3. **JSON Parsing with Error Handling:**
   ```python
   try:
       with open(result_file, 'r') as f:
           data = json.load(f)
       # ... processing ...
   except (json.JSONDecodeError, KeyError) as e:
       raise RuntimeError(f"Failed to parse result file {result_file}: {e}")
   ```
   - Identical exception handling: `(json.JSONDecodeError, KeyError)`
   - Both convert to `RuntimeError` with context
   - No generic `except Exception` handlers

4. **Summary Data Extraction:**
   ```python
   summary = data.get("summary", {})
   account_id = summary.get("account_id", "")
   account_name = summary.get("account_name", "")
   ```
   - Both extract from `summary` dictionary
   - Both use `.get()` with default empty strings

5. **Account ID Fallback Logic:**
   - Both handle missing `account_id` by looking up `account_name` in `organization_hierarchy.accounts`
   - Both iterate through all accounts to find matching name
   - Both raise `RuntimeError` if account not found in organization
   - Pattern:
   ```python
   if not account_id:
       found_account_id = None
       for acc_id, acc_info in organization_hierarchy.accounts.items():
           if acc_info.account_name == account_name:
               found_account_id = acc_id
               break
       if not found_account_id:
           raise RuntimeError(f"Account '{account_name}' not found...")
       account_id = found_account_id
   ```

6. **Organization Hierarchy Dependency:**
   - Both ultimately use `organization_hierarchy.accounts` for account lookups
   - SCP: Provided during placement determination phase (`determine_scp_placement`)
   - RCP: Provided during parsing phase (`parse_rcp_result_files`)

7. **Logging Pattern:**
   - Both use `logger.info()` for status messages
   - Both log when processing checks or looking up accounts

8. **RuntimeError Usage:**
   - Both use `RuntimeError` for critical failures (missing directories, accounts)
   - No silent failures or exception suppression

**Key Differences (SCP vs RCP):**

1. **Check Selection Strategy:**
   - **SCP (`parse_result_files`):** Iterates through ALL check directories, explicitly excludes RCP checks
     ```python
     RCP_CHECK_NAMES = {"third_party_role_access"}
     for check_dir in results_path.iterdir():
         if not check_dir.is_dir():
             continue
         if exclude_rcp_checks and check_name in RCP_CHECK_NAMES:
             continue  # Skip RCP checks
     ```
   - **RCP (`parse_rcp_result_files`):** Directly targets specific check directory
     ```python
     check_dir = results_path / "third_party_role_access"
     if not check_dir.exists():
         raise RuntimeError(f"Third-party role access check directory does not exist: {check_dir}")
     ```
   - **Rationale:** SCP parser is extensible for multiple checks; RCP parser is specialized for one check

2. **Data Extracted from JSON:**
   - **SCP:** Extracts compliance metrics for policy placement decisions
     ```python
     CheckResult(
         account_id=account_id,
         account_name=summary.get("account_name", ""),
         check_name=summary.get("check", check_name),
         violations=summary.get("violations", 0),
         exemptions=summary.get("exemptions", 0),
         compliant=summary.get("compliant", 0),
         total_instances=summary.get("total_instances", 0),
         compliance_percentage=summary.get("compliance_percentage", 0.0)
     )
     ```
   - **RCP:** Extracts third-party account patterns and wildcard status
     ```python
     third_party_accounts = summary.get("unique_third_party_accounts", [])
     roles_with_wildcards = summary.get("roles_with_wildcards", 0)
     # Results in: account_third_party_map[account_id] = set(third_party_accounts)
     ```
   - **Rationale:** SCPs care about violation counts; RCPs care about trust relationships

3. **Return Type:**
   - **SCP:** Returns `List[CheckResult]` - flat list of check results across all accounts and checks
   - **RCP:** Returns `RCPParseResult` - structured object with two components:
     ```python
     @dataclass
     class RCPParseResult:
         account_third_party_map: Dict[str, Set[str]]  # Eligible accounts
         accounts_with_wildcards: Set[str]              # Excluded accounts
     ```
   - **Rationale:** RCPs need to segregate wildcard accounts (unsafe) from normal accounts (safe)

4. **Wildcard Handling:**
   - **SCP:** No wildcard logic - treats all accounts uniformly based on violation counts
   - **RCP:** Special wildcard exclusion logic
     ```python
     if roles_with_wildcards > 0:
         accounts_with_wildcards.add(account_id)
         logger.info(f"Account {account_name} has {roles_with_wildcards} roles with wildcard principals - cannot deploy RCP")
         continue  # Skip this account from account_third_party_map
     ```
   - **Rationale:** Wildcard trust policies (`"Principal": "*"`) prevent safe RCP deployment

5. **Organization Hierarchy Timing:**
   - **SCP:** `organization_hierarchy` parameter NOT required in `parse_result_files()`, provided later in `determine_scp_placement()`
   - **RCP:** `organization_hierarchy` parameter REQUIRED in `parse_rcp_result_files()` for account name lookups
   - **Rationale:** RCP parsing needs immediate account ID resolution; SCP can defer until placement phase

6. **Data Processing:**
   - **SCP:** Appends each result to flat list; no filtering beyond check exclusion
   - **RCP:** Conditionally adds to map OR wildcard set based on `roles_with_wildcards`; uses `set()` for third-party IDs
   - **Rationale:** RCPs need set operations for union strategy; SCPs need comprehensive result lists

7. **Placement Philosophy:**
   - **SCP:** Based on ZERO VIOLATIONS principle - where can policy be deployed without breaking existing compliant resources
   - **RCP:** Based on COMMON PATTERNS principle - where do accounts share third-party trust relationships (union strategy)
   - **Rationale:** Different security control types require different deployment strategies

**Architectural Design Principles:**

1. **Separation of Concerns:** SCP and RCP parsing are separate functions in separate modules to avoid coupling
2. **Common Error Handling:** Both use identical exception patterns for consistency and maintainability
3. **Type Safety:** Both return strongly-typed dataclasses for downstream processing
4. **Fail-Loud:** Both raise exceptions on critical errors rather than returning partial results
5. **Logging:** Both provide informative logging for debugging and audit trails
6. **Organization Integration:** Both integrate with organization hierarchy for account metadata

**Module Organization:**
- **`parse_results.py`**: Module containing results analysis and organization structure processing
- **`generate_terraform.py`**: Module containing Terraform configuration generation functionality
- **Integration Point:** `parse_results(final_config)` called from `main.py` after SCP analysis completion
- **Data Models:** Structured dataclasses for organization hierarchy and SCP placement recommendations

**Organization Analysis Functions:**

**1. Organization Structure Analysis:**
```python
def analyze_organization_structure(session: boto3.Session) -> OrganizationHierarchy:
    """
    Analyze AWS Organizations structure including root, OUs, and account relationships.
    Returns comprehensive hierarchy mapping.
    """
```

**2. Account-to-OU Mapping:**
```python
def create_account_ou_mapping(session: boto3.Session) -> Dict[str, str]:
    """
    Create mapping of account IDs to their direct parent OU IDs.
    Returns dictionary with account_id -> parent_ou_id relationships.
    """
```

**3. Greatest Common Denominator Analysis:**
```python
def determine_scp_placement(results_data: List[CheckResults],
                          organization_hierarchy: OrganizationHierarchy) -> SCPPlacementRecommendations:
    """
    Analyze compliance results to determine optimal SCP/RCP placement level.
    Finds the highest organizational level where ALL accounts have zero violations.
    Ensures safe deployment without breaking existing violations that would cause operational issues.
    """
```

**Data Models:**
```python
@dataclass
class OrganizationHierarchy:
    root_id: str
    organizational_units: Dict[str, OrganizationalUnit]
    accounts: Dict[str, AccountOrgPlacement]

@dataclass
class OrganizationalUnit:
    ou_id: str
    name: str
    parent_ou_id: Optional[str]
    child_ous: List[str]
    accounts: List[str]

@dataclass
class AccountOrgPlacement:
    account_id: str
    account_name: str
    parent_ou_id: str
    ou_path: List[str]  # Full path from root to account

@dataclass
class SCPPlacementRecommendations:
    check_name: str
    recommended_level: str  # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    compliance_percentage: float
    reasoning: str
```

**Analysis Logic:**
- **Root Level:** Recommended when ALL accounts in the organization have zero violations
- **OU Level:** Recommended when ALL accounts within a specific OU have zero violations (but some accounts in other OUs have violations)
- **Account Level:** Recommended when only individual accounts have zero violations (but other accounts in the same OU have violations)

**Deployment Safety Principle:** SCPs/RCPs MUST only be deployed at levels where there are zero violations to prevent breaking existing violations that would cause operational issues.

**Integration Flow:**
1. **Post-Analysis Processing:** Called after all SCP checks complete in `main.py`
2. **Results Aggregation:** Parse all JSON result files from `headroom_results/` directories
3. **Organization Analysis:** Query AWS Organizations API for current structure
4. **Placement Calculation:** Determine optimal SCP/RCP placement based on violation patterns
5. **Recommendation Output:** Generate structured recommendations for SCP deployment

**Output Format:**
- **Console Reporting:** Summary of SCP placement recommendations with reasoning
- **Structured Data:** JSON output with detailed placement analysis per check
- **Integration Ready:** Results formatted for potential Terraform SCP generation

**Error Handling:**
- **Missing Results:** Graceful handling of incomplete or missing result files
- **Organization Access:** Proper error handling for Organizations API failures
- **Data Validation:** Comprehensive validation of organization structure data

### PR-008: Run Checks Optimization

**Requirement:** The system MUST optimize check execution by skipping accounts when results files already exist, preventing unnecessary re-execution of expensive AWS API calls.

**Implementation Specifications:**

**Skip Logic Architecture:**
- **Results Existence Check:** `results_exist(check_name, account_name, account_id, results_base_dir, exclude_account_ids)` function from `write_results.py`
- **File Path Resolution:** Checks for results at `{results_base_dir}/{check_name}/{account_name}_{account_id}.json` or `{account_name}.json` depending on configuration
- **Backward Compatibility:** Supports both filename formats (with and without account IDs) for checking existence
- **Skip Decision:** Modified `run_checks()` function to check results existence before executing checks
- **Logging Integration:** Informative logging when checks are skipped: `"Results already exist for account {account_identifier}, skipping checks"`

**Performance Benefits:**
- **Reduced AWS API Calls:** Prevents unnecessary re-execution of expensive cross-account role assumptions
- **Faster Iteration:** Enables rapid development and testing cycles without full re-analysis
- **Cost Optimization:** Reduces AWS API usage costs during development and testing
- **Incremental Analysis:** Supports partial re-analysis scenarios

**Implementation Details:**
```python
def results_exist(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> bool:
    """
    Check if results file already exists for a given check and account.

    Checks for both filename formats to handle backward compatibility.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        account_name: Account name
        account_id: Account ID
        results_base_dir: Base directory for results
        exclude_account_ids: If True, check for filename without account ID

    Returns:
        True if results file exists, False otherwise
    """
    results_file = get_results_path(
        check_name,
        account_name,
        account_id,
        results_base_dir,
        exclude_account_ids,
    )
    if results_file.exists():
        return True

    # Check alternate format for backward compatibility
    alternate_file = get_results_path(
        check_name,
        account_name,
        account_id,
        results_base_dir,
        not exclude_account_ids,
    )
    return alternate_file.exists()
```

**Integration Flow:**
1. **Pre-Check Validation:** Before assuming roles and running checks, verify if results already exist
2. **Skip Decision:** If results exist, log skip message and continue to next account
3. **Normal Execution:** If results don't exist, proceed with standard check execution
4. **Transparent Operation:** Skip functionality is transparent to end users

**Testing Strategy:**
- **Skip Functionality Test:** Verify accounts are skipped when results exist
- **Normal Execution Test:** Verify checks run normally when results don't exist
- **Mixed Scenario Test:** Verify partial skip behavior with some accounts having results
- **Backward Compatibility Test:** Verify both filename formats are checked
- **Mock Integration:** All tests properly mock `results_exist()` function from `write_results.py`

### PR-009: Auto-generation of Terraform

**Requirement:** The system MUST auto-generate Terraform configuration files to capture AWS Organizations structure data for SCP/RCP deployment targeting.

**Implementation Specifications:**

**Terraform Generation Architecture:**
- **Target Module:** `generate_terraform.py` module handles all Terraform configuration generation
- **Target File:** Generate `grab_org_info.tf` under `test_environment/scps/` directory
- **Data Source Generation:** Auto-generate data sources for root OU, organizational units, and account IDs
- **Organization Structure Integration:** Leverage `analyze_organization_structure()` function output from `parse_results.py`
- **Validation Logic:** Include safety checks to ensure data integrity before accessing array elements

**Generated Terraform Structure:**
```hcl
# Auto-generated Terraform configuration for AWS Organizations structure
# Generated by Headroom for SCP/RCP deployment targeting

# Get the root OU ID
data "aws_organizations_organization" "org" {}

data "aws_organizations_organizational_units" "root_ou" {
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

# Get accounts for each top-level OU
data "aws_organizations_organizational_unit_child_accounts" "production_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Production"
  ][0]
}

data "aws_organizations_organizational_unit_child_accounts" "garbage_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Garbage"
  ][0]
}

locals {
  # Validation check for root OU access
  validation_check_root = (length(data.aws_organizations_organization.org.roots) == 1) ? "All good. This is a no-op." : error("[Error] Expected exactly 1 root OU, found ${length(data.aws_organizations_organization.org.roots)}")

  # Root OU ID
  root_ou_id = data.aws_organizations_organization.org.roots[0].id

  # Top-level OU IDs by name
  # Validation for Production OU
  validation_check_production_ou = (length([for ou in data.aws_organizations_organizational_units.root_ou.children : ou.id if ou.name == "Production"]) == 1) ? "All good. This is a no-op." : error("[Error] Expected exactly 1 Production OU, found ${length([for ou in data.aws_organizations_organizational_units.root_ou.children : ou.id if ou.name == "Production"])}")

  top_level_production_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Production"
  ][0]

  # Validation for Garbage OU
  validation_check_garbage_ou = (length([for ou in data.aws_organizations_organizational_units.root_ou.children : ou.id if ou.name == "Garbage"]) == 1) ? "All good. This is a no-op." : error("[Error] Expected exactly 1 Garbage OU, found ${length([for ou in data.aws_organizations_organizational_units.root_ou.children : ou.id if ou.name == "Garbage"])}")

  top_level_garbage_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Garbage"
  ][0]

  # Account IDs by name
  # Validation for prod-account account
  validation_check_prod_account_account = (length([for account in data.aws_organizations_organizational_unit_child_accounts.production_accounts.accounts : account.id if account.name == "prod-account"]) == 1) ? "All good. This is a no-op." : error("[Error] Expected exactly 1 prod-account account, found ${length([for account in data.aws_organizations_organizational_unit_child_accounts.production_accounts.accounts : account.id if account.name == "prod-account"])}")

  prod_account_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.production_accounts.accounts :
    account.id if account.name == "prod-account"
  ][0]

  # Validation for garbage-account account
  validation_check_garbage_account_account = (length([for account in data.aws_organizations_organizational_unit_child_accounts.garbage_accounts.accounts : account.id if account.name == "garbage-account"]) == 1) ? "All good. This is a no-op." : error("[Error] Expected exactly 1 garbage-account account, found ${length([for account in data.aws_organizations_organizational_unit_child_accounts.garbage_accounts.accounts : account.id if account.name == "garbage-account"])}")

  garbage_account_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.garbage_accounts.accounts :
    account.id if account.name == "garbage-account"
  ][0]
}
```

**Implementation Functions:**

**1. Terraform Generation Function (in `terraform/generate_org_info.py`):**
```python
def generate_terraform_org_info(session: boto3.Session, output_path: str) -> None:
    """
    Generate grab_org_info.tf file with organization structure data sources.

    Args:
        session: AWS session with Organizations API access
        output_path: Path to write the Terraform file
    """
    logger.info("Generating Terraform organization info file")

    try:
        organization_hierarchy = analyze_organization_structure(session)
        logger.info(f"Found {len(organization_hierarchy.organizational_units)} OUs and {len(organization_hierarchy.accounts)} accounts")
    except RuntimeError as e:
        logger.error(f"Failed to analyze organization structure: {e}")
        return

    # Generate Terraform content
    terraform_content = _generate_terraform_content(organization_hierarchy)

    # Write to file
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(output_file, 'w') as f:
            f.write(terraform_content)
        logger.info(f"Successfully generated Terraform file: {output_path}")
    except IOError as e:
        logger.error(f"Failed to write Terraform file: {e}")
```

**2. Organization Structure Processing:**
- **Root OU Detection:** Extract root OU ID with validation
- **OU Hierarchy Mapping:** Generate data sources for all organizational units
- **Account Mapping:** Create data sources for accounts under each OU
- **Validation Integration:** Include safety checks for array access

**3. Terraform Template Generation:**
- **Data Source Templates:** Generate `aws_organizations_organization`, `aws_organizations_organizational_units`, and `aws_organizations_organizational_unit_child_accounts` data sources
- **Local Variable Templates:** Create validation locals for safe array access with inline validation checks
- **Multi-line Formatting:** Filtering expressions split across multiple lines for readability
- **ID-only Variables:** Generate only `_id` local variables (no `_name` variables)
- **Comprehensive Validation:** Each OU and account has its own validation check to ensure exactly one match

**Validation and Safety Features:**
- **Array Length Validation:** Check array lengths before accessing elements (e.g., `roots[0]`)
- **Single Element Validation:** Ensure filtering expressions return exactly one element before indexing `[0]`
- **Error Messages:** Provide clear error messages for validation failures
- **No-Op Validation:** Use conditional expressions for validation checks
- **Data Integrity:** Ensure generated Terraform is syntactically correct and safe

**Integration Points:**
- **Organization Analysis:** Leverage existing `analyze_organization_structure()` function from `aws.organization` module
- **Session Management:** Use existing AWS session handling from analysis module
- **Configuration Integration:** Respect existing configuration patterns with `scps_dir` from config
- **Output Directory:** Generate files in configured `scps_dir` directory (default: `test_environment/scps/`)
- **Module Separation:** Terraform generation isolated in dedicated `terraform/generate_org_info.py` module
- **Called From:** `parse_results()` function generates this file during SCP placement analysis phase

**Generated File Structure:**
- **Root Organization Data:** `aws_organizations_organization` data source
- **Root OU Data:** `aws_organizations_organizational_units` for root level
- **Account Data Sources:** Individual `aws_organizations_organizational_unit_child_accounts` data sources for each top-level OU
- **Local Variables:** ID-only variables with multi-line filtering expressions and inline validation
- **Validation Locals:** Comprehensive validation checks for root, each OU, and each account
- **No Output Variables:** Only local variables for internal use

**Error Handling:**
- **AWS API Failures:** Graceful handling of Organizations API errors
- **Data Validation:** Comprehensive validation of organization structure data
- **File Generation:** Proper error handling for file writing operations
- **Template Validation:** Ensure generated Terraform is syntactically valid

**Testing Strategy:**
- **Unit Tests:** Test Terraform generation with mock organization data
- **Integration Tests:** Test with real AWS Organizations API calls
- **Template Validation:** Verify generated Terraform syntax
- **Edge Case Testing:** Test with empty organizations, single OU, complex hierarchies

### PR-010: SCP Terraform Auto-Generation

**Requirement:** The system MUST auto-generate Terraform configuration files for SCP deployment based on compliance analysis results, creating account-specific, OU-specific, and root-level SCP configurations.

**Implementation Specifications:**

**SCP Generation Architecture:**
- **Target Module:** `terraform/generate_scps.py` module handles all SCP Terraform configuration generation
- **Target Directory:** Generate SCP files under `test_environment/scps/` directory
- **Safety-First Logic:** Only generate SCP configurations when compliance percentage is 100% (zero violations)
- **Multi-Level Support:** Generate configurations for account-level, OU-level, and root-level SCP deployment
- **Integration Ready:** Uses data sources from `grab_org_info.tf` for consistent referencing

**Generated SCP Terraform Structure:**

**Account-Level SCPs:**
```hcl
# Auto-generated SCP Terraform configuration for fort-knox
# Generated by Headroom based on compliance analysis

module "scps_fort_knox" {
  source = "./modules/scps"
  target_id = locals.fort_knox_account_id

  # deny_imds_v1_ec2
  deny_imds_v1_ec2 = true
}
```

**OU-Level SCPs:**
```hcl
# Auto-generated SCP Terraform configuration for production OU
# Generated by Headroom based on compliance analysis

module "scps_production_ou" {
  source = "./modules/scps"
  target_id = locals.top_level_production_ou_id

  # deny_imds_v1_ec2
  deny_imds_v1_ec2 = true
}
```

**Root-Level SCPs:**
```hcl
# Auto-generated SCP Terraform configuration for root
# Generated by Headroom based on compliance analysis

module "scps_root" {
  source = "./modules/scps"
  target_id = locals.root_ou_id

  # deny_imds_v1_ec2
  deny_imds_v1_ec2 = true
}
```

**Implementation Functions:**

**1. SCP Generation Function (in `terraform/generate_scps.py`):**
```python
def generate_scp_terraform(recommendations: List[SCPPlacementRecommendations],
                          organization_hierarchy: OrganizationHierarchy) -> None:
    """
    Generate SCP Terraform files based on compliance analysis recommendations.

    Args:
        recommendations: List of SCP placement recommendations from compliance analysis
        organization_hierarchy: AWS Organizations structure for OU and account lookup
    """
```

**2. Safety-First Logic:**
- **100% Compliance Check:** Only generates SCP configurations when `compliance_percentage == 100.0`
- **Zero Violations Principle:** Ensures SCPs won't break existing compliant resources
- **Account-Level Focus:** Currently implements account-level SCP deployment with framework for OU/root levels
- **Terraform Integration:** Generates proper Terraform module calls with correct target references

**3. File Naming Convention:**
- **Account Level:** `{safe_account_name}_scps.tf` (e.g., `fort_knox_scps.tf`)
- **OU Level:** `{safe_ou_name}_ou_scps.tf` (e.g., `production_ou_scps.tf`)
- **Root Level:** `root_scps.tf`

**4. Data Source Integration:**
- **Consistent Referencing:** Uses `locals.{account_name}_account_id` for account-level SCPs
- **OU References:** Uses `locals.top_level_{ou_name}_ou_id` for OU-level SCPs
- **Root References:** Uses `locals.root_ou_id` for root-level SCPs
- **Safe Naming:** Converts account/OU names to terraform-friendly format (replace hyphens/spaces with underscores, lowercase)

**Key Features:**
- **Safety-First Deployment:** Only enables SCPs when compliance is 100% (no existing violations)
- **Multi-Level Support:** Account, OU, and root level SCP deployment
- **Terraform Integration:** Generates proper Terraform module calls
- **Extensible Design:** Framework ready for additional SCP checks and deployment strategies
- **Comprehensive Logging:** Logs all recommendations and generation activities

**Integration Flow:**
1. **Post-Analysis Processing:** Called after `parse_results()` returns SCP placement recommendations
2. **Recommendation Processing:** Groups recommendations by level (account, OU, root)
3. **Compliance Validation:** Verifies 100% compliance before generating SCP configurations
4. **File Generation:** Creates Terraform files for each compliant target
5. **Logging Output:** Reports generation activities and skipped non-compliant targets

**Error Handling:**
- **Missing Recommendations:** Graceful handling when no recommendations are provided
- **Organization Access:** Proper error handling for organization hierarchy lookup failures
- **File Generation:** Comprehensive error handling for Terraform file writing operations
- **Data Validation:** Validation of recommendation data before processing

**Testing Strategy:**
- **Account-Level Tests:** Verify Terraform generation for account-level recommendations
- **OU-Level Tests:** Test OU-level SCP file generation
- **Root-Level Tests:** Test root-level SCP file generation
- **Compliance Validation:** Test that non-compliant accounts are skipped
- **File Content Validation:** Verify correct Terraform content generation
- **Integration Tests:** End-to-end testing with real recommendation data

### PR-011: RCP Compliance Analysis Engine

**Requirement:** The system MUST provide comprehensive Resource Control Policy (RCP) compliance analysis by examining IAM role trust policies to identify third-party account access patterns and automatically generate RCP Terraform configurations to enforce organization identity controls.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**RCP Analysis Architecture:**
- **IAM Trust Policy Analysis:** `aws/iam.py` module analyzes all IAM role trust policies across organization accounts
- **Third-Party Detection:** Identifies account IDs in trust policies that are external to the organization
- **Wildcard Detection:** Detects and reports roles with wildcard principals (requiring CloudTrail analysis)
- **Organization Account Baseline:** Compares trust policy principals against full organization account list
- **Check Orchestration:** `checks/check_third_party_role_access.py` coordinates RCP analysis execution
- **Fail-Loud Exception Handling:** All exceptions are specific (no generic `Exception` catching), logged with context, and immediately re-raised

**IAM Trust Policy Analysis:**

**Core Functions (in `aws/iam.py`):**
```python
def analyze_iam_roles_trust_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[TrustPolicyAnalysis]:
    """
    Analyze all IAM roles in an account to identify third-party account principals.

    Examines AssumeRole trust policies and extracts account IDs that are not part
    of the organization.

    Returns list of roles with third-party access or wildcard principals.
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from IAM policy principal field.

    Handles:
    - String principals (ARNs, account IDs, wildcards)
    - List principals (recursive processing)
    - Dict principals (AWS, Service, Federated keys)
    - Mixed principals (e.g., {"AWS": [...], "Service": "..."})

    Validates all principal types are known (AWS, Service, Federated).
    Only processes AWS principals for account ID extraction.
    Service and Federated principals are validated but skipped.
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """
    Check if principal contains wildcard (*) allowing any principal to assume role.
    """
```

**Data Model:**
```python
@dataclass
class TrustPolicyAnalysis:
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
```

**Principal Type Handling:**
- **AWS Principals:** Processed for account ID extraction from ARNs and plain account IDs
- **Service Principals:** Validated but skipped (e.g., `lambda.amazonaws.com`, `ec2.amazonaws.com`)
- **Federated Principals:** Validated but skipped (SAML/OIDC providers)
- **Mixed Principals:** Correctly handles dicts with multiple principal types
- **Unknown Types:** Raises `UnknownPrincipalTypeError` to catch typos or new AWS types

**Principal Validation:**
- **Allowed Types:** `{"AWS", "Service", "Federated"}` enforced via validation
- **Federated Action Validation:** Ensures Federated principals use `sts:AssumeRoleWithSAML` or `sts:AssumeRoleWithWebIdentity`, not `sts:AssumeRole`
- **Custom Exceptions:** `UnknownPrincipalTypeError` and `InvalidFederatedPrincipalError` for clear error messaging

**Exception Handling:**
- **Specific Exceptions Only:** No generic `except Exception:` - all handlers catch specific types
- **JSON Parsing:** `json.JSONDecodeError` for trust policy parsing failures
- **AWS API Errors:** `ClientError` for boto3/botocore API failures
- **Custom Validation:** `UnknownPrincipalTypeError`, `InvalidFederatedPrincipalError` for policy validation
- **Fail Loudly:** All exceptions logged with context and immediately re-raised
- **No Silent Failures:** System prevents partial results from suppressed errors

**RCP Check Implementation:**

**Check Function (in `checks/check_third_party_role_access.py`):**
```python
def check_third_party_role_access(
    headroom_session: boto3.Session,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool,
    org_account_ids: Set[str]
) -> Set[str]:
    """
    Check IAM roles for third-party account access in trust policies.

    Returns set of all third-party account IDs found.
    Writes detailed JSON results including role names, ARNs, and findings.
    """
```

**Result Structure:**
```json
{
  "summary": {
    "account_name": "account-name",
    "account_id": "111111111111",
    "check": "check_third_party_role_access",
    "total_roles_analyzed": 50,
    "roles_third_parties_can_access": 3,
    "roles_with_wildcards": 1,
    "unique_third_party_accounts": 2,
    "violations": 1
  },
  "roles_third_parties_can_access": [
    {
      "role_name": "CrossAccountRole",
      "role_arn": "arn:aws:iam::111111111111:role/CrossAccountRole",
      "third_party_account_ids": ["999999999999"]
    }
  ],
  "roles_with_wildcards": [
    {
      "role_name": "WildcardRole",
      "role_arn": "arn:aws:iam::111111111111:role/WildcardRole"
    }
  ]
}
```

**Violations Field:** The `violations` field in the summary counts roles with wildcard principals, as these represent violations that prevent RCP deployment at root/OU levels.

**Organization Account ID Retrieval:**

**Function (in `analysis.py`):**
```python
def get_all_organization_account_ids(
    config: HeadroomConfig,
    session: boto3.Session
) -> Set[str]:
    """
    Retrieve all account IDs in the organization including management account.

    Assumes OrgAndAccountInfoReader role in management account.
    Returns set of all account IDs for third-party filtering.
    """
```

**Wildcard Safety:**
- **Detection:** Identifies roles with `"Principal": "*"` or `"AWS": "*"` allowing any principal
- **Skip Logic:** Accounts with wildcard principals excluded from RCP generation
- **OU-Level Safety:** OU-level RCPs skipped if ANY account in OU has wildcards
- **CloudTrail TODO:** Comments indicate need for CloudTrail analysis to determine actual assuming accounts

### PR-012: RCP Terraform Auto-Generation

**Requirement:** The system MUST auto-generate Terraform configuration files for RCP deployment based on IAM trust policy analysis, creating RCP configurations that enforce organization identity controls while allowing approved third-party accounts.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**RCP Generation Architecture:**
- **Target Module:** `terraform/generate_rcps.py` handles all RCP Terraform configuration generation
- **Target Directory:** Generate RCP files under configured `rcps_dir` (default: `test_environment/rcps/`)
- **Safety-First Logic:** Excludes accounts with wildcard principals from RCP generation
- **Multi-Level Support:** Account-level, OU-level, and root-level RCP deployment
- **Union Strategy:** Third-party account IDs from multiple accounts/OUs are combined (unioned) together
- **Third-Party Allowlist:** Includes approved third-party account IDs in RCP policy allowlist
- **Missing Account ID Handling:** Looks up accounts by name in organization hierarchy when account_id is missing

**Generated RCP Terraform Structure:**

**Account-Level RCPs:**
```hcl
# Auto-generated RCP Terraform configuration for account-name
# Generated by Headroom based on IAM trust policy analysis

module "rcps_account_name" {
  source = "./modules/rcps"
  target_id = locals.account_name_account_id

  # Third-party accounts approved for role assumption
  third_party_assumerole_account_ids_allowlist = [
    "999999999999",
    "888888888888"
  ]
}
```

**OU-Level RCPs:**
```hcl
# Auto-generated RCP Terraform configuration for production OU
# Generated by Headroom based on IAM trust policy analysis

module "rcps_production_ou" {
  source = "./modules/rcps"
  target_id = locals.top_level_production_ou_id

  # Third-party accounts approved for role assumption (unioned from all accounts in OU)
  third_party_assumerole_account_ids_allowlist = [
    "999999999999",
    "888888888888"
  ]
}
```

**Root-Level RCPs:**
```hcl
# Auto-generated RCP Terraform configuration for root
# Generated by Headroom based on IAM trust policy analysis

module "rcps_root" {
  source = "./modules/rcps"
  target_id = locals.root_ou_id

  # Third-party accounts approved for role assumption (unioned from all accounts in organization)
  third_party_assumerole_account_ids_allowlist = [
    "999999999999",
    "888888888888"
  ]
}
```

**RCP Terraform Module (in `test_environment/modules/rcps/`):**

**Module Structure:**
- **`variables.tf`:** Defines `target_id` and `third_party_assumerole_account_ids_allowlist` variables
- **`locals.tf`:** Defines RCP policy with EnforceOrgIdentities statement
- **`rcps.tf`:** Creates `aws_organizations_policy` and `aws_organizations_policy_attachment` resources
- **`data.tf`:** Contains `aws_organizations_organization.current` data source for org ID
- **`README.md`:** Documents module usage and RCP policy logic

**RCP Policy Logic:**
```hcl
# Deny sts:AssumeRole EXCEPT:
# 1. Principals from the organization (aws:PrincipalOrgID)
# 2. Principals from approved third-party accounts (aws:PrincipalAccount)
# 3. Resources tagged with dp:exclude:identity: true
# 4. AWS service principals
```

**Implementation Functions:**

**1. Results Parsing (in `terraform/generate_rcps.py`):**
```python
def parse_rcp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> Tuple[Dict[str, Set[str]], Set[str]]:
    """
    Parse RCP check results and extract third-party account mappings.

    Args:
        results_dir: Directory containing RCP check result files
        organization_hierarchy: Organization structure for account lookup when account_id is missing

    Returns:
        Tuple of (account_third_party_map, accounts_with_wildcards)
        - account_third_party_map: Dict mapping account IDs to sets of third-party account IDs
        - accounts_with_wildcards: Set of account IDs that have roles with wildcard principals

    Missing Account ID Handling:
        When account_id is missing or empty (e.g., when exclude_account_ids=True),
        the function looks up the account_id by account_name in the organization hierarchy.
        Raises RuntimeError if account_name is not found.

    Accounts with wildcards are NOT excluded from the account_third_party_map (included with empty sets).
    Accounts with no third-party accounts are included with empty sets to ensure they get RCPs.
    """
```

**2. Placement Determination (in `terraform/generate_rcps.py`):**
```python
def determine_rcp_placement(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Determine optimal RCP placement levels based on third-party account patterns.

    Uses "union strategy" to combine third-party accounts at each level:
    - Root level: If NO accounts have wildcard principals, unions all third-party
                 account IDs from all accounts and deploys single RCP at root
    - OU level: If any accounts in an OU have wildcards, OU-level RCP is skipped for that OU;
               otherwise, unions all third-party account IDs from accounts in the OU
    - Account level: For accounts with wildcards, no RCP is generated (static analysis cannot
                    determine required principals)

    Union Strategy Rationale:
    - Third-party account IDs can be safely combined into a single allowlist
    - Account A trusts [111111111111], Account B trusts [222222222222] can both
      be protected with allowlist [111111111111, 222222222222]
    - More permissive than "identical sets" requirement, enables broader root/OU deployment
    - Still safe because RCPs use allowlists, not deny lists

    Critical Safety Rules:
    - Root-level RCPs are ONLY deployed if NO accounts have wildcards (affects ALL accounts)
    - OU-level RCPs are ONLY deployed if NO accounts in that OU have wildcards
    - Accounts with wildcards are excluded from ALL RCP recommendations
    - Single-account OUs receive OU-level RCPs (not account-level) for better hierarchy alignment
    """
```

**3. Terraform Generation (in `terraform/generate_rcps.py`):**
```python
def generate_rcp_terraform(
    recommendations: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_dir: str = "test_environment/rcps"
) -> None:
    """
    Generate RCP Terraform files based on placement recommendations.

    Args:
        recommendations: List of RCP placement recommendations
        organization_hierarchy: Organization structure for account/OU name lookup
        output_dir: Directory to write RCP Terraform files (default: test_environment/rcps)

    Creates separate .tf files for root, OU, and account level RCPs.
    Uses union strategy to combine third-party account IDs at each level.
    """
```

**Data Model:**
```python
@dataclass
class RCPPlacementRecommendations:
    check_name: str
    recommended_level: str  # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    third_party_account_ids: Set[str]
    reasoning: str
```

**Placement Logic:**

**Union Strategy (Default Behavior):**
- **Root Level:** Deploy at root when NO accounts have wildcards; combines (unions) all third-party account IDs from all accounts
- **OU Level:** Deploy at OU level when NO accounts in that OU have wildcards; combines third-party IDs from accounts in the OU
- **Account Level:** Deploy at account level for accounts with wildcards (but wildcards prevent RCP deployment, so effectively skipped)
- **Single-Account OUs:** Treated as OU-level deployments (not account-level) for organizational hierarchy alignment

**Critical Safety Rules:**
- **Wildcard Exclusion:** Accounts with wildcard principals (`"Principal": "*"`) are excluded from RCP deployment
- **Root Wildcard Blocking:** If ANY account has wildcards, root-level RCP is NOT deployed (would affect all accounts)
- **OU Wildcard Blocking:** If ANY account in an OU has wildcards, OU-level RCP is NOT deployed for that OU
- **Affected Accounts:** Root-level RCPs list ALL accounts in organization as affected (not just those without wildcards)
- **Union Allowlist:** Third-party account IDs are combined (unioned) together, not required to be identical

**Union Strategy Benefits:**
- More permissive than requiring identical third-party account sets
- Enables root/OU-level deployment in more scenarios
- Still safe because RCPs use allowlists (approved principals) not deny lists
- Example: Account A [111], Account B [222] → Root RCP allowlist [111, 222]

**Integration Flow:**
1. **Analysis Phase:** IAM trust policy analysis identifies third-party accounts and wildcards
2. **Results Parsing:** Parse check results from `headroom_results/check_third_party_role_access/` directory
3. **Wildcard Filtering:** Separate accounts with wildcards from those eligible for RCP deployment
4. **Placement Calculation:** Determine optimal RCP levels based on common third-party account patterns
5. **OU Safety Check:** Verify no wildcards exist in OU before creating OU-level RCP
6. **Terraform Generation:** Create RCP Terraform files with appropriate third-party account whitelists
7. **Console Output:** Display RCP recommendations including level, target, accounts, and reasoning

**Testing Strategy:**
- **IAM Analysis Tests:** 27 tests covering principal extraction, wildcard detection, exception handling
- **Check Tests:** 6 tests covering aggregation, wildcards, empty results, violations counting
- **RCP Generation Tests:** 30+ tests covering parsing, placement, union strategy, wildcard safety, Terraform generation, missing account ID lookup
- **Integration Tests:** End-to-end RCP display and generation flow
- **BDD-Style Test Names:** Descriptive test names following "test_<action>_when_<condition>" pattern
- **100% Coverage:** All RCP-related code fully covered (245 total tests passing, 1022+ statements in headroom/, 2466+ in tests/)

**Code Quality:**
- **Specific Exceptions:** All exception handlers catch specific types (`json.JSONDecodeError`, `ClientError`, custom exceptions)
- **No Silent Failures:** All exceptions logged and re-raised
- **Type Safety:** Full type annotations satisfying mypy strict mode
- **Clean Architecture:** Clear separation between IAM analysis, check execution, and Terraform generation
- **DRY Compliance:** Shared utilities in `terraform/utils.py` for variable name generation

### PR-013: RCP Code Quality & Bug Fixes

**Requirement:** The system MUST maintain high code quality standards and fix critical bugs discovered during RCP implementation.

**Implementation Status:** ✅ COMPLETED (rcp_support_initial branch)

**Refactoring Improvements:**

1. **Function Extraction for Single Responsibility:**
   - Created `_should_skip_ou_for_rcp()` helper function (32 lines) to encapsulate OU validation logic
   - Separated file writing from content generation with `_write_terraform_file()` helper (10 lines)
   - Reduced code duplication and improved testability
   - Simplified calling functions from 10 lines of inline logic to 1-line function calls

2. **Pattern Alignment:**
   - Aligned RCP generation pattern with SCP pattern (grouping-then-generating approach)
   - Changed from inline switching to two-phase approach: group by level, then generate files
   - Improved consistency across SCP and RCP generation modules

3. **BDD-Style Test Names:**
   - Renamed tests to descriptive BDD format: `test_<action>_when_<condition>`
   - Example: `test_root_level_placement` → `test_recommends_root_level_when_all_accounts_have_identical_third_party_accounts`
   - Self-documenting tests that serve as specifications

**Critical Bug Fixes:**

1. **RCP Generation Writing to Wrong Directory:**
   - **Problem:** RCPs were being written to `test_environment/scps/` instead of `test_environment/rcps/`
   - **Root Cause:** Missing `rcps_dir` config field, wrong default directory in generate_rcps.py, missing CLI argument
   - **Solution:** Added `rcps_dir` config field with `DEFAULT_RCPS_DIR = "test_environment/rcps"` constant
   - **Impact:** RCPs and SCPs now properly separated into different directories

2. **RCP Check Generating SCP Terraform:**
   - **Problem:** `third_party_role_access` RCP check was generating SCP Terraform files
   - **Root Cause:** `parse_result_files()` was processing ALL checks including RCP checks
   - **Solution:** Added `exclude_rcp_checks: bool = True` parameter and `RCP_CHECK_NAMES = {"third_party_role_access"}` set
   - **Impact:** RCP checks now only processed by RCP-specific flow, not SCP flow

3. **Missing Account ID Handling:**
   - **Problem:** When `exclude_account_ids=True`, account_id was empty and parsing failed
   - **Root Cause:** No fallback mechanism to look up accounts by name
   - **Solution:** Added organization_hierarchy parameter to parse functions, lookup by account_name when account_id missing
   - **Impact:** Tool now works correctly with `exclude_account_ids=True` configuration

4. **Accounts Without Third-Party Access Excluded:**
   - **Problem:** Accounts with no third-party accounts were being skipped entirely
   - **Root Cause:** Condition `if account_id and third_party_accounts:` evaluated to False for empty lists
   - **Solution:** Changed to `if account_id:` to include accounts with empty third-party lists
   - **Impact:** Accounts without third-party access now get organization-identities-only RCPs

5. **Incorrect Root-Level RCP Logic:**
   - **Problem:** Root-level RCPs showed wrong "Affected Accounts" count and ignored third-party accounts from wildcard accounts
   - **Root Cause:** Function only considered accounts without wildcards, but root RCPs affect ALL accounts
   - **Solution:** Added `organization_hierarchy` and `accounts_with_wildcards` parameters, include ALL org accounts in affected list
   - **Impact:** Root-level RCPs now correctly refused when ANY account has wildcards, preventing broken third-party access

6. **Violations Count Missing:**
   - **Problem:** RCP check results didn't include violations count needed for parse_results analysis
   - **Root Cause:** Summary section didn't include violations field
   - **Solution:** Added `"violations": len(roles_with_wildcards)` to summary
   - **Impact:** Wildcard trust relationships now properly counted as violations

7. **Conservative Identical-Sets Requirement:**
   - **Problem:** Root/OU-level RCPs only deployed when ALL accounts had IDENTICAL third-party account sets
   - **Root Cause:** Overly conservative placement logic
   - **Solution:** Implemented union strategy - combine (union) all third-party account IDs at each level
   - **Impact:** More permissive deployment enabling root/OU-level RCPs in many more scenarios

8. **Parameter Name Ambiguity:**
   - **Problem:** Parameter named `third_party_account_ids` didn't clearly indicate it was an allowlist
   - **Root Cause:** Generic parameter name
   - **Solution:** Renamed to `third_party_assumerole_account_ids_allowlist` throughout codebase
   - **Impact:** Clearer intent and purpose of the parameter

9. **Single-Account OU Handling:**
   - **Problem:** Single-account OUs were getting account-level RCPs instead of OU-level RCPs
   - **Root Cause:** `MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 2` arbitrary constraint
   - **Solution:** Changed to `MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 1`
   - **Impact:** Better organizational hierarchy alignment, future-proofing for additional accounts

**Files Modified:**
- `headroom/config.py`: Added rcps_dir field
- `headroom/main.py`: Updated to use rcps_dir, pass organization_hierarchy
- `headroom/usage.py`: Added --rcps-dir CLI argument
- `headroom/terraform/generate_rcps.py`: Fixed directory, union strategy, root-level logic, missing account ID lookup
- `headroom/parse_results.py`: Added RCP check exclusion, account lookup by name
- `headroom/checks/check_third_party_role_access.py`: Added violations count
- `test_environment/modules/rcps/variables.tf`: Renamed parameter
- `test_environment/modules/rcps/locals.tf`: Updated parameter reference
- `test_environment/modules/rcps/README.md`: Updated documentation
- `tests/test_config.py`: Added rcps_dir testing
- `tests/test_generate_rcps.py`: Added 8+ new tests, updated existing tests
- `tests/test_parse_results.py`: Added RCP exclusion test, account lookup tests
- `tests/test_checks_third_party_role_access.py`: Updated to assert violations field

**Verification:**
- All 245 tests pass with 100% code coverage
- No linter errors (flake8, autopep8, autoflake)
- Full mypy type safety compliance
- No behavioral regressions

### PR-014: Architectural Organization - SCP/RCP Directory Structure

**Requirement:** The system MUST organize SCP and RCP checks and results into clearly separated directory structures to improve code organization, scalability, and maintainability.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**Organizational Improvements:**

1. **Function and File Renaming for Clarity:**
   - Renamed `parse_result_files()` to `parse_scp_result_files()` to explicitly indicate SCP-specific parsing
   - Renamed `check_third_party_role_access` to `check_third_party_assumerole` for more accurate naming
   - Renamed variable `rcp_results_exist` to `third_party_assumerole_results_exist` for consistency
   - Updated `RCP_CHECK_NAMES` from `{"third_party_role_access"}` to `{"third_party_assumerole"}`

2. **Checks Directory Reorganization:**
   - Created `checks/scps/` subdirectory for Service Control Policy check implementations
   - Created `checks/rcps/` subdirectory for Resource Control Policy check implementations
   - Moved `deny_imds_v1_ec2.py` to `checks/scps/deny_imds_v1_ec2.py`
   - Moved and renamed `check_third_party_role_access.py` to `checks/rcps/check_third_party_assumerole.py`
   - Added `__init__.py` files to both subdirectories for proper Python package structure
   - Updated all relative imports to account for increased directory depth (using `...` for parent references)

3. **Results Directory Reorganization:**
   - Implemented hierarchical structure: `results_dir/scps/{check_name}/*.json` and `results_dir/rcps/{check_name}/*.json`
   - Added `CHECK_TYPE_MAP` in `write_results.py` mapping check names to types: `{"deny_imds_v1_ec2": "scps", "third_party_assumerole": "rcps"}`
   - Updated `get_results_dir()` to construct paths: `{results_base_dir}/{check_type}/{check_name}`
   - Updated `get_results_path()` to use new directory structure
   - **Breaking Change:** No backward compatibility for old flat results structure - clean break for better organization
   - Updated `parse_scp_result_files()` to look in `results_dir/scps/` subdirectory
   - Added warning when `scps/` subdirectory doesn't exist
   - Updated `parse_rcp_result_files()` to look in `results_dir/rcps/third_party_assumerole/` subdirectory

4. **Analysis Module Refactoring (analysis.py):**
   - Extracted `run_scp_checks()` function to encapsulate SCP check execution logic
     ```python
     def run_scp_checks(
         headroom_session: boto3.Session,
         account_info: AccountInfo,
         config: HeadroomConfig
     ) -> None:
         """Execute all SCP checks for a single account."""
     ```
   - Extracted `run_rcp_checks()` function to encapsulate RCP check execution logic
     ```python
     def run_rcp_checks(
         headroom_session: boto3.Session,
         account_info: AccountInfo,
         config: HeadroomConfig,
         org_account_ids: Set[str]
     ) -> None:
         """Execute all RCP checks for a single account."""
     ```
   - Added `all_scp_results_exist()` helper to check if all SCP results exist for an account
     ```python
     def all_scp_results_exist(
         account_info: AccountInfo,
         config: HeadroomConfig
     ) -> bool:
         """Check if all SCP check results exist for an account."""
     ```
   - Added `all_rcp_results_exist()` helper to check if all RCP results exist for an account
     ```python
     def all_rcp_results_exist(
         account_info: AccountInfo,
         config: HeadroomConfig
     ) -> bool:
         """Check if all RCP check results exist for an account."""
     ```
   - Simplified `run_checks()` to orchestrate the extracted functions with clearer skip logic
   - Updated log message from "Results already exist" to "All results already exist" for clarity

5. **RCP Generation Updates:**
   - Moved `MIN_ACCOUNTS_FOR_OU_LEVEL_RCP` constant to module level in `generate_rcps.py` for testability
   - Updated error messages to reference "Third-party AssumeRole" instead of "Third-party role access"
   - Updated check_name references in data structures to use "third_party_assumerole"

**Test Suite Updates:**

6. **Comprehensive Test Refactoring:**
   - Updated all import statements to reflect new directory structure:
     - `from headroom.checks.scps.deny_imds_v1_ec2 import check_deny_imds_v1_ec2`
     - `from headroom.checks.rcps.check_third_party_assumerole import check_third_party_assumerole`
   - Updated all path assertions in tests to expect `scps/` and `rcps/` subdirectories
   - Updated all `@patch` decorators to use new module paths:
     - `@patch("headroom.checks.scps.deny_imds_v1_ec2.get_imds_v1_ec2_analysis")`
     - `@patch("headroom.checks.rcps.check_third_party_assumerole.analyze_iam_roles_trust_policies")`
   - Updated all check name assertions from "third_party_role_access" to "third_party_assumerole"
   - Added `parents=True` to `mkdir()` calls to ensure parent directories are created
   - Updated mock `side_effect` values to account for additional `results_exist` calls from new helper functions
   - Renamed test file from `test_checks_third_party_role_access.py` to `test_checks_third_party_assumerole.py`
   - Renamed test class from `TestCheckThirdPartyRoleAccess` to `TestCheckThirdPartyAssumeRole`
   - Updated test directory structures in `test_environment/headroom_results/` to include `scps/` and `rcps/` subdirectories

**Coverage Improvements:**

7. **Edge Case Testing:**
   - Added test for non-directory files in `scps/` directory (covers `parse_results.py:60`)
   - Added test for unknown check names in `get_results_dir()` (covers `write_results.py:121`)
   - Added test for missing `scps/` subdirectory (covers `parse_results.py:54-55`)
   - Added test for OU-level RCP skip when below minimum accounts threshold (covers `generate_rcps.py:210`)
   - Achieved and maintained 100% code coverage (1044 statements in headroom/, 2515 statements in tests/)

**Architectural Benefits:**

- **Clear Separation of Concerns:** SCP and RCP checks are now clearly separated in both implementation and results
- **Improved Scalability:** Easy to add new SCP or RCP checks in their respective directories
- **Better Code Organization:** Single Responsibility Principle applied to check execution functions
- **Reduced Cognitive Load:** Developers can focus on SCP or RCP checks independently
- **Enhanced Maintainability:** Clear directory structure makes it easier to navigate and understand the codebase
- **Future-Proof:** Structure supports easy addition of new policy types (e.g., SCCPs, permission boundaries)
- **Module-Level Constants:** Testable configuration constants enable better test coverage
- **Explicit Function Names:** Function names clearly indicate their purpose and scope

**Files Modified:**

**Core Modules:**
- `headroom/analysis.py`: Extracted SCP/RCP check functions, added result existence helpers
- `headroom/parse_results.py`: Renamed to `parse_scp_result_files`, updated to use `scps/` subdirectory
- `headroom/write_results.py`: Added `CHECK_TYPE_MAP`, updated path generation functions
- `headroom/terraform/generate_rcps.py`: Updated to use `rcps/` subdirectory, moved constant to module level
- `headroom/checks/scps/deny_imds_v1_ec2.py`: Moved and updated relative imports (`.` to `...`)
- `headroom/checks/rcps/check_third_party_assumerole.py`: Renamed, moved, updated relative imports

**Test Files:**
- `tests/test_analysis.py`: Updated imports for new directory structure
- `tests/test_analysis_extended.py`: Updated imports, mock side effects, log message assertions
- `tests/test_checks_deny_imds_v1_ec2.py`: Updated all patch paths to `checks.scps.*`
- `tests/test_checks_third_party_assumerole.py`: Renamed file, updated all patch paths to `checks.rcps.*`, updated check name assertions
- `tests/test_parse_results.py`: Updated all path expectations with `scps/` subdirectory, added edge case tests
- `tests/test_generate_rcps.py`: Updated all path expectations with `rcps/` subdirectory, added MIN threshold test
- `tests/test_write_results.py`: Updated all path expectations, added unknown check name test
- `tests/test_main_integration.py`: Updated check name references

**Test Environment:**
- `test_environment/headroom_results/`: Reorganized into `scps/` and `rcps/` subdirectories

**Verification:**
- All 246 tests passing (increased from 245 due to new edge case tests)
- 100% code coverage maintained (1044 statements in headroom/, 2515 statements in tests/)
- All mypy type checks passing with strict mode
- All pre-commit hooks passing (flake8, autopep8, autoflake, trailing whitespace, end-of-file)
- No behavioral regressions in existing functionality
- Clean tox run with no warnings or errors

---

## Technical Architecture

### Core Data Flow

1. **Configuration Phase**
   - Parse CLI arguments (required `--config` flag)
   - Load YAML configuration file
   - Merge YAML + CLI with CLI taking precedence
   - Validate final configuration via Pydantic models

2. **AWS Integration Phase**
   - Establish security analysis session (optional cross-account)
   - Assume management account role for Organizations access
   - Extract account information with tag-based metadata

3. **Analysis Phase**
   - Retrieve all organization account IDs from management account via `get_all_organization_account_ids()`
   - Filter accounts using `get_relevant_subaccounts()` (currently returns all accounts)
   - For each account, check if results already exist via `check_results_exist()` (skip if found)
   - For accounts without results, assume `Headroom` role via `get_headroom_session()`
   - Execute SCP checks (e.g., `check_deny_imds_v1_ec2()`) using AWS library functions
   - Execute RCP checks (e.g., `check_third_party_role_access()`) with IAM trust policy analysis
   - Generate structured JSON results in `test_environment/headroom_results/`
   - Console output with compliance summaries per account

4. **Results Analysis Phase**
   - Parse all JSON result files from `test_environment/headroom_results/` directories
   - Analyze AWS Organizations structure for OU hierarchy and account relationships
   - Determine optimal SCP/RCP placement levels using greatest common denominator logic
   - Generate SCP placement recommendations with safety-first zero-violation principle
   - Output structured recommendations for SCP deployment strategy

5. **Terraform Generation Phase**
   - Generate `grab_org_info.tf` with AWS Organizations data sources and local variables
   - Auto-generate SCP Terraform configurations based on compliance analysis results
   - Auto-generate RCP Terraform configurations based on IAM trust policy analysis
   - Create account-specific, OU-specific, and root-level SCP deployment files
   - Create account-specific, OU-specific, and root-level RCP deployment files with third-party account whitelists
   - Ensure safety-first deployment (only 100% compliant SCPs, wildcard-free RCPs)
   - Output ready-to-use Terraform configurations in `test_environment/scps/` directory

### Error Handling Matrix

| Error Type | Handling Strategy | Exit Code | User Experience |
|------------|------------------|-----------|-----------------|
| Missing Config File | Graceful degradation to empty dict | 1 | Validation error message |
| Invalid YAML Syntax | Exception propagation | N/A | Raw exception for debugging |
| Configuration Validation | Caught ValueError/TypeError | 1 | Formatted error with field details |
| AWS Access Errors | Runtime exceptions with context | N/A | Clear AWS-specific error messages |
| Missing Required Fields | Pydantic validation error | 1 | Specific field requirements |

---

## Implementation Status

### Phase 1: Foundation (COMPLETED)
- ✅ CLI argument parsing with required configuration file
- ✅ YAML configuration loading with error handling
- ✅ Configuration merging and Pydantic validation
- ✅ AWS multi-account session management
- ✅ Organizations account information extraction
- ✅ Comprehensive test suite with 100% coverage
- ✅ Type safety with strict mypy configuration
- ✅ Pre-commit hooks and code quality standards

### Phase 2: SCP Analysis (COMPLETED)
- ✅ SCP policy compliance analysis (EC2 IMDS v1 check implemented)
- ✅ Multi-region AWS resource scanning with pagination
- ✅ Exemption tag support for policy flexibility
- ✅ JSON result generation with compliance metrics
- ✅ Console reporting with violation/exemption/compliant counts
- ✅ Static import architecture for improved reliability
- ✅ Comprehensive test coverage (100%) including edge cases
- ✅ Account filtering framework (extensible for OU/environment/owner)
- ✅ Cross-account role assumption with error handling

### Phase 3: SCP Results Analysis (COMPLETED)
- ✅ SCP/RCP compliance results analysis with organization structure mapping
- ✅ Greatest common denominator logic for safe SCP deployment
- ✅ AWS Organizations hierarchy analysis with OU and account relationships
- ✅ SCP placement recommendations (root, OU, account level)
- ✅ Zero-violation safety principle for deployment recommendations
- ✅ Comprehensive test coverage (120 tests) with 100% coverage
- ✅ Integration with main.py via parse_results(final_config) call

### Phase 4: Code Quality & Optimization (COMPLETED)
- ✅ Dynamic imports removal - all imports moved to top level
- ✅ Nested function extraction to minimize indentation
- ✅ Backslash-newline elimination using parentheses in with statements
- ✅ Run_checks optimization with skip functionality for existing results
- ✅ Comprehensive test refactoring using pytest best practices
- ✅ DRY principle implementation with centralized mock fixtures
- ✅ Modern Python formatting standards compliance

### Phase 5: Terraform Generation (COMPLETED)
- ✅ AWS Organizations data source generation (`grab_org_info.tf`)
- ✅ SCP Terraform auto-generation based on compliance analysis
- ✅ Account-level, OU-level, and root-level SCP deployment configurations
- ✅ Safety-first deployment logic (100% compliance requirement)
- ✅ Integration with existing Terraform module structure
- ✅ Comprehensive test coverage (137 tests) with 100% coverage

### Phase 6: Code Quality & Architecture (COMPLETED)
- ✅ Module separation and clean architecture implementation
- ✅ Terraform generation moved to dedicated `terraform/` module
- ✅ AWS service integrations consolidated in `aws/` module
- ✅ Shared types module (`types.py`) for data model consistency
- ✅ Circular import resolution and clean dependency management
- ✅ Early return refactoring for improved code readability
- ✅ Dynamic import elimination and top-level import organization

### Phase 7: RCP Analysis & Auto-Generation (COMPLETED)
- ✅ IAM trust policy analysis with account ID extraction (`aws/iam.py`)
- ✅ Third-party account detection and organization baseline comparison
- ✅ Wildcard principal detection with CloudTrail TODO comments
- ✅ RCP compliance check implementation (`check_third_party_assumerole`)
- ✅ RCP Terraform auto-generation with third-party account allowlists
- ✅ Multi-level RCP deployment (account, OU, root)
- ✅ Wildcard safety logic (OU-level RCPs excluded if any account has wildcards)
- ✅ Fail-loud exception handling (specific exceptions only, no silent failures)
- ✅ Principal type validation (AWS, Service, Federated)
- ✅ Mixed principal support (e.g., `{"AWS": [...], "Service": "..."}`)
- ✅ Custom exceptions (`UnknownPrincipalTypeError`, `InvalidFederatedPrincipalError`)
- ✅ Comprehensive test coverage (245 tests, 100% coverage for all modules)
- ✅ RCP Terraform module with EnforceOrgIdentities policy
- ✅ Union strategy for combining third-party accounts at root/OU levels
- ✅ Intelligent RCP placement at most specific safe level (root, OU, or account)
- ✅ Multi-level RCP deployment: root, OU (including single-account OUs), and account-level
- ✅ Violations counting for wildcard roles
- ✅ Separate RCP directory configuration and generation
- ✅ Missing account ID lookup by name when exclude_account_ids=True
- ✅ Critical bug fixes for RCP analysis and generation

### Phase 8: Architectural Organization (COMPLETED)
- ✅ Directory structure reorganization: `checks/scps/` and `checks/rcps/` subdirectories
- ✅ Results directory reorganization: `results_dir/scps/` and `results_dir/rcps/` subdirectories
- ✅ Function renaming for clarity: `parse_scp_result_files`, `check_third_party_assumerole`
- ✅ Analysis module refactoring: extracted `run_scp_checks()` and `run_rcp_checks()` functions
- ✅ Helper functions for result existence checking: `all_scp_results_exist()`, `all_rcp_results_exist()`
- ✅ `CHECK_TYPE_MAP` implementation for organizing results by policy type
- ✅ Module-level constants for testability (`MIN_ACCOUNTS_FOR_OU_LEVEL_RCP`)
- ✅ Comprehensive test suite updates (246 tests, all passing)
- ✅ Edge case testing for 100% code coverage (1044 statements in headroom/, 2515 in tests/)
- ✅ Breaking change: clean directory structure with no backward compatibility for flat results

### Phase 9: SCP Expansion (PLANNED)
- 🔄 Additional SCP checks for other AWS services
- 🔄 Metrics-based decision making for SCP deployment
- 🔄 CloudTrail historical analysis integration for actions items such as wildcard resolution
- 🔄 OU-based account filtering implementation
- 🔄 Advanced SCP deployment strategies

---

## Usage Examples

### Basic Configuration
```yaml
# config.yaml
management_account_id: '222222222222'

# Optional: only specify if running from the management account
# If omitted, assumes already running in the security analysis account
security_analysis_account_id: '111111111111'

exclude_account_ids: false

use_account_name_from_tags: false

# Tag keys to look for on AWS accounts
# All tags are optional - the tool will work even if these tags are not present on your accounts
account_tag_layout:
  environment: 'Environment'  # Falls back to "unknown" if tag is missing
  name: 'Name'                # Used when use_account_name_from_tags is true; falls back to account ID if missing
  owner: 'Owner'              # Falls back to "unknown" if tag is missing
```

### Execution

**Command-Line Arguments:**
- `--config CONFIG` (required): Path to configuration YAML file
- `--results-dir RESULTS_DIR` (optional): Override directory for results output (default: `test_environment/headroom_results`)
- `--scps-dir SCPS_DIR` (optional): Override directory for SCP Terraform output (default: `test_environment/scps`)
- `--rcps-dir RCPS_DIR` (optional): Override directory for RCP Terraform output (default: `test_environment/rcps`)
- `--security-analysis-account-id ID` (optional): Override security analysis account ID from YAML
- `--management-account-id ID` (optional): Override management account ID from YAML
- `--exclude-account-ids` (optional): Exclude account IDs from result files and filenames

**CLI arguments take precedence over YAML configuration values.**

```bash
# Install dependencies
pip install -r requirements.txt

# Run analysis with default configuration
python -m headroom --config config.yaml

# Run analysis with custom results and SCPs directories
python -m headroom --config config.yaml --results-dir ./my_results --scps-dir ./my_scps

# Run analysis excluding account IDs from results
python -m headroom --config config.yaml --exclude-account-ids

# Run tests
tox

# Type check
mypy headroom/ tests/
```

---

## Future Roadmap

### Planned Features
- **SCP Generation:** Auto-generate SCPs based on analysis
- **Terraform Integration:** Generate observability Terraform configurations
- **Metrics-Based Decisions:** Data-driven SCP deployment recommendations
- **AWS SSO Integration:** Role-based access policy generation
- **Multi-Language Query Support:** Splunk, SumoLogic query generation
- **GitHub Actions Integration:** CI/CD pipeline for SCP testing

### Extensibility Points
- **Analysis Engine:** Pluggable analysis modules for different security frameworks
- **Output Formats:** Multiple report formats (JSON, CSV, PDF)
- **Configuration Sources:** Support for additional configuration backends
- **Cloud Providers:** Potential extension to Azure/GCP multi-account scenarios

---

## Success Criteria

1. **Functional:** Successfully extract and analyze AWS account information across multi-account environments ✅
2. **Quality:** Maintain 100% test coverage and strict type safety ✅
3. **Usability:** Simple CLI interface requiring only configuration file ✅
4. **Reliability:** Robust error handling for all failure scenarios ✅
5. **Extensibility:** Clean architecture supporting future SCP analysis features ✅
6. **SCP Analysis:** Comprehensive SCP compliance analysis with detailed reporting ✅
7. **Results Processing:** SCP placement recommendations with organization structure analysis ✅
8. **Performance:** Optimized check execution with skip functionality for existing results ✅
9. **Code Quality:** Modern Python standards with comprehensive testing architecture ✅
10. **Terraform Generation:** Auto-generation of AWS Organizations data sources and SCP configurations ✅
11. **SCP Auto-Deployment:** Safety-first SCP Terraform generation for compliant targets ✅
12. **Architecture:** Clean module separation with terraform/ and aws/ folder organization ✅
13. **RCP Analysis:** IAM trust policy analysis with third-party account detection and wildcard identification ✅
14. **RCP Auto-Generation:** Terraform RCP configurations with third-party account allowlists and wildcard safety ✅
15. **Exception Handling:** Fail-loud with specific exception types, no silent failures or generic catches ✅
16. **Principal Validation:** Comprehensive handling of AWS, Service, Federated, and mixed principals ✅
17. **Union Strategy:** Third-party account IDs combined at root/OU levels for more permissive RCP deployment ✅
18. **Wildcard Safety:** Root/OU-level RCP deployment blocked when ANY account has wildcard principals ✅
19. **Configuration Separation:** Separate rcps_dir configuration for clean RCP/SCP directory separation ✅
20. **Missing Data Handling:** Account lookup by name when account_id missing (exclude_account_ids=True support) ✅
21. **Critical Bug Fixes:** All major RCP generation and analysis bugs fixed with comprehensive test coverage ✅
22. **Architectural Organization:** Clear separation of SCP and RCP code in checks/ and results directories ✅
23. **Function Extraction:** Single Responsibility Principle applied with dedicated check execution functions ✅
24. **Scalable Structure:** Directory organization supports easy addition of new SCP and RCP checks ✅
25. **Test Coverage Excellence:** 246 tests with 100% coverage maintained through comprehensive test refactoring ✅

---

*This PDR represents the complete specification for the current Headroom implementation and serves as the foundation for future development phases.*
