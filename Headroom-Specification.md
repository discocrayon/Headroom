# Headroom - AWS Multi-Account Security Analysis Tool
## Product Design Requirements (PDR)

**Version:** 4.5
**Created:** 2025-10-26
**Last Updated:** 2025-11-08
**Status:** Implementation Complete (Foundation + SCP Analysis + Results Processing + Code Quality Optimization + Terraform Generation + SCP Auto-Generation + RCP Analysis + RCP Auto-Generation + RCP Placement Optimization + RCP Union Strategy + Critical Bug Fixes + Architectural Organization + Framework Abstraction + Registry Pattern + Defensive Programming Elimination + Output Standardization + IAM User Creation SCP + IAM Module Refactoring)

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
- **`constants.py`**: Single source of truth for check names, type mappings, and dynamic check registration (`CHECK_TYPE_MAP`, `register_check_type()`)
- **`usage.py`**: CLI parsing, YAML loading, and configuration merging logic
- **`analysis.py`**: AWS integration, generic check execution via registry, session management, and organization account ID retrieval
- **`parse_results.py`**: SCP/RCP compliance results analysis and organization structure processing
- **`write_results.py`**: JSON result file writing, path resolution, and results existence checking
- **`types.py`**: Shared data models and type definitions for organization hierarchy, SCP recommendations, RCP placement recommendations, and PolicyRecommendation type alias
- **`output.py`**: Centralized output handler for consistent user-facing formatting (check completion, errors, success messages, section headers)
- **`aws/`**: AWS service integration modules
  - **`ec2.py`**: EC2 service integration and analysis functions
  - **`iam/`**: IAM analysis package with separation of concerns
    - **`roles.py`**: RCP-focused IAM role trust policy analysis and third-party account detection
    - **`users.py`**: SCP-focused IAM user enumeration for creation policy enforcement
    - **`__init__.py`**: Public API exports for clean module interface
  - **`organization.py`**: AWS Organizations API integration, hierarchy analysis, and shared account lookup utilities (`lookup_account_id_by_name`)
  - **`sessions.py`**: AWS session management and role assumption utilities (`assume_role`)
- **`checks/`**: SCP/RCP compliance check implementations organized by policy type
  - **`base.py`**: BaseCheck abstract class implementing Template Method pattern for check execution
  - **`registry.py`**: Check registration system with `@register_check` decorator and discovery functions
  - **`scps/`**: Service Control Policy check implementations
    - **`deny_imds_v1_ec2.py`**: EC2 IMDS v1 compliance check (DenyImdsV1Ec2Check class)
    - **`deny_iam_user_creation.py`**: IAM user discovery check for creation policy enforcement (DenyIamUserCreationCheck class)
  - **`rcps/`**: Resource Control Policy check implementations
    - **`check_third_party_assumerole.py`**: IAM trust policy third-party AssumeRole access check (ThirdPartyAssumeRoleCheck class)
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
- **SCP/RCP Separation:** `parse_scp_result_files()` excludes RCP checks by default to prevent RCP checks from generating SCP Terraform
- **Check Configuration:** `constants.py` module defines `CHECK_TYPE_MAP`, `SCP_CHECK_NAMES`, and `RCP_CHECK_NAMES` as single source of truth
- **RCP Check Filtering:** `RCP_CHECK_NAMES` imported from `constants.py` identifies checks to exclude from SCP analysis
- **Organization Structure Analysis:** Function to analyze AWS Organizations OU hierarchy and account relationships
- **Account-to-OU Mapping:** Function to create comprehensive mapping of accounts to their direct parent OUs
- **Account ID Lookup:** Shared `lookup_account_id_by_name()` function in `aws/organization.py` for consistent account resolution
- **Greatest Common Denominator Logic:** Function to determine optimal SCP/RCP placement level (root, OU, or account-specific)
- **Terraform Generation:** `generate_terraform.py` module generates Terraform configuration files for organization structure data
- **Directory Path Construction:** Centralized `get_results_dir()` function in `write_results.py` for consistent path resolution

**Results Parsing Implementation:**

The system implements two separate but structurally similar parsing flows for SCP and RCP checks. Understanding these patterns is critical for reproducing the implementation.

**Common Parsing Patterns (SCP and RCP):**

Both parsers share the following implementation patterns:

1. **Directory Structure Expectation:**
   - Both expect results in: `{results_dir}/{check_type}/{check_name}/*.json` where check_type is "scps" or "rcps"
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
   - Both handle missing `account_id` by using shared `lookup_account_id_by_name()` function
   - Function defined in `aws/organization.py` for DRY compliance
   - Raises `RuntimeError` if account not found in organization
   - Pattern:
   ```python
   if not account_id:
       account_id = lookup_account_id_by_name(
           account_name,
           organization_hierarchy,
           context="result file"  # or "SCP check result", "RCP result", etc.
       )
   ```
   - **Benefits:** Single source of truth, consistent error messages, reduced code duplication

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
   - **SCP (`parse_scp_result_files`):** Iterates through ALL check directories in scps/ subdirectory, explicitly excludes RCP checks
     ```python
     from .constants import RCP_CHECK_NAMES  # Imported from constants.py
     scps_path = results_path / "scps"
     for check_dir in scps_path.iterdir():
         if not check_dir.is_dir():
             continue
         if exclude_rcp_checks and check_name in RCP_CHECK_NAMES:
             continue  # Skip RCP checks
     ```
   - **RCP (`parse_rcp_result_files`):** Directly targets specific check directory using centralized path function
     ```python
     from ..constants import THIRD_PARTY_ASSUMEROLE
     from ..write_results import get_results_dir
     check_dir_str = get_results_dir(THIRD_PARTY_ASSUMEROLE, results_dir)
     check_dir = Path(check_dir_str)
     if not check_dir.exists():
         raise RuntimeError(f"Third-party AssumeRole check directory does not exist: {check_dir}")
     ```
   - **Rationale:** SCP parser is extensible for multiple checks; RCP parser is specialized for one check. Constants and path functions centralized for DRY compliance.

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
- **Check Orchestration:** `checks/rcps/check_third_party_assumerole.py` coordinates RCP analysis execution
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

**Check Function (in `checks/rcps/check_third_party_assumerole.py`):**
```python
def check_third_party_assumerole(
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
    "check": "third_party_assumerole",
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
2. **Results Parsing:** Parse check results from `headroom_results/rcps/third_party_assumerole/` directory
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

### PR-015: DRY Refactoring & Constants Module

**Requirement:** The system MUST eliminate code duplication and establish single sources of truth for configuration constants and shared utility functions.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**DRY Violations Identified and Fixed:**

1. **Constants Module Creation**
   - Created `headroom/constants.py` as dedicated module for check configuration
   - Moved check name constants from `write_results.py`
   - Moved `CHECK_TYPE_MAP` from `write_results.py`
   - Added pre-computed `SCP_CHECK_NAMES` and `RCP_CHECK_NAMES` sets

2. **CHECK_TYPE_MAP as Single Source of Truth**
   - **Before:** `RCP_CHECK_NAMES = {"third_party_assumerole"}` hardcoded in `parse_results.py`
   - **After:** Derived from `CHECK_TYPE_MAP` in `constants.py`:
     ```python
     RCP_CHECK_NAMES = {name for name, check_type in CHECK_TYPE_MAP.items() if check_type == "rcps"}
     SCP_CHECK_NAMES = {name for name, check_type in CHECK_TYPE_MAP.items() if check_type == "scps"}
     ```
   - **Impact:** Adding new checks only requires updating `CHECK_TYPE_MAP` in one place

3. **Shared Account ID Lookup Function**
   - **Before:** Duplicate lookup logic in `parse_results.py` (9 lines) and `generate_rcps.py` (12 lines)
   - **After:** Extracted to `aws/organization.py`:
     ```python
     def lookup_account_id_by_name(
         account_name: str,
         organization_hierarchy: OrganizationHierarchy,
         context: str = "result file"
     ) -> str:
         """Look up account ID by name in organization hierarchy."""
         for acc_id, acc_info in organization_hierarchy.accounts.items():
             if acc_info.account_name == account_name:
                 logger.info(f"Looked up account_id {acc_id} for account name '{account_name}'")
                 return acc_id
         raise RuntimeError(
             f"Account name '{account_name}' from {context} not found in organization hierarchy"
         )
     ```
   - **Impact:** 21 lines of duplicate code reduced to single 13-line function

4. **Check Name Constants**
   - **Before:** Magic strings scattered across 14 locations in 4 files
   - **After:** Constants in `constants.py`:
     ```python
     DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"
     THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"
     ```
   - **Locations Updated:**
     - `analysis.py`: 6 occurrences replaced with constants
     - `generate_rcps.py`: 4 occurrences replaced with constants
     - `check_deny_imds_v1_ec2.py`: 2 occurrences replaced with constants
     - `check_third_party_assumerole.py`: 2 occurrences replaced with constants
   - **Impact:** Type-safe, refactoring-friendly constant references

5. **Centralized Directory Path Construction**
   - **Before:** Manual path construction in `generate_rcps.py`:
     ```python
     check_dir = results_path / "rcps" / "third_party_assumerole"
     ```
   - **After:** Using centralized function:
     ```python
     check_dir_str = get_results_dir(THIRD_PARTY_ASSUMEROLE, results_dir)
     check_dir = Path(check_dir_str)
     ```
   - **Impact:** Single source of truth for results directory path logic

**Benefits Achieved:**

1. **Single Source of Truth:** Check classification, constants, and path construction all centralized
2. **Reduced Duplication:** ~30 lines of duplicate code eliminated
3. **Improved Maintainability:** Adding new checks requires fewer code changes
4. **Type Safety:** Using constants catches typos at import time
5. **Better Testability:** Shared functions can be tested independently
6. **Consistent Behavior:** Account lookup and path construction now uniform across modules
7. **Clearer Intent:** Dedicated constants module explicitly indicates purpose

**Files Modified:**

1. **Created:** `headroom/constants.py` (21 lines)
   - Check name constants: `DENY_IMDS_V1_EC2`, `THIRD_PARTY_ASSUMEROLE`
   - Type mapping: `CHECK_TYPE_MAP`
   - Derived sets: `SCP_CHECK_NAMES`, `RCP_CHECK_NAMES`

2. **Updated:** `headroom/write_results.py`
   - Removed local constant definitions
   - Added import: `from .constants import CHECK_TYPE_MAP`

3. **Updated:** `headroom/parse_results.py`
   - Changed to import `RCP_CHECK_NAMES` from `constants.py`
   - Removed local derivation of `RCP_CHECK_NAMES`
   - Import and use `lookup_account_id_by_name()`

4. **Updated:** `headroom/analysis.py`
   - Import constants from `constants.py`
   - Use constants instead of magic strings (6 replacements)

5. **Updated:** `headroom/terraform/generate_rcps.py`
   - Import constants from `constants.py`
   - Import and use `get_results_dir()`
   - Import and use `lookup_account_id_by_name()`
   - Use constants instead of magic strings (4 replacements)

6. **Updated:** `headroom/aws/organization.py`
   - Added `lookup_account_id_by_name()` shared function (13 lines)

7. **Updated:** `headroom/checks/scps/deny_imds_v1_ec2.py`
   - Import and use `DENY_IMDS_V1_EC2` constant (2 replacements)

8. **Updated:** `headroom/checks/rcps/check_third_party_assumerole.py`
   - Import and use `THIRD_PARTY_ASSUMEROLE` constant (2 replacements)

9. **Updated:** `tests/test_parse_results.py`
   - Updated error message assertion to match new shared function format

**Architecture Improvements:**

**Before:**
- Constants defined in `write_results.py`
- RCP check names derived locally in `parse_results.py`
- Account lookup logic duplicated in 2 modules
- Check names as magic strings in 4 files
- Directory paths manually constructed

**After:**
- All constants in dedicated `constants.py`
- Both SCP and RCP check name sets pre-computed
- Single shared account lookup function
- Check names as importable constants
- Directory paths via centralized function
- Clean separation of concerns

**Testing:**
- All 248 tests passing
- No behavioral changes
- No linter errors
- Full type safety maintained (mypy strict mode)
- 100% code coverage maintained

**Code Quality Metrics:**
- Lines of duplicate code removed: ~30
- Single sources of truth created: 3
- Magic strings eliminated: 14
- Shared functions created: 1
- Constants created: 2
- Pre-computed sets: 2

### PR-016: Check Framework Abstraction & Registry Pattern

**Requirement:** The system MUST provide a reusable, extensible framework for implementing compliance checks with zero-code-change addition of new checks through self-registration patterns.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**Check Framework Architecture:**

The check framework implements three design patterns:
1. **Template Method Pattern:** `BaseCheck` abstract class defines the skeleton of check execution
2. **Strategy Pattern:** Each concrete check implements its unique analysis logic
3. **Registry Pattern:** Checks self-register via decorators for auto-discovery

**1. BaseCheck Abstract Class (headroom/checks/base.py):**

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, List, TypeVar
import boto3
from dataclasses import dataclass

# Type variable for analysis result types
T = TypeVar('T')

@dataclass
class CategorizedCheckResult:
    """Result of categorizing check analysis."""
    violations: List[Dict[str, Any]]
    exemptions: List[Dict[str, Any]]
    compliant: List[Dict[str, Any]]

class BaseCheck(ABC, Generic[T]):
    """Base class for all compliance checks.

    Implements Template Method pattern for check execution flow.
    Subclasses must implement three abstract methods:
    - analyze(): Perform AWS API calls and return raw analysis results
    - categorize_result(): Categorize single result into violation/exemption/compliant
    - build_summary_fields(): Build check-specific summary fields

    These attributes are set by the @register_check decorator:
    """
    CHECK_NAME: str
    CHECK_TYPE: str

    def __init__(
        self,
        account_name: str,
        account_id: str,
        results_base_dir: str,
        exclude_account_ids: bool = False,
        **kwargs: Any
    ) -> None:
        """Initialize base check with common parameters.

        **kwargs allows subclasses to accept additional parameters
        without breaking uniform instantiation pattern.
        """
        self.account_name = account_name
        self.account_id = account_id
        self.results_base_dir = results_base_dir
        self.exclude_account_ids = exclude_account_ids
        self.check_name = self.CHECK_NAME

    @abstractmethod
    def analyze(self, session: boto3.Session) -> List[T]:
        """Perform analysis and return raw results.

        Subclasses implement AWS API calls here.
        """
        pass

    @abstractmethod
    def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
        """Categorize a single result.

        Returns:
            Tuple of (category, result_dict) where category is one of:
            - "violation": Non-compliant resource
            - "exemption": Exempted from compliance requirement
            - "compliant": Fully compliant resource
        """
        pass

    @abstractmethod
    def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """Build check-specific summary fields.

        Returns:
            Dictionary of summary fields like total_instances, compliance_percentage, etc.
        """
        pass

    def execute(self, session: boto3.Session) -> None:
        """Execute the check (Template Method).

        This method orchestrates the entire check execution flow:
        1. Call analyze() to get raw results
        2. Categorize each result via categorize_result()
        3. Build summary with base fields + check-specific fields
        4. Write results to JSON file
        5. Print completion message
        """
        # Step 1: Analyze
        analysis_results = self.analyze(session)

        # Step 2: Categorize
        violations: List[Dict[str, Any]] = []
        exemptions: List[Dict[str, Any]] = []
        compliant: List[Dict[str, Any]] = []

        for result in analysis_results:
            category, result_dict = self.categorize_result(result)
            if category == "violation":
                violations.append(result_dict)
            elif category == "exemption":
                exemptions.append(result_dict)
            elif category == "compliant":
                compliant.append(result_dict)

        check_result = CategorizedCheckResult(
            violations=violations,
            exemptions=exemptions,
            compliant=compliant
        )

        # Step 3: Build summary
        summary_fields = self.build_summary_fields(check_result)
        summary = {
            "account_name": self.account_name,
            "account_id": self.account_id if not self.exclude_account_ids else "",
            "check": self.check_name,
            **summary_fields
        }

        # Step 4: Write results
        results_data = self._build_results_data(summary, check_result)
        write_check_results(
            self.check_name,
            self.account_name,
            self.account_id,
            results_data,
            self.results_base_dir,
            self.exclude_account_ids
        )

        # Step 5: Print completion
        account_identifier = self.account_name
        if not self.exclude_account_ids:
            account_identifier = f"{self.account_name} ({self.account_id})"

        OutputHandler.check_completed(
            self.check_name,
            account_identifier,
            {
                "violations": len(violations),
                "exemptions": len(exemptions),
                "compliant": len(compliant),
            }
        )

    def _build_results_data(
        self,
        summary: Dict[str, Any],
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """Build results data structure.

        Hookpoint for subclasses with different result structures.
        Default returns standard structure with compliant_instances.
        """
        return {
            "summary": summary,
            "violations": check_result.violations,
            "exemptions": check_result.exemptions,
            "compliant_instances": check_result.compliant
        }
```

**Key Design Decisions:**
- **Generic Type Parameter `T`:** Each check specifies its analysis result type (e.g., `BaseCheck[DenyImdsV1Ec2]`)
- **Three Abstract Methods:** Minimal interface for maximum flexibility
- **Template Method:** `execute()` handles all orchestration, subclasses only implement domain logic
- **Hookpoint:** `_build_results_data()` allows custom result structures (used by RCP checks)
- **`**kwargs` Pattern:** Allows uniform instantiation while supporting check-specific parameters

**2. Registry Pattern (headroom/checks/registry.py):**

```python
from typing import Callable, Dict, List, Optional, Type
from .base import BaseCheck

# Registry storage
_CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {}

def register_check(check_type: str, check_name: str) -> Callable[[Type[BaseCheck]], Type[BaseCheck]]:
    """Decorator to register a check class.

    Args:
        check_type: "scps" or "rcps"
        check_name: Unique check identifier (e.g., "deny_imds_v1_ec2")

    Returns:
        Decorator function that registers a check class

    Usage:
        @register_check("scps", "deny_imds_v1_ec2")
        class DenyImdsV1Ec2Check(BaseCheck[DenyImdsV1Ec2]):
            pass
    """
    def decorator(cls: Type[BaseCheck]) -> Type[BaseCheck]:
        # Store in registry
        _CHECK_REGISTRY[check_name] = cls

        # Set class attributes for later access
        cls.CHECK_NAME = check_name
        cls.CHECK_TYPE = check_type

        # Register check type in constants module
        from ..constants import register_check_type
        register_check_type(check_name, check_type)

        return cls
    return decorator

def get_check_class(check_name: str) -> Type[BaseCheck]:
    """Retrieve check class by name."""
    if check_name not in _CHECK_REGISTRY:
        raise ValueError(
            f"Unknown check name: {check_name}. "
            f"Must be one of {list(_CHECK_REGISTRY.keys())}"
        )
    return _CHECK_REGISTRY[check_name]

def get_all_check_classes(check_type: Optional[str] = None) -> List[Type[BaseCheck]]:
    """Get all registered check classes, optionally filtered by type."""
    if check_type is None:
        return list(_CHECK_REGISTRY.values())

    return [
        cls for cls in _CHECK_REGISTRY.values()
        if cls.CHECK_TYPE == check_type
    ]

def get_check_names(check_type: str) -> List[str]:
    """Get all check names for a given type."""
    return [
        name for name, cls in _CHECK_REGISTRY.items()
        if cls.CHECK_TYPE == check_type
    ]
```

**Registry Benefits:**
- **Zero-Code-Change Extensibility:** Add new check = create class + add decorator
- **Auto-Discovery:** No hardcoded imports or lists
- **Type Safety:** Registry maintains type information
- **Dynamic Querying:** Can list checks by type at runtime

**3. Example Check Implementation:**

```python
# headroom/checks/scps/deny_imds_v1_ec2.py

from typing import Any, Dict, List
import boto3
from dataclasses import asdict

from ...aws.ec2 import get_imds_v1_ec2_analysis, DenyImdsV1Ec2
from ...constants import DENY_IMDS_V1_EC2
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check

@register_check("scps", DENY_IMDS_V1_EC2)
class DenyImdsV1Ec2Check(BaseCheck[DenyImdsV1Ec2]):
    """Check for EC2 instances allowing IMDSv1."""

    def analyze(self, session: boto3.Session) -> List[DenyImdsV1Ec2]:
        """Get all EC2 instances with IMDSv1 analysis."""
        return get_imds_v1_ec2_analysis(session)

    def categorize_result(self, result: DenyImdsV1Ec2) -> tuple[str, Dict[str, Any]]:
        """Categorize instance into violation/exemption/compliant."""
        result_dict = asdict(result)

        if result.imdsv1_allowed and result.exemption_tag_present:
            return ("exemption", result_dict)
        elif result.imdsv1_allowed:
            return ("violation", result_dict)
        else:
            return ("compliant", result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """Build summary with instance counts and compliance percentage."""
        total = (
            len(check_result.violations) +
            len(check_result.exemptions) +
            len(check_result.compliant)
        )

        if total == 0:
            compliance_percentage = 100.0
        else:
            compliant_count = len(check_result.exemptions) + len(check_result.compliant)
            compliance_percentage = (compliant_count / total) * 100

        return {
            "total_instances": total,
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "compliant": len(check_result.compliant),
            "compliance_percentage": round(compliance_percentage, 2)
        }
```

**Adding a New Check (Only 50 Lines):**

To add a new check, developers only need:
1. Create file in `checks/scps/` or `checks/rcps/`
2. Define class extending `BaseCheck[YourAnalysisType]`
3. Add `@register_check("scps", "your_check_name")` decorator
4. Implement 3 methods: `analyze()`, `categorize_result()`, `build_summary_fields()`

**No changes needed to:**
- ✅ constants.py (auto-updates via registration)
- ✅ analysis.py (auto-discovery)
- ✅ Any other files

**4. Generic Check Execution (headroom/analysis.py):**

```python
from headroom.checks.registry import get_all_check_classes

def run_checks_for_type(
    check_type: str,
    headroom_session: boto3.Session,
    account_info: AccountInfo,
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """Execute all checks of a given type for a single account.

    Discovers checks dynamically from registry.
    """
    check_classes = get_all_check_classes(check_type)

    for check_class in check_classes:
        check_name = check_class.CHECK_NAME

        # Skip if results already exist
        if results_exist(check_name, account_info.name, account_info.account_id,
                        config.results_dir, config.exclude_account_ids):
            logger.info(f"Results for {check_name} already exist for {account_info.name}, skipping")
            continue

        # Instantiate and execute check
        check = check_class(
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
            org_account_ids=org_account_ids  # RCP checks use this, SCP checks ignore via **kwargs
        )
        check.execute(headroom_session)

def run_checks(
    subaccounts: List[AccountInfo],
    config: HeadroomConfig,
    session: boto3.Session
) -> None:
    """Run all checks across all accounts."""
    org_account_ids = get_all_organization_account_ids(config, session)

    for account_info in subaccounts:
        # Skip if all results exist
        if (all_check_results_exist("scps", account_info, config) and
            all_check_results_exist("rcps", account_info, config)):
            logger.info(f"All results already exist for {account_info.name}, skipping")
            continue

        headroom_session = get_headroom_session(account_info.account_id, config)

        # Run SCP checks
        run_checks_for_type("scps", headroom_session, account_info, config, org_account_ids)

        # Run RCP checks
        run_checks_for_type("rcps", headroom_session, account_info, config, org_account_ids)
```

**Key Features:**
- **Dynamic Discovery:** Checks found via registry, not hardcoded imports
- **Uniform Execution:** Same code path for all checks regardless of type
- **Type-Aware:** Can filter by check type ("scps" or "rcps")
- **Extensible:** Adding new check types requires no code changes

**5. Constants Module Integration (headroom/constants.py):**

```python
# Check name constants
DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"

# Check type mapping (dynamically populated by registry)
_CHECK_TYPE_MAP: Dict[str, str] = {}

def register_check_type(check_name: str, check_type: str) -> None:
    """Register a check type in the CHECK_TYPE_MAP.

    Called by the @register_check decorator.
    """
    _CHECK_TYPE_MAP[check_name] = check_type

def get_check_type_map() -> Dict[str, str]:
    """Get the check type map.

    Returns dynamically-built map from check names to types.
    Lazy-loaded to ensure all checks are registered first.
    """
    if not _CHECK_TYPE_MAP:
        # Import checks to trigger registration
        import headroom.checks  # noqa: F401
    return _CHECK_TYPE_MAP

# Derived sets (computed from CHECK_TYPE_MAP)
def get_check_names(check_type: str) -> List[str]:
    """Get all check names for a given type."""
    from headroom.checks.registry import get_check_names as registry_get_check_names
    return registry_get_check_names(check_type)
```

**6. Check Module Initialization (headroom/checks/__init__.py):**

```python
"""
Compliance checks for Headroom security analysis.

Imports all check modules to ensure they register themselves via the
@register_check decorator.
"""

# These imports are required to trigger decorator execution and register checks.
# The @register_check decorator only runs when the module is imported, so without
# these imports, the checks would never register themselves in _CHECK_REGISTRY.
from .rcps import check_third_party_assumerole  # noqa: F401
from .scps import deny_imds_v1_ec2  # noqa: F401

__all__ = []
```

**Critical Detail:** Without these imports, decorators never execute and checks never register.

**Architecture Benefits:**

1. **Extensibility:**
   - Add new check: 1 file, ~50 lines, zero other changes
   - Add new check type: Add to CHECK_TYPE_MAP values, zero code changes

2. **Maintainability:**
   - Single source of truth for check execution flow (BaseCheck)
   - All checks benefit from improvements to base class
   - Consistent error handling and output formatting

3. **Type Safety:**
   - Generic type parameter ensures correct types in categorize_result()
   - Mypy validates entire flow from analysis to categorization

4. **Testability:**
   - Easy to test checks in isolation
   - Can mock BaseCheck methods for unit testing
   - Registry can be cleared/mocked in tests

5. **Clean Code:**
   - Each check focuses only on domain logic (3 methods)
   - No boilerplate code duplication
   - Template Method pattern eliminates copy-paste errors

**Files Created:**
- `headroom/checks/base.py` (189 lines)
- `headroom/checks/registry.py` (96 lines)
- `tests/test_checks_registry.py` (102 lines)

**Files Modified:**
- `headroom/checks/scps/deny_imds_v1_ec2.py`: Refactored to use BaseCheck (reduced from 88 to 115 lines, but public API is 9 lines)
- `headroom/checks/rcps/check_third_party_assumerole.py`: Refactored to use BaseCheck (190 lines with complex override logic)
- `headroom/analysis.py`: Replaced check-specific functions with generic `run_checks_for_type()`
- `headroom/constants.py`: Added dynamic check type registration
- `headroom/checks/__init__.py`: Added imports to trigger registration
- Multiple test files updated to use check classes instead of wrapper functions

**Test Coverage:**
- All 329 tests passing
- 100% code coverage maintained (1190 statements in headroom/, 3179 in tests/)
- Comprehensive registry tests covering all code paths

### PR-017: Session Management Extraction

**Requirement:** The system MUST eliminate code duplication in AWS session management by extracting the common role assumption pattern into a reusable utility function.

**Implementation Status:** ✅ COMPLETED

**Problem Statement:**

Three functions in `analysis.py` contained nearly identical session creation logic:
- `get_security_analysis_session()` - 21 lines
- `get_management_account_session()` - 34 lines (with docstring)
- `get_headroom_session()` - 17 lines

Each duplicated the same pattern:
1. Create STS client from a session
2. Call `assume_role()` with role ARN and session name
3. Handle `ClientError` exceptions
4. Extract credentials from response
5. Create new `boto3.Session` with temporary credentials

**Solution:**

Created `headroom/aws/sessions.py` with a single `assume_role()` function:

```python
from typing import Optional
import boto3
from botocore.exceptions import ClientError

def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[boto3.Session] = None
) -> boto3.Session:
    """Assume an IAM role and return a session with temporary credentials.

    Args:
        role_arn: ARN of the role to assume
        session_name: Name for the assumed role session
        base_session: Session to use for assuming the role (default: creates new session)

    Returns:
        New boto3 Session with temporary credentials from the assumed role

    Raises:
        ClientError: If role assumption fails (e.g., permission denied, role not found)
    """
    if base_session is None:
        base_session = boto3.Session()

    sts_client = base_session.client("sts")
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )
```

**Refactored Functions:**

```python
def get_security_analysis_session(config: HeadroomConfig) -> boto3.Session:
    """Get session for the security analysis account."""
    account_id = config.security_analysis_account_id
    if not account_id:
        return boto3.Session()
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
    return assume_role(role_arn, "HeadroomSecurityAnalysisSes")

def get_management_account_session(config: HeadroomConfig, session: boto3.Session) -> boto3.Session:
    """Assume role in management account for organization access."""
    if not config.management_account_id:
        raise RuntimeError("management_account_id must be set in config")
    role_arn = f"arn:aws:iam::{config.management_account_id}:role/OrgAndAccountInfoReader"
    return assume_role(role_arn, "HeadroomManagementAccountSession", session)

def get_headroom_session(account_id: str, config: HeadroomConfig) -> boto3.Session:
    """Get session for analyzing a specific account."""
    security_session = get_security_analysis_session(config)
    role_arn = f"arn:aws:iam::{account_id}:role/Headroom"
    return assume_role(role_arn, f"Headroom-{account_id}", security_session)
```

**Benefits:**
- **DRY Compliance:** Eliminated 53 lines of duplicate code
- **Single Source of Truth:** One place to update role assumption logic
- **Consistent Error Handling:** All role assumptions handle ClientError identically
- **Easier Testing:** Can mock single assume_role() function
- **Simplified Functions:** Each function now 2-3 lines of implementation

**Impact:**
- Lines removed: ~53 (from duplicated implementations)
- Lines added: ~28 (new sessions.py module + imports)
- Net change: -25 lines with significantly better architecture

**Test Coverage:**
- All existing tests updated to patch `headroom.aws.sessions.assume_role`
- All 329 tests passing with 100% coverage

### PR-018: Defensive Programming Elimination

**Requirement:** The system MUST eliminate defensive programming patterns that suppress errors and replace them with fail-loud error handling following the principle "Never do except Exception, always catch the specific exceptions that the code can raise."

**Implementation Status:** ✅ COMPLETED

**Anti-Patterns Eliminated:**

**1. Generic Exception Catching (4 occurrences removed):**

Before:
```python
try:
    # AWS API call
except Exception as e:  # ❌ Too broad
    logger.error(f"Error: {e}")
    # Silent failure or wrapping
```

After:
```python
try:
    # AWS API call
except ClientError as e:  # ✅ Specific exception
    logger.error(f"Error: {e}", exc_info=True)
    raise  # ✅ Re-raise for visibility
```

**2. Unnecessary Exception Wrapping (3 occurrences removed):**

Before:
```python
try:
    response = sts_client.assume_role(...)
except ClientError as e:
    raise RuntimeError(f"Failed to assume role: {e}")  # ❌ Double-wrapping
```

After:
```python
response = sts_client.assume_role(...)  # ✅ Let ClientError propagate
```

**Rationale:** `ClientError` already contains sufficient context (error code, message, role ARN). Wrapping in `RuntimeError` loses type information that callers might need (e.g., to distinguish AccessDenied from NoSuchEntity).

**3. Catch-Log-Raise (2 occurrences removed):**

Before:
```python
try:
    with open(file_path, 'w') as f:
        f.write(content)
except IOError as e:
    logger.error(f"Failed to write: {e}")  # ❌ Redundant logging
    raise  # Exception already has traceback
```

After:
```python
with open(file_path, 'w') as f:  # ✅ Let IOError propagate
    f.write(content)
```

**Rationale:** Python's traceback already shows the error location and context. Catch-log-raise adds no value and creates duplicate log entries.

**4. Defensive KeyError Catching (1 occurrence removed):**

Before:
```python
try:
    summary = data["summary"]
    account_id = summary["account_id"]
except KeyError as e:
    raise RuntimeError(f"Missing key: {e}")  # ❌ Impossible case
```

After:
```python
summary = data.get("summary", {})  # ✅ .get() handles missing keys
account_id = summary.get("account_id", "")
```

**Rationale:** Using `.get()` with defaults is cleaner than try/except for expected variations.

**5. Silent Failures (2 occurrences fixed):**

Before:
```python
try:
    regions_response = ec2_client.describe_regions()
except ClientError as e:
    logger.warning(f"Failed to list regions: {e}")
    regions = [fallback_region]  # ❌ Silent fallback hides permission issues
```

After:
```python
regions_response = ec2_client.describe_regions()  # ✅ Fail loudly
regions = [region['RegionName'] for region in regions_response['Regions']]
```

**Rationale:** If `describe_regions` fails, it indicates a serious problem (missing IAM permissions, AWS service issue). Silently falling back to one region could miss violations in other regions.

**Principles Applied:**

1. **Fail Fast:** Removed defensive code that handled "impossible" cases
2. **Let Exceptions Propagate:** Stopped wrapping exceptions that already contain sufficient context
3. **Preserve Exception Types:** Callers can now distinguish between different error conditions
4. **Make Silent Failures Visible:** Removed fallback behavior that hid permission/configuration issues
5. **Only Catch What You Can Handle:** Removed catches for generic exceptions

**Files Modified:**

1. **headroom/aws/organization.py:** Replaced 4x `except Exception` with `except ClientError`
2. **headroom/aws/sessions.py:** Removed unnecessary `ClientError` wrapping
3. **headroom/aws/ec2.py:** Removed silent region fallback
4. **headroom/parse_results.py:** Removed unnecessary `KeyError` catching
5. **headroom/write_results.py:** Removed catch-log-raise pattern
6. **headroom/analysis.py:** Removed double-wrapping of exceptions

**Test Updates:**

Updated tests to expect natural exception propagation:
- Tests now assert `ClientError` is raised (not wrapped `RuntimeError`)
- Removed tests for fallback behaviors that no longer exist
- Added `exc_info=True` assertions for proper logging

**Benefits:**

1. **Clearer Error Messages:** Exception types and messages now accurately reflect the actual problem
2. **Better Debugging:** Full stack traces preserved without log noise
3. **Type Safety:** Callers can catch specific exceptions (e.g., `ClientError`) with proper type information
4. **No Hidden Failures:** All errors are visible immediately
5. **Simpler Code:** Removed ~80 lines of unnecessary exception handling

**Test Results:**
- All 313 tests passing
- 100% code coverage maintained
- Zero generic `except Exception` blocks remaining

### PR-019: Output Standardization

**Requirement:** The system MUST standardize all user-facing output through a centralized handler to ensure consistent formatting, enable future enhancements, and eliminate scattered print statements.

**Implementation Status:** ✅ COMPLETED

**Problem Statement:**

Output was scattered across multiple modules with inconsistent formatting:
- Print statements in `main.py` for configuration validation
- Print statements in `checks/base.py` for check completion
- Print statements in `parse_results.py` for section headers
- Inconsistent emoji usage and formatting

**Solution:**

Created `headroom/output.py` with `OutputHandler` class:

```python
from typing import Any, Dict, Optional

class OutputHandler:
    """Centralized handler for all user-facing output.

    Provides consistent formatting for different message types:
    - check_completed(): Check execution completion with statistics
    - error(): Error messages with 🚨 emoji
    - success(): Success messages with ✅ emoji
    - section_header(): Section dividers with formatting

    Future enhancements (not yet implemented):
    - Colored output (green for success, red for errors)
    - Quiet mode (suppress non-error output)
    - JSON output mode (machine-readable)
    - Log file redirection
    """

    @staticmethod
    def check_completed(check_name: str, account_identifier: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Print check completion message with optional statistics."""
        print(f"✅ Completed {check_name} for account {account_identifier}")
        if not data:
            return

        violations = data.get("violations", 0)
        exemptions = data.get("exemptions", 0)
        compliant = data.get("compliant", 0)

        print(f"   Violations: {violations}, Exemptions: {exemptions}, Compliant: {compliant}")

    @staticmethod
    def error(title: str, error: Exception) -> None:
        """Print error message with 🚨 emoji."""
        print(f"\n🚨 {title}:\n{error}\n")

    @staticmethod
    def success(title: str, data: Any) -> None:
        """Print success message with ✅ emoji."""
        print(f"\n✅ {title}:")
        print(data)

    @staticmethod
    def section_header(title: str) -> None:
        """Print section header with formatting."""
        print(f"\n{'='*80}")
        print(f"{title}")
        print(f"{'='*80}\n")
```

**Integration Points:**

1. **Configuration Validation (main.py):**
```python
# Before
print(f"\n🚨 Configuration Validation Error:\n{e}\n")

# After
OutputHandler.error("Configuration Error", e)
```

2. **Check Completion (checks/base.py):**
```python
# Before
print(f"✅ Completed {check_name} for account {account_identifier}")
print(f"   Violations: {violations}, Exemptions: {exemptions}, Compliant: {compliant}")

# After
OutputHandler.check_completed(check_name, account_identifier, {
    "violations": len(violations),
    "exemptions": len(exemptions),
    "compliant": len(compliant),
})
```

3. **Section Headers (parse_results.py):**
```python
# Before
print(f"\n{'='*80}")
print(f"{title}")
print(f"{'='*80}\n")

# After
OutputHandler.section_header(title)
```

**Benefits:**

1. **Consistent Formatting:** All output goes through one handler
2. **DRY Compliance:** No duplicate formatting code
3. **Maintainability:** Change output style in one place
4. **Extensibility:** Easy to add features like:
   - Colored terminal output
   - Quiet mode flag
   - JSON output format
   - Log file redirection
   - Progress indicators
5. **Professional Appearance:** Consistent emoji usage and formatting
6. **Early Returns:** Used in implementation to minimize indentation

**Files Created:**
- `headroom/output.py` (76 lines)
- `tests/test_output.py` (102 lines with 8 test cases)

**Files Modified:**
- `headroom/main.py`: Replaced 4 print statements with OutputHandler calls
- `headroom/checks/base.py`: Replaced check completion print with OutputHandler call
- `headroom/parse_results.py`: Replaced section header prints with OutputHandler calls
- Multiple test files updated to match new output format

**Test Coverage:**
- All 329 tests passing
- 100% code coverage maintained
- Comprehensive OutputHandler tests covering all methods and edge cases

### PR-020: Minor Code Quality Improvements

**Requirement:** The system MUST complete remaining low-priority code quality improvements identified in REFACTORING_IDEAS.md.

**Implementation Status:** ✅ COMPLETED

**Improvements Implemented:**

**1. Type Alias for Union (Item 11):**

Before:
```python
def print_policy_recommendations(
    recommendations: Sequence[Union[SCPPlacementRecommendations, RCPPlacementRecommendations]],
    ...
```

After (in types.py):
```python
PolicyRecommendation = Union["SCPPlacementRecommendations", "RCPPlacementRecommendations"]
"""Type alias for either SCP or RCP placement recommendations."""

# Usage
def print_policy_recommendations(
    recommendations: Sequence[PolicyRecommendation],
    ...
```

**2. Simplified Config Validation (Item 7):**

Before:
```python
except ValueError as e:
    OutputHandler.error("Configuration Validation Error", e)
    exit(1)
except TypeError as e:
    OutputHandler.error("Configuration Type Error", e)
    exit(1)
```

After:
```python
except (ValueError, TypeError) as e:
    OutputHandler.error("Configuration Error", e)
    exit(1)
```

**3. Refactored Account ID Extraction (Item 8):**

Before (nested conditionals):
```python
account_id: str = summary.get("account_id", "")
if not account_id:
    account_name = summary.get("account_name", "")
    if not account_name:
        raise RuntimeError(...)
    looked_up_id: str = lookup_account_id_by_name(...)
    return looked_up_id
return account_id
```

After (early returns):
```python
# Happy path: account_id present
account_id: str = summary.get("account_id", "")
if account_id:
    return account_id

# Fallback: look up by account name
account_name = summary.get("account_name", "")
if not account_name:
    raise RuntimeError(...)

return lookup_account_id_by_name(...)
```

**4. Removed MIN_ACCOUNTS Constant (Item 10):**

Before:
```python
MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 1  # Threshold with no effect

def is_safe_for_ou_rcp(ou_id: str, results: List[Dict[str, Any]]) -> bool:
    if _should_skip_ou_for_rcp(...):
        return False
    return len(results) >= MIN_ACCOUNTS_FOR_OU_LEVEL_RCP
```

After:
```python
def is_safe_for_ou_rcp(ou_id: str, results: List[Dict[str, Any]]) -> bool:
    return not _should_skip_ou_for_rcp(...)
```

**Benefits:**
- Reduced cognitive complexity (Item 8: from 4 to 2)
- Eliminated unnecessary variable (Item 8: `looked_up_id`)
- Clearer guard clause pattern (Item 8)
- Removed confusing constant with no effect (Item 10)
- Simplified boolean logic (Item 10)
- More readable type signatures (Item 11)
- Combined duplicate exception handling (Item 7)

**Line Count Changes:**
- Item 11: +3 lines (type alias definition), -2 characters per usage
- Item 7: -4 lines
- Item 8: -3 lines (better readability, same functionality)
- Item 10: -6 lines
- **Net change:** -10 lines with significantly better code quality

**Test Updates:**
- Updated tests to expect "Configuration Error" instead of "Configuration Validation Error"
- Updated test for single-account OUs to verify they now get OU-level recommendations
- All 329 tests passing with 100% coverage

### PR-021: IAM User Creation SCP

**Requirement:** The system MUST provide an SCP check for discovering IAM users and auto-generating SCPs with allowlists to enforce IAM user creation policies across accounts and OUs.

**Implementation Status:** ✅ COMPLETED

**Implementation Specifications:**

**Design Philosophy:**

This check implements **automatic allowlist generation** where Python both discovers users and generates Terraform with appropriate allowlists:
- **Python Role:** Discover and list all IAM users in each account, union ARNs across accounts/OUs
- **Terraform Role:** Use `allowed_iam_users` variable with `NotResource` to deny creation of users not on allowlist
- **Automatic Union Logic:** IAM user ARNs from all affected accounts are automatically combined into allowlists
- **Smart ARN Transformation:** Account IDs in ARNs are replaced with Terraform local variable references for maintainability

**Key Design Decision:**

Rather than requiring manual allowlist configuration, the system automatically unions all discovered IAM user ARNs from affected accounts when generating SCPs. This ensures existing users can continue to exist while preventing creation of new users not explicitly approved.

**Data Model:**

```python
@dataclass
class IamUserAnalysis:
    """
    Analysis of an IAM user.

    Attributes:
        user_name: Name of the IAM user
        user_arn: ARN of the IAM user
        path: Path of the IAM user (e.g., "/", "/admins/")
    """
    user_name: str
    user_arn: str
    path: str

@dataclass
class SCPCheckResult(CheckResult):
    """Extended check result with SCP-specific fields."""
    violations: int
    exemptions: int
    compliant: int
    compliance_percentage: float
    total_instances: Optional[int] = None
    iam_user_arns: Optional[List[str]] = None  # New field for IAM user ARNs

@dataclass
class SCPPlacementRecommendations:
    """SCP placement recommendations with allowlist support."""
    check_name: str
    recommended_level: str
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    compliance_percentage: float
    reasoning: str
    allowed_iam_user_arns: Optional[List[str]] = None  # New field for IAM user allowlists
```

**Analysis Function (in `aws/iam/users.py`):**

```python
def get_iam_users_analysis(session: boto3.Session) -> List[IamUserAnalysis]:
    """
    Get all IAM users in an account.

    Uses IAM list_users API with pagination support.
    Returns list of all users regardless of path or tags.
    No filtering logic - pure enumeration for discovery.

    Args:
        session: boto3 Session for the target account

    Returns:
        List of IamUserAnalysis for all IAM users

    Raises:
        ClientError: If list_users API call fails
    """
```

**Check Implementation:**

```python
@register_check("scps", DENY_IAM_USER_CREATION)
class DenyIamUserCreationCheck(BaseCheck[IamUserAnalysis]):
    """
    Check for IAM users in accounts with the deny_iam_user_creation SCP.

    This check lists all IAM users in the account. The discovered users are:
    - Categorized as "compliant" (we're listing, not evaluating)
    - Automatically unioned into allowlists during SCP placement analysis
    - Used to generate SCPs that prevent creation of non-allowlisted users

    Key Features:
    - Automatic allowlist generation from discovered users
    - Union logic across accounts/OUs for comprehensive coverage
    - ARN transformation for Terraform local variable references
    """

    def analyze(self, session: boto3.Session) -> List[IamUserAnalysis]:
        """Discover all IAM users in the account."""
        return get_iam_users_analysis(session)

    def categorize_result(self, result: IamUserAnalysis) -> tuple[str, Dict[str, Any]]:
        """Categorize user as compliant (listing for allowlist generation)."""
        result_dict = {
            "user_name": result.user_name,
            "user_arn": result.user_arn,
            "path": result.path,
        }
        return ("compliant", result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """Build summary with user ARNs for allowlist generation."""
        total = len(check_result.compliant)
        return {
            "total_users": total,
            "users": [user["user_arn"] for user in check_result.compliant],
        }
```

**Result Structure:**

```json
{
  "summary": {
    "account_name": "prod-account",
    "account_id": "123456789012",
    "check": "deny_iam_user_creation",
    "total_users": 5,
    "users": [
      "arn:aws:iam::123456789012:user/terraform-user",
      "arn:aws:iam::123456789012:user/service/github-actions",
      "arn:aws:iam::123456789012:user/contractors/temp-contractor"
    ]
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {
      "user_name": "terraform-user",
      "user_arn": "arn:aws:iam::123456789012:user/terraform-user",
      "path": "/"
    },
    {
      "user_name": "github-actions",
      "user_arn": "arn:aws:iam::123456789012:user/service/github-actions",
      "path": "/service/"
    },
    {
      "user_name": "temp-contractor",
      "user_arn": "arn:aws:iam::123456789012:user/contractors/temp-contractor",
      "path": "/contractors/"
    }
  ]
}
```

**Un-Redaction Logic:**

When `exclude_account_ids=True`, account IDs in result files are redacted as "REDACTED". During SCP placement analysis, the system automatically un-redacts these ARNs by replacing "REDACTED" with the actual account ID looked up from the organization hierarchy.

**Union Logic for Allowlists:**

During SCP placement analysis (`determine_scp_placement()` in `parse_results.py`):
1. For each placement candidate (root, OU, or account level)
2. If check is `deny_iam_user_creation`, collect all IAM user ARNs from affected accounts
3. Union the ARNs into a single set, removing duplicates
4. Sort and attach to `SCPPlacementRecommendations.allowed_iam_user_arns`
5. Pass to Terraform generation for automatic allowlist creation

**ARN Transformation for Terraform:**

During Terraform generation (`generate_scps.py`):
1. For each IAM user ARN in allowlist
2. Parse ARN to extract account ID: `arn:aws:iam::111111111111:user/path/name`
3. Look up account name from organization hierarchy
4. Replace account ID with local variable reference: `arn:aws:iam::${local.account_name_account_id}:user/path/name`
5. This ensures Terraform references are maintainable and changes to account IDs are handled automatically

**Terraform Module Integration:**

**Variables (test_environment/modules/scps/variables.tf):**

```hcl
# IAM

variable "deny_iam_user_creation" {
  type    = bool
}

variable "allowed_iam_users" {
  type        = list(string)
  default     = []
  description = "List of IAM user ARNs allowed to be created. Format: arn:aws:iam::ACCOUNT_ID:user/USERNAME"
}
```

**Policy Logic (test_environment/modules/scps/locals.tf):**

```hcl
# var.deny_iam_user_creation
# -->
# Sid: DenyIamUserCreation
# Denies creation of IAM users not on the allowed list
{
  include = var.deny_iam_user_creation,
  statement = {
    Action = "iam:CreateUser"
    NotResource = var.allowed_iam_users
  }
}
```

**Generated Terraform Example (root_scps.tf):**

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

**Integration Points:**

- **Constants:** `DENY_IAM_USER_CREATION = "deny_iam_user_creation"` in `constants.py`
- **Registry:** Auto-registers via `@register_check("scps", DENY_IAM_USER_CREATION)`
- **Check Type Map:** Automatically added to `CHECK_TYPE_MAP` as "scps" type
- **Results Directory:** Results written to `{results_dir}/scps/deny_iam_user_creation/`
- **Module Location:** `headroom/checks/scps/deny_iam_user_creation.py`

**Testing Strategy:**

- **User Enumeration:** Test with various user counts (0, 1, multiple)
- **Pagination:** Verify pagination support for accounts with many users
- **Path Handling:** Test users in root path (/) and nested paths (/admins/)
- **Categorization:** Verify all users marked as "compliant"
- **Result Structure:** Validate JSON output format matches specification
- **Module Imports:** Test imports from `headroom.aws.iam.users`

**Key Implementation Features:**

1. **Automatic Allowlist Generation:** No manual configuration required - system automatically unions IAM user ARNs from all affected accounts
2. **Un-Redaction Support:** Handles `exclude_account_ids=True` by automatically un-redacting ARNs during placement analysis
3. **ARN Transformation:** Replaces account IDs in ARNs with Terraform local variable references for maintainability
4. **Organized Terraform Output:** SCP modules now have explicit sections (EC2, IAM) with boolean flags for all checks
5. **Required Variables:** All SCP boolean flags are now required (no defaults), ensuring explicit policy decisions

**Files Created:**

- `headroom/checks/scps/deny_iam_user_creation.py` (69 lines)
- `tests/test_checks_deny_iam_user_creation.py` (131 lines)
- `test_environment/test_deny_iam_user_creation.tf` (57 lines with 5 test IAM users)

**Files Modified:**

- `headroom/constants.py`: Added `DENY_IAM_USER_CREATION` constant
- `headroom/checks/__init__.py`: Added import for auto-registration
- `headroom/types.py`: Added `iam_user_arns` field to `SCPCheckResult`, `allowed_iam_user_arns` field to `SCPPlacementRecommendations`
- `headroom/parse_results.py`: Added un-redaction logic and union logic for IAM user ARNs
- `headroom/terraform/generate_scps.py`: Added ARN transformation and organized Terraform output with EC2/IAM sections
- `test_environment/modules/scps/variables.tf`: Added `deny_iam_user_creation` and `allowed_iam_users` variables, made all booleans required
- `test_environment/modules/scps/locals.tf`: Added SCP statement for IAM user creation
- `test_environment/modules/scps/README.md`: Documented new variables and policy
- `test_environment/account_scps.tf`: Updated module calls with new required variables
- `test_environment/scps/root_scps.tf`: Example output with IAM user allowlist

**Test Results:**

- All 370 tests passing (increased from 367, added 18 new tests)
- 100% code coverage maintained (1277 statements in headroom/, 0 missed)
- Comprehensive test coverage for:
  - IAM user enumeration and categorization
  - Un-redaction logic for ARNs
  - Union logic for allowlist generation
  - ARN transformation for Terraform references
  - SCP module generation with organized sections

### PR-022: IAM Module Refactoring - Separation of Concerns

**Requirement:** The system MUST organize IAM-related code by purpose (RCP vs SCP) to improve maintainability and separation of concerns.

**Implementation Status:** ✅ COMPLETED (as part of deny_iam_user_creation implementation)

**Problem Statement:**

The monolithic `headroom/aws/iam.py` file contained two distinct responsibilities:
1. **IAM Role Trust Policy Analysis** (for RCP checks) - ~225 lines after expansion
2. **IAM User Enumeration** (for SCP checks) - needed for new deny_iam_user_creation check

These serve different purposes:
- **RCP Focus:** Analyzing trust relationships, detecting third-party accounts, validating principals
- **SCP Focus:** Discovering IAM users for creation policy enforcement

Mixing these concerns in one file violated the Single Responsibility Principle and made the codebase harder to navigate. This refactoring was done as part of implementing the deny_iam_user_creation check.

**Solution: Package-Based Separation**

Refactored `headroom/aws/iam.py` into a package structure:

```
headroom/aws/iam/
├── __init__.py          # Public API exports
├── roles.py             # RCP-focused: trust policy analysis (225 lines)
└── users.py             # SCP-focused: user enumeration (66 lines)
```

**Module Responsibilities:**

**1. roles.py (RCP-Focused):**

Contains all IAM role trust policy analysis logic:

```python
"""
AWS IAM role analysis module.

This module contains functions for analyzing IAM roles and their trust policies.
"""

# Exports:
- TrustPolicyAnalysis (dataclass)
- UnknownPrincipalTypeError (exception)
- InvalidFederatedPrincipalError (exception)
- ALLOWED_PRINCIPAL_TYPES (constant)
- _extract_account_ids_from_principal() (helper)
- _has_wildcard_principal() (helper)
- analyze_iam_roles_trust_policies() (main function)
```

**Key Functions:**
- `analyze_iam_roles_trust_policies()`: Main analysis function for RCP checks
- `_extract_account_ids_from_principal()`: Parse AWS account IDs from principal field
- `_has_wildcard_principal()`: Detect wildcard principals requiring CloudTrail analysis
- Custom exceptions for principal validation errors

**2. users.py (SCP-Focused):**

Contains all IAM user enumeration logic:

```python
"""
AWS IAM user analysis module.

This module contains functions for enumerating IAM users.
"""

# Exports:
- IamUserAnalysis (dataclass)
- get_iam_users_analysis() (main function)
```

**Key Functions:**
- `get_iam_users_analysis()`: Enumerate all IAM users with pagination
- Simple, focused implementation for user discovery

**3. __init__.py (Public API):**

Re-exports public API components for clean imports:

```python
"""AWS IAM analysis module."""

# Trust policy analysis (RCP checks)
from .roles import (
    InvalidFederatedPrincipalError,
    TrustPolicyAnalysis,
    UnknownPrincipalTypeError,
    analyze_iam_roles_trust_policies,
)

# User enumeration (SCP checks)
from .users import (
    IamUserAnalysis,
    get_iam_users_analysis,
)

__all__ = [
    # Roles (RCP)
    "TrustPolicyAnalysis",
    "UnknownPrincipalTypeError",
    "InvalidFederatedPrincipalError",
    "analyze_iam_roles_trust_policies",
    # Users (SCP)
    "IamUserAnalysis",
    "get_iam_users_analysis",
]
```

**Design Decision: No Backward Compatibility**

Following user direction: "I don't care about backward compatibility"

Private helper functions NOT exported in `__init__.py`:
- `_extract_account_ids_from_principal`
- `_has_wildcard_principal`
- `ALLOWED_PRINCIPAL_TYPES`

These must be imported directly from `headroom.aws.iam.roles` if needed (e.g., in tests).

**Import Pattern Updates:**

**Check Modules:**

```python
# Before
from ...aws.iam import TrustPolicyAnalysis, analyze_iam_roles_trust_policies

# After
from ...aws.iam.roles import TrustPolicyAnalysis, analyze_iam_roles_trust_policies
```

```python
# Before
from ...aws.iam import IamUserAnalysis, get_iam_users_analysis

# After
from ...aws.iam.users import IamUserAnalysis, get_iam_users_analysis
```

**Test Modules:**

```python
# Public API imports still work via __init__.py
from headroom.aws.iam import (
    InvalidFederatedPrincipalError,
    UnknownPrincipalTypeError,
    analyze_iam_roles_trust_policies,
)

# Private helpers require direct import
from headroom.aws.iam.roles import (
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
)

# User functions
from headroom.aws.iam.users import get_iam_users_analysis
```

**Benefits:**

1. **Separation of Concerns:**
   - RCP logic isolated in `roles.py`
   - SCP logic isolated in `users.py`
   - Clear boundaries between different check types

2. **Improved Maintainability:**
   - Each file focuses on single responsibility
   - Easier to locate relevant code
   - Changes to RCP checks don't touch SCP code

3. **Better Scalability:**
   - Easy to add new role analysis functions to `roles.py`
   - Easy to add new user analysis functions to `users.py`
   - Package structure supports future IAM check types

4. **Cleaner Public API:**
   - `__init__.py` explicitly defines public interface
   - Private helpers kept internal (not re-exported)
   - Clear distinction between public and private functions

5. **Explicit Imports:**
   - Direct imports from submodules are more readable
   - Clear indication of which IAM functionality is being used
   - No ambiguity about data sources

**Files Created:**

- `headroom/aws/iam/__init__.py` (33 lines)
- `headroom/aws/iam/roles.py` (225 lines, moved from iam.py)
- `headroom/aws/iam/users.py` (66 lines, moved from iam.py)

**Files Deleted:**

- `headroom/aws/iam.py` (monolithic 150+ line file)

**Files Modified:**

- `headroom/checks/rcps/check_third_party_assumerole.py`: Updated imports to use `.roles`
- `headroom/checks/scps/deny_iam_user_creation.py`: Updated imports to use `.users`
- `tests/test_aws_iam.py`: Updated imports to use submodules for private helpers
- All test files importing IAM functions updated accordingly

**Test Results:**

- All 370 tests passing (part of deny_iam_user_creation implementation)
- 100% code coverage maintained (headroom: 1277 statements, tests: 3662 lines)
- mypy passes with no issues (53 files)
- All pre-commit hooks passing

**Architectural Improvements:**

**Before:**
- Single 150+ line file mixing concerns
- RCP and SCP logic intermingled
- Hard to navigate and understand purpose
- Private helpers exposed via single-file import

**After:**
- Clear package structure with focused modules
- RCP and SCP logic physically separated
- Easy to navigate: roles.py for RCP, users.py for SCP
- Clean public API with explicit exports
- Private helpers require intentional import

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
   - For each account, check if results already exist via `all_scp_results_exist()` and `all_rcp_results_exist()` (skip if found)
   - For accounts without results, assume `Headroom` role via `get_headroom_session()`
   - Execute SCP checks (e.g., `check_deny_imds_v1_ec2()`) using AWS library functions
   - Execute RCP checks (e.g., `check_third_party_assumerole()`) with IAM trust policy analysis
   - Generate structured JSON results in `test_environment/headroom_results/scps/` and `test_environment/headroom_results/rcps/`
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

### Phase 8.5: DRY Refactoring & Constants Module (COMPLETED)
- ✅ Created dedicated `constants.py` module for check configuration
- ✅ Established `CHECK_TYPE_MAP` as single source of truth for check type classification
- ✅ Pre-computed `SCP_CHECK_NAMES` and `RCP_CHECK_NAMES` sets for convenience
- ✅ Extracted shared `lookup_account_id_by_name()` function to eliminate 21 lines of duplicate code
- ✅ Centralized directory path construction with `get_results_dir()` function
- ✅ Replaced 14 hardcoded check name strings with constants
- ✅ All 248 tests passing with 100% coverage maintained

### Phase 9: Framework Abstraction & Code Quality (COMPLETED)
- ✅ **Check Framework Abstraction (PR-016):** Implemented BaseCheck abstract class with Template Method pattern
- ✅ **Registry Pattern (PR-016):** Self-registering checks via `@register_check` decorator
- ✅ **Zero-Code-Change Extensibility:** Adding new checks requires only 1 file (~50 lines), zero other changes
- ✅ **Generic Check Execution:** Unified `run_checks_for_type()` function for all check types
- ✅ **Session Management (PR-017):** Extracted `assume_role()` function, eliminated 53 lines of duplication
- ✅ **Defensive Programming Elimination (PR-018):** Removed all generic exception catches, fail-loud error handling
- ✅ **No Silent Failures:** Removed 2 silent fallback behaviors that hid permission/configuration issues
- ✅ **Output Standardization (PR-019):** Centralized OutputHandler for consistent user-facing output
- ✅ **Code Quality Improvements (PR-020):** Type aliases, simplified validation, early returns, removed ineffective constants
- ✅ All 329 tests passing with 100% coverage (1190 statements in headroom/, 3179 in tests/)
- ✅ Zero mypy errors with strict mode
- ✅ All pre-commit hooks passing

### Phase 10: SCP Expansion - IAM User Creation Policy (COMPLETED)
- ✅ **IAM User Creation SCP (PR-021):** Automatic IAM user allowlist generation with union logic and ARN transformation
- ✅ **Automatic Allowlist Generation:** IAM user ARNs from affected accounts automatically unioned into SCP allowlists
- ✅ **IAM User Enumeration:** `get_iam_users_analysis()` with pagination support for complete user discovery
- ✅ **Check Implementation:** `DenyIamUserCreationCheck` using BaseCheck framework, lists all users for allowlist generation
- ✅ **Union Logic:** IAM user ARNs automatically combined across accounts/OUs during placement analysis
- ✅ **Un-Redaction Support:** Handles `exclude_account_ids=True` by un-redacting ARNs during placement analysis
- ✅ **ARN Transformation:** Account IDs in ARNs replaced with Terraform local variable references for maintainability
- ✅ **Organized Terraform Output:** SCP modules now have explicit EC2/IAM sections with boolean flags for all checks
- ✅ **Required Variables:** All SCP boolean flags now required (no defaults) for explicit policy decisions
- ✅ **Terraform Integration:** SCP module with `deny_iam_user_creation` boolean and `allowed_iam_users` list (default empty)
- ✅ **IAM Module Refactoring (PR-022):** Split monolithic `iam.py` into package structure with `roles.py` and `users.py`
- ✅ **Separation of Concerns:** RCP logic in `roles.py`, SCP logic in `users.py`
- ✅ **Clean Public API:** `__init__.py` exports public functions, private helpers require direct import
- ✅ **No Backward Compatibility:** Direct imports from submodules required per design decision
- ✅ All 370 tests passing (increased from 367, added 18 new tests) with 100% coverage (1277 statements in headroom/, 0 missed)
- ✅ Zero mypy errors with strict mode (53 files)
- ✅ All pre-commit hooks passing
- ✅ Comprehensive test coverage for union logic, un-redaction, ARN transformation, and organized Terraform output

### Phase 11: Future SCP Expansion (PLANNED)
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
25. **Test Coverage Excellence:** 248 tests with 100% coverage maintained through comprehensive test refactoring ✅
26. **DRY Compliance:** Code duplication eliminated through shared functions and centralized constants ✅
27. **Constants Module:** Dedicated `constants.py` for single source of truth on check configuration ✅
28. **Shared Utilities:** Account lookup and path construction functions reusable across modules ✅
29. **Type-Safe Constants:** Check names as importable constants instead of magic strings ✅
30. **Maintainable Architecture:** Adding new checks requires minimal code changes in single location ✅
31. **Check Framework Abstraction:** BaseCheck abstract class with Template Method pattern for reusable check execution ✅
32. **Registry Pattern:** Self-registering checks via decorators enable zero-code-change extensibility ✅
33. **Generic Check Execution:** Unified run_checks_for_type() function replaces check-specific execution code ✅
34. **Session Management Extraction:** Single assume_role() function eliminates 53 lines of duplication ✅
35. **Fail-Loud Error Handling:** All exceptions are specific, no silent failures or generic catches ✅
36. **Output Standardization:** Centralized OutputHandler for consistent user-facing output formatting ✅
37. **Code Quality Excellence:** 329 tests with 100% coverage, zero mypy errors, all pre-commit hooks passing ✅
38. **IAM User Creation SCP:** Automatic allowlist generation with IAM user ARN union logic and smart Terraform integration ✅
39. **Automatic Allowlist Generation:** System automatically unions IAM user ARNs from affected accounts into SCP allowlists ✅
40. **IAM Module Organization:** Package structure separating RCP concerns (roles.py) from SCP concerns (users.py) ✅
41. **Clean Module Interface:** Public API via __init__.py with intentional access to private helpers ✅
42. **Union Logic for SCPs:** IAM user ARNs automatically combined across accounts/OUs during placement analysis ✅
43. **Un-Redaction Support:** Handles exclude_account_ids=True by un-redacting ARNs during placement analysis ✅
44. **ARN Transformation:** Account IDs in ARNs replaced with Terraform local variable references for maintainability ✅
45. **Organized SCP Output:** Terraform modules have explicit sections (EC2, IAM) with boolean flags for all checks ✅
46. **Required SCP Variables:** All boolean flags required (no defaults) for explicit policy decisions ✅
47. **Comprehensive Test Coverage:** 370 tests (41 new from baseline) with 100% coverage maintained (1277 statements, 0 missed) ✅

---

*This PDR represents the complete specification for the current Headroom implementation and serves as the foundation for future development phases.*
