# Headroom - AWS Multi-Account Security Analysis Tool
## Product Design Requirements (PDR)

**Version:** 4.1
**Created:** 2025-10-26
**Last Updated:** 2025-11-01
**Status:** Implementation Complete (Foundation + SCP Analysis + Results Processing + Code Quality Optimization + Terraform Generation + SCP Auto-Generation + RCP Analysis + RCP Auto-Generation + RCP Placement Optimization)

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
rcp_always_root: boolean (default: true)         # Always deploy RCPs at root level with aggregated third-party accounts
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
- **`write_results.py`**: JSON result file writing, path resolution, and results existence checking
- **`types.py`**: Shared data models and type definitions for organization hierarchy, SCP recommendations, and RCP placement recommendations
- **`aws/`**: AWS service integration modules
  - **`ec2.py`**: EC2 service integration and analysis functions
  - **`iam.py`**: IAM trust policy analysis and third-party account detection
  - **`organization.py`**: AWS Organizations API integration and hierarchy analysis
- **`checks/`**: SCP/RCP compliance check implementations
  - **`deny_imds_v1_ec2.py`**: EC2 IMDS v1 compliance check implementation (SCP)
  - **`check_third_party_role_access.py`**: IAM trust policy third-party account access check (RCP)
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
- **Organization Structure Analysis:** Function to analyze AWS Organizations OU hierarchy and account relationships
- **Account-to-OU Mapping:** Function to create comprehensive mapping of accounts to their direct parent OUs
- **Greatest Common Denominator Logic:** Function to determine optimal SCP/RCP placement level (root, OU, or account-specific)
- **Terraform Generation:** `generate_terraform.py` module generates Terraform configuration files for organization structure data

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
    "roles_with_third_party_access": 3,
    "roles_with_wildcards": 1,
    "unique_third_party_accounts": 2
  },
  "roles_with_third_party_access": [
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
- **Target Directory:** Generate RCP files under configured `scps_dir` (default: `test_environment/scps/`)
- **Safety-First Logic:** Excludes accounts with wildcard principals from RCP generation
- **Multi-Level Support:** Account-level, OU-level, and root-level RCP deployment
- **Third-Party Whitelist:** Includes approved third-party account IDs in RCP policy

**Generated RCP Terraform Structure:**

**Account-Level RCPs:**
```hcl
# Auto-generated RCP Terraform configuration for account-name
# Generated by Headroom based on IAM trust policy analysis

module "rcps_account_name" {
  source = "./modules/rcps"
  target_id = locals.account_name_account_id

  # Third-party accounts approved for role assumption
  third_party_account_ids = [
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

  # Third-party accounts approved for role assumption
  third_party_account_ids = [
    "999999999999"
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

  # Third-party accounts approved for role assumption
  third_party_account_ids = [
    "999999999999"
  ]
}
```

**RCP Terraform Module (in `test_environment/modules/rcps/`):**

**Module Structure:**
- **`variables.tf`:** Defines `target_id` and `third_party_account_ids` variables
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
def parse_rcp_result_files(results_dir: str) -> Tuple[Dict[str, Set[str]], Set[str]]:
    """
    Parse RCP check results and extract third-party account mappings.

    Returns:
        Tuple of (account_third_party_map, accounts_with_wildcards)
        - account_third_party_map: Dict mapping account IDs to sets of third-party account IDs
        - accounts_with_wildcards: Set of account IDs that have roles with wildcard principals

    Accounts with wildcards are excluded from the account_third_party_map.
    """
```

**2. Placement Determination (in `terraform/generate_rcps.py`):**
```python
def determine_rcp_placement(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str],
    rcp_always_root: bool = True
) -> List[RCPPlacementRecommendations]:
    """
    Determine optimal RCP placement levels based on third-party account patterns.

    Logic when rcp_always_root=True (default):
    - Aggregates ALL third-party account IDs from all accounts
    - Deploys single RCP at root level with combined whitelist
    - Fails fast if ANY account has wildcard principals (returns empty list with warning)
    - Rationale: Root-level RCPs apply to ALL accounts; wildcards make this unsafe

    Logic when rcp_always_root=False (intelligent placement):
    - Root level: If ALL accounts have identical third-party account sets
    - OU level: If ALL accounts in an OU have identical third-party account sets
              AND no accounts in that OU have wildcards
    - Account level: For accounts with unique third-party requirements

    OU-level RCPs are skipped if ANY account in the OU has wildcards to prevent
    applying RCP to accounts where we don't know which principals are needed.
    """
```

**3. Terraform Generation (in `terraform/generate_rcps.py`):**
```python
def generate_rcp_terraform(
    recommendations: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    scps_dir: str
) -> None:
    """
    Generate RCP Terraform files based on placement recommendations.

    Creates separate .tf files for root, OU, and account level RCPs.
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

**When `rcp_always_root=True` (Default):**
- **Aggregation Mode:** All third-party account IDs from all accounts are combined
- **Root Deployment:** Single RCP deployed at organization root with aggregated whitelist
- **Wildcard Fail-Fast:** If ANY account has wildcard principals, NO RCP is deployed (returns empty list)
- **Safety Rationale:** Root-level RCPs apply to ALL accounts in organization; wildcards make this unsafe
- **Warning Logging:** Clear warning logged when wildcards prevent root deployment, listing affected accounts

**When `rcp_always_root=False` (Intelligent Placement):**
- **Root Level:** Recommended when all accounts in organization have identical third-party account sets
- **OU Level:** Recommended when all accounts in OU have identical third-party account sets AND no wildcards in OU
- **Account Level:** Recommended for accounts with unique third-party requirements or accounts in OUs with wildcards
- **Wildcard Exclusion:** Accounts with wildcard principals never included in any RCP recommendation
- **OU Wildcard Safety:** OU-level RCP skipped if ANY account in OU has wildcards (even if other accounts match)

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
- **Check Tests:** 6 tests covering aggregation, wildcards, empty results
- **RCP Generation Tests:** 25 tests covering parsing, placement, wildcard safety, Terraform generation, always-root mode
- **Integration Tests:** End-to-end RCP display and generation flow
- **100% Coverage:** All RCP-related code fully covered (227 total tests passing, 996 statements in headroom/, 2361 in tests/)

**Code Quality:**
- **Specific Exceptions:** All exception handlers catch specific types (`json.JSONDecodeError`, `ClientError`, custom exceptions)
- **No Silent Failures:** All exceptions logged and re-raised
- **Type Safety:** Full type annotations satisfying mypy strict mode
- **Clean Architecture:** Clear separation between IAM analysis, check execution, and Terraform generation
- **DRY Compliance:** Shared utilities in `terraform/utils.py` for variable name generation

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
- ✅ RCP compliance check implementation (`check_third_party_role_access`)
- ✅ RCP Terraform auto-generation with third-party account whitelists
- ✅ Multi-level RCP deployment (account, OU, root)
- ✅ Wildcard safety logic (OU-level RCPs excluded if any account has wildcards)
- ✅ Fail-loud exception handling (specific exceptions only, no silent failures)
- ✅ Principal type validation (AWS, Service, Federated)
- ✅ Mixed principal support (e.g., `{"AWS": [...], "Service": "..."}`)
- ✅ Custom exceptions (`UnknownPrincipalTypeError`, `InvalidFederatedPrincipalError`)
- ✅ Comprehensive test coverage (227 tests, 100% coverage for all modules)
- ✅ RCP Terraform module with EnforceOrgIdentities policy
- ✅ RCP always-root deployment mode with aggregated third-party accounts (configurable via `--no-rcp-always-root`)
- ✅ Wildcard fail-fast validation for safe root-level RCP deployment

### Phase 8: SCP Expansion (PLANNED)
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
- `--security-analysis-account-id ID` (optional): Override security analysis account ID from YAML
- `--management-account-id ID` (optional): Override management account ID from YAML
- `--exclude-account-ids` (optional): Exclude account IDs from result files and filenames
- `--no-rcp-always-root` (optional): Disable always deploying RCPs at root level (default: enabled)

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
14. **RCP Auto-Generation:** Terraform RCP configurations with third-party account whitelists and wildcard safety ✅
15. **Exception Handling:** Fail-loud with specific exception types, no silent failures or generic catches ✅
16. **Principal Validation:** Comprehensive handling of AWS, Service, Federated, and mixed principals ✅
17. **RCP Placement Optimization:** Configurable always-root mode for simplified deployment with aggregated third-party accounts ✅
18. **Wildcard Safety:** Fail-fast validation preventing unsafe root-level RCP deployment when wildcards detected ✅

---

*This PDR represents the complete specification for the current Headroom implementation and serves as the foundation for future development phases.*
