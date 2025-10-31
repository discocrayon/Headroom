## 2025-10-26, 12:10 PM - Fixed terminology: "root account" to "management account"

### Changes Made

Updated documentation to consistently use "management account ID" instead of "root account ID".

#### Files Updated

1. **README.md** (line 186)
   - Changed: "AWS Organizations root account ID"
   - To: "AWS Organizations management account ID"

2. **Headroom-Specification.md** (line 39)
   - Changed: "AWS Organizations root account"
   - To: "AWS Organizations management account"

#### Rationale

AWS Organizations uses "management account" as the official terminology for the account that manages the organization. Using "root account" can be confusing as it might be confused with the root user of an account. Consistent terminology improves clarity.

**Note**: The test file `test_parse_results.py` uses "root accounts" in a different context (referring to accounts at the root of the organizational unit hierarchy), so those references were left unchanged.

## 2025-10-26, 12:11 PM - Standardized AWS account IDs in documentation and tests

### Changes Made

Replaced all references to AWS account IDs with standardized values:
- Management account ID: 345678901234 → 222222222222
- Security analysis account ID: 123456789012 → 111111111111

#### Files Updated

1. **Headroom-Specification.md**
   - Replaced 1 instance of 345678901234 with 222222222222
   - Replaced 2 instances of 123456789012 with 111111111111

2. **tests/test_parse_results.py**
   - Replaced 6 instances of 345678901234 with 222222222222
   - Replaced 10 instances of 123456789012 with 111111111111

3. **tests/test_config.py**
   - Replaced 3 instances of 123456789012 with 111111111111

4. **tests/test_analysis_extended.py**
   - Replaced 4 instances of 123456789012 with 111111111111

5. **tests/test_analysis.py**
   - Replaced 4 instances of 123456789012 with 111111111111

6. **tests/test_write_results.py**
   - Replaced 18 instances of 123456789012 with 111111111111

7. **tests/test_checks_deny_imds_v1_ec2.py**
   - Replaced 2 instances of 123456789012 with 111111111111

#### Rationale

Using consistent, standardized account IDs across all documentation and tests makes the codebase more coherent and easier to understand. The new IDs follow a more memorable pattern (111111111111 for security analysis, 222222222222 for management account).

## 2025-10-26, 12:30 PM - Refactored duplicate _make_safe_variable_name functions

### Changes Made

Consolidated two identical `_make_safe_variable_name` functions that existed in both `generate_scps.py` and `generate_org_info.py` into a single shared function in a new `utils.py` module.

#### Files Created

1. **headroom/terraform/utils.py** (new file)
   - Created shared utilities module for Terraform generation
   - Added `make_safe_variable_name` function (public, without underscore prefix)
   - Function converts names to Terraform-safe variable names by replacing spaces and special characters with underscores, removing consecutive underscores, and ensuring the name starts with a letter

#### Files Updated

1. **headroom/terraform/__init__.py**
   - Added import: `from .utils import make_safe_variable_name`
   - Added to `__all__` exports

2. **headroom/terraform/generate_scps.py**
   - Removed duplicate `_make_safe_variable_name` function (lines 161-185)
   - Changed import from `from . import make_safe_variable_name` to `from .utils import make_safe_variable_name`
   - Updated 2 function calls from `_make_safe_variable_name` to `make_safe_variable_name`

3. **headroom/terraform/generate_org_info.py**
   - Removed duplicate `_make_safe_variable_name` function (lines 174-196)
   - Changed import from `from . import make_safe_variable_name` to `from .utils import make_safe_variable_name`
   - Updated 4 function calls from `_make_safe_variable_name` to `make_safe_variable_name`

4. **tests/test_generate_scps.py**
   - Updated import to: `from headroom.terraform import make_safe_variable_name`
   - Updated 3 function calls from `_make_safe_variable_name` to `make_safe_variable_name`

5. **tests/test_generate_terraform.py**
   - Updated import to: `from headroom.terraform import make_safe_variable_name`
   - Updated 9 function calls from `_make_safe_variable_name` to `make_safe_variable_name`

#### Rationale

Both functions were completely identical, violating the DRY (Don't Repeat Yourself) principle. Consolidating them into a shared utility module (`utils.py`) improves maintainability by ensuring there's a single source of truth. The function was made public (renamed from `_make_safe_variable_name` to `make_safe_variable_name`) since it's now part of the module's public API. Using a separate `utils.py` file avoids circular import issues and complies with Python import best practices (E402 flake8 rule).

## 2025-10-26, 12:35 PM - Fixed misleading "root-account" naming in test_parse_results.py

### Changes Made

Renamed "root-account" to "management-account" and added clarifying comments to avoid confusion between organization root IDs and account IDs.

#### Files Updated

1. **tests/test_parse_results.py**
   - Line 64: Changed "root-account" to "management-account" in mock response
   - Line 116: Changed "root-account" to "management-account" in AccountOrgPlacement
   - Line 156: Changed "root-account" to "management-account" in mock response
   - Line 928: Added clarifying comment: "Note: r-1234 is the org root ID, not an account. Accounts are placed under it."
   - Line 970: Added clarifying comment: "Note: r-1234 is the org root ID. Accounts can be placed under it or under OUs."

#### Rationale

AWS Organizations uses different ID formats:
- Organization root IDs: Start with "r-" (e.g., "r-1234")
- Organizational unit IDs: Start with "ou-" (e.g., "ou-1234")
- Account IDs: 12-digit numbers (e.g., "111111111111")

The previous naming of "root-account" was confusing because:
1. It suggested the account ID might be "r-1234" (which is actually an org root ID, not an account)
2. "root account" could be confused with AWS root user or management account

The test data was actually representing an account placed directly under the organization root (not in any OU), which is valid but needed clearer naming. Changing to "management-account" and adding comments makes the distinction crystal clear: r-1234 is the organization root container, and accounts (with 12-digit IDs) are placed either under it or under OUs.

## 2025-10-31, 12:00 PM - Created Terraform RCP module

### Changes Made

Created a new Terraform module for Resource Control Policies (RCPs) similar to the existing SCP module structure.

#### Files Created

1. **test_environment/modules/rcps/variables.tf** (new file)
   - Added `target_id` variable with validation for account IDs, OU IDs, or root IDs
   - Added `third_party_account_ids` variable (list of strings) with validation for 12-digit AWS account IDs
   - Variable is used to specify which third-party accounts can assume roles in the organization

2. **test_environment/modules/rcps/locals.tf** (new file)
   - Created `rcp_1_content` using jsonencode pattern for minimized policies
   - Added validation check for RCP maximum length of 5,120 bytes at plan time
   - Defined `rcp_1_policy` with EnforceOrgIdentities statement that:
     - Denies `sts:AssumeRole` actions
     - Allows principals from the organization (via `aws:PrincipalOrgID`)
     - Allows principals from third-party accounts (via `aws:PrincipalAccount`)
     - Allows resources tagged with `dp:exclude:identity: true`
     - Allows AWS service principals
   - Used `data.aws_organizations_organization.current.id` to get the organization ID dynamically

3. **test_environment/modules/rcps/rcps.tf** (new file)
   - Created `aws_organizations_policy` resource for RCP with type `RESOURCE_CONTROL_POLICY`
   - Created `aws_organizations_policy_attachment` resource to attach RCP to target
   - Named policy as "Rcp1For-{target_id}"

4. **test_environment/modules/rcps/README.md** (new file)
   - Documented module overview and purpose
   - Explained RCP policy details and conditions
   - Provided usage example
   - Listed variables and notes about RCP limits

#### Files Already Present

- **test_environment/modules/rcps/data.tf** - Already contained the `aws_organizations_organization.current` data source

#### Rationale

Resource Control Policies (RCPs) are AWS Organizations policies that enforce security controls on resources across an organization. This module implements an RCP that enforces organization identity for role assumptions, ensuring that only principals from the organization, approved third-party accounts, or AWS services can assume roles. The module follows the same structure as the existing SCP module for consistency and maintainability.

## 2025-10-31, 1:00 PM - Created comprehensive RCP check and Terraform generation system

### Changes Made

Implemented a complete system for analyzing IAM role trust policies, identifying third-party account access, and generating Resource Control Policy (RCP) Terraform code.

#### Files Created

1. **headroom/aws/iam.py** (new file)
   - Created module for analyzing IAM roles and trust policies
   - Implemented `analyze_iam_roles_trust_policies()` function that iterates through all IAM roles in an account
   - Implemented `_extract_account_ids_from_principal()` function to parse account IDs from IAM policy principals (handles ARNs, account IDs, lists, dicts)
   - Implemented `_has_wildcard_principal()` function to detect wildcard principals in trust policies
   - Function examines AssumeRole statements and extracts account IDs
   - Compares extracted account IDs against organization account IDs to identify third-party accounts
   - Detects wildcard principals and adds TODO comment about checking CloudTrail logs
   - Returns `TrustPolicyAnalysis` dataclass with role information

2. **headroom/checks/check_third_party_role_access.py** (new file)
   - Created RCP check module that uses the Headroom role to analyze IAM roles
   - Calls `analyze_iam_roles_trust_policies()` with organization account IDs
   - Aggregates all third-party account IDs found across all roles
   - Separates roles with third-party access from roles with wildcards
   - Returns set of all third-party account IDs found
   - Writes detailed JSON results including role names, ARNs, and third-party accounts

3. **headroom/terraform/generate_rcps.py** (new file)
   - Created module for generating RCP Terraform files
   - Implemented `parse_rcp_result_files()` to read third_party_role_access check results
   - Implemented `determine_rcp_placement()` with intelligent placement logic:
     - Root level: if all accounts have identical third-party account sets
     - OU level: if all accounts in an OU have identical third-party account sets
     - Account level: for accounts with unique third-party requirements
   - Implemented `generate_rcp_terraform()` to create Terraform module calls
   - Generates separate .tf files for root, OU, and account level RCPs
   - Uses the RCP module created earlier with `third_party_account_ids` variable

4. **tests/test_aws_iam.py** (new file)
   - Created comprehensive tests for IAM analysis functions
   - Tests account ID extraction from various principal formats (ARNs, plain IDs, lists, dicts)
   - Tests wildcard detection in principals
   - Tests full role analysis with third-party accounts, wildcards, service principals
   - Tests filtering logic (Deny statements ignored, service principals ignored, org accounts filtered out)
   - 21 tests, all passing

5. **tests/test_checks_third_party_role_access.py** (new file)
   - Created tests for RCP check module
   - Tests aggregation of third-party accounts across multiple roles
   - Tests wildcard detection and reporting
   - Tests roles with both wildcards and third-party accounts
   - Tests empty result scenarios
   - Tests result data structure validation
   - 6 tests, all passing

6. **tests/test_generate_rcps.py** (new file)
   - Created tests for RCP Terraform generation
   - Tests parsing of RCP result files from JSON
   - Tests placement determination (root, OU, account levels)
   - Tests Terraform file generation for all placement levels
   - Tests content validation of generated Terraform files
   - 12 tests, all passing

#### Files Updated

1. **headroom/types.py**
   - Added `RCPCheckResult` dataclass for parsed RCP check results
   - Added `RCPPlacementRecommendations` dataclass for RCP placement recommendations
   - Includes fields: check_name, recommended_level, target_ou_id, affected_accounts, third_party_account_ids, reasoning

2. **headroom/analysis.py**
   - Added import for `check_third_party_role_access`
   - Created `get_all_organization_account_ids()` function to retrieve all account IDs in organization (including management account)
   - Updated `run_checks()` to accept `org_account_ids` parameter
   - Updated `run_checks()` to check for existing RCP results
   - Updated `run_checks()` to call RCP check with organization account IDs
   - Updated `perform_analysis()` to fetch organization account IDs and pass to `run_checks()`

3. **headroom/main.py**
   - Added imports for RCP Terraform generation functions
   - Added RCP result parsing after security analysis
   - Added RCP placement determination using `determine_rcp_placement()`
   - Added RCP recommendation output display
   - Added RCP Terraform generation call
   - Both SCP and RCP Terraform files are now generated

#### Rationale

This implementation provides a complete automated workflow for managing third-party account access via RCPs:

1. **Analysis Phase**: The system assumes the Headroom role in each account and examines all IAM role trust policies
2. **Identification Phase**: Account IDs in trust policies are compared against the organization to identify third-party accounts
3. **Aggregation Phase**: Third-party accounts are collected across all accounts
4. **Optimization Phase**: The system determines the most efficient RCP placement (root, OU, or account level) based on commonality
5. **Generation Phase**: Terraform code is automatically generated to deploy RCPs at the recommended levels

The wildcard detection includes a TODO comment about using CloudTrail to determine which accounts actually assume roles, as requested. This is important for security auditing when wildcards are found.

The system follows the same patterns as the existing SCP code for consistency and integrates seamlessly into the existing Headroom workflow.

## 2025-10-31, 2:30 PM - Improved RCP system robustness and clarity

### Changes Made

Enhanced the RCP system with more robust ARN parsing, wildcard handling, and better code clarity.

#### Files Updated

1. **headroom/aws/iam.py**
   - Improved `_extract_account_ids_from_principal()` function with more robust ARN regex
   - Changed from generic `\d{12}` search to specific ARN pattern: `^arn:aws:iam::(\d{12}):`
   - This ensures we extract the account ID from the correct position (5th field) in the ARN
   - Added check for plain 12-digit account IDs as fallback: `^\d{12}$`
   - Reordered logic to check for Service principals explicitly and skip them
   - Updated to handle mixed principals like `{"AWS": [...], "Service": "..."}`
   - Now processes AWS principals even when Service key is present in the same dict
   - Added clarifying comments about which principal types are ignored (Service, Federated)

2. **headroom/types.py**
   - Added `has_wildcard: bool` attribute to `RCPCheckResult` dataclass
   - This attribute tracks whether an account has any roles with wildcard principals
   - Critical for determining whether RCPs can be safely deployed to an account

3. **headroom/terraform/generate_rcps.py**
   - Updated `parse_rcp_result_files()` to check for wildcards in results
   - Accounts with `roles_with_wildcards > 0` are now skipped for RCP generation
   - Added logging when accounts are skipped due to wildcards
   - Added clarifying comment: "Skip OUs with less than 2 accounts - not worth creating an OU-level RCP for a single account (use account-level instead)"
   - Updated docstring to note that accounts with wildcards are excluded

#### Rationale

**ARN Regex Improvements:**
- The previous regex `\d{12}` was too permissive and could match account IDs anywhere in a string
- The new regex `^arn:aws:iam::(\d{12}):` is specific to IAM ARNs and extracts the account ID from the correct position
- This prevents false matches and ensures we only get account IDs from valid IAM ARNs
- The fallback check for plain 12-digit IDs handles cases where the principal is just an account ID

**Service Principal Handling:**
- Service principals (like `ec2.amazonaws.com`) should not be treated as third-party accounts
- The updated logic explicitly checks for and skips Service keys
- Mixed principals (both AWS and Service in same dict) are now handled correctly
- Only AWS principals are processed for account ID extraction

**Wildcard Safety:**
- RCPs cannot be safely deployed when roles have wildcard principals
- Without knowing which specific accounts assume roles, we cannot create an accurate RCP whitelist
- The `has_wildcard` attribute allows us to track this at the account level
- Accounts with wildcards are logged and skipped during RCP generation
- This prevents creating RCPs that could block legitimate access or allow unintended access

**Code Clarity:**
- The comment about OU account count threshold makes the logic immediately clear
- Prevents confusion about why we skip OUs with single accounts

## 2025-10-31, 3:00 PM - Critical OU-level RCP safety fix and explicit Service/Federated principal handling

### Changes Made

Fixed a critical safety issue where OU-level RCPs could be deployed to OUs containing accounts with wildcards, and added explicit handling for Service and Federated principals.

#### Files Updated

1. **headroom/aws/iam.py**
   - Added explicit comments documenting that Service and Federated principals are skipped
   - Clarified that Service principals (like `ec2.amazonaws.com`) are not third-party accounts
   - Clarified that Federated principals (like SAML providers) are not third-party accounts
   - Logic processes AWS key if present, but explicitly ignores Service and Federated keys
   - Handles mixed principals correctly (e.g., `{"AWS": [...], "Service": "..."}`)

2. **headroom/terraform/generate_rcps.py**
   - **CRITICAL FIX**: Changed `parse_rcp_result_files()` return type to tuple containing accounts with wildcards
   - Now returns `tuple[Dict[str, Set[str]], Set[str]]` instead of just `Dict[str, Set[str]]`
   - Tracks which accounts have wildcard principals separately
   - Updated `determine_rcp_placement()` to accept `accounts_with_wildcards` parameter
   - Added OU-level wildcard check: before creating OU-level RCP, checks ALL accounts in that OU
   - If ANY account in an OU has wildcards, OU-level RCP is skipped with logging
   - This prevents deploying OU-level RCPs that would apply to accounts with wildcards
   - Updated reasoning messages for clarity

3. **headroom/main.py**
   - Updated to unpack tuple from `parse_rcp_result_files()`
   - Passes `accounts_with_wildcards` to `determine_rcp_placement()`

4. **tests/test_generate_rcps.py**
   - Updated all test signatures to handle new tuple return type
   - Added assertions to verify `accounts_with_wildcards` set
   - Added new test: `test_ou_with_wildcard_account_skipped()`
   - This test verifies that OUs with ANY account having wildcards don't get OU-level RCPs
   - Updated all existing tests to pass empty wildcard set where appropriate

5. **tests/test_main_integration.py**
   - Updated mock for `parse_rcp_result_files` to return tuple `({}, set())`

#### Rationale

**Critical OU-level Safety Issue:**
- Previously, when accounts with wildcards were skipped, they simply didn't appear in `account_third_party_map`
- If an OU had 5 accounts and 2 had wildcards, only 3 would appear in the map
- We might create an OU-level RCP for those 3 accounts
- **PROBLEM**: OU-level RCPs apply to ALL accounts in the OU, including those with wildcards!
- This would break the wildcard accounts since we don't know which third-party principals they need
- **FIX**: Now we track wildcard accounts separately and explicitly check ALL accounts in an OU
- If ANY account in an OU has wildcards, we skip OU-level RCP for that entire OU
- Those accounts without wildcards will get account-level RCPs instead

**Explicit Service/Federated Handling:**
- Comments now explicitly document that Service and Federated keys are skipped
- Makes it clear these are intentionally ignored, not accidentally overlooked
- Service principals (AWS services) are not third-party accounts
- Federated principals (SAML/OIDC) are not third-party accounts
- Only AWS principals are processed for account ID extraction

#### Test Coverage

- **206 tests passing** (added 1 new test)
- New test verifies OU with wildcard accounts gets skipped for OU-level RCP
- All existing tests updated to handle new tuple return signature
- Comprehensive coverage of wildcard handling at both account and OU levels

## 2025-10-31, 3:30 PM - Added strict principal type validation and Federated principal checks

### Changes Made

Added explicit validation for IAM principal types with custom exceptions to catch configuration errors early. Also added validation to ensure Federated principals don't use `sts:AssumeRole` action.

#### Files Updated

1. **headroom/aws/iam.py**
   - Added `UnknownPrincipalTypeError` exception class for unknown principal types
   - Added `InvalidFederatedPrincipalError` exception class for invalid Federated principal configurations
   - Added `ALLOWED_PRINCIPAL_TYPES` constant set containing: `{"AWS", "Service", "Federated"}`
   - Updated `_extract_account_ids_from_principal()`:
     - Added explicit validation that dict principal keys are in `ALLOWED_PRINCIPAL_TYPES`
     - Raises `UnknownPrincipalTypeError` with descriptive message if unknown types found
     - This catches typos or new AWS principal types we don't handle
   - Updated `analyze_iam_roles_trust_policies()`:
     - Added validation that Federated principals don't have `sts:AssumeRole` action
     - Federated principals should use `sts:AssumeRoleWithSAML` or `sts:AssumeRoleWithWebIdentity`
     - Raises `InvalidFederatedPrincipalError` with descriptive message if misconfigured
     - Added per-role try/except to catch validation errors
     - `UnknownPrincipalTypeError` and `InvalidFederatedPrincipalError` are logged and re-raised
     - Other exceptions are logged as warnings and processing continues

2. **tests/test_aws_iam.py**
   - Added imports for `UnknownPrincipalTypeError` and `InvalidFederatedPrincipalError`
   - Added `test_unknown_principal_type_raises_error()`:
     - Tests that principal with `{"UnknownType": "something"}` raises `UnknownPrincipalTypeError`
     - Verifies error message contains the unknown type name
   - Added `test_federated_with_assume_role_raises_error()`:
     - Tests that Federated principal with `sts:AssumeRole` raises `InvalidFederatedPrincipalError`
     - Verifies error message mentions correct actions (`AssumeRoleWithSAML` or `AssumeRoleWithWebIdentity`)
   - Added `test_federated_with_assume_role_with_saml_allowed()`:
     - Tests that Federated principal with `sts:AssumeRoleWithSAML` works correctly
     - No exception should be raised for valid Federated configurations

#### Rationale

**Defensive Programming:**
- Explicitly validating principal types prevents silent failures
- Instead of ignoring unknown principal types, we fail fast with a clear error message
- This helps catch AWS API changes, typos in trust policies, or new principal types we don't handle

**Federated Principal Validation:**
- Federated principals (SAML, OIDC) have specific assume role actions they should use
- `sts:AssumeRole` is for IAM principals, not Federated principals
- Catching this misconfiguration helps identify trust policies that won't work as intended
- Clear error message guides users to the correct actions

**Error Handling Strategy:**
- Validation errors are logged and re-raised (fail fast for serious issues)
- Other exceptions during role processing are logged as warnings and skipped
- This allows the analysis to continue even if individual roles have issues
- Critical validation errors still stop execution for safety

**Code Quality:**
- No comments about logic, only executable validation code
- Exceptions provide clear, actionable error messages
- Type safety maintained with specific exception classes

#### Test Coverage

- **209 tests passing** (added 3 new tests)
- All validation paths covered: unknown types, invalid Federated config, valid Federated config
- Error messages verified to contain useful debugging information

#### Code Quality Updates

1. **headroom/aws/__init__.py**
   - Added exports for `UnknownPrincipalTypeError` and `InvalidFederatedPrincipalError`
   - Added exports for `TrustPolicyAnalysis` and `analyze_iam_roles_trust_policies`
   - Makes exceptions and functions available at package level

2. **tests/test_aws_iam.py**
   - Added `test_role_without_principal_skipped()` for statements with no Principal field
   - Added `test_role_with_invalid_json_skipped()` for malformed trust policies with graceful degradation

3. **tests/test_generate_rcps.py**
   - Added `test_parse_invalid_json()` for handling invalid JSON result files
   - Added `test_parse_missing_summary_key()` for handling malformed result files
   - Added `test_account_not_in_hierarchy_for_ou_mapping()` for accounts missing from org hierarchy
   - Added `test_generate_skips_missing_ou()` for OU not found in hierarchy during Terraform generation
   - Added `test_generate_skips_missing_account()` for account not found in hierarchy during Terraform generation

#### Final Test Results

- **216 tests passing** (added 7 additional tests)
- **97% overall code coverage**
- **100% coverage** for all new code: `headroom/aws/iam.py` and `headroom/terraform/generate_rcps.py`
- Remaining 3% uncovered is AWS SDK integration code and display output code
- All linting passes
- Comprehensive error handling tested

#### Summary

Added robust principal type validation with custom exceptions that fail fast when encountering:
- Unknown principal types (typos, new AWS types)
- Invalid Federated principal configurations

All validation is code-based (no comments) with clear, actionable error messages. Error handling allows analysis to continue when individual roles have issues, but stops for critical validation errors. The system is now production-ready with comprehensive test coverage.
