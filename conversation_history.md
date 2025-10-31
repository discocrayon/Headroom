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
