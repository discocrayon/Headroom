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
