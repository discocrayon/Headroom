# Refactoring Ideas

This document tracks refactoring opportunities identified in the codebase. Items marked with ✅ have been completed.

## Completed Refactorings

### ✅ Part 1: Extract Role Assumption Pattern
- **Status**: Completed 2025-11-06
- **Files**: `headroom/analysis.py`, `headroom/main.py`, `headroom/parse_results.py`
- **Impact**: Eliminated 60 lines of duplicated code, created reusable `get_management_account_session()` function
- **Details**: See `conversation_history.md` for full documentation

### ✅ Part 2: Break Up parse_scp_results()
- **Status**: Completed 2025-11-06
- **Files**: `headroom/parse_results.py`
- **Impact**: Reduced function from 65 lines to 28 lines (57% reduction)
- **Created Functions**:
  - `_get_organization_context()` - session and org structure setup
  - `_print_scp_recommendations()` - console output formatting
- **Details**: See `conversation_history.md` for full documentation

### ✅ Part 3: Break Up get_subaccount_information()
- **Status**: Completed 2025-11-06
- **Files**: `headroom/analysis.py`
- **Impact**: Reduced function from 52 lines to 31 lines (40% reduction)
- **Created Functions**:
  - `_fetch_account_tags()` - AWS API call with error handling
  - `_determine_account_name()` - business logic for name selection
- **Details**: See `conversation_history.md` for full documentation

### ✅ Add boto3 Type Stubs for Organizations
- **Status**: Completed 2025-11-06
- **Files**: `requirements.txt`, `tox.ini`, `headroom/analysis.py`
- **Impact**: Replaced `Any` types with proper boto3 type hints
- **Benefits**: Type safety, IDE autocomplete, self-documenting code
- **Details**: See `conversation_history.md` for full documentation

### ✅ Part 4: Break Up _generate_terraform_content()
- **Status**: Completed 2025-11-06
- **Files**: `headroom/terraform/generate_org_info.py`, `tests/test_generate_terraform.py`
- **Impact**: Reduced main function from 118 lines to 28 lines (76% reduction)
- **Created Functions**:
  - `_generate_terraform_header()` - file header and root data sources
  - `_generate_ou_data_sources()` - data sources for top-level OUs
  - `_generate_locals_header()` - locals block opening with validation
  - `_generate_ou_locals()` - OU local variables with validations
  - `_generate_account_locals()` - account local variables with hierarchy traversal
- **Tests Added**: 19 new BDD-style unit tests
- **Benefits**: Single responsibility, better testability, easier maintenance
- **Details**: See `conversation_history.md` for full documentation

### ✅ Part 5: Refactor generate_scp_terraform()
- **Status**: Completed 2025-11-07
- **Files**: `headroom/terraform/generate_scps.py`, `tests/test_generate_scps.py`
- **Impact**: Reduced main function from 139 lines to 47 lines (66% reduction in main function)
- **Created Functions**:
  - `_build_scp_terraform_module()` - Reusable Terraform module builder
  - `_generate_account_scp_terraform()` - Account-level file generation
  - `_generate_ou_scp_terraform()` - OU-level file generation
  - `_generate_root_scp_terraform()` - Root-level file generation
- **Tests Added**: 16 new BDD-style unit tests
- **Benefits**: Eliminated code duplication, consistent pattern with generate_rcps.py, better testability
- **Details**: See `conversation_history.md` for full documentation

### ✅ Part 6: Add boto3-stubs for Remaining AWS Services
- **Status**: Completed 2025-11-07
- **Files**: `requirements.txt`, `tox.ini`, all AWS modules, check modules, test files, `main.py`
- **Impact**: Complete type safety across entire codebase, removed all boto3/botocore `# type: ignore` comments
- **Updated Dependencies**:
  - `boto3-stubs[ec2,iam,organizations,sts]>=1.35.0` in both requirements.txt and tox.ini
- **Type Hints Added**:
  - `EC2Client` type hints in `headroom/aws/ec2.py`
  - `IAMClient` type hints in `headroom/aws/iam.py`
  - `OrganizationsClient` type hints in `headroom/aws/organization.py`
- **Files Updated**: 11 files total (3 AWS modules, 3 check modules, 4 test files, 1 main file)
- **Benefits**: Full IDE autocomplete, catch AWS API misuse at type-check time, self-documenting code
- **Mypy Result**: Success - no issues found in 40 source files
- **Details**: See `conversation_history.md` for full documentation

### ✅ Part 7: Extract Shared Helpers from parse_scp_result_files() and parse_rcp_result_files()
- **Status**: Completed 2025-11-07
- **Files**: `headroom/parse_results.py`, `headroom/terraform/generate_rcps.py`, `tests/test_parse_results.py`, `tests/test_generate_rcps.py`
- **Impact**: Unified parsing logic, eliminated technical debt (filename parsing), reduced main functions by 52-54%
- **Shared Helpers Created**:
  - `_load_result_file_json()` - Shared JSON loading with error handling
  - `_extract_account_id_from_result()` - Unified account ID extraction (org hierarchy lookup)
- **SCP-Specific Helper**:
  - `_parse_single_scp_result_file()` - Parse single SCP result file
- **RCP-Specific Helper**:
  - `_parse_single_rcp_result_file()` - Parse single RCP result file with third-party data
- **Signature Change**: `parse_scp_result_files()` now requires `organization_hierarchy` parameter (breaking change)
- **Technical Debt Removed**: Eliminated fragile filename parsing (`name_id.json`) in favor of robust org hierarchy lookup
- **Main Functions Reduced**:
  - `parse_scp_result_files()`: 73 lines → 36 lines (51% reduction)
  - `parse_rcp_result_files()`: 65 lines → 30 lines (54% reduction)
- **Benefits**: Consistent strategy across both parsers, better testability, removes legacy workarounds
- **Mypy Result**: Success - no issues found, full type safety maintained
- **Details**: See `conversation_history.md` for full documentation

### ✅ Parts 6 & 7 Combined: Terraform Generation DRY Improvements
- **Status**: Completed 2025-11-07
- **Files**: `headroom/terraform/utils.py`, `headroom/terraform/generate_rcps.py`, `headroom/terraform/generate_scps.py`, `tests/test_generate_rcps.py`
- **Approach**: Combined items 6 and 7 for maximum efficiency and consistency
- **Impact**: Extracted shared utilities, refactored RCP generation, unified patterns across SCP and RCP modules
- **Shared Utility Created**:
  - `write_terraform_file()` in `utils.py` - Centralized file writing with logging
- **RCP Helpers Created**:
  - `_generate_account_rcp_terraform()` - Account-level RCP file generation
  - `_generate_ou_rcp_terraform()` - OU-level RCP file generation
  - `_generate_root_rcp_terraform()` - Root-level RCP file generation
- **SCP Updates**: Updated existing helpers to use shared `write_terraform_file()`
- **Main Function Reduction**:
  - `generate_rcp_terraform()`: 88 lines → 47 lines (47% reduction)
- **Code Elimination**: ~30 lines of duplicated file writing code across both modules
- **Tests Added**: 9 new BDD-style tests (4 test classes, 216 lines)
- **Test Coverage**: 100% maintained (292 tests passing)
- **Benefits**: DRY principle applied, pattern consistency, easy to add new policy types, single point of update for file writing
- **Mypy Result**: Success - no issues found in 40 source files
- **Details**: See `conversation_history.md` for full documentation

---

## Pending Refactorings

### Priority 1: High-Impact Refactorings

#### NONE - All Priority 1 items completed! 🎉

---

### Priority 2: Medium-Impact Refactorings

#### NONE - Items 4 and 5 completed! 🎉

---

### Priority 3: Nice-to-Have Refactorings

#### NONE - Items 6 and 7 completed! 🎉

The following sections remain for historical reference but are no longer needed:

<details>
<summary>Historical Item 6: Refactor generate_rcp_terraform() (COMPLETED)</summary>

#### 6. Refactor generate_rcp_terraform()
**Location**: `headroom/terraform/generate_rcps.py` (lines 399-486)

**Problem**: Repetitive file writing and filepath construction logic

**Current State**: Has `_build_rcp_terraform_module()` but still duplicates file writing

**Proposed Solution**:
```python
def _write_account_rcp_terraform(
    account_id: str,
    rec: RCPPlacementRecommendations,
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """Generate and write Terraform file for account-level RCP."""

def _write_ou_rcp_terraform(
    ou_id: str,
    rec: RCPPlacementRecommendations,
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """Generate and write Terraform file for OU-level RCP."""

def _write_root_rcp_terraform(
    rec: RCPPlacementRecommendations,
    output_path: Path
) -> None:
    """Generate and write Terraform file for root-level RCP."""
```

**Expected Impact**:
- Eliminate duplication in file writing
- Consistent with generate_scps.py pattern
- Easier to modify output logic

</details>

<details>
<summary>Historical Item 7: Extract Common Terraform Generation Patterns (COMPLETED)</summary>

#### 7. Consider Extracting Common Terraform Generation Patterns
**Location**: Both `generate_scps.py` and `generate_rcps.py`

**Observation**: Both files share patterns:
- Grouping recommendations by level (root/ou/account)
- Iterating over each level to generate files
- File path construction
- Terraform module formatting

**Proposed Solution**: Consider creating shared utilities in `terraform/utils.py`:
```python
def group_recommendations_by_level(
    recommendations: List[Union[SCPPlacementRecommendations, RCPPlacementRecommendations]]
) -> Dict[str, Any]:
    """Group recommendations by deployment level."""

def write_terraform_file(filepath: Path, content: str) -> None:
    """Write Terraform content to file with logging."""
```

**Expected Impact**:
- DRY principle applied across Terraform generators
- Centralized file writing with consistent error handling
- Easier to add new policy types in future

</details>

---

#### 8. Consider Type Aliases for Complex Types
**Location**: Various files with complex type hints

**Observation**: Some type hints are repeated and verbose:
- `Dict[str, Set[str]]` for account third-party mappings
- `Dict[str, List[SCPPlacementRecommendations]]` for grouped recommendations

**Proposed Solution**: Add type aliases to `types.py`:
```python
AccountThirdPartyMap = Dict[str, Set[str]]
GroupedSCPRecommendations = Dict[str, List[SCPPlacementRecommendations]]
GroupedRCPRecommendations = Dict[str, List[RCPPlacementRecommendations]]
```

**Expected Impact**:
- More readable type hints
- Single source of truth for complex types
- Easier to refactor type definitions

---

## How to Use This Document

1. **Prioritize**: Work through Priority 1 items first for highest impact
2. **Document**: When completing a refactoring, move it to the "Completed" section
3. **Update**: Add new refactoring ideas as they're discovered
4. **Reference**: Link to this document in code reviews when identifying refactoring opportunities

## Refactoring Principles

When implementing these refactorings, follow these principles:

1. **Single Responsibility**: Each function should do one thing well
2. **DRY (Don't Repeat Yourself)**: Extract common patterns
3. **Clear Naming**: Function names should describe what they do
4. **Type Safety**: Use proper type hints, not `Any`
5. **Test Coverage**: Maintain 100% test coverage
6. **Small Steps**: Make incremental changes with tests passing at each step

## Testing Checklist

After each refactoring:
- [ ] All tests pass (`tox`)
- [ ] 100% code coverage maintained
- [ ] No mypy errors
- [ ] All pre-commit checks pass
- [ ] Documentation updated (if needed)
- [ ] `conversation_history.md` updated with details
