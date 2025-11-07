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

---

## Pending Refactorings

### Priority 1: High-Impact Refactorings

#### 1. Refactor generate_scp_terraform() [generate_scps.py]
**Location**: `headroom/terraform/generate_scps.py` (lines 18-157)

**Problem**: 139-line function mixing:
1. Recommendation grouping logic (lines 37-53)
2. Account-level Terraform generation (lines 56-89)
3. OU-level Terraform generation (lines 92-125)
4. Root-level Terraform generation (lines 128-157)

**Current Issue**: Repetitive code for building Terraform modules

**Proposed Solution**: Extract functions similar to generate_rcps.py pattern:
```python
def _build_scp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[SCPPlacementRecommendations],
    comment: str
) -> str:
    """Build Terraform module call for SCP deployment."""
    
def _generate_account_scp_terraform(
    account_id: str,
    account_recs: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """Generate Terraform file for account-level SCPs."""
    
def _generate_ou_scp_terraform(
    ou_id: str,
    ou_recs: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """Generate Terraform file for OU-level SCPs."""
    
def _generate_root_scp_terraform(
    root_recommendations: List[SCPPlacementRecommendations],
    output_path: Path
) -> None:
    """Generate Terraform file for root-level SCPs."""
```

**Expected Impact**:
- Eliminate code duplication
- Main function becomes simple orchestrator
- Easier to modify Terraform output format
- Consistent pattern with generate_rcps.py

---

#### 2. Add boto3-stubs for Remaining AWS Services
**Location**: Multiple files across codebase

**Problem**: Still using `# type: ignore` comments for boto3 imports in:
- `headroom/aws/ec2.py` - EC2 client
- `headroom/aws/iam.py` - IAM client
- `headroom/terraform/generate_org_info.py` - boto3.Session
- Various test files

**Proposed Solution**:
1. Add to `requirements.txt` and `tox.ini`:
   ```
   boto3-stubs[ec2,iam,sts]>=1.35.0
   ```

2. Update imports in affected files:
   ```python
   # Instead of:
   import boto3  # type: ignore
   
   # Use:
   import boto3
   from mypy_boto3_ec2.client import EC2Client
   from mypy_boto3_iam.client import IAMClient
   from mypy_boto3_sts.client import STSClient
   ```

3. Update function signatures:
   ```python
   # ec2.py
   def get_imds_v1_ec2_analysis(session: boto3.Session) -> List[DenyImdsV1Ec2]:
       ec2_client: EC2Client = session.client('ec2')
   
   # iam.py
   def analyze_iam_roles_trust_policies(
       session: boto3.Session,
       org_account_ids: Set[str]
   ) -> List[TrustPolicyAnalysis]:
       iam_client: IAMClient = session.client("iam")
   ```

**Expected Impact**:
- Complete type safety across entire codebase
- Full IDE autocomplete for all AWS service methods
- Remove all `# type: ignore` comments for boto3
- Catch AWS API misuse at type-check time instead of runtime

**Files to Update**:
- `headroom/aws/ec2.py`
- `headroom/aws/iam.py`
- `headroom/aws/organization.py` (if not already done)
- `headroom/terraform/generate_org_info.py`
- `headroom/checks/scps/deny_imds_v1_ec2.py`
- `headroom/checks/rcps/check_third_party_assumerole.py`
- `tests/test_aws_ec2.py`
- `tests/test_aws_iam.py`
- Other files with `# type: ignore` on boto3 imports

---

### Priority 2: Medium-Impact Refactorings

#### 4. Extract Helpers from parse_scp_result_files()
**Location**: `headroom/parse_results.py` (lines 30-102)

**Problem**: Mixes file I/O with parsing logic:
1. Directory traversal and file finding (lines 43-70)
2. JSON parsing (lines 72-73)
3. Account ID extraction with fallback logic (lines 78-86)
4. CheckResult object creation (lines 88-97)

**Proposed Solution**:
```python
def _extract_account_id_from_result(summary: Dict[str, Any], filename: str) -> str:
    """Extract account ID from result summary or filename."""
    
def _parse_single_result_file(result_file: Path, check_name: str) -> CheckResult:
    """Parse a single result JSON file into CheckResult object."""
```

**Expected Impact**:
- Clearer separation of concerns
- Easier to test parsing logic independently
- Reusable components

---

#### 5. Extract Helpers from parse_rcp_result_files()
**Location**: `headroom/terraform/generate_rcps.py` (lines 27-91)

**Problem**: Same as #4 - mixes file I/O with business logic

**Proposed Solution**:
```python
def _parse_single_rcp_result_file(
    result_file: Path,
    organization_hierarchy: OrganizationHierarchy
) -> Tuple[str, Set[str], bool]:
    """
    Parse single RCP result file.
    
    Returns:
        Tuple of (account_id, third_party_accounts, has_wildcards)
    """
```

**Expected Impact**:
- Consistent pattern with parse_scp_result_files()
- Better testability
- Clearer error handling

---

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

---

### Priority 3: Nice-to-Have Refactorings

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

