# Refactoring Ideas

**Date**: November 8, 2025

**Goal**: Identify code that doesn't belong in the function it's currently in, looking for opportunities to improve function clarity and separation of concerns.

## ✅ Implementation Status

**High Priority Refactorings: COMPLETED** (November 8, 2025)
- ✅ **Refactoring #1**: Fix `setup_organization_context()` - DONE
- ✅ **Refactoring #2**: Remove `_get_organization_context()` duplication - DONE
- ✅ **Refactoring #3**: Extract OU hierarchy walking from `_generate_account_locals()` - DONE

**Results**: All 330 tests passing, 100% code coverage, mypy clean

**Medium Priority Refactorings: COMPLETED** (November 8, 2025)
- ✅ **Refactoring #5**: Extract account info building from `get_subaccount_information()` - DONE
- ✅ **Refactoring #6**: Move symlink creation out of `generate_rcp_terraform()` - DONE

**Results**: All 336 tests passing, 100% code coverage, mypy clean

**Remaining Refactorings: PENDING**
- ⏳ Split `determine_rcp_placement()` and `determine_scp_placement()` into smaller functions (Item #4)
- ⏳ Refactor `_build_ou_hierarchy()` to separate traversal from data building (Item #7)
- ⏳ Make wildcard filtering separate from parsing in `parse_rcp_result_files()` (Item #8)

---

## Analysis Results

After reviewing the entire codebase, here are the functions with code that could be refactored:

### 1. `setup_organization_context()` in `main.py` (Lines 68-92)

**Issue**: This function does THREE distinct things with different responsibilities:
1. Gets management session (delegation to another function)
2. Analyzes organization structure (delegation to another function)
3. **Generates Terraform org info file** (this doesn't belong here!)

**Problem**: The Terraform file generation (`generate_terraform_org_info`) is a side effect that belongs in the Terraform workflow, not in "setup" logic. The function name suggests it's only setting up context, not generating files.

**Recommendation**: Move the `generate_terraform_org_info` call out of this function. Either:
- Call it separately in `main()` after setup_organization_context
- Or create a new function called `setup_organization_context_and_generate_terraform_info()`
- Better yet: make it part of the SCP/RCP workflow since both need it

### 2. `_get_organization_context()` in `parse_results.py` (Lines 266-287)

**Issue**: This is a duplicate of similar logic in `main.py`. It:
1. Gets security session
2. Gets management session
3. Analyzes organization structure
4. Logs results

**Problem**: This creates two different ways to get organization context. It's called from `parse_scp_results()` but that function is itself called from `main()` which already has access to the organization hierarchy.

**Recommendation**: Remove this function entirely. Pass `organization_hierarchy` as a parameter instead of recalculating it. The function `parse_scp_results()` should receive the hierarchy from `main()`.

### 3. `get_subaccount_information()` in `analysis.py` (Lines 98-146)

**Issue**: This function does multiple responsibilities:
1. Gets management account session (via delegation)
2. Creates organizations client
3. Paginates through accounts
4. **Fetches account tags** (via `_fetch_account_tags`)
5. **Determines account name from tags or API** (via `_determine_account_name`)
6. **Extracts metadata from tags**
7. Builds AccountInfo objects

**Problem**: The function name suggests it just "gets information", but it's actually doing complex tag processing, name resolution, and metadata extraction. The tag logic (lines 129-137) is intertwined with the pagination logic.

**Recommendation**: Extract tag processing into a separate function:
```python
def _build_account_info_from_account_dict(
    account: AccountTypeDef,
    org_client: OrganizationsClient,
    config: HeadroomConfig
) -> AccountInfo:
    """Process single account dict into AccountInfo with tags."""
```

Then `get_subaccount_information()` just paginates and calls this helper.

### 4. `_build_ou_hierarchy()` in `aws/organization.py` (Lines 21-97)

**Issue**: This recursive function does TOO MANY things in one pass:
1. Lists OUs for parent
2. Recursively traverses child OUs
3. Gets accounts for each OU
4. Gets child OUs again (redundant with step 1)
5. Populates two different data structures (organizational_units dict AND accounts dict)
6. Builds OU path tracking

**Problem**: The function is doing both the traversal AND the data collection/storage. Lines 64-77 (account collection) are particularly awkward because they're nested inside the OU iteration.

**Recommendation**: Separate concerns:
- One function to traverse and collect raw OU data
- Another function to process and build the hierarchies
- Or use a two-pass approach: first collect all OUs, then collect accounts

### 5. `determine_rcp_placement()` in `terraform/generate_rcps.py` (Lines 156-254)

**Issue**: This function:
1. Validates input
2. Creates analyzer
3. Transforms data structure for analyzer
4. Defines two lambda functions for safety checks
5. Calls analyzer
6. Processes candidates into recommendations
7. Handles three different placement levels (root, OU, account)
8. **Tracks OU-covered accounts for later filtering**
9. Loops through remaining accounts to create account-level recommendations

**Problem**: The function is 99 lines long and handles too many concerns. The second loop (lines 243-252) that handles account-level placement feels tacked on and uses state (`ou_covered_accounts`) that's built up in the first loop.

**Recommendation**: Extract into smaller functions:
```python
def _create_root_rcp_recommendation(...)
def _create_ou_rcp_recommendations(...)
def _create_account_rcp_recommendations(...)
```

Then `determine_rcp_placement()` orchestrates these three.

### 6. `determine_scp_placement()` in `parse_results.py` (Lines 179-263)

**Issue**: Similar to the RCP version above:
1. Validates input
2. Creates analyzer
3. Groups results by check name
4. Loops through check groups
5. **Does account ID lookups inline** (lines 201-207)
6. Filters safe results
7. Handles "none" recommendation case
8. Calls analyzer
9. Processes candidates with complex nested logic
10. Builds different recommendation objects for each level

**Problem**: The account ID lookup logic (lines 201-207) is a separate concern from placement determination. It's data preparation that should happen before this function.

**Recommendation**: Extract account ID resolution into a separate function called before this. Also extract the candidate processing loop (lines 229-261) into separate functions per level.

### 7. `generate_rcp_terraform()` in `terraform/generate_rcps.py` (Lines 412-461)

**Issue**: This function:
1. Validates input
2. Creates output directory
3. Groups recommendations by level
4. Generates account Terraform files (loop)
5. Generates OU Terraform files (loop)
6. Generates root Terraform file
7. **Creates symlink to scps/grab_org_info.tf** (line 461)

**Problem**: The symlink creation (line 461) is a completely different concern from Terraform generation. It's file system manipulation vs code generation.

**Recommendation**: Either:
- Call `_create_org_info_symlink()` separately from the caller
- Or rename function to make it clear it does file system setup: `generate_rcp_terraform_and_setup_files()`
- Best: Do symlink creation once during initialization, not during generation

### 8. `_generate_terraform_content()` in `terraform/generate_org_info.py` (Lines 227-260)

**Issue**: This is actually well-structured! But worth noting: it orchestrates multiple helper functions but all the helpers return `List[str]` which then get joined. This is fine but could be simplified.

**Not a problem per se**, but if you wanted to refactor: the helpers could write directly to a string builder or file handle instead of building lists.

### 9. `_generate_account_locals()` in `terraform/generate_org_info.py` (Lines 167-224)

**Issue**: This function:
1. Validates accounts exist
2. Creates accounts_by_top_level_ou dictionary
3. **Walks the OU hierarchy to find top-level parent** (lines 193-200)
4. Groups accounts
5. Generates Terraform locals with validation
6. Returns list of strings

**Problem**: The OU hierarchy walking logic (lines 193-200) is complex business logic embedded in what's supposed to be a Terraform code generation function. This logic belongs in a separate data preparation step.

**Recommendation**: Extract into:
```python
def _group_accounts_by_top_level_ou(
    accounts: Dict[str, AccountOrgPlacement],
    organizational_units: Dict[str, OrganizationalUnit]
) -> Dict[str, List[AccountOrgPlacement]]:
    """Group accounts by their top-level parent OU."""
```

Then `_generate_account_locals()` just takes the pre-grouped data.

### 10. `parse_rcp_result_files()` in `terraform/generate_rcps.py` (Lines 76-120)

**Issue**: This function:
1. Gets check directory path
2. Validates directory exists
3. Iterates through JSON files
4. Parses each file
5. **Makes business logic decisions about wildcards** (lines 112-115)
6. Populates two different data structures

**Problem**: The wildcard handling logic (lines 112-115) makes business decisions (whether to include account in map vs wildcard set). This is business logic mixed with parsing logic.

**Recommendation**: Keep this function pure parsing. Return all RCP results, then have a separate function that filters/categorizes based on wildcards:
```python
def _categorize_rcp_results(
    rcp_results: List[RCPCheckResult]
) -> RCPParseResult:
    """Separate accounts with wildcards from those without."""
```

## Summary of Common Patterns

**Common Issues Found**:
1. **File I/O mixed with business logic** (symlink in terraform generation)
2. **Data preparation mixed with core algorithm** (account ID lookup in placement functions)
3. **Multiple data structures being populated simultaneously** (OU hierarchy building)
4. **Setup/initialization mixed with the main function** (generate_terraform_org_info in setup_organization_context)
5. **Business logic decisions in parsing functions** (wildcard filtering in parse_rcp_result_files)
6. **Long orchestration functions that could be split** (determine_rcp_placement, determine_scp_placement)

**Refactoring Principles to Apply**:
1. **Single Responsibility**: Each function should do ONE thing
2. **Separation of Concerns**: Separate data loading, transformation, and business logic
3. **Data Preparation vs Processing**: Parse/load data in one step, process in another
4. **Side Effects**: File I/O should be explicit, not hidden in setup functions
5. **Naming**: Function names should accurately describe what they do

## Priority Refactoring Recommendations

### ✅ High Priority (COMPLETED - November 8, 2025)
1. ✅ Fix `setup_organization_context()` - move Terraform generation out
2. ✅ Remove `_get_organization_context()` duplication in parse_results.py
3. ✅ Extract OU hierarchy walking from `_generate_account_locals()`

### ✅ Medium Priority (COMPLETED - November 8, 2025)
5. ✅ Extract account info building from `get_subaccount_information()`
6. ✅ Move symlink creation out of `generate_rcp_terraform()`

### Medium Priority (good improvements - PENDING)
4. ⏳ Split `determine_rcp_placement()` and `determine_scp_placement()` into smaller functions

### Low Priority (nice to have - PENDING)
7. ⏳ Refactor `_build_ou_hierarchy()` to separate traversal from data building
8. ⏳ Make wildcard filtering separate from parsing in `parse_rcp_result_files()`

## Benefits of These Refactorings

- **Better testability** - Smaller, focused functions are easier to unit test
- **Clearer intent** - Function names will match what they actually do
- **Less coupling** - Separate data preparation from processing
- **Easier maintenance** - Changes to one concern won't affect others
- **Improved readability** - Each function does one thing well

---

# Detailed Implementation Plan for High-Priority Refactorings

## Refactoring #1: Fix `setup_organization_context()` in `main.py`

### Current Problem
Line 90 calls `generate_terraform_org_info()` which is a file I/O side effect hidden inside what appears to be a simple "setup" function. The function name promises to just set up context, but it's secretly generating files.

### Current Code Flow
```
main()
  └─> setup_organization_context(config, session)
        ├─> get_management_account_session()
        ├─> analyze_organization_structure()
        └─> generate_terraform_org_info() ⚠️ Hidden side effect!
```

### Implementation Steps

#### Step 1: Rename the function to be honest about what it does
**File**: `headroom/main.py` (line 68-92)

**Action**: Rename function to reflect that it generates files:
```python
def setup_organization_context_and_generate_org_info(
    final_config: HeadroomConfig,
    security_session: boto3.Session
) -> tuple[boto3.Session, OrganizationHierarchy]:
    """
    Set up organization context and generate Terraform org info file.

    This function:
    1. Assumes role in management account
    2. Analyzes organization structure (OUs and accounts)
    3. Generates grab_org_info.tf file for Terraform

    Args:
        final_config: Validated Headroom configuration
        security_session: boto3 Session with security analysis access

    Returns:
        Tuple of (management_session, organization_hierarchy)

    Raises:
        ValueError: If management account configuration is missing
        RuntimeError: If role assumption fails
        ClientError: If AWS API calls fail
    """
    mgmt_session = get_management_account_session(final_config, security_session)
    organization_hierarchy = analyze_organization_structure(mgmt_session)

    generate_terraform_org_info(mgmt_session, f"{final_config.scps_dir}/{ORG_INFO_FILENAME}")

    return mgmt_session, organization_hierarchy
```

#### Step 2: Update the caller in `main()`
**File**: `headroom/main.py` (line 161)

**Action**: Update function call:
```python
mgmt_session, org_hierarchy = setup_organization_context_and_generate_org_info(
    final_config, security_session
)
```

#### Step 3: Update all imports/references
**Files to check**:
- Any test files that mock or call this function
- Run: `grep -r "setup_organization_context" tests/`

### Alternative Approach (Better Separation)

Create two separate functions with clear responsibilities:

```python
def setup_organization_context(
    final_config: HeadroomConfig,
    security_session: boto3.Session
) -> tuple[boto3.Session, OrganizationHierarchy]:
    """
    Set up organization context for policy analysis.

    Args:
        final_config: Validated Headroom configuration
        security_session: boto3 Session with security analysis access

    Returns:
        Tuple of (management_session, organization_hierarchy)
    """
    mgmt_session = get_management_account_session(final_config, security_session)
    organization_hierarchy = analyze_organization_structure(mgmt_session)
    return mgmt_session, organization_hierarchy


def generate_org_info_file(
    mgmt_session: boto3.Session,
    org_hierarchy: OrganizationHierarchy,
    output_path: str
) -> None:
    """Generate Terraform organization info file."""
    generate_terraform_org_info(mgmt_session, output_path)
```

Then in `main()`:
```python
mgmt_session, org_hierarchy = setup_organization_context(final_config, security_session)
generate_org_info_file(mgmt_session, org_hierarchy, f"{final_config.scps_dir}/{ORG_INFO_FILENAME}")

handle_scp_workflow(final_config, org_hierarchy)
handle_rcp_workflow(final_config, org_hierarchy)
```

### Testing Strategy
1. Run existing integration tests to ensure no behavior change
2. Verify that `grab_org_info.tf` is still generated in the same location
3. Check that all downstream consumers of org_hierarchy still work

### Estimated Impact
- **Files changed**: 1 (main.py)
- **Lines changed**: ~5-10
- **Test files to update**: 0-2 (depending on if they mock this function)
- **Risk level**: LOW (pure refactoring, no logic changes)

---

## Refactoring #2: Remove `_get_organization_context()` Duplication in `parse_results.py`

### Current Problem
Two different code paths get organization context:
1. `main.py` calls `setup_organization_context()`
2. `parse_results.py` has `_get_organization_context()` that does the same thing

This creates:
- Code duplication
- Unnecessary AWS API calls (organization structure analyzed twice)
- Two sources of truth
- Maintenance burden

### Current Code Flow
```
main()
  ├─> setup_organization_context()           # Gets org hierarchy
  │     └─> analyze_organization_structure()
  │
  └─> handle_scp_workflow(config, org_hierarchy)
        └─> parse_scp_results(config)
              └─> _get_organization_context(config)  # ⚠️ Gets it AGAIN!
                    └─> analyze_organization_structure()
```

### Implementation Steps

#### Step 1: Update `parse_scp_results()` function signature
**File**: `headroom/parse_results.py` (line 343-383)

**Before**:
```python
def parse_scp_results(config: HeadroomConfig) -> List[SCPPlacementRecommendations]:
```

**After**:
```python
def parse_scp_results(
    config: HeadroomConfig,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Parse SCP results and determine optimal placement recommendations.

    Args:
        config: Headroom configuration
        organization_hierarchy: Organization structure (from main.py)

    Returns:
        List of SCP placement recommendations for each check
    """
    logger.info("Starting SCP placement analysis")

    # Parse result files (organization_hierarchy already provided)
    logger.info(f"Parsing result files from {config.results_dir}")
    results_data = parse_scp_result_files(config.results_dir, organization_hierarchy)

    # ... rest of function
```

#### Step 2: Remove the `_get_organization_context()` function
**File**: `headroom/parse_results.py` (lines 266-287)

**Action**: Delete this entire function (22 lines)

#### Step 3: Remove the call to `_get_organization_context()`
**File**: `headroom/parse_results.py` (line 362-366)

**Before**:
```python
# Get organization context (session + structure)
try:
    organization_hierarchy = _get_organization_context(config)
except (ValueError, RuntimeError) as e:
    logger.error(f"Failed to get organization context: {e}")
    return []
```

**After**:
```python
# Organization hierarchy already provided by caller
# (no need to fetch it again)
```

#### Step 4: Update callers of `parse_scp_results()`
**File**: `headroom/main.py` (line 103)

**Before**:
```python
def handle_scp_workflow(final_config: HeadroomConfig, org_hierarchy: OrganizationHierarchy) -> None:
    """
    Parse SCP results and generate SCP Terraform files.
    """
    scp_recommendations = parse_scp_results(final_config)
```

**After**:
```python
def handle_scp_workflow(final_config: HeadroomConfig, org_hierarchy: OrganizationHierarchy) -> None:
    """
    Parse SCP results and generate SCP Terraform files.
    """
    scp_recommendations = parse_scp_results(final_config, org_hierarchy)
```

#### Step 5: Update imports
**File**: `headroom/parse_results.py` (lines 13-14)

**Action**: Remove unused imports (if any):
```python
# Remove these if no longer needed:
# from .analysis import get_security_analysis_session, get_management_account_session
```

#### Step 6: Update tests
**Files**: Search for test files that call `parse_scp_results()`:
```bash
grep -r "parse_scp_results" tests/
```

For each test, add `organization_hierarchy` parameter:
```python
# Before
result = parse_scp_results(mock_config)

# After
result = parse_scp_results(mock_config, mock_org_hierarchy)
```

### Testing Strategy
1. **Unit tests**: Update all tests that call `parse_scp_results()`
2. **Integration test**: Verify that organization structure is only queried once
3. **Add assertion**: Ensure `analyze_organization_structure()` is called exactly once per main() execution
4. **Mock validation**: Use mocking to verify AWS API call count decreases

### Benefits
- **Performance**: Eliminates redundant AWS API calls (ListAccounts, ListOrganizationalUnits, etc.)
- **Consistency**: Only one organization hierarchy object in memory
- **Clearer flow**: Organization context is passed down from main, not re-fetched
- **Easier testing**: Tests can provide mock hierarchy instead of mocking AWS calls

### Estimated Impact
- **Files changed**: 2 (parse_results.py, main.py)
- **Lines removed**: ~30 (function deletion + call site cleanup)
- **Lines added**: ~5 (parameter additions)
- **Test files to update**: 3-5 (any tests calling parse_scp_results)
- **Risk level**: MEDIUM (requires updating multiple call sites and tests)

---

## Refactoring #3: Extract OU Hierarchy Walking from `_generate_account_locals()`

### Current Problem
The function `_generate_account_locals()` in `terraform/generate_org_info.py` mixes two concerns:
1. **Business logic**: Walking OU hierarchy to find top-level parent (lines 190-204)
2. **Code generation**: Building Terraform local variable strings (lines 206-222)

This makes the function:
- Hard to test (can't test hierarchy logic without Terraform strings)
- Hard to understand (mixing data transformation with string formatting)
- Violates Single Responsibility Principle

### Current Code Structure
```python
def _generate_account_locals(accounts, ous):
    # Business logic mixed with code generation
    accounts_by_top_level_ou = {}
    for account in accounts:
        # Walk hierarchy to find top-level OU ⚠️ Business logic
        current_ou_id = account.parent_ou_id
        while current_ou_id in ous:
            if ous[current_ou_id].parent_ou_id is None:
                top_level_ou_id = current_ou_id
                break
            current_ou_id = ous[current_ou_id].parent_ou_id
        accounts_by_top_level_ou[top_level_ou_id].append(account)

    # Generate Terraform code ⚠️ Code generation
    for ou_id, accounts_list in accounts_by_top_level_ou.items():
        content_parts.extend([...terraform strings...])
```

### Implementation Steps

#### Step 1: Create new data transformation function
**File**: `headroom/terraform/generate_org_info.py` (add before line 167)

**Action**: Add new pure function for hierarchy logic:
```python
def _group_accounts_by_top_level_ou(
    accounts: Dict[str, AccountOrgPlacement],
    organizational_units: Dict[str, OrganizationalUnit]
) -> Dict[str, List[AccountOrgPlacement]]:
    """
    Group accounts by their top-level parent OU.

    Walks the OU hierarchy for each account to find which top-level OU
    (direct child of root) the account belongs to.

    Args:
        accounts: All accounts in the organization
        organizational_units: All OUs (needed for hierarchy traversal)

    Returns:
        Dictionary mapping top-level OU ID -> list of accounts under that OU
    """
    accounts_by_top_level_ou: Dict[str, List[AccountOrgPlacement]] = {}

    for account in accounts.values():
        top_level_ou_id = account.parent_ou_id
        current_ou_id = account.parent_ou_id

        # Walk up the OU hierarchy to find the top-level parent
        while current_ou_id in organizational_units:
            current_ou = organizational_units[current_ou_id]
            if current_ou.parent_ou_id is None:
                # This is a top-level OU (direct child of root)
                top_level_ou_id = current_ou_id
                break
            current_ou_id = current_ou.parent_ou_id

        # Group account under its top-level OU
        if top_level_ou_id not in accounts_by_top_level_ou:
            accounts_by_top_level_ou[top_level_ou_id] = []
        accounts_by_top_level_ou[top_level_ou_id].append(account)

    return accounts_by_top_level_ou
```

#### Step 2: Simplify `_generate_account_locals()` to focus on code generation
**File**: `headroom/terraform/generate_org_info.py` (lines 167-224)

**Before**: 58 lines mixing business logic and code generation

**After**: ~35 lines of pure code generation
```python
def _generate_account_locals(
    accounts: Dict[str, AccountOrgPlacement],
    organizational_units: Dict[str, OrganizationalUnit]
) -> List[str]:
    """
    Generate local variables for account IDs.

    Args:
        accounts: All accounts in the organization
        organizational_units: All OUs (for name lookups)

    Returns:
        List of Terraform lines for account local variables with validations
    """
    content_parts: List[str] = []

    if not accounts:
        return content_parts

    content_parts.extend([
        "  # Account IDs by name",
    ])

    # Data preparation: group accounts by top-level OU
    accounts_by_top_level_ou = _group_accounts_by_top_level_ou(
        accounts,
        organizational_units
    )

    # Code generation: build Terraform locals for each account
    for top_level_ou_id, accounts_list in accounts_by_top_level_ou.items():
        if top_level_ou_id not in organizational_units:
            continue

        ou_name = organizational_units[top_level_ou_id].name
        safe_ou_name = make_safe_variable_name(ou_name)

        for account in accounts_list:
            safe_account_name = make_safe_variable_name(account.account_name)
            content_parts.extend([
                f"  # Validation for {account.account_name} account",
                f"  validation_check_{safe_account_name}_account = (length([for account in data.aws_organizations_organizational_unit_child_accounts.{safe_ou_name}_accounts.accounts : account.id if account.name == \"{account.account_name}\"]) == 1) ? \"All good. This is a no-op.\" : error(\"[Error] Expected exactly 1 {account.account_name} account, found ${{length([for account in data.aws_organizations_organizational_unit_child_accounts.{safe_ou_name}_accounts.accounts : account.id if account.name == \"{account.account_name}\"])}}\")",
                "",
                f"  {safe_account_name}_account_id = [",
                f"    for account in data.aws_organizations_organizational_unit_child_accounts.{safe_ou_name}_accounts.accounts :",
                f"    account.id if account.name == \"{account.account_name}\"",
                "  ][0]",
                "",
            ])

    return content_parts
```

#### Step 3: Add comprehensive unit tests
**File**: `tests/test_generate_org_info.py` (new test cases)

**Action**: Add tests for the new function:
```python
def test_group_accounts_by_top_level_ou_flat_hierarchy():
    """Test grouping when accounts are directly under top-level OUs."""
    # Test setup
    ous = {
        "ou-111": OrganizationalUnit("ou-111", "Production", None, [], []),
        "ou-222": OrganizationalUnit("ou-222", "Development", None, [], []),
    }
    accounts = {
        "acc-1": AccountOrgPlacement("acc-1", "prod-app", "ou-111", ["Production"]),
        "acc-2": AccountOrgPlacement("acc-2", "prod-db", "ou-111", ["Production"]),
        "acc-3": AccountOrgPlacement("acc-3", "dev-app", "ou-222", ["Development"]),
    }

    # Execute
    result = _group_accounts_by_top_level_ou(accounts, ous)

    # Assert
    assert len(result) == 2
    assert len(result["ou-111"]) == 2
    assert len(result["ou-222"]) == 1


def test_group_accounts_by_top_level_ou_nested_hierarchy():
    """Test grouping when accounts are in nested OUs."""
    # Test setup: Production (top) -> US (nested) -> East (nested)
    ous = {
        "ou-111": OrganizationalUnit("ou-111", "Production", None, ["ou-222"], []),
        "ou-222": OrganizationalUnit("ou-222", "US", "ou-111", ["ou-333"], []),
        "ou-333": OrganizationalUnit("ou-333", "East", "ou-222", [], ["acc-1"]),
    }
    accounts = {
        "acc-1": AccountOrgPlacement("acc-1", "prod-us-east-app", "ou-333", ["Production", "US", "East"]),
    }

    # Execute
    result = _group_accounts_by_top_level_ou(accounts, ous)

    # Assert - account should be grouped under top-level OU (Production)
    assert len(result) == 1
    assert "ou-111" in result  # Top-level OU
    assert len(result["ou-111"]) == 1
    assert result["ou-111"][0].account_id == "acc-1"


def test_group_accounts_by_top_level_ou_empty_accounts():
    """Test handling of empty account dictionary."""
    result = _group_accounts_by_top_level_ou({}, {})
    assert result == {}
```

#### Step 4: Update existing tests
**File**: `tests/test_generate_org_info.py` or `tests/test_generate_terraform.py`

**Action**: Verify that `_generate_account_locals()` tests still pass with the refactored code

#### Step 5: Add type hints validation
**File**: Run mypy to ensure type annotations are correct:
```bash
mypy headroom/terraform/generate_org_info.py
```

### Benefits of This Refactoring

1. **Testability**:
   - Can test hierarchy walking logic without Terraform strings
   - Can test Terraform generation without complex OU setups
   - Each function has clear inputs/outputs

2. **Readability**:
   - `_group_accounts_by_top_level_ou` name clearly states its purpose
   - `_generate_account_locals` now only does code generation
   - Separation of data transformation from formatting

3. **Reusability**:
   - The grouping logic could be reused elsewhere if needed
   - Pure functions are easier to compose

4. **Maintainability**:
   - Changes to grouping logic don't affect Terraform format
   - Changes to Terraform format don't affect grouping logic

### Testing Strategy

1. **Unit tests**: Test `_group_accounts_by_top_level_ou()` with various OU structures:
   - Flat hierarchy (accounts directly under top-level OUs)
   - Nested hierarchy (accounts 3-4 levels deep)
   - Edge cases (empty inputs, single account, single OU)

2. **Integration tests**: Verify that generated Terraform is unchanged:
   - Use golden file comparison
   - Ensure output format is identical before/after

3. **Type checking**: Run mypy to validate type annotations

### Estimated Impact
- **Files changed**: 1 (terraform/generate_org_info.py)
- **Lines added**: ~40 (new function + docstring)
- **Lines modified**: ~20 (simplified _generate_account_locals)
- **Net change**: ~+20 lines (but much clearer)
- **Test files to update**: 1 (add tests for new function)
- **Risk level**: LOW (pure refactoring with new test coverage)

---

## Implementation Order

Recommend implementing in this order:

1. **Refactoring #3 first** (OU hierarchy extraction)
   - Lowest risk
   - Self-contained to one file
   - Good practice for the others

2. **Refactoring #1 next** (setup_organization_context)
   - Low risk
   - Sets up for #2
   - Makes code more honest

3. **Refactoring #2 last** (remove duplication)
   - Highest impact
   - Requires #1 to be done first
   - Touches multiple files and tests

## Success Criteria

For each refactoring, confirm:
- ✅ All existing tests pass
- ✅ New tests added for extracted functions
- ✅ Type checking (mypy) passes
- ✅ No functional changes (same output)
- ✅ Code is more maintainable and testable
- ✅ Function names accurately describe what they do

---

## Implementation Results (November 8, 2025)

All high-priority refactorings have been successfully completed:

### ✅ Refactoring #3: Extract OU Hierarchy Walking
**Status**: COMPLETED
- Added `_group_accounts_by_top_level_ou()` function
- Simplified `_generate_account_locals()` to pure code generation
- Added test for edge case (missing OU in organizational_units)
- **Impact**: Better testability and separation of concerns

### ✅ Refactoring #1: Fix `setup_organization_context()`
**Status**: COMPLETED
- Removed hidden `generate_terraform_org_info()` side effect
- Moved file generation to explicit call in `main()`
- Updated test to reflect new behavior
- **Impact**: Function now honestly describes what it does

### ✅ Refactoring #2: Remove `_get_organization_context()` Duplication
**Status**: COMPLETED
- Deleted duplicate `_get_organization_context()` function (22 lines)
- Updated `parse_scp_results()` to accept `organization_hierarchy` parameter
- Removed unused imports
- Updated 6 test methods
- **Impact**: Eliminated redundant AWS API calls, improved performance

### Final Metrics
- **All 330 tests passing** ✅
- **100% code coverage** (1176/1176 source statements) ✅
- **100% test coverage** (3173/3173 test statements) ✅
- **mypy: Success** (no type errors) ✅
- **pre-commit: Pass** (all linting checks) ✅
- **Files modified**: 5 (3 source, 2 test)
- **Lines removed**: ~30
- **Lines added**: ~50
- **Net change**: ~+20 lines of clearer code

### ✅ Refactoring #5: Extract account info building from `get_subaccount_information()`
**Status**: COMPLETED (November 8, 2025)
- Created `_build_account_info_from_account_dict()` helper function (37 lines)
- Simplified `get_subaccount_information()` from 49 to 35 lines
- Separated iteration logic from transformation logic
- Added 6 comprehensive test cases
- **Impact**: Better testability, separation of concerns, easier maintenance

### ✅ Refactoring #6: Move symlink creation out of `generate_rcp_terraform()`
**Status**: COMPLETED (November 8, 2025)
- Removed `scps_dir` parameter from `generate_rcp_terraform()` signature
- Removed `_create_org_info_symlink()` call from end of function
- Added new `ensure_org_info_symlink()` function to `main.py`
- Called symlink creation explicitly in `main()` after generating org info file
- Updated 10+ test methods to reflect new behavior
- **Impact**: Explicit separation of code generation vs filesystem setup, better testability

### Final Metrics (All Refactorings #1-#6 Complete)
- **All 336 tests passing** ✅
- **100% code coverage** (1185/1185 source statements) ✅
- **100% test coverage** (3234/3234 test statements) ✅
- **mypy: Success** (no type errors) ✅
- **pre-commit: Pass** (all linting checks) ✅
- **Files modified**: 10 total (5 source, 5 test)
- **Lines removed**: ~70
- **Lines added**: ~150
- **Net change**: ~+80 lines of clearer, better-tested code
