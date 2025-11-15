# Refactoring Plan - Headroom Codebase

**Based On:** Clean Code Analysis (November 15, 2025)
**Philosophy:** Incremental improvements, test after each step

---

## Phase 3: Break Up Large Functions

### Step 3.1: Refactor `determine_scp_placement()`
**Time:** 3 hours
**Risk:** Medium-High
**Files to modify:** `headroom/parse_results.py`

**Create helper functions:**
```python
def _group_results_by_check_name(
    results_data: List[SCPCheckResult]
) -> Dict[str, List[SCPCheckResult]]:
    """Group check results by check name."""
    check_groups: Dict[str, List[SCPCheckResult]] = {}
    for result in results_data:
        if result.check_name not in check_groups:
            check_groups[result.check_name] = []
        check_groups[result.check_name].append(result)
    return check_groups

def _ensure_account_ids_present(
    check_results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> None:
    """Ensure all check results have account IDs populated."""
    for result in check_results:
        if not result.account_id:
            result.account_id = lookup_account_id_by_name(
                result.account_name,
                organization_hierarchy,
                "SCP check result"
            )

def _get_safe_results(
    check_results: List[SCPCheckResult]
) -> List[SCPCheckResult]:
    """Filter results to only those with zero violations."""
    return [r for r in check_results if r.violations == ZERO_VIOLATIONS]

def _create_no_deployment_recommendation(
    check_name: str
) -> SCPPlacementRecommendations:
    """Create recommendation for check that cannot be deployed."""
    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level=PlacementLevel.NONE,
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=0.0,
        reasoning="No accounts have zero violations - SCP deployment would break existing violations"
    )

def _build_iam_user_arns_for_recommendation(
    check_name: str,
    check_results: List[SCPCheckResult],
    affected_accounts: List[str]
) -> Optional[List[str]]:
    """Build list of allowed IAM user ARNs for deny_iam_user_creation check."""
    if check_name != "deny_iam_user_creation":
        return None

    iam_user_arns_set = set()
    for result in check_results:
        if result.account_id in affected_accounts and result.iam_user_arns:
            iam_user_arns_set.update(result.iam_user_arns)

    return sorted(list(iam_user_arns_set)) if iam_user_arns_set else []

def _build_root_recommendation(
    check_name: str,
    candidate: PlacementCandidate,
    check_results: List[SCPCheckResult]
) -> SCPPlacementRecommendations:
    """Build root-level placement recommendation."""
    allowed_iam_user_arns = _build_iam_user_arns_for_recommendation(
        check_name,
        check_results,
        candidate.affected_accounts
    )

    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level=PlacementLevel.ROOT,
        target_ou_id=None,
        affected_accounts=candidate.affected_accounts,
        compliance_percentage=FULL_COMPLIANCE_PERCENTAGE,
        reasoning="All accounts in organization have zero violations - safe to deploy at root level",
        allowed_iam_user_arns=allowed_iam_user_arns
    )

def _build_ou_recommendation(
    check_name: str,
    candidate: PlacementCandidate,
    check_results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> SCPPlacementRecommendations:
    """Build OU-level placement recommendation."""
    ou_name = organization_hierarchy.organizational_units.get(
        candidate.target_id,
        OrganizationalUnit("", "", None, [], [])
    ).name

    allowed_iam_user_arns = _build_iam_user_arns_for_recommendation(
        check_name,
        check_results,
        candidate.affected_accounts
    )

    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level=PlacementLevel.OU,
        target_ou_id=candidate.target_id,
        affected_accounts=candidate.affected_accounts,
        compliance_percentage=FULL_COMPLIANCE_PERCENTAGE,
        reasoning=f"All accounts in OU '{ou_name}' have zero violations - safe to deploy at OU level",
        allowed_iam_user_arns=allowed_iam_user_arns
    )

def _build_account_recommendation(
    check_name: str,
    safe_check_results: List[SCPCheckResult],
    total_results: int
) -> SCPPlacementRecommendations:
    """Build account-level placement recommendation."""
    allowed_iam_user_arns = _build_iam_user_arns_for_recommendation(
        check_name,
        safe_check_results,
        [r.account_id for r in safe_check_results]
    )

    compliance_pct = len(safe_check_results) / total_results * 100.0

    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level=PlacementLevel.ACCOUNT,
        target_ou_id=None,
        affected_accounts=[r.account_id for r in safe_check_results],
        compliance_percentage=compliance_pct,
        reasoning=f"Only {len(safe_check_results)} out of {total_results} accounts have zero violations - deploy at individual account level",
        allowed_iam_user_arns=allowed_iam_user_arns
    )

def _determine_check_placement(
    check_name: str,
    check_results: List[SCPCheckResult],
    analyzer: HierarchyPlacementAnalyzer,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """Determine placement recommendations for a single check."""
    safe_check_results = _get_safe_results(check_results)

    if not safe_check_results:
        return [_create_no_deployment_recommendation(check_name)]

    candidates = analyzer.determine_placement(
        check_results=check_results,
        is_safe_for_root=lambda results: all(r.violations == ZERO_VIOLATIONS for r in results),
        is_safe_for_ou=lambda ou_id, results: all(r.violations == ZERO_VIOLATIONS for r in results),
        get_account_id=lambda r: r.account_id
    )

    recommendations = []
    for candidate in candidates:
        if candidate.level == PlacementLevel.ROOT:
            rec = _build_root_recommendation(check_name, candidate, check_results)
            recommendations.append(rec)
        elif candidate.level == PlacementLevel.OU and candidate.target_id is not None:
            rec = _build_ou_recommendation(
                check_name,
                candidate,
                check_results,
                organization_hierarchy
            )
            recommendations.append(rec)
        elif candidate.level == PlacementLevel.ACCOUNT:
            rec = _build_account_recommendation(
                check_name,
                safe_check_results,
                len(check_results)
            )
            recommendations.append(rec)
            break  # Only one account-level recommendation needed

    return recommendations

def determine_scp_placement(
    results_data: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Analyze compliance results to determine optimal SCP placement level.

    Finds the highest organizational level where ALL accounts have zero violations.
    """
    recommendations: List[SCPPlacementRecommendations] = []
    analyzer = HierarchyPlacementAnalyzer(organization_hierarchy)

    check_groups = _group_results_by_check_name(results_data)

    for check_name, check_results in check_groups.items():
        logger.info(f"Analyzing placement for check: {check_name}")

        _ensure_account_ids_present(check_results, organization_hierarchy)

        check_recommendations = _determine_check_placement(
            check_name,
            check_results,
            analyzer,
            organization_hierarchy
        )
        recommendations.extend(check_recommendations)

    return recommendations
```

**Test:**
- All existing tests in `tests/test_parse_results.py` should pass
- Add tests for new helper functions
- Run `tox`

---

### Step 3.2: Refactor `run_checks()` in `analysis.py`
**Time:** 2 hours
**Risk:** Medium
**Files to modify:** `headroom/analysis.py`

**Implementation:** (See detailed example in CLEAN_CODE_ANALYSIS.md)

**Test:**
- Run `tests/test_analysis.py`
- Run integration tests
- Run `tox`

---

### Step 3.3: Refactor `_build_scp_terraform_module()` in `generate_scps.py`
**Time:** 3 hours
**Risk:** Medium-High
**Files to modify:** `headroom/terraform/generate_scps.py`

**Implementation:** (See detailed example in CLEAN_CODE_ANALYSIS.md)

**Test:**
- Run `tests/test_generate_scps.py`
- Manually verify generated Terraform files
- Run `tox`

---

### Step 3.4: Refactor `determine_rcp_placement()` in `generate_rcps.py`
**Time:** 1.5 hours
**Risk:** Low-Medium
**Files to modify:** `headroom/terraform/generate_rcps.py`

**Focus:**
- Extract lambda functions to named helper functions
- Ensure consistency with SCP refactoring patterns
- Already partially refactored, so lighter work needed

**Test:**
- Run `tests/test_generate_rcps.py`
- Run `tox`

---

## Phase 4: Improve Testability

### Step 4.1: Separate Terraform Structure from Rendering
**Time:** 4 hours
**Risk:** Medium
**Files to create:** `headroom/terraform/models.py`

**Create data models:**
```python
from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass
class TerraformParameter:
    """Single parameter in a Terraform module."""
    key: str
    value: Any

    def render(self) -> str:
        """Render parameter as HCL."""
        if isinstance(self.value, bool):
            return f"  {self.key} = {str(self.value).lower()}"
        elif isinstance(self.value, list):
            if not self.value:
                return f"  {self.key} = []"
            items = [f'    "{item}",' for item in self.value]
            return f"  {self.key} = [\n" + "\n".join(items) + "\n  ]"
        elif isinstance(self.value, str):
            return f'  {self.key} = "{self.value}"'
        else:
            return f"  {self.key} = {self.value}"

@dataclass
class TerraformModule:
    """Structured representation of Terraform module."""
    name: str
    source: str
    target_id: str
    parameters: List[TerraformParameter]
    comment: str = ""

    def render(self) -> str:
        """Render module as Terraform HCL."""
        lines = []

        if self.comment:
            lines.append(f"# Auto-generated SCP Terraform configuration for {self.comment}")
            lines.append("# Generated by Headroom based on compliance analysis")
            lines.append("")

        lines.extend([
            f'module "{self.name}" {{',
            f'  source = "{self.source}"',
            f'  target_id = {self.target_id}',
            ""
        ])

        for param in self.parameters:
            lines.append(param.render())

        lines.append("}")
        return "\n".join(lines) + "\n"
```

**Refactor builders to create models:**
```python
def _build_scp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[SCPPlacementRecommendations],
    comment: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """Build Terraform module call for SCP deployment."""
    config = _extract_scp_configuration(recommendations, organization_hierarchy)
    parameters = _build_terraform_parameters(config)

    module = TerraformModule(
        name=module_name,
        source="../modules/scps",
        target_id=target_id_reference,
        parameters=parameters,
        comment=comment
    )

    return module.render()
```

**Test:**
- Create tests for TerraformModule and TerraformParameter rendering
- Test parameter building separately from rendering
- Run `tox`

---

## Phase 5: Consistent Naming and Organization

### Step 5.1: Rename Functions for Consistency
**Time:** 1 hour
**Risk:** Low (mostly find-and-replace)

**Renames:**
- `parse_scp_results()` → `analyze_scp_placement()` (to match its actual behavior)
- Or split into: `parse_scp_result_files()` + `analyze_scp_placement()`

**Files to update:**
- `headroom/main.py`
- `headroom/parse_results.py`
- Test files

**Test:** Run `tox`

---

### Step 5.2: Organize Utility Functions
**Time:** 30 minutes
**Risk:** Low

**Create `headroom/utils.py` with:**
- `format_account_identifier()`
- `make_safe_variable_name()` (move from terraform/utils.py)
- Other shared utilities

**Update imports throughout codebase**

**Test:** Run `tox`

---

## Phase 6: Performance Optimizations

### Step 6.1: Pre-build Lookup Maps in `determine_scp_placement()`
**Time:** 1 hour
**Risk:** Low

**Implementation:** See CLEAN_CODE_ANALYSIS.md for details

**Test:**
- Run performance benchmarks
- Run all tests
- Run `tox`

---

## Testing Strategy

### After Each Phase:
1. Run `tox` to execute all tests
2. Run integration test: `python -m headroom --config my_config.yaml`
3. Review generated Terraform files
4. Check linting: `mypy headroom/`

### Regression Testing Checklist:
- [ ] All existing tests pass
- [ ] No new mypy errors
- [ ] No new linting errors
- [ ] Generated Terraform files unchanged (or intentionally changed)
- [ ] Performance not degraded

---

## Rollback Plan

### If Issues Arise:
1. Git checkout to previous commit
2. Review specific changes that caused issues
3. Fix and re-apply

### Keep These Branches:
- `main` - production code
- `refactor/phase-1` - Phase 1 changes
- `refactor/phase-2` - Phase 2 changes
- etc.

---

## Success Metrics

### Code Quality Metrics:
- [ ] Functions average < 30 lines
- [ ] No functions > 50 lines
- [ ] Cyclomatic complexity < 10 for all functions
- [ ] Test coverage maintained or improved
- [ ] No magic strings (use enums/constants)
- [ ] All code passes mypy strict mode

### Maintainability Metrics:
- [ ] New developer can add a check in < 1 hour
- [ ] Code reviews take < 30 minutes
- [ ] Bug fixes require < 3 file changes

---

## Timeline Estimate

- **Phase 1:** 1-2 days
- **Phase 2:** 2-3 days
- **Phase 3:** 4-5 days
- **Phase 4:** 2-3 days
- **Phase 5:** 1 day
- **Phase 6:** 1 day

**Total:** 11-15 days (approximately 2-3 weeks)

---

## Notes

- Take breaks between phases
- Don't rush - quality over speed
- Write tests first when possible
- Review your own code before committing
- Consider pair programming for high-risk changes
